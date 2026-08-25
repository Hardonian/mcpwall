//! High-performance bidirectional stdio firewall proxy engine.

use crate::approval::{approval_status, enqueue_approval, now_seconds, request_hash};
use crate::audit::audit;
use crate::config::Policy;
use crate::jsonrpc::{
    CODE_APPROVAL_REQUIRED, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND,
    CODE_RATE_LIMITED, error_response, extract_all_strings, parse_request, request_id_value,
    request_method, request_tool,
};
use crate::policy::{
    RateLimiter, argument_violation, is_tool_allowed, path_allowed, tool_schema_violation,
};
use crate::sandbox::{apply_sandbox, arm_timeout, kill_process_group};
use crate::schema::{json_schema_violation, load_schema_validators};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;

/// Runs the main MCPWall stdio firewall proxy loop.
pub fn proxy(p: &Policy) -> Result<(), String> {
    let validators = load_schema_validators(p)?;
    let mut command = Command::new(&p.command);
    command.args(&p.args);
    apply_sandbox(&mut command, &p.sandbox)?;

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", p.command))?;

    let timeout_seconds = if p.sandbox.enabled {
        p.sandbox.timeout_seconds
    } else {
        0
    };
    let (finished, watchdog) = arm_timeout(child.id(), timeout_seconds);

    let mut child_in = child.stdin.take().ok_or("child stdin unavailable")?;
    let child_out = child.stdout.take().ok_or("child stdout unavailable")?;
    let mut child_out = BufReader::new(child_out);

    let stdin = io::stdin();
    let mut rate_limiter = RateLimiter::new();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }

        let request = match parse_request(&line, p.max_request_bytes) {
            Ok(value) => value,
            Err(reason) => {
                let out = error_response("null", CODE_INVALID_REQUEST, &reason);
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(
                        r#"{{"event":"deny","reason":"invalid_request","detail":"{}"}}"#,
                        reason.replace('"', "'")
                    ),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
        };

        let method = request_method(&request);
        let tool = if method == "tools/call" {
            request_tool(&request)
        } else {
            None
        };
        let id = request_id_value(&request);
        let hash = request_hash(&line);
        let ts = now_seconds();

        // Rate limiting check
        if !rate_limiter.check_and_record(p.max_calls_per_minute) {
            let out = error_response(&id, CODE_RATE_LIMITED, "rate limit exceeded");
            println!("{out}");
            audit(
                &p.audit_path,
                &format!(r#"{{"event":"deny","reason":"rate_limit","id":{id}}}"#),
                &p.redact_patterns,
            )
            .map_err(|e| e.to_string())?;
            continue;
        }

        if let Some(t) = tool {
            // JSON Schema validation
            if let Some(reason) = json_schema_violation(&request, t, &validators) {
                let out = error_response(&id, CODE_INVALID_PARAMS, &reason);
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"json_schema","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }

            // Granular tool schema policy
            if let Some(reason) = tool_schema_violation(&request, t, p) {
                let out = error_response(&id, CODE_INVALID_PARAMS, &reason);
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"schema","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }

            // General argument content checks
            if let Some(reason) = argument_violation(&request, p) {
                let out = error_response(&id, CODE_INVALID_PARAMS, &reason);
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"argument","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }

            // Tool allow/deny & inventory checks
            if let Err(reason) = is_tool_allowed(p, t) {
                let out = error_response(&id, CODE_METHOD_NOT_FOUND, reason);
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"tool","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }

            // Deep path validation across all extracted string arguments
            let mut path_denied = false;
            let extracted_strings = extract_all_strings(&request);
            for value in extracted_strings {
                if (value.starts_with('/') || value.contains(":\\") || value.starts_with("\\\\"))
                    && !path_allowed(value, &p.allowed_roots)
                {
                    path_denied = true;
                    break;
                }
            }
            if path_denied {
                let out = error_response(&id, CODE_INVALID_PARAMS, "path denied by policy");
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"path","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }

            // Approval check
            if p.require_approval.iter().any(|x| x == t) && !approval_status(p, &id, &hash, ts)? {
                enqueue_approval(p, &id, &hash, t, ts)?;
                let out = error_response(
                    &id,
                    CODE_APPROVAL_REQUIRED,
                    &format!("approval required; request_id={id}; request_hash={hash}"),
                );
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(
                        r#"{{"event":"approval_required","tool":"{t}","id":{id},"request_hash":"{hash}","request":{line}}}"#
                    ),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
        }

        // Forward verified request to child
        child_in
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;
        child_in.write_all(b"\n").map_err(|e| e.to_string())?;
        child_in.flush().map_err(|e| e.to_string())?;

        let mut response = String::new();
        child_out
            .read_line(&mut response)
            .map_err(|e| e.to_string())?;

        if response.is_empty() {
            let timed_out = !finished.swap(true, Ordering::SeqCst);
            kill_process_group(&mut child);
            if let Some(handle) = watchdog {
                let _ = handle.join();
            }
            return Err(if timed_out && p.sandbox.timeout_seconds > 0 {
                "child process timed out".into()
            } else {
                "child exited without a JSON-RPC response".into()
            });
        }

        print!("{response}");
        io::stdout().flush().map_err(|e| e.to_string())?;
        audit(
            &p.audit_path,
            &format!(
                r#"{{"event":"forward","method":"{method}","tool":{},"id":{id},"request":{line},"response":{}}}"#,
                tool.map(|x| format!("\"{x}\"")).unwrap_or_else(|| "null".into()),
                response.trim_end()
            ),
            &p.redact_patterns,
        )
        .map_err(|e| e.to_string())?;
    }

    finished.store(true, Ordering::SeqCst);
    kill_process_group(&mut child);
    if let Some(handle) = watchdog {
        let _ = handle.join();
    }
    Ok(())
}
