use std::collections::VecDeque;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Default, Clone)]
struct Policy {
    command: String,
    args: Vec<String>,
    allowed_tools: Vec<String>,
    denied_tools: Vec<String>,
    require_approval: Vec<String>,
    allowed_roots: Vec<String>,
    redact_patterns: Vec<String>,
    max_calls_per_minute: usize,
    audit_path: PathBuf,
}

fn usage() {
    println!(
        "mcpwall 0.1.0 — local MCP policy firewall\n\nUsage:\n  mcpwall doctor --config FILE --server NAME\n  mcpwall proxy  --config FILE --server NAME\n  mcpwall approve --config FILE --server NAME REQUEST_ID\n  mcpwall deny    --config FILE --server NAME REQUEST_ID\n  mcpwall --help\n\nThe proxy speaks newline-delimited JSON-RPC over stdin/stdout."
    );
}

fn value_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{} =", key);
    line.strip_prefix(&prefix).map(str::trim)
}

fn parse_string(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return Err(format!("expected quoted string: {s}"));
    }
    Ok(s[1..s.len() - 1]
        .replace("\\\"", "\"")
        .replace("\\\\", "\\"))
}

fn parse_array(raw: &str) -> Result<Vec<String>, String> {
    let s = raw.trim();
    if s == "[]" {
        return Ok(Vec::new());
    }
    if !s.starts_with('[') || !s.ends_with(']') {
        return Err(format!("expected string array: {s}"));
    }
    s[1..s.len() - 1].split(',').map(parse_string).collect()
}

fn load_policy(path: &Path, server: &str) -> Result<Policy, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let wanted = format!("[server.{server}]");
    let mut active = false;
    let mut p = Policy {
        max_calls_per_minute: 60,
        audit_path: PathBuf::from("mcpwall-audit.jsonl"),
        ..Policy::default()
    };
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            active = line == wanted;
            continue;
        }
        if !active {
            continue;
        }
        if let Some(v) = value_after(line, "command") {
            p.command = parse_string(v)?;
        } else if let Some(v) = value_after(line, "args") {
            p.args = parse_array(v)?;
        } else if let Some(v) = value_after(line, "allowed_tools") {
            p.allowed_tools = parse_array(v)?;
        } else if let Some(v) = value_after(line, "denied_tools") {
            p.denied_tools = parse_array(v)?;
        } else if let Some(v) = value_after(line, "require_approval") {
            p.require_approval = parse_array(v)?;
        } else if let Some(v) = value_after(line, "allowed_roots") {
            p.allowed_roots = parse_array(v)?;
        } else if let Some(v) = value_after(line, "redact_patterns") {
            p.redact_patterns = parse_array(v)?;
        } else if let Some(v) = value_after(line, "max_calls_per_minute") {
            p.max_calls_per_minute = v
                .parse()
                .map_err(|_| format!("invalid max_calls_per_minute: {v}"))?;
        } else if let Some(v) = value_after(line, "audit_path") {
            p.audit_path = PathBuf::from(parse_string(v)?);
        }
    }
    if !active {
        return Err(format!("server section not found: {server}"));
    }
    if p.command.is_empty() {
        return Err("command is required".into());
    }
    if p.max_calls_per_minute == 0 {
        return Err("max_calls_per_minute must be greater than zero".into());
    }
    Ok(p)
}

fn json_string_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                if !escaped && bytes[i] == b'"' {
                    out.push(line[start..i].replace("\\\"", "\"").replace("\\\\", "\\"));
                    i += 1;
                    break;
                }
                escaped = !escaped && bytes[i] == b'\\';
                if bytes[i] != b'\\' {
                    escaped = false;
                }
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

fn json_field(line: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let pos = line.find(&needle)?;
    let rest = line[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')? + 1;
        Some(rest[..=end].to_string())
    } else {
        Some(rest.split([',', '}']).next()?.trim().to_string())
    }
}

fn tool_name(line: &str) -> Option<String> {
    json_field(line, "name").and_then(|x| parse_string(&x).ok())
}
fn request_id(line: &str) -> String {
    json_field(line, "id").unwrap_or_else(|| "null".into())
}

fn redact(mut line: String, patterns: &[String]) -> String {
    for pattern in patterns {
        let needle = format!("\"{pattern}\"");
        let mut from = 0;
        while let Some(rel) = line[from..].find(&needle) {
            let key = from + rel;
            let colon = match line[key + needle.len()..].find(':') {
                Some(offset) => key + needle.len() + offset,
                None => break,
            };
            let mut value_start = colon + 1;
            while line
                .as_bytes()
                .get(value_start)
                .is_some_and(|b| b.is_ascii_whitespace())
            {
                value_start += 1;
            }
            if line.as_bytes().get(value_start) != Some(&b'"') {
                from = key + needle.len();
                continue;
            }
            let Some(end) = line[value_start + 1..].find('"') else {
                from = key + needle.len();
                continue;
            };
            let value_end = value_start + 1 + end;
            line.replace_range(value_start + 1..value_end, "***REDACTED***");
            from = value_start + 15;
            continue;
        }
    }
    line
}

fn audit(path: &Path, event: &str, patterns: &[String]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let safe = redact(event.to_string(), patterns);
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{safe}")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn error_response(id: &str, message: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":-32001,"message":"{}"}}}}"#,
        id,
        message.replace('"', "'")
    )
}

fn approved_path(p: &Policy) -> PathBuf {
    PathBuf::from(format!("{}.approved", p.audit_path.display()))
}
fn is_approved(p: &Policy, id: &str) -> io::Result<bool> {
    Ok(fs::read_to_string(approved_path(p))
        .unwrap_or_default()
        .lines()
        .any(|x| x.trim() == id))
}
fn set_approval(p: &Policy, id: &str, allow: bool) -> io::Result<()> {
    let path = approved_path(p);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut ids: Vec<String> = fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .filter(|x| x != id)
        .collect();
    if allow {
        ids.push(id.to_owned());
    }
    fs::write(
        path,
        ids.join("\n") + if ids.is_empty() { "" } else { "\n" },
    )
}

fn doctor(p: &Policy) -> Result<(), String> {
    println!("policy: ok");
    println!("command: {}", p.command);
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v '{}'", p.command.replace('\'', "'\\''")))
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() && !Path::new(&p.command).exists() {
        return Err(format!("command not found: {}", p.command));
    }
    println!("command: available");
    if p.allowed_tools.is_empty() {
        println!("tools: allow-all except explicit denies");
    } else {
        println!("tools: {} allowed", p.allowed_tools.len());
    }
    println!("approval rules: {}", p.require_approval.len());
    println!("audit: {}", p.audit_path.display());
    println!("status: healthy");
    Ok(())
}

fn proxy(p: &Policy) -> Result<(), String> {
    let mut child = Command::new(&p.command)
        .args(&p.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", p.command))?;
    let mut child_in = child.stdin.take().ok_or("child stdin unavailable")?;
    let child_out = child.stdout.take().ok_or("child stdout unavailable")?;
    let mut child_out = BufReader::new(child_out);
    let stdin = io::stdin();
    let mut calls: VecDeque<u64> = VecDeque::new();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let method = json_field(&line, "method")
            .and_then(|x| parse_string(&x).ok())
            .unwrap_or_default();
        let tool = if method == "tools/call" {
            tool_name(&line)
        } else {
            None
        };
        let id = request_id(&line);
        let ts = now();
        while calls.front().is_some_and(|x| *x + 60 <= ts) {
            calls.pop_front();
        }
        if calls.len() >= p.max_calls_per_minute {
            let out = error_response(&id, "rate limit exceeded");
            println!("{out}");
            audit(
                &p.audit_path,
                &format!(r#"{{"event":"deny","reason":"rate_limit","id":{id}}}"#),
                &p.redact_patterns,
            )
            .map_err(|e| e.to_string())?;
            continue;
        }
        calls.push_back(ts);
        if let Some(t) = &tool {
            if p.denied_tools.iter().any(|x| x == t)
                || (!p.allowed_tools.is_empty() && !p.allowed_tools.iter().any(|x| x == t))
            {
                let out = error_response(&id, "tool denied by policy");
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"tool","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
            let mut path_denied = false;
            for value in json_string_fields(&line)
                .into_iter()
                .filter(|x| x.starts_with('/'))
            {
                if !p.allowed_roots.is_empty()
                    && !p
                        .allowed_roots
                        .iter()
                        .any(|root| value == *root || value.starts_with(&(root.clone() + "/")))
                {
                    path_denied = true;
                    break;
                }
            }
            if path_denied {
                let out = error_response(&id, "path denied by policy");
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"path","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
            if p.require_approval.iter().any(|x| x == t)
                && !is_approved(p, &id).map_err(|e| e.to_string())?
            {
                let out = error_response(&id, &format!("approval required; request_id={id}"));
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(
                        r#"{{"event":"approval_required","tool":"{t}","id":{id},"request":{line}}}"#
                    ),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
        }
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
            return Err("child exited without a JSON-RPC response".into());
        }
        print!("{response}");
        io::stdout().flush().map_err(|e| e.to_string())?;
        audit(&p.audit_path, &format!(r#"{{"event":"forward","method":"{method}","tool":{},"id":{id},"request":{line},"response":{}}}"#, tool.map(|x| format!("\"{x}\"")).unwrap_or_else(|| "null".into()), response.trim_end()), &p.redact_patterns).map_err(|e| e.to_string())?;
    }
    let _ = child.kill();
    Ok(())
}

fn arg_value(args: &[String], name: &str) -> Result<String, String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .ok_or_else(|| format!("missing {name}"))
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|x| x == "--help" || x == "-h") {
        usage();
        return;
    }
    let command = &args[0];
    let result = (|| -> Result<(), String> {
        let config = PathBuf::from(arg_value(&args, "--config")?);
        let server = arg_value(&args, "--server")?;
        let policy = load_policy(&config, &server)?;
        match command.as_str() {
            "doctor" => doctor(&policy),
            "proxy" => proxy(&policy),
            "approve" | "deny" => {
                let id = args.last().ok_or("missing request id")?;
                set_approval(&policy, id, command == "approve").map_err(|e| e.to_string())?;
                println!("{} {}", command, id);
                Ok(())
            }
            _ => Err(format!("unknown command: {command}")),
        }
    })();
    if let Err(e) = result {
        eprintln!("mcpwall: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arrays_parse() {
        assert_eq!(parse_array("[\"a\", \"b\"]").unwrap(), vec!["a", "b"]);
    }
    #[test]
    fn fields_parse() {
        assert_eq!(
            tool_name(r#"{"method":"tools/call","params":{"name":"read_file"}}"#).as_deref(),
            Some("read_file")
        );
    }
    #[test]
    fn redacts_values() {
        let got = redact(
            r#"{"api_key":"secret-value","ok":true}"#.into(),
            &["api_key".into()],
        );
        assert!(got.contains("***REDACTED***"));
        assert!(!got.contains("secret-value"));
    }
}
