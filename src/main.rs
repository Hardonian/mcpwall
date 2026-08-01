use sha2::{Digest, Sha256};
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
    approval_ttl_seconds: u64,
    audit_path: PathBuf,
    inventory_path: Option<PathBuf>,
    require_known_tools: bool,
}

fn usage() {
    println!(
        "mcpwall 0.3.0 — local MCP policy firewall\n\nUsage:\n  mcpwall doctor --config FILE --server NAME\n  mcpwall proxy  --config FILE --server NAME\n  mcpwall approvals --config FILE --server NAME\n  mcpwall approve --config FILE --server NAME --hash HASH REQUEST_ID\n  mcpwall deny    --config FILE --server NAME --hash HASH REQUEST_ID\n  mcpwall inventory --config FILE --server NAME\n  mcpwall --help\n\nThe proxy speaks newline-delimited JSON-RPC over stdin/stdout. Approval decisions are hash-bound and one-time."
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
        approval_ttl_seconds: 300,
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
        } else if let Some(v) = value_after(line, "approval_ttl_seconds") {
            p.approval_ttl_seconds = v
                .parse()
                .map_err(|_| format!("invalid approval_ttl_seconds: {v}"))?;
        } else if let Some(v) = value_after(line, "inventory_path") {
            p.inventory_path = Some(PathBuf::from(parse_string(v)?));
        } else if let Some(v) = value_after(line, "require_known_tools") {
            p.require_known_tools = v
                .parse()
                .map_err(|_| format!("invalid require_known_tools: {v}"))?;
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

fn named_values(line: &str, field: &str) -> Vec<String> {
    let needle = format!("\"{field}\"");
    let mut values = Vec::new();
    let mut from = 0;
    while let Some(rel) = line[from..].find(&needle) {
        let pos = from + rel;
        let rest = line[pos + needle.len()..].trim_start();
        let Some(rest) = rest.strip_prefix(':').map(str::trim_start) else {
            from = pos + needle.len();
            continue;
        };
        let Some(end) = rest.strip_prefix('"').and_then(|x| x.find('"')) else {
            from = pos + needle.len();
            continue;
        };
        values.push(rest[1..=end].to_owned());
        from = pos + needle.len();
    }
    values
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Approval {
    request_id: String,
    request_hash: String,
    tool: String,
    state: String,
    created_at: u64,
    expires_at: u64,
}

fn approval_path(p: &Policy) -> PathBuf {
    PathBuf::from(format!("{}.approvals.tsv", p.audit_path.display()))
}
fn approval_lock_path(p: &Policy) -> PathBuf {
    PathBuf::from(format!("{}.lock", approval_path(p).display()))
}
fn escape_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}
fn unescape_field(value: &str) -> String {
    value
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\\\", "\\")
}
fn serialize_approval(a: &Approval) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        escape_field(&a.request_id),
        a.request_hash,
        escape_field(&a.tool),
        a.state,
        a.created_at,
        a.expires_at
    )
}
fn parse_approval(line: &str) -> Option<Approval> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != 6 {
        return None;
    }
    Some(Approval {
        request_id: unescape_field(fields[0]),
        request_hash: fields[1].to_owned(),
        tool: unescape_field(fields[2]),
        state: fields[3].to_owned(),
        created_at: fields[4].parse().ok()?,
        expires_at: fields[5].parse().ok()?,
    })
}
fn load_approvals(p: &Policy) -> Vec<Approval> {
    fs::read_to_string(approval_path(p))
        .unwrap_or_default()
        .lines()
        .filter_map(parse_approval)
        .collect()
}
fn save_approvals(p: &Policy, records: &[Approval]) -> io::Result<()> {
    let path = approval_path(p);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
    let body = records
        .iter()
        .map(serialize_approval)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        &tmp,
        if body.is_empty() {
            String::new()
        } else {
            body + "\n"
        },
    )?;
    fs::rename(tmp, path)
}
struct QueueLock {
    path: PathBuf,
}
impl Drop for QueueLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
fn acquire_queue_lock(p: &Policy) -> io::Result<QueueLock> {
    let path = approval_lock_path(p);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    for _ in 0..50 {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(QueueLock { path }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "approval queue is locked",
    ))
}
fn request_hash(line: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(line.as_bytes());
    format!("{:x}", digest.finalize())
}
fn approval_status(p: &Policy, request_id: &str, hash: &str, now: u64) -> Result<bool, String> {
    let mut records = load_approvals(p);
    let mut changed = false;
    let mut approved = false;
    for record in &mut records {
        if record.request_id == request_id && record.request_hash == hash {
            if record.state == "approved" && record.expires_at > now {
                record.state = "consumed".into();
                approved = true;
                changed = true;
            } else if record.state == "approved" && record.expires_at <= now {
                record.state = "expired".into();
                changed = true;
            }
        }
    }
    if changed {
        let _lock = acquire_queue_lock(p).map_err(|e| e.to_string())?;
        save_approvals(p, &records).map_err(|e| e.to_string())?;
    }
    Ok(approved)
}
fn enqueue_approval(
    p: &Policy,
    request_id: &str,
    hash: &str,
    tool: &str,
    now: u64,
) -> Result<(), String> {
    let _lock = acquire_queue_lock(p).map_err(|e| e.to_string())?;
    let mut records = load_approvals(p);
    if !records
        .iter()
        .any(|x| x.request_id == request_id && x.request_hash == hash)
    {
        records.push(Approval {
            request_id: request_id.into(),
            request_hash: hash.into(),
            tool: tool.into(),
            state: "pending".into(),
            created_at: now,
            expires_at: now + p.approval_ttl_seconds,
        });
        save_approvals(p, &records).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn mutate_approval(
    p: &Policy,
    request_id: &str,
    hash: &str,
    state: &str,
    ttl: u64,
) -> Result<(), String> {
    let _lock = acquire_queue_lock(p).map_err(|e| e.to_string())?;
    let mut records = load_approvals(p);
    let now = now();
    let mut found = false;
    for record in &mut records {
        if record.request_id == request_id
            && record.request_hash == hash
            && record.state == "pending"
        {
            record.state = state.into();
            record.expires_at = now + ttl;
            found = true;
        }
    }
    if !found {
        return Err("no matching pending approval (request ID and hash must match)".into());
    }
    save_approvals(p, &records).map_err(|e| e.to_string())
}
fn list_approvals(p: &Policy) {
    for record in load_approvals(p) {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            record.request_id,
            record.request_hash,
            record.tool,
            record.state,
            record.created_at,
            record.expires_at
        );
    }
}

fn inventory_path(p: &Policy) -> PathBuf {
    p.inventory_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.tools", p.audit_path.display())))
}
fn inventory(p: &Policy) -> Result<(), String> {
    let mut child = Command::new(&p.command)
        .args(&p.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", p.command))?;
    let mut input = child.stdin.take().ok_or("child stdin unavailable")?;
    let output = child.stdout.take().ok_or("child stdout unavailable")?;
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n")
        .map_err(|e| e.to_string())?;
    input.flush().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(output);
    let mut response = String::new();
    reader.read_line(&mut response).map_err(|e| e.to_string())?;
    if response.is_empty() {
        return Err("child exited without tools/list response".into());
    }
    let mut names = named_values(&response, "name");
    names.sort();
    names.dedup();
    let path = inventory_path(p);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
    fs::write(
        &tmp,
        if names.is_empty() {
            String::new()
        } else {
            names.join("\n") + "\n"
        },
    )
    .map_err(|e| e.to_string())?;
    fs::rename(tmp, &path).map_err(|e| e.to_string())?;
    let _ = child.kill();
    println!("inventory: {} tools", names.len());
    println!("path: {}", path.display());
    for name in names {
        println!("tool: {name}");
    }
    Ok(())
}
fn known_tool(p: &Policy, tool: &str) -> bool {
    if !p.require_known_tools {
        return true;
    }
    fs::read_to_string(inventory_path(p))
        .unwrap_or_default()
        .lines()
        .any(|x| x.trim() == tool)
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
    println!("approval ttl: {}s", p.approval_ttl_seconds);
    if p.require_known_tools {
        let path = inventory_path(p);
        if !path.exists() {
            return Err(format!(
                "tool inventory missing: {} (run inventory first)",
                path.display()
            ));
        }
        println!("inventory: {}", path.display());
    }
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
        let hash = request_hash(&line);
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
                || !known_tool(p, t)
            {
                let reason = if !known_tool(p, t) {
                    "tool not present in inventory"
                } else {
                    "tool denied by policy"
                };
                let out = error_response(&id, reason);
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
            if p.require_approval.iter().any(|x| x == t) && !approval_status(p, &id, &hash, ts)? {
                enqueue_approval(p, &id, &hash, t, ts)?;
                let out = error_response(
                    &id,
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
            "inventory" => inventory(&policy),
            "approvals" => {
                list_approvals(&policy);
                Ok(())
            }
            "approve" | "deny" => {
                let id = args.last().ok_or("missing request id")?;
                let hash = arg_value(&args, "--hash")?;
                let ttl = args
                    .windows(2)
                    .find(|w| w[0] == "--ttl")
                    .map(|w| w[1].parse::<u64>().map_err(|_| "invalid --ttl"))
                    .transpose()?
                    .unwrap_or(policy.approval_ttl_seconds);
                let state = if command == "approve" {
                    "approved"
                } else {
                    "denied"
                };
                mutate_approval(&policy, id, &hash, state, ttl)?;
                println!("{} {} {}", command, id, hash);
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
    #[test]
    fn request_hash_is_sha256() {
        assert_eq!(
            request_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn approval_round_trip() {
        let original = Approval {
            request_id: "7".into(),
            request_hash: "abc".into(),
            tool: "delete_file".into(),
            state: "pending".into(),
            created_at: 10,
            expires_at: 20,
        };
        assert_eq!(
            parse_approval(&serialize_approval(&original)),
            Some(original)
        );
    }
}
