use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Clone, Default)]
struct Policy {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    allowed_tools: Vec<String>,
    #[serde(default)]
    denied_tools: Vec<String>,
    #[serde(default)]
    require_approval: Vec<String>,
    #[serde(default)]
    allowed_roots: Vec<String>,
    #[serde(default)]
    redact_patterns: Vec<String>,
    #[serde(default = "default_calls")]
    max_calls_per_minute: usize,
    #[serde(default = "default_request_bytes")]
    max_request_bytes: usize,
    #[serde(default = "default_argument_bytes")]
    max_argument_bytes: usize,
    #[serde(default)]
    denied_argument_keys: Vec<String>,
    #[serde(default)]
    denied_argument_values: Vec<String>,
    #[serde(default = "default_approval_ttl")]
    approval_ttl_seconds: u64,
    #[serde(default)]
    inventory_max_age_seconds: u64,
    #[serde(default = "default_audit_path")]
    audit_path: PathBuf,
    inventory_path: Option<PathBuf>,
    #[serde(default)]
    require_known_tools: bool,
}

fn default_calls() -> usize {
    60
}
fn default_request_bytes() -> usize {
    65_536
}
fn default_argument_bytes() -> usize {
    32_768
}
fn default_approval_ttl() -> u64 {
    300
}
fn default_audit_path() -> PathBuf {
    PathBuf::from("mcpwall-audit.jsonl")
}

#[derive(Debug, Deserialize)]
struct Config {
    server: BTreeMap<String, Policy>,
}

fn usage() {
    println!(
        "mcpwall 0.5.0 — local MCP policy firewall\n\nUsage:\n  mcpwall doctor --config FILE --server NAME\n  mcpwall proxy  --config FILE --server NAME\n  mcpwall status --config FILE --server NAME\n  mcpwall inventory --config FILE --server NAME\n  mcpwall approvals --config FILE --server NAME\n  mcpwall approve --config FILE --server NAME --hash HASH REQUEST_ID\n  mcpwall deny    --config FILE --server NAME --hash HASH REQUEST_ID\n  mcpwall --help\n\nThe proxy speaks newline-delimited JSON-RPC over stdin/stdout. Approval decisions are hash-bound and one-time."
    );
}

fn load_policy(path: &Path, server: &str) -> Result<Policy, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let config: Config =
        toml::from_str(&content).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let mut policy = config
        .server
        .get(server)
        .cloned()
        .ok_or_else(|| format!("server section not found: {server}"))?;
    if policy.command.is_empty() {
        return Err("command is required".into());
    }
    if policy.max_calls_per_minute == 0 {
        return Err("max_calls_per_minute must be greater than zero".into());
    }
    if policy.max_request_bytes == 0 {
        return Err("max_request_bytes must be greater than zero".into());
    }
    if policy.max_argument_bytes == 0 {
        return Err("max_argument_bytes must be greater than zero".into());
    }
    if policy.audit_path.as_os_str().is_empty() {
        policy.audit_path = default_audit_path();
    }
    Ok(policy)
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
    #[cfg(unix)]
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut f = options.open(path)?;
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
    let content = if body.is_empty() {
        String::new()
    } else {
        body + "\n"
    };
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
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
    if !p.require_known_tools || !inventory_fresh(p) {
        return !p.require_known_tools;
    }
    fs::read_to_string(inventory_path(p))
        .unwrap_or_default()
        .lines()
        .any(|x| x.trim() == tool)
}

fn inventory_fresh(p: &Policy) -> bool {
    if p.inventory_max_age_seconds == 0 {
        return true;
    }
    fs::metadata(inventory_path(p))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age.as_secs() <= p.inventory_max_age_seconds)
}
fn parse_request(line: &str, max_bytes: usize) -> Result<Value, String> {
    if line.len() > max_bytes {
        return Err(format!("request exceeds max_request_bytes={max_bytes}"));
    }
    serde_json::from_str(line).map_err(|e| format!("invalid JSON-RPC request: {e}"))
}
fn request_method(request: &Value) -> String {
    request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
fn request_tool(request: &Value) -> Option<String> {
    request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .map(str::to_owned)
}
fn request_id_value(request: &Value) -> String {
    request
        .get("id")
        .map(ToString::to_string)
        .unwrap_or_else(|| "null".into())
}
fn argument_violation(value: &Value, p: &Policy) -> Option<String> {
    let args = value.pointer("/params/arguments").unwrap_or(&Value::Null);
    if args.to_string().len() > p.max_argument_bytes {
        return Some(format!(
            "arguments exceed max_argument_bytes={}",
            p.max_argument_bytes
        ));
    }
    fn walk(value: &Value, p: &Policy) -> Option<String> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if p.denied_argument_keys.iter().any(|x| x == key) {
                        return Some(format!("argument key denied: {key}"));
                    }
                    match child {
                        Value::String(text)
                            if p.denied_argument_values.iter().any(|x| text.contains(x)) =>
                        {
                            return Some(format!("argument value denied for key: {key}"));
                        }
                        _ => {}
                    }
                    if let Some(reason) = walk(child, p) {
                        return Some(reason);
                    }
                }
            }
            Value::Array(items) => {
                for child in items {
                    if let Some(reason) = walk(child, p) {
                        return Some(reason);
                    }
                }
            }
            _ => {}
        }
        None
    }
    walk(args, p)
}

fn status(p: &Policy) -> Result<(), String> {
    let approvals = load_approvals(p);
    let mut counts = std::collections::BTreeMap::new();
    for approval in approvals {
        *counts.entry(approval.state).or_insert(0usize) += 1;
    }
    println!("version: 0.5.0");
    println!("command: {}", p.command);
    println!("audit_exists: {}", p.audit_path.exists());
    println!(
        "audit_bytes: {}",
        fs::metadata(&p.audit_path).map(|m| m.len()).unwrap_or(0)
    );
    println!("approval_queue: {}", approval_path(p).display());
    println!("approval_counts: {:?}", counts);
    println!("inventory: {}", inventory_path(p).display());
    println!("inventory_fresh: {}", inventory_fresh(p));
    println!(
        "limits: request_bytes={} argument_bytes={} calls_per_minute={}",
        p.max_request_bytes, p.max_argument_bytes, p.max_calls_per_minute
    );
    println!("status: healthy");
    Ok(())
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
        if !inventory_fresh(p) {
            return Err(format!("tool inventory is stale: {}", path.display()));
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
        let request = match parse_request(&line, p.max_request_bytes) {
            Ok(value) => value,
            Err(reason) => {
                let out = error_response("null", &reason);
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
            if let Some(reason) = argument_violation(&request, p) {
                let out = error_response(&id, &reason);
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"argument","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
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
            "status" => status(&policy),
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
    fn toml_config_parses_escaped_values() {
        let config: Config = toml::from_str(
            "[server.fixture]\ncommand = \"/bin/sh\"\nargs = [\"-c\", \"printf # safe\"]\n",
        )
        .unwrap();
        assert_eq!(config.server["fixture"].args[1], "printf # safe");
    }
    #[test]
    fn fields_parse() {
        let value: Value =
            serde_json::from_str(r#"{"method":"tools/call","params":{"name":"read_file"}}"#)
                .unwrap();
        assert_eq!(request_tool(&value).as_deref(), Some("read_file"));
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
    fn argument_policy_blocks_dangerous_key_and_value() {
        let p = Policy {
            max_argument_bytes: 100,
            denied_argument_keys: vec!["shell".into()],
            denied_argument_values: vec!["PRIVATE".into()],
            ..Policy::default()
        };
        let key: Value = serde_json::from_str(r#"{"params":{"arguments":{"shell":"x"}}}"#).unwrap();
        assert!(argument_violation(&key, &p).is_some());
        let value: Value =
            serde_json::from_str(r#"{"params":{"arguments":{"note":"PRIVATE"}}}"#).unwrap();
        assert!(argument_violation(&value, &p).is_some());
    }
    #[test]
    fn malformed_and_oversized_requests_fail_closed() {
        assert!(parse_request("not-json", 100).is_err());
        assert!(parse_request("{}", 1).is_err());
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
