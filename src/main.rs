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
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    tool_policies: BTreeMap<String, ToolPolicy>,
    #[serde(default)]
    tool_schemas: BTreeMap<String, PathBuf>,
    #[serde(default)]
    sandbox: SandboxPolicy,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
struct SandboxPolicy {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    clear_environment: bool,
    #[serde(default)]
    environment_allowlist: Vec<String>,
    working_dir: Option<PathBuf>,
    #[serde(default)]
    timeout_seconds: u64,
    #[serde(default)]
    max_memory_bytes: u64,
    #[serde(default)]
    max_cpu_seconds: u64,
    #[serde(default)]
    max_file_bytes: u64,
    #[serde(default)]
    max_open_files: u64,
    #[serde(default)]
    max_processes: u64,
    #[serde(default)]
    network_namespace: bool,
    #[serde(default)]
    seccomp_deny_dangerous: bool,
    #[serde(default)]
    mount_namespace: bool,
    #[serde(default)]
    read_only_filesystem: bool,
    #[serde(default)]
    drop_capabilities: Vec<u32>,
    run_as_uid: Option<u32>,
    run_as_gid: Option<u32>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
struct ToolPolicy {
    #[serde(default)]
    allowed_arguments: Vec<String>,
    #[serde(default)]
    required_arguments: Vec<String>,
    #[serde(default)]
    argument_types: BTreeMap<String, String>,
    #[serde(default)]
    path_arguments: Vec<String>,
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
#[serde(deny_unknown_fields)]
struct Config {
    server: BTreeMap<String, Policy>,
}

fn usage() {
    println!(
        "mcpwall 1.0.4 — local MCP policy firewall\n\nUsage:\n  mcpwall doctor --config FILE --server NAME\n  mcpwall proxy  --config FILE --server NAME\n  mcpwall status --config FILE --server NAME\n  mcpwall inventory --config FILE --server NAME\n  mcpwall approvals --config FILE --server NAME\n  mcpwall approve --config FILE --server NAME --hash HASH REQUEST_ID\n  mcpwall deny    --config FILE --server NAME --hash HASH REQUEST_ID\n  mcpwall --help\n\nThe proxy speaks newline-delimited JSON-RPC over stdin/stdout. Approval decisions are hash-bound and one-time."
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
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    for schema_path in policy.tool_schemas.values_mut() {
        if schema_path.is_relative() {
            *schema_path = config_dir.join(&*schema_path);
        }
    }
    validate_schema_files(&policy)?;
    validate_sandbox_policy(&policy.sandbox)?;
    Ok(policy)
}

fn validate_sandbox_policy(sandbox: &SandboxPolicy) -> Result<(), String> {
    if sandbox.read_only_filesystem && !sandbox.mount_namespace {
        return Err("sandbox.read_only_filesystem requires mount_namespace = true".into());
    }
    if sandbox.drop_capabilities.iter().any(|cap| *cap > 63) {
        return Err(
            "sandbox.drop_capabilities values must be Linux capability numbers 0..=63".into(),
        );
    }
    if sandbox
        .drop_capabilities
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err("sandbox.drop_capabilities must not contain duplicates".into());
    }
    if sandbox.run_as_uid.is_some() != sandbox.run_as_gid.is_some() {
        return Err("sandbox.run_as_uid and run_as_gid must be provided together".into());
    }
    if sandbox.run_as_uid == Some(0) {
        return Err("sandbox.run_as_uid must not be root (0)".into());
    }
    if !sandbox.enabled {
        return Ok(());
    }
    if !sandbox.environment_allowlist.is_empty() && !sandbox.clear_environment {
        return Err("sandbox.environment_allowlist requires clear_environment = true".into());
    }
    if sandbox
        .working_dir
        .as_ref()
        .is_some_and(|dir| !dir.is_dir())
    {
        let dir = sandbox.working_dir.as_ref().expect("checked above");
        return Err(format!(
            "sandbox working_dir is not a directory: {}",
            dir.display()
        ));
    }
    Ok(())
}

fn validate_schema_files(p: &Policy) -> Result<(), String> {
    for (tool, path) in &p.tool_schemas {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("read JSON Schema for {tool} ({}): {e}", path.display()))?;
        let schema: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("parse JSON Schema for {tool} ({}): {e}", path.display()))?;
        jsonschema::validator_for(&schema)
            .map_err(|e| format!("compile JSON Schema for {tool} ({}): {e}", path.display()))?;
    }
    Ok(())
}

fn load_schema_validators(p: &Policy) -> Result<BTreeMap<String, jsonschema::Validator>, String> {
    let mut validators = BTreeMap::new();
    for (tool, path) in &p.tool_schemas {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("read JSON Schema for {tool} ({}): {e}", path.display()))?;
        let schema: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("parse JSON Schema for {tool} ({}): {e}", path.display()))?;
        let validator = jsonschema::validator_for(&schema)
            .map_err(|e| format!("compile JSON Schema for {tool} ({}): {e}", path.display()))?;
        validators.insert(tool.clone(), validator);
    }
    Ok(validators)
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
    let mut command = Command::new(&p.command);
    command.args(&p.args);
    apply_sandbox(&mut command, &p.sandbox)?;
    let mut child = command
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
    drop(input);
    let (response_tx, response_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(output);
        let mut response = String::new();
        let result = reader.read_line(&mut response).map(|_| response);
        let _ = response_tx.send(result);
    });
    let timeout = if p.sandbox.timeout_seconds == 0 {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(p.sandbox.timeout_seconds)
    };
    let deadline = Instant::now() + timeout;
    let response = loop {
        match response_rx.try_recv() {
            Ok(result) => break result.map_err(|e| e.to_string())?,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("child output reader stopped unexpectedly".into());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if child
            .try_wait()
            .map_err(|e| format!("wait for inventory child: {e}"))?
            .is_some()
        {
            return Err("child exited without tools/list response".into());
        }
        if Instant::now() >= deadline {
            kill_process_group(&mut child);
            let _ = child.wait();
            return Err("inventory child timed out".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    if response.is_empty() {
        kill_process_group(&mut child);
        let _ = child.wait();
        return Err("child exited without tools/list response".into());
    }
    let mut names = named_values(&response, "name");
    names.sort();
    names.dedup();
    kill_process_group(&mut child);
    let _ = child.wait();
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
fn path_allowed(value: &str, roots: &[String]) -> bool {
    if roots.is_empty() {
        return true;
    }
    let candidate = Path::new(value);
    if !candidate.is_absolute() {
        return false;
    }
    let candidate = normalized_path(candidate);
    roots.iter().any(|root| {
        let root_path = normalized_path(Path::new(root));
        candidate == root_path || candidate.strip_prefix(&root_path).is_ok()
    })
}

fn normalized_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn parse_request(line: &str, max_bytes: usize) -> Result<Value, String> {
    if line.len() > max_bytes {
        return Err(format!("request exceeds max_request_bytes={max_bytes}"));
    }
    let value: Value =
        serde_json::from_str(line).map_err(|e| format!("invalid JSON-RPC request: {e}"))?;
    if !value.is_object() {
        return Err("JSON-RPC batch requests and scalar values are not supported".into());
    }
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err("JSON-RPC version must be \"2.0\"".into());
    }
    if value.get("method").and_then(Value::as_str).is_none() {
        return Err("JSON-RPC method is required".into());
    }
    Ok(value)
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

fn json_schema_violation(
    request: &Value,
    tool: &str,
    validators: &BTreeMap<String, jsonschema::Validator>,
) -> Option<String> {
    let validator = validators.get(tool)?;
    let arguments = request.pointer("/params/arguments").unwrap_or(&Value::Null);
    validator
        .validate(arguments)
        .err()
        .map(|error| format!("JSON Schema validation failed for {tool}: {error}"))
}

fn tool_schema_violation(request: &Value, tool: &str, p: &Policy) -> Option<String> {
    let rule = p.tool_policies.get(tool)?;
    let args = request
        .pointer("/params/arguments")
        .and_then(Value::as_object);
    let Some(args) = args else {
        return Some("tool arguments must be a JSON object".into());
    };
    for key in &rule.required_arguments {
        if !args.contains_key(key) {
            return Some(format!("required argument missing: {key}"));
        }
    }
    if !rule.allowed_arguments.is_empty()
        && args.keys().any(|key| !rule.allowed_arguments.contains(key))
    {
        let key = args
            .keys()
            .find(|key| !rule.allowed_arguments.contains(key))
            .expect("argument key exists after any check");
        return Some(format!("argument not allowed for {tool}: {key}"));
    }
    for (key, expected) in &rule.argument_types {
        let Some(value) = args.get(key) else {
            continue;
        };
        let valid = match expected.as_str() {
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "number" => value.is_number(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "object" => value.is_object(),
            "array" => value.is_array(),
            "null" => value.is_null(),
            other => {
                return Some(format!(
                    "unsupported argument type in policy: {key}={other}"
                ));
            }
        };
        if !valid {
            return Some(format!("argument type mismatch: {key} expected {expected}"));
        }
    }
    for key in &rule.path_arguments {
        let Some(value) = args.get(key).and_then(Value::as_str) else {
            return Some(format!("path argument must be a string: {key}"));
        };
        if !path_allowed(value, &p.allowed_roots) {
            return Some(format!("path argument denied: {key}"));
        }
    }
    None
}

fn status(p: &Policy) -> Result<(), String> {
    let approvals = load_approvals(p);
    let mut counts = std::collections::BTreeMap::new();
    for approval in approvals {
        *counts.entry(approval.state).or_insert(0usize) += 1;
    }
    let inventory_ready = !p.require_known_tools || inventory_fresh(p);
    println!("version: 1.0.4");
    println!("command: {}", p.command);
    println!("audit_exists: {}", p.audit_path.exists());
    println!(
        "audit_bytes: {}",
        fs::metadata(&p.audit_path).map(|m| m.len()).unwrap_or(0)
    );
    println!("approval_queue: {}", approval_path(p).display());
    println!("approval_counts: {:?}", counts);
    println!("json_schemas: {}", p.tool_schemas.len());
    println!("inventory: {}", inventory_path(p).display());
    println!("inventory_fresh: {}", inventory_fresh(p));
    println!(
        "readiness: {}",
        if inventory_ready {
            "healthy"
        } else {
            "degraded"
        }
    );
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
    println!(
        "sandbox: enabled={} timeout_seconds={} network_namespace={} seccomp_deny_dangerous={} mount_namespace={} read_only_filesystem={} drop_capabilities={:?} run_as_uid={:?} run_as_gid={:?}",
        p.sandbox.enabled,
        p.sandbox.timeout_seconds,
        p.sandbox.network_namespace,
        p.sandbox.seccomp_deny_dangerous,
        p.sandbox.mount_namespace,
        p.sandbox.read_only_filesystem,
        p.sandbox.drop_capabilities,
        p.sandbox.run_as_uid,
        p.sandbox.run_as_gid
    );
    println!("json schemas: {}", p.tool_schemas.len());
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

#[cfg(target_arch = "x86_64")]
fn install_seccomp_deny_filter() -> io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JA: u16 = 0x05;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_RET_ERRNO: u32 = 0x00050000;
    const SECCOMP_SET_MODE_FILTER: libc::c_int = 1;
    const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
    const SECCOMP_DATA_NR: u32 = 0;
    const SECCOMP_DATA_ARCH: u32 = 4;
    let denied = [
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_open_by_handle_at,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_keyctl,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
    ];
    let mut filter = Vec::with_capacity(4 + denied.len() * 2);
    filter.push(libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH,
    });
    filter.push(libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_X86_64,
    });
    filter.push(libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    filter.push(libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR,
    });
    for syscall_nr in denied {
        filter.push(libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall_nr as u32,
        });
        filter.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
        });
    }
    filter.push(libc::sock_filter {
        code: BPF_JMP_JA,
        jt: 0,
        jf: 0,
        k: 0,
    });
    filter.push(libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    });
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &program as *const libc::sock_fprog,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn install_seccomp_deny_filter() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "seccomp filter only implemented for x86_64",
    ))
}

#[cfg(unix)]
fn apply_uid_gid(uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    match (uid, gid) {
        (Some(uid), Some(gid)) => unsafe {
            let current_uid = libc::geteuid();
            let current_gid = libc::getegid();
            let group_change = current_gid != gid as libc::gid_t;
            let uid_change = current_uid != uid as libc::uid_t;
            let groups_ok = !group_change || libc::setgroups(0, std::ptr::null()) == 0;
            let gid_ok = !group_change || libc::setgid(gid as libc::gid_t) == 0;
            let uid_ok = !uid_change || libc::setuid(uid as libc::uid_t) == 0;
            if groups_ok && gid_ok && uid_ok {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        },
        (None, None) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UID/GID must be paired",
        )),
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_mount_hardening(
    mount_namespace: bool,
    read_only_filesystem: bool,
) -> io::Result<()> {
    if !mount_namespace {
        return if read_only_filesystem {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read-only filesystem requires mount namespace",
            ))
        } else {
            Ok(())
        };
    }
    unsafe {
        if libc::unshare(libc::CLONE_NEWNS) == -1 {
            return Err(io::Error::last_os_error());
        }
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }
        if read_only_filesystem
            && libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
                std::ptr::null(),
            ) == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_linux_mount_hardening(
    mount_namespace: bool,
    _read_only_filesystem: bool,
) -> io::Result<()> {
    if mount_namespace {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mount namespace is only implemented on Linux",
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn drop_linux_capabilities(capabilities: &[u32]) -> io::Result<()> {
    for &capability in capabilities {
        let result =
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability as libc::c_ulong, 0, 0, 0) };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_linux_capabilities(capabilities: &[u32]) -> io::Result<()> {
    if capabilities.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "capability dropping is only implemented on Linux",
        ))
    }
}

#[cfg(unix)]
fn apply_sandbox(command: &mut Command, sandbox: &SandboxPolicy) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    if !sandbox.enabled {
        return Ok(());
    }
    let allowlist = sandbox.environment_allowlist.clone();
    if sandbox.clear_environment {
        let inherited: Vec<(String, String)> = env::vars()
            .filter(|(key, _)| allowlist.iter().any(|allowed| allowed == key))
            .collect();
        command.env_clear().envs(inherited);
    } else if !allowlist.is_empty() {
        return Err("sandbox.environment_allowlist requires clear_environment = true".into());
    }
    if let Some(dir) = &sandbox.working_dir {
        if !dir.is_dir() {
            return Err(format!(
                "sandbox working_dir is not a directory: {}",
                dir.display()
            ));
        }
        command.current_dir(dir);
    }
    let limits = sandbox.clone();
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            apply_linux_mount_hardening(limits.mount_namespace, limits.read_only_filesystem)?;
            if limits.network_namespace && libc::unshare(libc::CLONE_NEWNET) == -1 {
                return Err(io::Error::last_os_error());
            }
            apply_uid_gid(limits.run_as_uid, limits.run_as_gid)?;
            drop_linux_capabilities(&limits.drop_capabilities)?;
            if limits.seccomp_deny_dangerous {
                install_seccomp_deny_filter()?;
            }
            set_limit(libc::RLIMIT_AS, limits.max_memory_bytes)?;
            set_limit(libc::RLIMIT_CPU, limits.max_cpu_seconds)?;
            set_limit(libc::RLIMIT_FSIZE, limits.max_file_bytes)?;
            set_limit(libc::RLIMIT_NOFILE, limits.max_open_files)?;
            set_limit(libc::RLIMIT_NPROC, limits.max_processes)?;
            Ok(())
        });
    }
    Ok(())
}

#[cfg(unix)]
fn set_limit(resource: libc::__rlimit_resource_t, value: u64) -> io::Result<()> {
    if value == 0 {
        return Ok(());
    }
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(resource, &limit) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn apply_sandbox(_command: &mut Command, sandbox: &SandboxPolicy) -> Result<(), String> {
    if sandbox.enabled {
        Err("sandbox mode is only implemented on Unix hosts".into())
    } else {
        Ok(())
    }
}

fn kill_process_group(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        let pid = child.id() as libc::pid_t;
        let _ = libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
}

fn arm_timeout(pid: u32, seconds: u64) -> (Arc<AtomicBool>, Option<thread::JoinHandle<()>>) {
    let done = Arc::new(AtomicBool::new(false));
    if seconds == 0 {
        return (done, None);
    }
    let finished = Arc::clone(&done);
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_secs(seconds));
        if !finished.load(Ordering::SeqCst) {
            #[cfg(unix)]
            unsafe {
                let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
    });
    (done, Some(handle))
}

fn proxy(p: &Policy) -> Result<(), String> {
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
            if let Some(reason) = json_schema_violation(&request, t, &validators) {
                let out = error_response(&id, &reason);
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"json_schema","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
            if let Some(reason) = tool_schema_violation(&request, t, p) {
                let out = error_response(&id, &reason);
                println!("{out}");
                audit(
                    &p.audit_path,
                    &format!(r#"{{"event":"deny","reason":"schema","tool":"{t}","id":{id}}}"#),
                    &p.redact_patterns,
                )
                .map_err(|e| e.to_string())?;
                continue;
            }
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
                if !path_allowed(&value, &p.allowed_roots) {
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
        audit(&p.audit_path, &format!(r#"{{"event":"forward","method":"{method}","tool":{},"id":{id},"request":{line},"response":{}}}"#, tool.map(|x| format!("\"{x}\"")).unwrap_or_else(|| "null".into()), response.trim_end()), &p.redact_patterns).map_err(|e| e.to_string())?;
    }
    finished.store(true, Ordering::SeqCst);
    kill_process_group(&mut child);
    if let Some(handle) = watchdog {
        let _ = handle.join();
    }
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
    fn tool_schema_enforces_required_allowed_type_and_path() {
        let mut policies = BTreeMap::new();
        policies.insert(
            "read_file".into(),
            ToolPolicy {
                allowed_arguments: vec!["path".into()],
                required_arguments: vec!["path".into()],
                argument_types: BTreeMap::from([(String::from("path"), String::from("string"))]),
                path_arguments: vec!["path".into()],
            },
        );
        let p = Policy {
            allowed_roots: vec!["/home/scott/projects".into()],
            tool_policies: policies,
            ..Policy::default()
        };
        let good: Value = serde_json::from_str(
            r#"{"params":{"name":"read_file","arguments":{"path":"/home/scott/projects/a"}}}"#,
        )
        .unwrap();
        assert_eq!(tool_schema_violation(&good, "read_file", &p), None);
        let bad_type: Value =
            serde_json::from_str(r#"{"params":{"arguments":{"path":true}}}"#).unwrap();
        assert!(
            tool_schema_violation(&bad_type, "read_file", &p)
                .unwrap()
                .contains("type mismatch")
        );
        let bad_path: Value =
            serde_json::from_str(r#"{"params":{"arguments":{"path":"/etc/passwd"}}}"#).unwrap();
        assert!(
            tool_schema_violation(&bad_path, "read_file", &p)
                .unwrap()
                .contains("path argument denied")
        );
    }
    #[test]
    fn arbitrary_json_schema_enforces_nested_required_enum_and_pattern() {
        let schema: Value = serde_json::json!({
            "type": "object",
            "required": ["path", "mode"],
            "properties": {
                "path": {"$ref": "#/$defs/path"},
                "mode": {"enum": ["read", "metadata"]},
                "options": {
                    "type": "object",
                    "required": ["recursive"],
                    "properties": {"recursive": {"type": "boolean"}}
                }
            },
            "$defs": {
                "path": {"type": "string", "pattern": "^/home/scott/projects/"}
            },
            "additionalProperties": false
        });
        let mut validators = BTreeMap::new();
        validators.insert(
            "read_file".into(),
            jsonschema::validator_for(&schema).unwrap(),
        );
        let valid: Value = serde_json::json!({"params":{"arguments":{"path":"/home/scott/projects/a","mode":"read","options":{"recursive":false}}}});
        assert_eq!(
            json_schema_violation(&valid, "read_file", &validators),
            None
        );
        let invalid: Value = serde_json::json!({"params":{"arguments":{"path":"/etc/passwd","mode":"write","extra":true}}});
        assert!(
            json_schema_violation(&invalid, "read_file", &validators)
                .unwrap()
                .contains("JSON Schema validation failed")
        );
    }
    #[cfg(unix)]
    #[test]
    fn path_policy_resolves_symlinked_parents() {
        let root = PathBuf::from("/tmp/mcpwall-path-policy-test");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("escape")).unwrap();
        assert!(!path_allowed(
            &root.join("escape/passwd").display().to_string(),
            &[root.display().to_string()]
        ));
        assert!(!path_allowed(
            "../../etc/passwd",
            &[root.display().to_string()]
        ));
        assert!(!path_allowed(
            &format!("{}-private/file", root.display()),
            &[root.display().to_string()]
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_security_configuration_is_rejected() {
        let result: Result<Config, _> = toml::from_str(
            "[server.fixture]\ncommand = \"/bin/true\"\nseccomp_deny_dangerousg = true\n",
        );
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_rejects_allowlist_without_environment_clear() {
        let mut command = Command::new("/bin/true");
        let sandbox = SandboxPolicy {
            enabled: true,
            environment_allowlist: vec!["PATH".into()],
            ..SandboxPolicy::default()
        };
        assert!(
            apply_sandbox(&mut command, &sandbox)
                .unwrap_err()
                .contains("clear_environment")
        );
    }

    #[test]
    fn sandbox_rejects_unpaired_or_root_identity() {
        let unpaired = SandboxPolicy {
            run_as_uid: Some(65534),
            ..SandboxPolicy::default()
        };
        assert!(validate_sandbox_policy(&unpaired).is_err());
        let root = SandboxPolicy {
            run_as_uid: Some(0),
            run_as_gid: Some(0),
            ..SandboxPolicy::default()
        };
        assert!(validate_sandbox_policy(&root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn same_identity_privilege_path_is_allowed() {
        assert!(
            apply_uid_gid(
                Some(unsafe { libc::geteuid() } as u32),
                Some(unsafe { libc::getegid() } as u32)
            )
            .is_ok()
        );
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
