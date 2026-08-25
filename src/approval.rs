//! Cryptographic, TTL-bound, single-use human approval queue and state machine.

use crate::config::{Policy, approval_lock_path, approval_path};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds.
pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Computes the SHA-256 hex digest of a raw request line.
pub fn request_hash(line: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(line.as_bytes());
    let res = digest.finalize();
    res.iter().map(|b| format!("{b:02x}")).collect()
}

/// Represents a single request approval record in the persistent queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub request_id: String,
    pub request_hash: String,
    pub tool: String,
    pub state: String,
    pub created_at: u64,
    pub expires_at: u64,
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

pub fn serialize_approval(a: &Approval) -> String {
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

pub fn parse_approval(line: &str) -> Option<Approval> {
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

pub fn load_approvals(p: &Policy) -> Vec<Approval> {
    fs::read_to_string(approval_path(p))
        .unwrap_or_default()
        .lines()
        .filter_map(parse_approval)
        .collect()
}

pub fn save_approvals(p: &Policy, records: &[Approval]) -> io::Result<()> {
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

    #[cfg(windows)]
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(tmp, path)
}

/// Advisory queue lock with automatic stale-lock recovery.
pub struct QueueLock {
    path: PathBuf,
}

impl Drop for QueueLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn acquire_queue_lock(p: &Policy) -> io::Result<QueueLock> {
    let path = approval_lock_path(p);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    for _ in 0..50 {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(QueueLock { path }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Check for stale lock (older than 10 seconds)
                if fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .and_then(|m| m.elapsed().map_err(io::Error::other))
                    .is_ok_and(|elapsed| elapsed > Duration::from_secs(10))
                {
                    let _ = fs::remove_file(&path);
                    continue;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "approval queue is locked",
    ))
}

/// Checks and consumes an approved request atomically.
pub fn approval_status(p: &Policy, request_id: &str, hash: &str, now: u64) -> Result<bool, String> {
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

/// Enqueues a new pending request into the approval queue.
pub fn enqueue_approval(
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

/// Mutates the state of a pending approval (approve or deny).
pub fn mutate_approval(
    p: &Policy,
    request_id: &str,
    hash: &str,
    state: &str,
    ttl: u64,
) -> Result<(), String> {
    let _lock = acquire_queue_lock(p).map_err(|e| e.to_string())?;
    let mut records = load_approvals(p);
    let now = now_seconds();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_serialization_round_trip() {
        let original = Approval {
            request_id: "req-1\twith\\tabs".into(),
            request_hash: "abcd1234".into(),
            tool: "delete_file".into(),
            state: "pending".into(),
            created_at: 1000,
            expires_at: 1300,
        };
        let line = serialize_approval(&original);
        let parsed = parse_approval(&line).expect("valid parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn request_hashing_is_stable() {
        let hash1 = request_hash(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#);
        let hash2 = request_hash(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }
}
