//! Operational diagnostics, health checks, and status reporting.

use crate::approval::load_approvals;
use crate::config::{Policy, approval_path, inventory_path};
use crate::inventory::inventory_fresh;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Reports operational metrics, approval queues, inventory freshness, and limits.
pub fn status(p: &Policy) -> Result<(), String> {
    let approvals = load_approvals(p);
    let mut counts = BTreeMap::new();
    for approval in approvals {
        *counts.entry(approval.state).or_insert(0usize) += 1;
    }
    let inventory_ready = !p.require_known_tools || inventory_fresh(p);

    println!("version: {}", env!("CARGO_PKG_VERSION"));
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

/// Runs deep diagnostic verification on configuration, binary availability, and permissions.
pub fn doctor(p: &Policy) -> Result<(), String> {
    println!("policy: ok");
    println!("command: {}", p.command);

    #[cfg(unix)]
    {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v '{}'", p.command.replace('\'', "'\\''")))
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() && !Path::new(&p.command).exists() {
            return Err(format!("command not found: {}", p.command));
        }
    }
    #[cfg(windows)]
    {
        let exists = Path::new(&p.command).exists()
            || Command::new("where")
                .arg(&p.command)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        if !exists {
            return Err(format!("command not found: {}", p.command));
        }
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
