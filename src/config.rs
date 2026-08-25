//! Configuration schema, TOML deserialization, and production-mode validation.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Root policy configuration for a single MCP server.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub denied_tools: Vec<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
    #[serde(default)]
    pub allowed_roots: Vec<String>,
    #[serde(default)]
    pub redact_patterns: Vec<String>,
    #[serde(default = "default_calls")]
    pub max_calls_per_minute: usize,
    #[serde(default = "default_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_argument_bytes")]
    pub max_argument_bytes: usize,
    #[serde(default)]
    pub denied_argument_keys: Vec<String>,
    #[serde(default)]
    pub denied_argument_values: Vec<String>,
    #[serde(default = "default_approval_ttl")]
    pub approval_ttl_seconds: u64,
    #[serde(default)]
    pub inventory_max_age_seconds: u64,
    #[serde(default = "default_audit_path")]
    pub audit_path: PathBuf,
    pub inventory_path: Option<PathBuf>,
    #[serde(default)]
    pub require_known_tools: bool,
    #[serde(default)]
    pub production_mode: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub tool_policies: BTreeMap<String, ToolPolicy>,
    #[serde(default)]
    pub tool_schemas: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub sandbox: SandboxPolicy,
}

/// Linux child sandbox and resource limit configuration.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub clear_environment: bool,
    #[serde(default)]
    pub environment_allowlist: Vec<String>,
    pub working_dir: Option<PathBuf>,
    #[serde(default)]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub max_memory_bytes: u64,
    #[serde(default)]
    pub max_cpu_seconds: u64,
    #[serde(default)]
    pub max_file_bytes: u64,
    #[serde(default)]
    pub max_open_files: u64,
    #[serde(default)]
    pub max_processes: u64,
    #[serde(default)]
    pub network_namespace: bool,
    #[serde(default)]
    pub seccomp_deny_dangerous: bool,
    #[serde(default)]
    pub mount_namespace: bool,
    #[serde(default)]
    pub read_only_filesystem: bool,
    #[serde(default)]
    pub drop_capabilities: Vec<u32>,
    pub run_as_uid: Option<u32>,
    pub run_as_gid: Option<u32>,
}

/// Granular per-tool argument validation policy.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    #[serde(default)]
    pub allowed_arguments: Vec<String>,
    #[serde(default)]
    pub required_arguments: Vec<String>,
    #[serde(default)]
    pub argument_types: BTreeMap<String, String>,
    #[serde(default)]
    pub path_arguments: Vec<String>,
}

pub fn default_calls() -> usize {
    60
}
pub fn default_request_bytes() -> usize {
    65_536
}
pub fn default_argument_bytes() -> usize {
    32_768
}
pub fn default_approval_ttl() -> u64 {
    300
}
pub fn default_audit_path() -> PathBuf {
    PathBuf::from("mcpwall-audit.jsonl")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: BTreeMap<String, Policy>,
}

/// Returns the path to the inventory tool list cache file.
pub fn inventory_path(p: &Policy) -> PathBuf {
    p.inventory_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.tools", p.audit_path.display())))
}

/// Returns the path to the TSV approvals database file.
pub fn approval_path(p: &Policy) -> PathBuf {
    PathBuf::from(format!("{}.approvals.tsv", p.audit_path.display()))
}

/// Returns the path to the approval queue advisory lock file.
pub fn approval_lock_path(p: &Policy) -> PathBuf {
    PathBuf::from(format!("{}.lock", approval_path(p).display()))
}

/// Loads and validates a policy file for the requested server name.
pub fn load_policy(path: &Path, server: &str) -> Result<Policy, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let config: Config =
        toml::from_str(&content).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let mut policy = config
        .server
        .get(server)
        .cloned()
        .ok_or_else(|| format!("server section not found: {server}"))?;

    if policy.command.trim().is_empty() {
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

    if policy.production_mode {
        #[cfg(unix)]
        {
            if !policy.sandbox.enabled {
                return Err("production_mode requires sandbox.enabled = true".into());
            }
            if policy.sandbox.run_as_uid.is_none() || policy.sandbox.run_as_gid.is_none() {
                return Err("production_mode requires sandbox.run_as_uid and run_as_gid".into());
            }
        }
        if policy.allowed_tools.is_empty() {
            return Err("production_mode requires a non-empty allowed_tools list".into());
        }
        if policy.sandbox.enabled && policy.sandbox.timeout_seconds == 0 {
            return Err("production_mode requires sandbox.timeout_seconds > 0".into());
        }
        let has_path_policy = policy
            .tool_policies
            .values()
            .any(|rule| !rule.path_arguments.is_empty());
        if has_path_policy && policy.allowed_roots.is_empty() {
            return Err("production_mode path policies require non-empty allowed_roots".into());
        }
        validate_private_state_path(&policy.audit_path)?;
        validate_private_state_path(&inventory_path(&policy))?;
    }

    validate_schema_files(&policy)?;
    validate_sandbox_policy(&policy.sandbox)?;
    Ok(policy)
}

/// Validates that state directories and files are private and secure.
pub fn validate_private_state_path(path: &Path) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    if parent.as_os_str().is_empty() {
        return Ok(());
    }

    if let Ok(parent_meta) = fs::symlink_metadata(parent) {
        if !parent_meta.is_dir() {
            return Err(format!(
                "private state parent is not a directory: {}",
                parent.display()
            ));
        }
        #[cfg(unix)]
        {
            if parent_meta.uid() != unsafe { libc::geteuid() } as u32
                || parent_meta.mode() & 0o077 != 0
            {
                return Err(format!(
                    "private state directory must be owner-only (0700) and owned by the effective user: {}",
                    parent.display()
                ));
            }
        }
    }

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(format!(
                "private state path is not a regular file: {}",
                path.display()
            ));
        }
        #[cfg(unix)]
        if meta.uid() != unsafe { libc::geteuid() } as u32 || meta.mode() & 0o077 != 0 {
            return Err(format!(
                "private state file must be owner-only (0600): {}",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Validates sandbox configuration parameters for consistency and safety.
pub fn validate_sandbox_policy(sandbox: &SandboxPolicy) -> Result<(), String> {
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

/// Validates that all referenced JSON Schema files exist and compile cleanly.
pub fn validate_schema_files(p: &Policy) -> Result<(), String> {
    for (tool, path) in &p.tool_schemas {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("read JSON Schema for {tool} ({}): {e}", path.display()))?;
        let schema: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| format!("parse JSON Schema for {tool} ({}): {e}", path.display()))?;
        jsonschema::validator_for(&schema)
            .map_err(|e| format!("compile JSON Schema for {tool} ({}): {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_policy() {
        let toml_str = r#"
        [server.test]
        command = "/bin/echo"
        allowed_tools = ["test_tool"]
        max_calls_per_minute = 100
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let policy = config.server.get("test").unwrap();
        assert_eq!(policy.command, "/bin/echo");
        assert_eq!(policy.allowed_tools, vec!["test_tool"]);
        assert_eq!(policy.max_calls_per_minute, 100);
    }

    #[test]
    fn rejects_unknown_fields() {
        let toml_str = r#"
        [server.test]
        command = "/bin/echo"
        unknown_field = "boom"
        "#;
        let res: Result<Config, _> = toml::from_str(toml_str);
        assert!(res.is_err());
    }

    #[test]
    fn sandbox_validation_checks() {
        let bad_caps = SandboxPolicy {
            drop_capabilities: vec![100],
            ..SandboxPolicy::default()
        };
        assert!(validate_sandbox_policy(&bad_caps).is_err());

        let root_uid = SandboxPolicy {
            run_as_uid: Some(0),
            run_as_gid: Some(0),
            ..SandboxPolicy::default()
        };
        assert!(validate_sandbox_policy(&root_uid).is_err());
    }
}
