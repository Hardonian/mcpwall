//! Core policy evaluation engine: tool rules, argument checks, paths, and rate limiting.

use crate::config::Policy;
use crate::inventory::known_tool;
use serde_json::Value;
use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

/// Normalizes a path, resolving `.` and `..` without requiring the target file to exist.
pub fn normalized_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir => {
                normalized.push(Component::RootDir.as_os_str());
            }
            Component::Prefix(prefix) => {
                normalized.push(prefix.as_os_str());
            }
            Component::Normal(normal) => {
                normalized.push(normal);
            }
        }
    }
    normalized
}

/// Checks whether a given path string is within the allowed roots list.
pub fn path_allowed(value: &str, roots: &[String]) -> bool {
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
        candidate == root_path || candidate.starts_with(&root_path)
    })
}

/// Checks if any argument key or value violates configured policy denials or byte limits.
pub fn argument_violation(value: &Value, p: &Policy) -> Option<String> {
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
                    if matches!(child, Value::String(text) if p.denied_argument_values.iter().any(|x| text.contains(x)))
                    {
                        return Some(format!("argument value denied for key: {key}"));
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

/// Validates arguments against per-tool policy (required/allowed keys, types, path roots).
pub fn tool_schema_violation(request: &Value, tool: &str, p: &Policy) -> Option<String> {
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

    if !rule.allowed_arguments.is_empty() {
        let not_allowed = args
            .keys()
            .find(|key| !rule.allowed_arguments.contains(key));
        if let Some(key) = not_allowed {
            return Some(format!("argument not allowed for {tool}: {key}"));
        }
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

/// Checks if a tool name is permitted by tool allowlists, denylists, and inventory.
pub fn is_tool_allowed(p: &Policy, tool: &str) -> Result<(), &'static str> {
    if p.denied_tools.iter().any(|x| x == tool) {
        return Err("tool denied by policy");
    }
    if !p.allowed_tools.is_empty() && !p.allowed_tools.iter().any(|x| x == tool) {
        return Err("tool not in allowed_tools list");
    }
    if !known_tool(p, tool) {
        return Err("tool not present in inventory");
    }
    Ok(())
}

/// High-precision sliding window rate limiter.
#[derive(Debug, Default)]
pub struct RateLimiter {
    calls: VecDeque<Instant>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            calls: VecDeque::new(),
        }
    }

    /// Checks if a new call is permitted within `max_calls_per_minute`.
    pub fn check_and_record(&mut self, max_calls_per_minute: usize) -> bool {
        let now = Instant::now();
        let one_minute_ago = now
            .checked_sub(std::time::Duration::from_secs(60))
            .unwrap_or(now);

        while self.calls.front().is_some_and(|t| *t < one_minute_ago) {
            self.calls.pop_front();
        }

        if self.calls.len() >= max_calls_per_minute {
            false
        } else {
            self.calls.push_back(now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ToolPolicy;
    use std::collections::BTreeMap;

    #[test]
    fn path_traversal_detection() {
        let roots = vec!["/home/scott/projects".into()];
        assert!(path_allowed("/home/scott/projects/a/b.txt", &roots));
        assert!(!path_allowed(
            "/home/scott/projects/../../etc/passwd",
            &roots
        ));
        assert!(!path_allowed("/home/scott/projects_other/file", &roots));
        assert!(!path_allowed("relative/path", &roots));
    }

    #[test]
    fn argument_policy_enforcement() {
        let p = Policy {
            denied_argument_keys: vec!["eval".into()],
            denied_argument_values: vec!["BEGIN RSA".into()],
            ..Policy::default()
        };

        let bad_key = serde_json::json!({"params":{"arguments":{"eval":"1+1"}}});
        assert!(argument_violation(&bad_key, &p).is_some());

        let bad_val =
            serde_json::json!({"params":{"arguments":{"key":"-----BEGIN RSA PRIVATE KEY-----"}}});
        assert!(argument_violation(&bad_val, &p).is_some());

        let good = serde_json::json!({"params":{"arguments":{"name":"scott"}}});
        assert!(argument_violation(&good, &p).is_none());
    }

    #[test]
    fn tool_policy_type_and_path_checks() {
        let mut tool_policies = BTreeMap::new();
        tool_policies.insert(
            "write_file".into(),
            ToolPolicy {
                allowed_arguments: vec!["path".into(), "content".into()],
                required_arguments: vec!["path".into()],
                argument_types: BTreeMap::from([
                    ("path".into(), "string".into()),
                    ("content".into(), "string".into()),
                ]),
                path_arguments: vec!["path".into()],
            },
        );
        let p = Policy {
            allowed_roots: vec!["/projects".into()],
            tool_policies,
            ..Policy::default()
        };

        let valid = serde_json::json!({
            "params": {
                "arguments": {
                    "path": "/projects/doc.md",
                    "content": "hello"
                }
            }
        });
        assert_eq!(tool_schema_violation(&valid, "write_file", &p), None);

        let unallowed_arg = serde_json::json!({
            "params": {
                "arguments": {
                    "path": "/projects/doc.md",
                    "extra": true
                }
            }
        });
        assert!(tool_schema_violation(&unallowed_arg, "write_file", &p).is_some());
    }

    #[test]
    fn rate_limiter_limits_bursts() {
        let mut limiter = RateLimiter::new();
        for _ in 0..5 {
            assert!(limiter.check_and_record(5));
        }
        assert!(!limiter.check_and_record(5));
    }
}
