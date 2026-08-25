//! Secure, redacted JSONL audit logging with restrictive file permissions.

use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Redacts sensitive keys and values in a parsed JSON AST.
pub fn redact_json_value(value: &mut Value, patterns: &[String]) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let key_matches = patterns.iter().any(|p| {
                    !p.is_empty()
                        && (key.eq_ignore_ascii_case(p)
                            || key.to_ascii_lowercase().contains(&p.to_ascii_lowercase()))
                });
                if key_matches {
                    *child = Value::String("***REDACTED***".into());
                } else {
                    redact_json_value(child, patterns);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_json_value(item, patterns);
            }
        }
        Value::String(s) => {
            let lower = s.to_ascii_lowercase();
            if patterns
                .iter()
                .any(|p| !p.is_empty() && lower.contains(&p.to_ascii_lowercase()))
            {
                *s = "***REDACTED***".into();
            }
        }
        _ => {}
    }
}

/// Redacts sensitive key-value pairs from a JSON string representation.
pub fn redact(mut line: String, patterns: &[String]) -> String {
    // If it is valid JSON, perform structured AST redaction first
    if let Ok(mut parsed) = serde_json::from_str::<Value>(&line) {
        redact_json_value(&mut parsed, patterns);
        if let Ok(serialized) = serde_json::to_string(&parsed) {
            line = serialized;
        }
    }

    // Fallback string scanner for any unparsed or embedded snippets
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
        }
    }
    line
}

/// Writes an event string to the designated audit file with redaction applied.
pub fn audit(path: &Path, event: &str, patterns: &[String]) -> io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let safe = redact(event.to_string(), patterns);

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);

    #[cfg(unix)]
    if path.exists() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    let mut f = options.open(path)?;
    writeln!(f, "{safe}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_keys_in_json() {
        let raw =
            r#"{"api_key":"super-secret-token","nested":{"password":"12345","normal":"val"}}"#;
        let patterns = vec!["api_key".into(), "password".into()];
        let redacted = redact(raw.into(), &patterns);
        assert!(!redacted.contains("super-secret-token"));
        assert!(!redacted.contains("12345"));
        assert!(redacted.contains("***REDACTED***"));
        assert!(redacted.contains("normal"));
    }

    #[test]
    fn redacts_case_insensitively() {
        let raw = r#"{"API_KEY":"secret"}"#;
        let patterns = vec!["api_key".into()];
        let redacted = redact(raw.into(), &patterns);
        assert!(!redacted.contains("secret"));
        assert!(redacted.contains("***REDACTED***"));
    }

    #[test]
    fn redacts_sensitive_values_in_strings() {
        let raw = r#"{"payload":"Authorization: Bearer my-secret-token-123","normal":"ok"}"#;
        let patterns = vec!["my-secret-token".into()];
        let redacted = redact(raw.into(), &patterns);
        assert!(!redacted.contains("my-secret-token"));
        assert!(redacted.contains("***REDACTED***"));
        assert!(redacted.contains("normal"));
    }
}
