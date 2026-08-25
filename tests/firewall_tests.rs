//! Comprehensive integration and verification test suite for mcpwall.

use mcpwall::approval::{
    Approval, approval_status, enqueue_approval, mutate_approval, parse_approval, request_hash,
    serialize_approval,
};
use mcpwall::audit::{audit, redact};
use mcpwall::config::{Config, Policy, SandboxPolicy, ToolPolicy, validate_sandbox_policy};
use mcpwall::inventory::inventory_tool_names;
use mcpwall::jsonrpc::{
    CODE_APPROVAL_REQUIRED, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND,
    CODE_RATE_LIMITED, error_response, extract_all_strings, is_notification, parse_request,
    request_id_value, request_method, request_tool,
};
use mcpwall::policy::{
    RateLimiter, argument_violation, is_tool_allowed, path_allowed, tool_schema_violation,
};
use mcpwall::schema::json_schema_violation;
use std::collections::BTreeMap;
use std::fs;

#[test]
fn test_config_parsing_and_defaults() {
    let toml_content = r#"
    [server.mcp_server]
    command = "/usr/bin/python3"
    args = ["-m", "mcp_server"]
    allowed_tools = ["read_data", "process_data"]
    "#;

    let config: Config = toml::from_str(toml_content).expect("valid TOML");
    let policy = config.server.get("mcp_server").expect("server found");

    assert_eq!(policy.command, "/usr/bin/python3");
    assert_eq!(policy.args, vec!["-m", "mcp_server"]);
    assert_eq!(policy.allowed_tools, vec!["read_data", "process_data"]);
    assert_eq!(policy.max_calls_per_minute, 60);
    assert_eq!(policy.max_request_bytes, 65536);
    assert_eq!(policy.max_argument_bytes, 32768);
    assert_eq!(policy.approval_ttl_seconds, 300);
}

#[test]
fn test_jsonrpc_request_parsing_and_extraction() {
    let raw = r#"{"jsonrpc":"2.0","id":"req-42","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/file.txt"}}}"#;
    let req = parse_request(raw, 4096).expect("valid JSON-RPC");

    assert_eq!(request_method(&req), "tools/call");
    assert_eq!(request_tool(&req), Some("read_file"));
    assert_eq!(request_id_value(&req), "\"req-42\"");

    let strings = extract_all_strings(&req);
    assert!(strings.contains(&"/home/user/file.txt"));
    assert!(strings.contains(&"read_file"));
}

#[test]
fn test_jsonrpc_error_codes() {
    let err1 = error_response("1", CODE_INVALID_REQUEST, "invalid json");
    assert!(err1.contains(r#""code":-32600"#));

    let err2 = error_response("2", CODE_METHOD_NOT_FOUND, "tool not allowed");
    assert!(err2.contains(r#""code":-32601"#));

    let err3 = error_response("3", CODE_INVALID_PARAMS, "path denied");
    assert!(err3.contains(r#""code":-32602"#));

    let err4 = error_response("4", CODE_APPROVAL_REQUIRED, "approval required");
    assert!(err4.contains(r#""code":-32001"#));

    let err5 = error_response("5", CODE_RATE_LIMITED, "rate limit exceeded");
    assert!(err5.contains(r#""code":-32029"#));
}

#[test]
fn test_path_traversal_and_root_boundaries() {
    let roots = vec!["/home/scott/workspace".to_string()];

    // Direct match and descendant matches
    assert!(path_allowed("/home/scott/workspace/file.rs", &roots));
    assert!(path_allowed(
        "/home/scott/workspace/nested/dir/file.rs",
        &roots
    ));

    // Traversal attempts
    assert!(!path_allowed(
        "/home/scott/workspace/../../etc/shadow",
        &roots
    ));
    assert!(!path_allowed(
        "/home/scott/workspace_forbidden/file.rs",
        &roots
    ));
    assert!(!path_allowed("relative/path/without/root", &roots));
    assert!(!path_allowed("/etc/passwd", &roots));
}

#[test]
fn test_tool_policy_argument_rules() {
    let mut tool_policies = BTreeMap::new();
    tool_policies.insert(
        "query_db".into(),
        ToolPolicy {
            allowed_arguments: vec!["query".into(), "limit".into(), "timeout".into()],
            required_arguments: vec!["query".into()],
            argument_types: BTreeMap::from([
                ("query".into(), "string".into()),
                ("limit".into(), "integer".into()),
                ("timeout".into(), "number".into()),
            ]),
            path_arguments: vec![],
        },
    );

    let p = Policy {
        tool_policies,
        ..Policy::default()
    };

    // Valid call
    let valid = serde_json::json!({
        "params": {
            "arguments": {
                "query": "SELECT * FROM users",
                "limit": 100,
                "timeout": 5.5
            }
        }
    });
    assert_eq!(tool_schema_violation(&valid, "query_db", &p), None);

    // Missing required
    let missing = serde_json::json!({
        "params": {
            "arguments": {
                "limit": 10
            }
        }
    });
    let err = tool_schema_violation(&missing, "query_db", &p).unwrap();
    assert!(err.contains("required argument missing: query"));

    // Disallowed argument key
    let extra = serde_json::json!({
        "params": {
            "arguments": {
                "query": "SELECT 1",
                "drop_table": true
            }
        }
    });
    let err = tool_schema_violation(&extra, "query_db", &p).unwrap();
    assert!(err.contains("argument not allowed for query_db: drop_table"));

    // Type mismatch
    let type_err = serde_json::json!({
        "params": {
            "arguments": {
                "query": 12345
            }
        }
    });
    let err = tool_schema_violation(&type_err, "query_db", &p).unwrap();
    assert!(err.contains("argument type mismatch: query expected string"));
}

#[test]
fn test_json_schema_validation_engine() {
    let schema_val = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["source", "destination", "options"],
        "properties": {
            "source": { "type": "string", "pattern": "^/data/" },
            "destination": { "type": "string", "pattern": "^/backup/" },
            "options": {
                "type": "object",
                "required": ["compress", "retries"],
                "properties": {
                    "compress": { "type": "boolean" },
                    "retries": { "type": "integer", "minimum": 0, "maximum": 5 }
                }
            }
        },
        "additionalProperties": false
    });

    let validator = jsonschema::validator_for(&schema_val).expect("valid schema");
    let mut validators = BTreeMap::new();
    validators.insert("backup_tool".into(), validator);

    let valid_req = serde_json::json!({
        "params": {
            "arguments": {
                "source": "/data/records.csv",
                "destination": "/backup/records.csv.gz",
                "options": {
                    "compress": true,
                    "retries": 3
                }
            }
        }
    });
    assert_eq!(
        json_schema_violation(&valid_req, "backup_tool", &validators),
        None
    );

    let invalid_req = serde_json::json!({
        "params": {
            "arguments": {
                "source": "/root/secret.txt",
                "destination": "/backup/secret.txt",
                "options": {
                    "compress": false,
                    "retries": 10 // exceeds maximum 5
                }
            }
        }
    });
    let err = json_schema_violation(&invalid_req, "backup_tool", &validators);
    assert!(err.is_some());
}

#[test]
fn test_approval_lifecycle_state_machine() {
    let tmp_dir = std::env::temp_dir().join(format!("mcpwall-test-{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp_dir);
    let audit_file = tmp_dir.join("audit.jsonl");

    let policy = Policy {
        audit_path: audit_file.clone(),
        approval_ttl_seconds: 60,
        ..Policy::default()
    };

    let req_id = "test-req-101";
    let hash = request_hash(r#"{"method":"tools/call","params":{"name":"delete_file"}}"#);
    let now = 1000;

    // Enqueue
    enqueue_approval(&policy, req_id, &hash, "delete_file", now).expect("enqueued");

    // Initially pending -> approval_status should return false
    assert!(!approval_status(&policy, req_id, &hash, now).expect("check status"));

    // Approve
    mutate_approval(&policy, req_id, &hash, "approved", 60).expect("approved");

    // Verify consumption (single-use)
    assert!(approval_status(&policy, req_id, &hash, now + 10).expect("first check after approval"));
    // Second check should be false because it transitioned to "consumed"
    assert!(!approval_status(&policy, req_id, &hash, now + 15).expect("second check consumed"));

    let _ = fs::remove_dir_all(tmp_dir);
}

#[test]
fn test_secret_redaction_and_audit() {
    let tmp_dir = std::env::temp_dir().join(format!("mcpwall-audit-test-{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp_dir);
    let audit_file = tmp_dir.join("test_audit.jsonl");

    let patterns = vec!["api_key".into(), "token".into(), "password".into()];
    let event = r#"{"event":"forward","arguments":{"api_key":"sk-secret-12345","token":"bearer-abc","user":"scott"}}"#;

    audit(&audit_file, event, &patterns).expect("audit write");

    let written = fs::read_to_string(&audit_file).expect("audit read");
    assert!(!written.contains("sk-secret-12345"));
    assert!(!written.contains("bearer-abc"));
    assert!(written.contains("***REDACTED***"));
    assert!(written.contains("scott"));

    let _ = fs::remove_dir_all(tmp_dir);
}

#[test]
fn test_rate_limiter_sliding_window() {
    let mut limiter = RateLimiter::new();
    let limit = 3;

    assert!(limiter.check_and_record(limit));
    assert!(limiter.check_and_record(limit));
    assert!(limiter.check_and_record(limit));
    assert!(!limiter.check_and_record(limit)); // 4th call blocked
}

#[test]
fn test_tool_allow_deny_rules() {
    let policy = Policy {
        allowed_tools: vec!["fetch".into(), "search".into()],
        denied_tools: vec!["execute".into()],
        ..Policy::default()
    };

    assert!(is_tool_allowed(&policy, "fetch").is_ok());
    assert!(is_tool_allowed(&policy, "search").is_ok());
    assert!(is_tool_allowed(&policy, "execute").is_err());
    assert!(is_tool_allowed(&policy, "unknown_tool").is_err());
}

#[test]
fn test_approval_serialization_and_deserialization() {
    let approval = Approval {
        request_id: "req\t1\n2".into(),
        request_hash: "hash123".into(),
        tool: "delete_file".into(),
        state: "pending".into(),
        created_at: 100,
        expires_at: 200,
    };
    let serialized = serialize_approval(&approval);
    let parsed = parse_approval(&serialized).expect("parsed approval");
    assert_eq!(parsed, approval);
}

#[test]
fn test_redaction_unit() {
    let raw = r#"{"secret":"xyz123","normal":"ok"}"#;
    let redacted = redact(raw.into(), &["secret".into()]);
    assert!(!redacted.contains("xyz123"));
    assert!(redacted.contains("***REDACTED***"));
    assert!(redacted.contains("normal"));
}

#[test]
fn test_inventory_tool_names_parsing() {
    let resp = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read"},{"name":"write"}]}}"#;
    let names = inventory_tool_names(resp).expect("tool names");
    assert_eq!(names, vec!["read", "write"]);
}

#[test]
fn test_argument_violation_and_byte_limits() {
    let p = Policy {
        max_argument_bytes: 50,
        denied_argument_keys: vec!["danger".into()],
        denied_argument_values: vec!["MALICIOUS".into()],
        ..Policy::default()
    };

    let bad_key = serde_json::json!({"params":{"arguments":{"danger":"val"}}});
    assert!(argument_violation(&bad_key, &p).is_some());

    let bad_val = serde_json::json!({"params":{"arguments":{"msg":"this is MALICIOUS content"}}});
    assert!(argument_violation(&bad_val, &p).is_some());

    let oversized = serde_json::json!({"params":{"arguments":{"long_key":"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"}}});
    assert!(argument_violation(&oversized, &p).is_some());
}

#[test]
fn test_sandbox_validation_constraints() {
    let valid_sandbox = SandboxPolicy {
        enabled: true,
        timeout_seconds: 60,
        clear_environment: true,
        environment_allowlist: vec!["PATH".into()],
        ..SandboxPolicy::default()
    };
    assert!(validate_sandbox_policy(&valid_sandbox).is_ok());

    let bad_env = SandboxPolicy {
        enabled: true,
        clear_environment: false,
        environment_allowlist: vec!["PATH".into()],
        ..SandboxPolicy::default()
    };
    assert!(validate_sandbox_policy(&bad_env).is_err());
}

#[test]
fn test_jsonrpc_notification_handling() {
    let raw = r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{"protocolVersion":"2024-11-05"}}"#;
    let req = parse_request(raw, 4096).expect("valid notification");
    assert!(is_notification(&req));
    assert_eq!(request_method(&req), "notifications/initialized");
    assert_eq!(request_id_value(&req), "null");
}

#[test]
fn test_deep_secret_value_redaction() {
    let raw = r#"{"headers":{"authorization":"Bearer sec-token-9988"},"data":{"key":"sensitive"}}"#;
    let patterns = vec!["sec-token".into(), "key".into()];
    let redacted = redact(raw.into(), &patterns);
    assert!(!redacted.contains("sec-token-9988"));
    assert!(!redacted.contains("sensitive"));
    assert!(redacted.contains("***REDACTED***"));
}

#[test]
fn test_dry_run_policy_defaults() {
    let p = Policy {
        dry_run: true,
        ..Policy::default()
    };
    assert!(p.dry_run);
    assert_eq!(p.max_calls_per_minute, 60);
}
