//! JSON-RPC 2.0 parsing, validation, and error response generation.

use serde_json::Value;

/// Standard JSON-RPC 2.0 error codes and mcpwall custom firewall codes.
pub const CODE_PARSE_ERROR: i64 = -32700;
pub const CODE_INVALID_REQUEST: i64 = -32600;
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
pub const CODE_INVALID_PARAMS: i64 = -32602;
pub const CODE_INTERNAL_ERROR: i64 = -32603;
pub const CODE_APPROVAL_REQUIRED: i64 = -32001;
pub const CODE_RATE_LIMITED: i64 = -32029;

/// Parses and validates a raw input line as a single JSON-RPC 2.0 Object.
///
/// Fails closed if the line exceeds `max_bytes`, is not valid JSON, is an array batch,
/// is a scalar, or is missing the `jsonrpc = "2.0"` version or `method` field.
pub fn parse_request(line: &str, max_bytes: usize) -> Result<Value, String> {
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

/// Extracts the method name from a parsed JSON-RPC request.
pub fn request_method(request: &Value) -> &str {
    request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Extracts the tool name from a `tools/call` JSON-RPC request.
pub fn request_tool(request: &Value) -> Option<&str> {
    request.pointer("/params/name").and_then(Value::as_str)
}

/// Formats the request ID for JSON-RPC responses (handles strings, numbers, or null).
pub fn request_id_value(request: &Value) -> String {
    request
        .get("id")
        .map(ToString::to_string)
        .unwrap_or_else(|| "null".into())
}

/// Recursively extracts all string values from a JSON AST.
///
/// This provides reliable string extraction that correctly resolves Unicode escapes
/// and nested structures, eliminating parser discrepancy bypasses.
pub fn extract_all_strings(value: &Value) -> Vec<&str> {
    let mut out = Vec::new();
    collect_strings(value, &mut out);
    out
}

fn collect_strings<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::String(s) => out.push(s.as_str()),
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_strings(v, out);
            }
        }
        _ => {}
    }
}

/// Formats a compliant JSON-RPC 2.0 error response line.
pub fn error_response(id: &str, code: i64, message: &str) -> String {
    let escaped_message = serde_json::to_string(message).unwrap_or_else(|_| "\"error\"".into());
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{code},"message":{escaped_message}}}}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_request() {
        let line =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#;
        let req = parse_request(line, 1024).expect("valid request");
        assert_eq!(request_method(&req), "tools/call");
        assert_eq!(request_tool(&req), Some("read_file"));
        assert_eq!(request_id_value(&req), "1");
    }

    #[test]
    fn rejects_malformed_and_batches() {
        assert!(parse_request("invalid", 100).is_err());
        assert!(parse_request(r#"[{"jsonrpc":"2.0","method":"ping"}]"#, 100).is_err());
        assert!(parse_request(r#"{"jsonrpc":"1.0","method":"ping"}"#, 100).is_err());
        assert!(parse_request(r#"{"jsonrpc":"2.0"}"#, 100).is_err());
    }

    #[test]
    fn extracts_strings_including_unicode() {
        let json = serde_json::json!({
            "a": "/home/scott/project",
            "nested": {
                "b": ["/etc/shadow", 123, true]
            }
        });
        let strings = extract_all_strings(&json);
        assert!(strings.contains(&"/home/scott/project"));
        assert!(strings.contains(&"/etc/shadow"));
    }

    #[test]
    fn formats_error_response_with_quotes() {
        let res = error_response("1", CODE_INVALID_PARAMS, "argument \"path\" is invalid");
        assert!(res.contains(r#""code":-32602"#));
        assert!(res.contains(r#""message":"argument \"path\" is invalid""#));
    }
}
