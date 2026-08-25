//! Local JSON Schema compilation, caching, and validation for MCP tool calls.

use crate::config::Policy;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

/// Loads and compiles JSON Schema validators for all configured tools.
pub fn load_schema_validators(
    p: &Policy,
) -> Result<BTreeMap<String, jsonschema::Validator>, String> {
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

/// Evaluates arguments against a tool's compiled JSON Schema validator.
pub fn json_schema_violation(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_schema_with_defs_and_patterns() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["path", "mode"],
            "properties": {
                "path": {"$ref": "#/$defs/path"},
                "mode": {"enum": ["read", "metadata"]}
            },
            "$defs": {
                "path": {"type": "string", "pattern": "^/projects/"}
            },
            "additionalProperties": false
        });
        let validator = jsonschema::validator_for(&schema).unwrap();
        let mut validators = BTreeMap::new();
        validators.insert("test_tool".to_string(), validator);

        let valid = serde_json::json!({
            "params": {
                "arguments": {
                    "path": "/projects/file.txt",
                    "mode": "read"
                }
            }
        });
        assert_eq!(
            json_schema_violation(&valid, "test_tool", &validators),
            None
        );

        let invalid = serde_json::json!({
            "params": {
                "arguments": {
                    "path": "/etc/passwd",
                    "mode": "read"
                }
            }
        });
        assert!(json_schema_violation(&invalid, "test_tool", &validators).is_some());
    }
}
