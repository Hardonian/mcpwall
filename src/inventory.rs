//! MCP capability inventory discovery, caching, and freshness verification.

use crate::config::{Policy, inventory_path};
use crate::sandbox::{apply_sandbox, kill_process_group};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Parses tool names from a `tools/list` JSON-RPC 2.0 response.
pub fn inventory_tool_names(response: &str) -> Result<Vec<String>, String> {
    if response.len() > 1_048_576 {
        return Err("inventory response exceeds 1 MiB".into());
    }
    let value: Value = serde_json::from_str(response)
        .map_err(|e| format!("invalid inventory JSON-RPC response: {e}"))?;
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || value.get("id").and_then(Value::as_i64) != Some(1)
    {
        return Err("inventory response has invalid JSON-RPC version or id".into());
    }
    let tools = value
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("inventory response missing result.tools array")?;

    let mut names = Vec::with_capacity(tools.len());
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or("inventory tool missing string name")?;
        if name.is_empty() || name.len() > 256 {
            return Err("inventory tool name is empty or too long".into());
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

/// Checks if an existing inventory cache file is within its maximum age.
pub fn inventory_fresh(p: &Policy) -> bool {
    if p.inventory_max_age_seconds == 0 {
        return true;
    }
    fs::metadata(inventory_path(p))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age.as_secs() <= p.inventory_max_age_seconds)
}

/// Checks whether a tool is present in the recorded inventory.
pub fn known_tool(p: &Policy, tool: &str) -> bool {
    if !p.require_known_tools || !inventory_fresh(p) {
        return !p.require_known_tools;
    }
    fs::read_to_string(inventory_path(p))
        .unwrap_or_default()
        .lines()
        .any(|x| x.trim() == tool)
}

/// Probes the child MCP server for `tools/list` and records the tool names.
pub fn inventory(p: &Policy) -> Result<(), String> {
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

    let mut names = inventory_tool_names(&response)?;
    names.sort();
    names.dedup();
    kill_process_group(&mut child);
    let _ = child.wait();

    let path = inventory_path(p);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
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

    #[cfg(windows)]
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(tmp, &path).map_err(|e| e.to_string())?;

    println!("inventory: {} tools", names.len());
    println!("path: {}", path.display());
    for name in names {
        println!("tool: {name}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_tools_list_response() {
        let res = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"},{"name":"write_file"}]}}"#;
        let tools = inventory_tool_names(res).expect("parsed tools");
        assert_eq!(tools, vec!["read_file", "write_file"]);
    }

    #[test]
    fn rejects_invalid_id_or_empty_tools() {
        let bad_id = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#;
        assert!(inventory_tool_names(bad_id).is_err());

        let bad_type = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":123}]}}"#;
        assert!(inventory_tool_names(bad_type).is_err());
    }
}
