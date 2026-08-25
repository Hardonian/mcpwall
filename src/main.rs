//! mcpwall CLI entrypoint.

use mcpwall::approval::{load_approvals, mutate_approval};
use mcpwall::config::load_policy;
use mcpwall::doctor::{doctor, status};
use mcpwall::inventory::inventory;
use mcpwall::proxy::proxy;
use std::env;
use std::path::PathBuf;

fn usage() {
    println!(
        "mcpwall {} — local MCP policy firewall\n\nUsage:\n  mcpwall doctor    --config FILE --server NAME\n  mcpwall proxy     --config FILE --server NAME\n  mcpwall status    --config FILE --server NAME\n  mcpwall inventory --config FILE --server NAME\n  mcpwall validate  --config FILE --server NAME\n  mcpwall approvals --config FILE --server NAME\n  mcpwall approve   --config FILE --server NAME --hash HASH REQUEST_ID\n  mcpwall deny      --config FILE --server NAME --hash HASH REQUEST_ID\n  mcpwall version\n  mcpwall --help\n\nThe proxy speaks newline-delimited JSON-RPC over stdin/stdout. Approval decisions are hash-bound and one-time.",
        env!("CARGO_PKG_VERSION")
    );
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
    if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
        println!("mcpwall {}", env!("CARGO_PKG_VERSION"));
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
            "validate" => {
                println!("policy: valid");
                println!(
                    "schemas: {} compiled successfully",
                    policy.tool_schemas.len()
                );
                Ok(())
            }
            "proxy" => proxy(&policy),
            "inventory" => inventory(&policy),
            "approvals" => {
                for record in load_approvals(&policy) {
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
