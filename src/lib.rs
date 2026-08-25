//! mcpwall — A local-first policy firewall and audit proxy for MCP stdio servers.

pub mod approval;
pub mod audit;
pub mod config;
pub mod doctor;
pub mod inventory;
pub mod jsonrpc;
pub mod policy;
pub mod proxy;
pub mod sandbox;
pub mod schema;

// Re-export key types for library consumers
pub use approval::{Approval, approval_status, enqueue_approval, mutate_approval, request_hash};
pub use audit::audit;
pub use config::{Config, Policy, SandboxPolicy, ToolPolicy, load_policy};
pub use doctor::{doctor, status};
pub use inventory::inventory;
pub use jsonrpc::{error_response, parse_request, request_id_value, request_method, request_tool};
pub use policy::{
    RateLimiter, argument_violation, is_tool_allowed, path_allowed, tool_schema_violation,
};
pub use proxy::proxy;
pub use sandbox::{apply_sandbox, arm_timeout, kill_process_group};
pub use schema::{json_schema_violation, load_schema_validators};
