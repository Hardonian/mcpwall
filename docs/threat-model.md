# Threat model

mcpwall reduces accidental and low-complexity tool misuse by applying a local policy before forwarding MCP calls.

Protected assets:

- Files outside explicitly permitted roots
- API keys and secrets in audit records
- Destructive MCP tools
- Local MCP server availability

Out of scope for v0.1:

- Kernel-level sandboxing
- Symlink-safe filesystem confinement
- TLS/network MCP transport
- Full JSON parser/schema validation
- Malicious same-user processes
- Compromised MCP server binaries

Required deployment posture:

1. Run the proxy as the least-privileged user that can access the intended roots.
2. Make the policy and audit directory user-readable only (`chmod 700` directory, `chmod 600` files).
3. Use unique JSON-RPC IDs when approval gates are enabled.
4. Treat the audit log as sensitive operational data.
5. Keep the MCP client and proxy local unless a separately authenticated transport is added.
