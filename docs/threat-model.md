# Threat model

mcpwall reduces accidental and low-complexity tool misuse by applying a local policy before forwarding MCP calls.

Protected assets:

- Files outside explicitly permitted roots
- API keys and secrets in audit records
- Destructive MCP tools
- Local MCP server availability

## Current scope and limitations

The optional Linux sandbox now provides process groups, environment isolation, resource limits, wall-clock cleanup, `PR_SET_NO_NEW_PRIVS`, a selected x86_64 seccomp deny filter, and optional UID/GID dropping. These controls are user-space hardening, not a complete kernel sandbox.

Still out of scope:

- Mount namespace or read-only root filesystem isolation
- Automatic user namespace mapping
- Complete syscall allowlisting
- Protection against root, kernel compromise, or malicious same-user processes
- Compromised MCP server binaries that exploit an unblocked kernel/application path
- TLS/network MCP transport

Required deployment posture:

1. Run the proxy as the least-privileged user that can access the intended roots.
2. Make the policy and audit directory user-readable only (`chmod 700` directory, `chmod 600` files).
3. Use unique JSON-RPC IDs when approval gates are enabled.
4. Treat the audit log as sensitive operational data.
5. Keep the MCP client and proxy local unless a separately authenticated transport is added.
