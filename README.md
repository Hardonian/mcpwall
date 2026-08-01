# mcpwall

Local-first policy firewall and audit proxy for MCP stdio servers.

mcpwall is a small Rust native binary that sits between an MCP client and an MCP server. It forwards newline-delimited JSON-RPC only when the request satisfies a local policy.

It currently provides:

- Explicit tool allowlists and denylists
- Approval gates for destructive tools
- Absolute-path restrictions for tool arguments
- Per-minute call limits
- Redacted JSONL audit records
- Hash-bound, one-time approval queue with TTLs
- `approvals` status command and atomic local queue writes
- MCP `tools/list` inventory capture with optional fail-closed known-tool enforcement
- `doctor` checks before starting a server
- No cloud service, telemetry, Docker, or application runtime

This is a security boundary, not a complete MCP protocol implementation. It intentionally uses a conservative JSON-RPC line proxy for MCP stdio servers and should be placed in front of a server that uses one JSON message per line.

## Build

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

The release binary is `target/release/mcpwall` (currently v0.4.0).

## Configure

Copy `mcpwall.example.toml` and change the server command, arguments, roots, and audit path. The parser intentionally supports the small policy subset used by mcpwall; it is not a general TOML implementation.

```sh
cp mcpwall.example.toml /tmp/mcpwall.toml
./target/release/mcpwall doctor --config /tmp/mcpwall.toml --server filesystem
```

## Run as an MCP stdio proxy

```sh
./target/release/mcpwall proxy \
  --config /tmp/mcpwall.toml \
  --server filesystem
```

The proxy reads requests from stdin and writes responses to stdout. Child stderr is inherited for diagnostics. Audit records are written to the configured path. Never put secrets in the policy file or command-line arguments.

## v0.2 approval queue

A request whose tool is listed in `require_approval` returns an error containing both `request_id` and a SHA-256 `request_hash`. The exact request body must be approved; changing the arguments produces a different hash and cannot reuse the approval.

```sh
# list request_id, request_hash, tool, state, created_at, expires_at
./target/release/mcpwall approvals --config /tmp/mcpwall.toml --server filesystem

./target/release/mcpwall approve \
  --config /tmp/mcpwall.toml \
  --server filesystem \
  --hash REQUEST_HASH \
  --ttl 300 \
  REQUEST_ID

./target/release/mcpwall deny \
  --config /tmp/mcpwall.toml \
  --server filesystem \
  --hash REQUEST_HASH \
  REQUEST_ID
```

Approved requests are consumed once and expire automatically. Queue updates use a create-new lock and atomic rename. The queue is stored beside the audit file as `<audit_path>.approvals.tsv`; it contains no request payload, only the hash and metadata.

## v0.3 capability inventory

Capture the child server's advertised tools before enabling known-tool enforcement:

```sh
./target/release/mcpwall inventory --config /tmp/mcpwall.toml --server filesystem
```

Set these policy fields:

```toml
inventory_path = "/tmp/mcpwall-filesystem.tools"
require_known_tools = true
```

When enabled, a `tools/call` for a tool absent from the captured inventory is rejected. This is a conservative capability snapshot, not a substitute for full JSON Schema validation.

## v0.4 hardening and operations

v0.4 adds a real JSON parser and fail-closed request controls:

```toml
max_request_bytes = 65536
max_argument_bytes = 32768
denied_argument_keys = ["command", "shell", "eval"]
denied_argument_values = ["/etc/shadow", "BEGIN OPENSSH PRIVATE KEY"]
inventory_max_age_seconds = 86400
```

Malformed JSON-RPC, oversized requests, oversized arguments, denied argument keys, and denied argument values are rejected before forwarding. Audit and approval files are forced to mode `0600` on Unix systems.

Operational status:

```sh
./target/release/mcpwall status --config /tmp/mcpwall.toml --server filesystem
```

`status` reports audit size, approval state counts, inventory freshness, and active limits without starting the child server.

## Security model and limitations

- Bind the MCP client and server to the same user account or use filesystem permissions around the proxy and audit files.
- Keep the audit file outside shared or web-served directories.
- Path checks are lexical in v0.4; they do not resolve symlinks. Do not treat them as a complete filesystem sandbox.
- There is no TLS because stdio is local. For network transport, use a separately authenticated local gateway.
- The policy parser is deliberately narrow. Invalid or missing policy values fail closed.
- Approval records bind the JSON-RPC request ID and SHA-256 request hash; clients should use unique request IDs for approval-gated calls.

## Development fixture

The repository includes a tiny shell MCP-like line server for integration smoke tests:

```sh
chmod +x tests/fixture.sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/scott/projects/a.txt","api_key":"do-not-log"}}}' \
  | ./target/release/mcpwall proxy --config /tmp/mcpwall.toml --server filesystem
```

## License

MIT
