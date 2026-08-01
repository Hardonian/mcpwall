# mcpwall

Local-first policy firewall and audit proxy for MCP stdio servers.

mcpwall is a small Rust native binary that sits between an MCP client and an MCP server. It forwards newline-delimited JSON-RPC only when the request satisfies a local policy.

It currently provides:

- Explicit tool allowlists and denylists
- Approval gates for destructive tools
- Absolute-path restrictions for tool arguments
- Per-minute call limits
- Redacted JSONL audit records
- Local approval and denial commands
- `doctor` checks before starting a server
- No cloud service, telemetry, Docker, or runtime dependency

This is a security boundary, not a complete MCP protocol implementation. It intentionally uses a conservative JSON-RPC line proxy for MCP stdio servers and should be placed in front of a server that uses one JSON message per line.

## Build

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

The release binary is `target/release/mcpwall`.

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

## Approval flow

A request whose tool is listed in `require_approval` returns a JSON-RPC error containing the request ID and is not forwarded. Approve or deny that exact request ID from another local operator shell:

```sh
./target/release/mcpwall approve --config /tmp/mcpwall.toml --server filesystem 42
./target/release/mcpwall deny --config /tmp/mcpwall.toml --server filesystem 42
```

Approval state is stored beside the audit file in `<audit_path>.approved`. This v0.1 flow is intentionally explicit and local; v0.2 should add a structured request queue and TTLs.

## Security model and limitations

- Bind the MCP client and server to the same user account or use filesystem permissions around the proxy and audit files.
- Keep the audit file outside shared or web-served directories.
- Path checks are lexical in v0.1; they do not resolve symlinks. Do not treat them as a complete filesystem sandbox.
- There is no TLS because stdio is local. For network transport, use a separately authenticated local gateway.
- The policy parser is deliberately narrow. Invalid or missing policy values fail closed.
- Approval IDs are currently based on JSON-RPC request IDs; clients must use unique IDs for approval-gated calls.

## Development fixture

The repository includes a tiny shell MCP-like line server for integration smoke tests:

```sh
chmod +x tests/fixture.sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/scott/projects/a.txt","api_key":"do-not-log"}}}' \
  | ./target/release/mcpwall proxy --config /tmp/mcpwall.toml --server filesystem
```

## License

MIT
