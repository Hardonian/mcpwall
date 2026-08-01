# mcpwall lab operations

## Install

Build and install locally without root:

```sh
PREFIX="$HOME/.local" ./install.sh
"$HOME/.local/bin/mcpwall" --help
```

The current release target is Linux x86_64 GNU/glibc. The release artifact is intentionally documented as dynamically linked; do not call it static unless a musl build is separately verified.

## Configure a server

Copy `mcpwall.example.toml`, set the real child command and arguments, then run the non-destructive checks:

```sh
mcpwall doctor --config "$HOME/.config/mcpwall/filesystem.toml" --server filesystem
mcpwall inventory --config "$HOME/.config/mcpwall/filesystem.toml" --server filesystem
mcpwall status --config "$HOME/.config/mcpwall/filesystem.toml" --server filesystem
```

Enable `require_known_tools = true` only after the inventory has been captured. Set `inventory_max_age_seconds` so a changed or stale server capability set fails closed.

For high-risk tools, add a per-tool schema:

```toml
[server.filesystem.tool_policies.read_file]
allowed_arguments = ["path"]
required_arguments = ["path"]
argument_types = { path = "string" }
path_arguments = ["path"]
```

Schema enforcement runs before generic argument and path policy. The release manifest and `SHA256SUMS` must be distributed with the binary; the manifest is integrity metadata, not a signature.

## Runtime pattern

Put mcpwall between the MCP client and child server. Keep the policy, audit file, approval queue, and inventory on a private local filesystem. Do not put audit output in a web-served directory.

For interactive approval:

1. Start the proxy and capture the returned `request_id` and `request_hash`.
2. Inspect the queue with `approvals`.
3. Approve the exact hash with `approve --hash HASH ID`.
4. Retry the exact request once.
5. Confirm the queue state is `consumed`.

An approval does not authorize modified arguments and cannot be replayed.

## Lab health checks

```sh
mcpwall doctor --config CONFIG --server SERVER
mcpwall status --config CONFIG --server SERVER
stat -c '%a %n' AUDIT_PATH AUDIT_PATH.approvals.tsv
```

Expected private artifact permissions on Linux are `600` for audit and approval files.

## Upgrade and rollback

Before upgrading, copy the policy file and record the current version:

```sh
mcpwall --help | sed -n '1p'
cp CONFIG CONFIG.bak
```

To roll back a local source checkout:

```sh
git revert RELEASE_COMMIT
cargo build --release
```

Never delete the audit or approval queue during a routine upgrade. Preserve them for incident review.

## Known limits

- Stdio JSON-RPC only; no network transport or TLS.
- Path checks are lexical and do not resolve symlinks.
- Inventory is a capability snapshot, not JSON Schema authorization.
- A compromised host, root user, or compromised child process can bypass this user-space boundary.
- The default release binary is dynamically linked to glibc.
