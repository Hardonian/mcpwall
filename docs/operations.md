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

For high-risk tools, add a per-tool compatibility rule or a full JSON Schema file:

```toml
# Paths are relative to the policy file.
tool_schemas = { read_file = "schemas/read_file.json" }

[server.filesystem.tool_policies.read_file]
allowed_arguments = ["path"]
required_arguments = ["path"]
argument_types = { path = "string" }
path_arguments = ["path"]
```

Full JSON Schemas are compiled before the child starts and can use nested properties, arrays, `$ref`, enums, combinators, conditional rules, and `additionalProperties`. Network resolution is disabled; keep schemas local. Schema enforcement runs before generic argument and path policy. The release manifest and `SHA256SUMS` must be distributed with the binary; the manifest is integrity metadata, not a signature.

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

## Optional Linux sandbox

Enable the sandbox per server only after testing the child’s requirements:

```toml
[server.filesystem.sandbox]
enabled = true
clear_environment = true
environment_allowlist = ["PATH", "HOME", "LANG"]
working_dir = "/home/scott/projects"
timeout_seconds = 120
max_memory_bytes = 1073741824
max_cpu_seconds = 60
max_file_bytes = 104857600
max_open_files = 256
max_processes = 0
network_namespace = false
seccomp_deny_dangerous = true
mount_namespace = true
read_only_filesystem = true
drop_capabilities = [21, 22]
# Optional identity drop; different UID/GID requires a privileged launcher.
# run_as_uid = 65534
# run_as_gid = 65534
```

Verify with `doctor`, then run a representative request. The launcher sets `NoNewPrivileges`, creates a dedicated process group, applies configured Unix resource limits, and kills the entire process group on timeout. `seccomp_deny_dangerous` installs a Linux x86_64 deny filter for selected high-risk kernel interfaces and returns `EPERM`; it is not a complete syscall allowlist. `run_as_uid` and `run_as_gid` must be supplied together, cannot target root, and fail closed if the parent lacks permission to change identity. `max_processes` is a Linux per-user/thread limit rather than a child-only limit; keep it disabled unless the host-wide consequence is understood. `network_namespace = true` requires the host to permit `unshare(CLONE_NEWNET)` and fails closed otherwise.

Sandbox controls do not provide mount namespaces, automatic UID remapping, or protection against a privileged host attacker. Treat them as a process-hardening layer, not a complete container replacement.

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
