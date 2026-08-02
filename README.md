# mcpwall

[![CI](https://github.com/Hardonian/mcpwall/actions/workflows/ci.yml/badge.svg)](https://github.com/Hardonian/mcpwall/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Hardonian/mcpwall?display_name=tag&sort=semver)](https://github.com/Hardonian/mcpwall/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A local-first policy firewall and audit proxy for MCP stdio servers.**

mcpwall sits between an MCP client and a local MCP server, validates every JSON-RPC request against an inspectable TOML policy, and forwards only requests that pass. It is a small Rust binary with no cloud control plane, telemetry, Docker dependency, database, or network transport.

It is designed for operators who want a boring, reviewable trust boundary around filesystem tools, coding agents, browser agents, automation servers, and private AI infrastructure.

## Why mcpwall

MCP servers can expose powerful capabilities through a convenient tool interface. The operational failure mode is rarely an exotic exploit; it is an over-broad tool, an unsafe path, an accidental secret in logs, a stale capability list, or a destructive call that was forwarded without a human gate.

mcpwall makes those decisions explicit and locally auditable:

- **Policy before forwarding** — malformed, oversized, unauthorized, or unsafe requests fail closed.
- **Least privilege** — tool allowlists, denylists, per-tool argument rules, JSON Schema, and path roots.
- **Human gates** — destructive calls bind to an exact request ID and SHA-256 request hash, expire, and can be consumed once.
- **Runtime hardening** — optional process groups, environment isolation, resource limits, timeout cleanup, `NoNewPrivileges`, seccomp denial rules, and UID/GID dropping.
- **Evidence** — redacted JSONL audit records, capability inventory, status diagnostics, checksums, and release manifests.
- **Sovereign operation** — local TOML and JSON Schema files; network schema resolution is disabled.

## What it is — and is not

mcpwall is a local policy firewall and process-hardening layer. It is not a complete MCP implementation, container runtime, kernel security boundary, or hosted security service. It cannot protect against root, a malicious same-user process, a compromised kernel/host, or a fully compromised child that finds a vulnerability outside the controls enabled in its policy.

Use it when you need a small, inspectable control point. Use a properly configured container, VM, dedicated service account, or stronger sandbox when you need those guarantees.

## Features

- Single-object newline-delimited JSON-RPC 2.0 validation
- Tool allowlists and denylists
- Per-tool allowed and required argument fields
- Per-tool JSON type checks
- External local JSON Schema validation with `$ref`/`$defs`, nested objects, arrays, combinators, enums, patterns, and conditionals supported by the validator
- Symlink-aware canonical path enforcement for existing files and parents
- Request and argument byte limits
- Denied argument keys and values
- Per-minute rate limits
- One-time, TTL-bound, SHA-256-bound approvals
- MCP `tools/list` inventory capture and optional known-tool enforcement
- Redacted JSONL audit logging with restrictive Unix permissions
- Optional Linux sandbox process groups and descendant cleanup
- Optional Linux x86_64 seccomp deny filter for selected high-risk syscalls
- Optional Linux mount namespace and read-only root filesystem hardening
- Optional Linux capability bounding-set drops
- Optional non-root UID/GID execution identity with fail-closed validation
- `doctor`, `status`, `inventory`, `approvals`, `approve`, and `deny` commands
- Release manifests, SHA-256 checksums, dependency metadata, and CI verification

## Quick start

Build locally:

```sh
cargo build --release
./target/release/mcpwall --help
```

Install from a source checkout:

```sh
PREFIX="$HOME/.local" ./install.sh
"$HOME/.local/bin/mcpwall" --help
```

Copy and inspect the example policy:

```sh
cp mcpwall.example.toml /tmp/mcpwall.toml
./target/release/mcpwall doctor --config /tmp/mcpwall.toml --server filesystem
```

The example command is intentionally a placeholder. Replace `command`, `args`, allowed roots, and audit paths before using it with a real server.

## Minimal policy

```toml
[server.filesystem]
command = "/usr/local/bin/mcp-filesystem"
args = ["/home/scott/projects"]
allowed_tools = ["read_file", "list_directory"]
denied_tools = ["write_file", "delete_file"]
allowed_roots = ["/home/scott/projects"]
audit_path = "/home/scott/.local/state/mcpwall/filesystem.jsonl"

[server.filesystem.tool_policies.read_file]
allowed_arguments = ["path"]
required_arguments = ["path"]
argument_types = { path = "string" }
path_arguments = ["path"]
```

Run the proxy:

```sh
./target/release/mcpwall proxy \
  --config /tmp/mcpwall.toml \
  --server filesystem
```

The proxy reads requests from stdin and writes responses to stdout. Child stderr is inherited for diagnostics. Keep policy, audit, approval, and inventory files on a private local filesystem.

## Operational workflow

1. Run `doctor` and fix every reported configuration error.
2. Capture the child capability set with `inventory`.
3. Enable `require_known_tools` only after reviewing the inventory.
4. Run `status` and confirm audit/approval permissions.
5. Exercise a representative allowed request and a denied request.
6. For destructive tools, capture `request_id` and `request_hash`, approve the exact hash, retry once, and verify the approval becomes `consumed`.
7. Keep the proxy and child under the least-privileged suitable account.

See [docs/operations.md](docs/operations.md) for installation, rollback, approvals, inventory freshness, sandbox operation, and incident handling.

## Security model

See [docs/threat-model.md](docs/threat-model.md) for protected assets, assumptions, mitigations, and explicit limitations. Security controls are opt-in where compatibility requires it; the default policy remains conservative but does not silently alter an existing child’s runtime.

## Linux runtime hardening

The sandbox is opt-in per server:

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
seccomp_deny_dangerous = true
mount_namespace = true
read_only_filesystem = true
drop_capabilities = [21, 22]
# run_as_uid = 65534
# run_as_gid = 65534
```

The launcher provides process groups, environment isolation, resource limits, wall-clock cleanup, `PR_SET_NO_NEW_PRIVS`, selected x86_64 seccomp denial, optional mount namespace/read-only root hardening, capability bounding-set drops, and optional UID/GID dropping. `RLIMIT_NPROC` is per-user/thread rather than child-only. Mount and capability controls require host privileges such as `CAP_SYS_ADMIN`; if the host denies them, startup fails closed. This is not a complete container, syscall allowlist, user-namespace mapping, or protection from a privileged host attacker.


Each tagged release produces:

- Linux x86_64 GNU/glibc binary
- `RELEASE-MANIFEST.json` containing version, target, asset, and SHA-256
- `SHA256SUMS` covering the binary, manifest, and dependency metadata
- `DEPENDENCY-METADATA.json` generated from the locked Cargo graph
- A compressed release archive
- GitHub Actions build provenance when the release workflow runs with repository attestation permissions

Checksums are integrity metadata. They are not a signature. Verify the artifact before installation:

```sh
sha256sum -c SHA256SUMS
```

The default artifact is dynamically linked to glibc; it is not advertised as static.

## Development verification

```sh
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo audit
cargo build --release
```

The repository includes a deterministic shell MCP fixture under `tests/fixture.sh`. Runtime hardening probes cover environment isolation, working-directory enforcement, `NoNewPrivileges`, timeout process-group cleanup, seccomp denial, network namespace fail-closed behavior, and identity-drop behavior.

## License

MIT
