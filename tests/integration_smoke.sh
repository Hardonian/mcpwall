#!/usr/bin/env bash
set -Eeuo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
chmod 700 "$root"
cat >"$root/policy.toml" <<EOF
[server.fixture]
command = "$(pwd)/tests/fixture.sh"
allowed_tools = ["read_file"]
allowed_roots = ["$root/allowed"]
require_known_tools = true
inventory_max_age_seconds = 300
inventory_path = "$root/inventory.tools"
audit_path = "$root/audit.jsonl"

[server.fixture.tool_policies.read_file]
allowed_arguments = ["path"]
required_arguments = ["path"]
argument_types = { path = "string" }
path_arguments = ["path"]
EOF
mkdir "$root/allowed"

./target/release/mcpwall inventory --config "$root/policy.toml" --server fixture >/dev/null
[ "$(cat "$root/inventory.tools")" = "delete_file
read_file" ]
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../etc/passwd"}}}' \
  | ./target/release/mcpwall proxy --config "$root/policy.toml" --server fixture \
  | grep -q 'path argument denied'
printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"$root/allowed/file\"}}}" \
  | ./target/release/mcpwall proxy --config "$root/policy.toml" --server fixture \
  | grep -q '\"result\"'
printf 'integration smoke: passed\n'
