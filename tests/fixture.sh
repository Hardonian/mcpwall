#!/bin/sh
set -eu
while IFS= read -r line; do
  case "$line" in
    *'"method":"tools/list"'* ) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Read a permitted file"},{"name":"delete_file","description":"Delete a file"}]}}' ;;
    *'"id":1'* ) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe"}]}}' ;;
    *'"id":2'* ) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"forwarded"}]}}' ;;
    * ) printf '%s\n' '{"jsonrpc":"2.0","id":99,"result":{}}' ;;
  esac
done
