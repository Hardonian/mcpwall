# Contributing

1. Create a focused branch from `main`.
2. Preserve the local-first, dependency-light architecture.
3. Never add network schema resolution, telemetry, secrets, or cloud requirements.
4. Run the complete local gate before opening a pull request:

```sh
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo audit
cargo build --release
bash -n install.sh tests/fixture.sh
git diff --check
```

5. Document the security boundary and rollback path for security-sensitive changes.
6. Do not claim sandbox strength without a real runtime probe.
