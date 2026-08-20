# Contributing

Contributions are welcome when they preserve the small security boundary: `aictx` selects and isolates credentials for official vendor CLIs; it is not an alternate API or OAuth client.

Security vulnerabilities belong in the private process described by [SECURITY.md](SECURITY.md), not a public issue or pull request.

## Development setup

Install Rust 1.89 or newer. The checked-in toolchain file selects the repository's development toolchain.

From a source checkout:

```bash
cargo build --locked
cargo test --all-targets --all-features --locked
```

Tests must not depend on real Claude/Codex accounts, keyrings, tokens, network access, or personal home-directory state. Use `tempfile`, `--root`, and explicit fake-vendor executable flags.

## Required checks

Run before submitting:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo test --doc --locked
```

If installed, also run:

```bash
cargo deny check
```

CI repeats these checks across the declared matrix and also runs dependency-policy and full-history secret scans. A lockfile change should be intentional and reviewed. Do not weaken either security gate or add an allow-list entry without documenting the exact false positive and reviewing the affected history.

## Change design

Prefer a narrow adapter around a documented official vendor contract. A proposal needs an explicit threat analysis before adding any of the following:

- a provider or credential storage mechanism;
- OAuth, WIF, or credential-cache parsing;
- repository-local configuration or trust exceptions;
- custom endpoints/model providers;
- command hooks or plugin execution;
- remote services, telemetry, self-update, or credential synchronization;
- unsafe Rust.

Do not add fallbacks that silently switch authentication modes, endpoints, accounts, or billing domains. Do not accept credentials in ordinary arguments. Do not use a shell to compose vendor commands. Do not inspect undocumented token internals just to improve display output.

## Testing expectations

Security-sensitive changes should include the failure case as well as the happy path. Depending on scope, cover:

- hostile argument preservation;
- environment sanitization and selected-secret isolation;
- output/debug redaction;
- invalid auth/billing/config combinations;
- symlink, ownership, mode, and path-search rejection;
- repository settings inspection;
- interrupted/parallel metadata updates and profile locking;
- vendor nonzero exit and signal propagation;
- non-interactive and untrusted-CI refusal.

Real-vendor validation is manual and must use a disposable test account or organizational test workspace. Record CLI/OS versions and results without committing account output or state. Never add real credentials to fixtures.

## Documentation and compatibility

Update the command/configuration docs and changelog with behavior changes. Do not claim an OS, vendor flow, keyring mode, signing mechanism, or release channel is tested unless evidence exists. Put deployment-specific results in qualification evidence; do not guess vendor version ranges.

Schema changes require a migration/downgrade plan and an update to `SCHEMA_VERSION`. A release must not silently reinterpret older metadata.

## Pull requests

Keep changes focused. Explain:

- the problem and intended behavior;
- security/trust-boundary impact;
- tests performed, including OS limitations;
- documentation or migration impact;
- any vendor contract relied upon.

By submitting a contribution, you agree that it may be distributed under the Apache License 2.0.
