# Contributing

Contributions are welcome when they preserve the small security boundary: `ctxlane` selects and isolates credentials for official vendor CLIs; it is not an alternate API or OAuth client.

Security vulnerabilities belong in the private process described by [SECURITY.md](SECURITY.md), not a public issue or pull request.

## Development setup

Install Rust 1.89 or newer. The checked-in toolchain file selects the repository's development toolchain.

From a source checkout:

```bash
cargo build --locked
cargo test --all-targets --all-features --locked
```

Tests must not depend on real Claude/Codex accounts, keyrings, tokens, network access, or personal home-directory state. Use `tempfile`, `--root`, and explicit fake-vendor executable flags.

Read [Testing](docs/testing.md) before changing a process, credential, terminal, or platform boundary. It explains the automated layers and the separate deployment-qualification process.

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
cargo deny --all-features --locked check
```

CI repeats these checks across the declared matrix and also runs dependency-policy, full-history secret scans, and coverage floors of 75% regions, 60% functions, and 70% lines. A lockfile change should be intentional and reviewed. Do not weaken a security or coverage gate without explaining the reason and reviewing the affected evidence.

Useful focused commands are:

```bash
cargo test --locked --test cli_workflow
cargo test --locked --test error_contract
cargo test --locked --test runner_contract
cargo test --locked --features test-fixtures --test native_vendor_contract
cargo test --locked --test tui_pty
```

The native fake-vendor suite is the offline process-level E2E layer. It proves local wrapper contracts, not live provider compatibility. The Unix runner suite is disabled on Windows; a zero-test result there is not Windows evidence.

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

Choose the lowest test layer that proves the rule. Add a CLI, fake-vendor, or PTY test when the public process boundary is part of the behavior. Platform-gated behavior needs a native job on that platform; compilation alone cannot prove ACL, terminal, or process semantics.

Real-vendor validation is manual or private and must use a disposable test account or organizational test workspace. The public suite does not test live Claude/Codex login, remote WIF exchange, billing attribution, native OS-keyring prompts, Windows deployment behavior, Authenticode, Apple signing, or macOS notarization. Record versions and results in the approved private evidence system without committing account output or state. Never add real credentials to fixtures.

Coverage measures executed code, not security or compatibility. Do not lower a coverage number by excluding hard modules, and do not add shallow assertions only to raise it. When reporting coverage, include the revision, host, toolchain, exact command, and region/function/line values.

## Documentation and compatibility

Update the command/configuration docs and changelog with behavior changes. Do not claim an OS, vendor flow, keyring mode, signing mechanism, or release channel is tested unless evidence exists. Put deployment-specific results in qualification evidence; do not guess vendor version ranges.

Schema changes require a migration/downgrade plan and an update to `SCHEMA_VERSION`. A release must not silently reinterpret older metadata.

## Pull requests

Keep changes focused. Explain:

- the problem and intended behavior;
- security/trust-boundary impact;
- tests performed, including OS limitations;
- automated layer and any private qualification that must be repeated;
- documentation or migration impact;
- any vendor contract relied upon.

By submitting a contribution, you agree that it may be distributed under the Apache License 2.0.
