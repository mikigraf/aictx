# Testing

This page explains what the repository tests prove and what still needs private deployment qualification.

## Evidence model

`aictx` uses three kinds of evidence:

1. **Automated tests** check the wrapper with synthetic data, temporary directories, and fake vendor programs. They do not use a network or a real credential.
2. **CI results** show that one committed revision passed the configured jobs. A workflow file by itself is not proof that a revision passed.
3. **Deployment qualification** checks real accounts, operating-system services, and release controls in the environment where `aictx` will run. This evidence is private and manual unless an organization supplies its own protected test system.

In this project, “automated end to end” means that the compiled `aictx` binary starts a compiled native fake-vendor process and verifies selected local contracts through the operating-system process boundary. It does not mean that a test contacted Claude or Codex.

## Automated layers

| Layer | Location | What it checks |
| --- | --- | --- |
| Unit | `src/**` test modules | parsing, validation, resolution, activation, environment construction, policy scanners, shell quoting, error rendering, and TUI state/rendering |
| CLI lifecycle | `tests/cli_workflow.rs`, `tests/error_contract.rs` | the public binary, initialization, profile/context lifecycle, bindings, status, doctor readiness/JSON, shell output, completions, stable exit categories, recovery hints, locking, and local filesystem policy |
| Unix runner contracts | `tests/runner_contract.rs` | argument and exit propagation, environment cleaning, lifecycle locks, process signals, repository-policy refusals, and injected-secret routing through temporary shell fixtures |
| Native fake-vendor E2E | `tests/native_vendor_contract.rs`, `tests/fixtures/native_vendor.rs` | a compiled fake vendor executable on the host OS, including WIF selectors, Codex OAuth preflight, static Claude preflight, isolated state, secret absence, and vendor exit status |
| Terminal/PTY | `tests/tui_pty.rs` | dashboard startup, resize handling, `q`, `Ctrl-C`, alternate-screen and cursor restoration, and refusal before raw mode |
| Toolchain and OS matrix | `.github/workflows/ci.yml` | Rust 1.89 check/tests on Linux and pinned Rust tests on native Linux, macOS, and Windows runners |
| Security and release gates | `.github/workflows/ci.yml`, `.github/workflows/release.yml` | formatting, Clippy, rustdoc tests, package creation, dependency policy, full-history secret scanning, checksums, SBOM generation, Sigstore bundles, and GitHub provenance |

The Unix runner suite uses shell fixtures and is disabled on Windows. The native fake-vendor and CLI suites provide process coverage without a shell fixture. Platform-gated code still needs a native job on the matching operating system.

## Run the checks

Run the same local quality checks used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo test --doc --locked
```

`--all-features` enables the compiled `aictx-test-vendor` fixture. Default builds and installs exclude it. The feature exists only for repository tests; do not use `cargo install --all-features --bins` for a production installation because that explicit command also builds the fixture target.

Run one integration layer while developing:

```bash
cargo test --locked --test cli_workflow
cargo test --locked --test error_contract
cargo test --locked --test runner_contract
cargo test --locked --features test-fixtures --test native_vendor_contract
cargo test --locked --test tui_pty
```

On Windows, `runner_contract` contains no tests because the file is Unix-only. Do not treat that result as Windows runner coverage.

Check the minimum supported Rust version separately:

```bash
rustup toolchain install 1.89.0
cargo +1.89.0 check --all-targets --all-features --locked
cargo +1.89.0 test --all-targets --all-features --locked
```

The repository toolchain is pinned in `rust-toolchain.toml`. The CI OS matrix uses native GitHub-hosted runners; it is not a promise for every architecture, distribution, terminal, or vendor release.

## Coverage

CI measures region, function, and line coverage with Rust 1.97.1, `llvm-tools-preview`, and `cargo-llvm-cov` 0.9.0:

```bash
rustup component add llvm-tools-preview --toolchain 1.97.1
cargo install cargo-llvm-cov --version 0.9.0 --locked
CI=true GITHUB_EVENT_NAME=push cargo +1.97.1 llvm-cov \
  --all-targets --all-features --locked --summary-only \
  --fail-under-lines 70 \
  --fail-under-functions 60 \
  --fail-under-regions 75
```

The pre-commit engineering baseline on 2026-08-20 used macOS on arm64, Rust 1.97.1, and `cargo-llvm-cov` 0.9.0 with all targets, all features, the lockfile, and `GITHUB_EVENT_NAME=pull_request`. It ran 95 tests:

| Metric | Measured | CI floor |
| --- | ---: | ---: |
| Regions | 77.79% | 75% |
| Functions | 62.25% | 60% |
| Lines | 74.98% | 70% |

This local measurement describes the reviewed pre-commit worktree, not an immutable revision. Use the green CI report for the committed revision as release evidence.

Coverage is a map of exercised Rust code, not a security score or a provider compatibility claim. Host-only reports do not include code compiled only for another operating system. Record the revision, OS, architecture, Rust version, command, and tool version with every final published measurement. Stable Rust region instrumentation does not provide a reliable branch percentage, so do not present an empty branch column as complete branch coverage.

## What remains private or manual

The public automated suite must stay offline and credential-free. The following evidence requires a protected qualification environment:

| Area | Required qualification |
| --- | --- |
| Live Claude and Codex | login, status, one harmless request, logout, and re-login with approved official CLI versions and disposable test identities |
| Native OS keyring | store, read, delete, missing item, locked store, consent prompt, and access control on each supported OS |
| Claude WIF | real identity-provider issuance, official Claude exchange and refresh, expiry, rotation, denied exchange, and upstream revocation |
| Billing and workspace | confirm the selected account, organization/workspace, and billing destination through vendor-supported account controls |
| Windows runtime | native `.exe` discovery, ACL behavior, console/PTY restoration, argument handling, process exit/signal behavior, and installed vendor launchers |
| Release signing | Authenticode, Apple Developer ID signing, and macOS notarization when required; the public workflow currently supplies checksums, Sigstore bundles, SBOMs, and GitHub provenance |

Keep live qualification output out of the repository. Record only the date, OS, architecture, official vendor version, auth mode, result, and approved evidence location. Never commit account identifiers, token material, vendor state, keyring references, raw environment dumps, or billing records.

See [Compatibility and validation status](compatibility.md) for the deployment checklist and known limits.

## Adding tests

Use the lowest layer that proves the behavior, then add a process-level test when the boundary matters.

- Put deterministic parsing and state transitions in unit tests.
- Use an explicit temporary `--root` for CLI tests. Do not read a developer home directory.
- Use injected secrets or synthetic markers. Do not open the host keyring.
- Use the native fake vendor when executable discovery, stdin/stdout, environment, state, or exit status is part of the contract.
- Use a PTY only for terminal behavior. Always set a short timeout and verify terminal restoration.
- Add native platform coverage for platform-gated behavior. A cross-compile check cannot prove runtime permissions or process behavior.
- Test the refusal path before the credential-access or vendor-spawn marker.
- Assert that diagnostics, records, and debug output do not contain the synthetic secret.

Changes to vendor contracts should also update [Compatibility and validation status](compatibility.md) and state which live qualification must be repeated.
