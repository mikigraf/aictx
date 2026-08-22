# Testing

This page explains what the repository tests prove and what still needs private deployment qualification.

## Evidence model

`ctxlane` uses three kinds of evidence:

1. **Automated tests** check the wrapper with synthetic data, temporary directories, and fake vendor programs. They do not use a network or a real credential.
2. **CI results** show that one committed revision passed the configured jobs. A workflow file by itself is not proof that a revision passed.
3. **Deployment qualification** checks real accounts, operating-system services, and release controls in the environment where `ctxlane` will run. This evidence is private and manual unless an organization supplies its own protected test system.

In this project, “automated end to end” means that the compiled `ctxlane` binary starts a compiled native fake-vendor process and verifies selected local contracts through the operating-system process boundary. It does not mean that a test contacted Claude or Codex. The ordinary CLI/TUI suites are standalone and do not start or require a service, controller, MCP server, ASF, or Runmill.

## Automated layers

| Layer | Location | What it checks |
| --- | --- | --- |
| Unit | `src/**` test modules | parsing, config-v2 installation/profile UID and automation-policy invariants, Codex WIF enrollment validation, resolution, activation, environment construction, policy scanners, shell quoting, error rendering, and deterministic TUI state, rendering, and form-input checks |
| Automation wire contracts | `src/automation/contracts/**`, `schemas/**` | strict Rust serialization and validation, Draft 2020-12 schemas, schema/Rust parity, authority-field sensitivity, stable status/reason matrices, secret-surface exclusions, canonical request hashing, and the public Ed25519 signing vector |
| Automation policy/lease domain | `src/automation/policy/**`, `src/automation/lease/**`, `tests/automation_domain.rs`, `tests/automation_domain/**` | profile/request/controller intersection and no-widening, effective-policy digest and capacity binding, replay handling, issuance and monotonic deadlines, fencing, renewal acknowledgement, and terminal-state invariants; no service, persistence, credential access, or process execution |
| Automation store foundation | `src/automation/store/**` | owner-private SQLite creation, defensive connection settings, schema and installation binding, service locking, recovery typestate, atomic request/replay/refusal/audit records, replay-retention bounds, corruption and crash-retry handling, extension denial, and unsupported-platform refusal; no public service, activation, renewal, process reconciliation, or pruning |
| Config v2 foundation | `tests/config_v2_foundation.rs`, `tests/fixtures/v0_2_0_schema_v1/**` | frozen config-v1 upgrade, diagnostic-only projection, stable installation/profile UIDs, default-disabled policy, active/retired UID disjointness, required v2 automation blocks, and redacted malformed-config errors |
| Metadata management | `tests/management_service.rs` | temporary-root profile, context, and binding Add/Edit/Rename/Remove lifecycles, immutable profile-UID preservation and retirement, default-disabled policy, reference rewrites, active-context rename refusal, stale snapshots, collision guards, immutable private state, secret-reference preservation, detached-state retention without reuse, and missing-path binding removal |
| CLI lifecycle | `tests/cli_workflow.rs`, `tests/error_contract.rs`, `tests/standalone_automation_boundary.rs` | the public binary, plain initialization, non-interactive guided refusal, profile/context lifecycle, strict Codex WIF enrollment and unqualified-runtime refusal, bindings, status, doctor readiness/JSON and count-only automation-policy visibility, shell output, completions, stable exit categories, recovery hints, locking, local filesystem policy, and ordinary-command independence from an invalid would-be automation database |
| v0.1 migration | `tests/migration_core.rs`, `tests/migration_cli.rs`, `tests/migration_locking.rs`, `tests/migration_recovery.rs`, `tests/migration_windows.rs`, `tests/v01_migration_compat.rs` | frozen v0.1 input, explicit dry run/copy/recovery, path rewriting, keyring-reference preservation, source-data preservation with advisory lock coordination, simultaneous startup, collisions, symlinks/reparse points, journals, and every interrupted recovery transition |
| Branding contract | `tests/branding_contract.rs` | current product naming across tracked files and an exact allowlist for required v0.1 migration literals |
| Unix runner contracts | `tests/runner_contract.rs` | argument and exit propagation, environment cleaning, lifecycle locks, process signals, repository-policy refusals, and injected-secret routing through temporary shell fixtures |
| Native fake-vendor E2E | `tests/native_vendor_contract.rs`, `tests/setup_token_pty.rs`, `tests/fixtures/native_vendor.rs` | a compiled fake vendor executable on the host OS, including guided Claude setup-token invocation/failure, Claude WIF selectors, Codex OAuth preflight, static Claude route checks, isolated state, secret absence, and vendor exit status |
| Terminal/PTY | `tests/tui_pty.rs`, `tests/setup_token_pty.rs` | dashboard startup beside an invalid would-be automation database, resize, scripted profile Add/Edit/Rename/Remove with persisted-state checks and secret-reference non-disclosure, `Ctrl-C`/normal exit, output synchronization, and terminal restoration; plus guided setup-token preflight preservation, protected wrapped-paste handling, queued-input draining into a next-shell check, cancellation, signals, and bracketed-paste cleanup |
| Toolchain and OS matrix | `.github/workflows/ci.yml` | Rust 1.89 check/tests on Linux and pinned Rust tests on native Linux, macOS, and Windows runners |
| Security and release gates | `.github/workflows/ci.yml`, `.github/workflows/release.yml` | formatting, Clippy, rustdoc tests, package creation, dependency policy, full-history secret scanning, checksums, SBOM generation, Sigstore bundles, and GitHub provenance |

The Unix runner suite uses shell fixtures and is disabled on Windows. The native fake-vendor and CLI suites provide process coverage without a shell fixture. Platform-gated code still needs a native job on the matching operating system.

Deterministic TUI tests cover editor input, its ordinary supported profile-auth forms and Claude WIF form, form navigation, and non-disclosure of stored identity metadata. Codex WIF enrollment and authority-field editing are intentionally absent from the dashboard. Separate temporary-root lifecycle tests cover the metadata mutations without reading a host keyring or starting a vendor CLI. The real dashboard PTY suite drives a metadata-only profile through Add, Edit, Rename, and Remove, reloads persisted configuration after every transition, proves its secret reference is never rendered, and verifies terminal restoration. It does not call login, logout, a vendor process, or a native keyring.

The Claude static-auth contracts prove that the selected credential reaches the expected local `claude auth status --json` route. They do not make a model request. The public suite therefore cannot prove remote credential validity; that evidence starts with a successful request in the protected qualification environment.

The Codex WIF contracts prove only strict metadata enrollment and validation, immutable persistence, fail-closed `login`, `logout`, `run`, and `env` boundaries, and doctor runtime refusal without a Codex token probe. They distinguish pure config-shape validation from the enrollment-time Git-worktree-ancestry check and the explicit credential-check file probe. The login/logout/run paths refuse before token-path-derived filesystem inspection or vendor launch; `env` refuses before exporting an unsupported `CODEX_HOME`. These contracts do not prove a native Codex WIF environment contract, token exchange, principal/workspace verification, or workload qualification; that runtime does not exist in this release.

The automation wire/schema and pure policy/lease-domain tests prove data shape, authority intersection, replay, deadline, fencing, renewal, and state-machine invariants. The separate sealed-store tests prove only the initial durable request/refusal/replay/audit transaction boundary and a conservative recovery gate on supported local filesystems. Together they still do not provide a lease service, caller authentication, signature verifier, lease activation/renewal persistence, process reconciler, provider harness, pruning implementation, controller, or automation MCP server.

Store tests use temporary local roots. They do not qualify SQLite WAL operation on NFS or another network filesystem. Linux deployment code must eventually verify a supported local-filesystem environment before opening the production service; macOS remains development-only, and the Windows store stub must fail before creating any file.

Doctor policy-view tests may assert disabled/eligible levels, warnings for either explicit exception acknowledgement, and environment/role/caller counts. They must not render the underlying scope values, and those checks do not claim lease readiness.

## Run the checks

Run the same local quality checks used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo test --doc --locked
```

CI also creates an isolated pinned Python environment from the hash-locked
`schemas/tests/requirements.txt` file and runs:

```bash
python3 schemas/tests/validate_contracts.py
```

That gate validates every published example and negative invariant against the
actual Draft 2020-12 schemas and verifies the public Ed25519 signing vector.

`--all-features` enables the compiled `ctxlane-test-vendor` fixture. Default builds and installs exclude it. The feature exists only for repository tests; do not use `cargo install --all-features --bins` for a production installation because that explicit command also builds the fixture target.

Run one integration layer while developing:

```bash
cargo test --locked --test cli_workflow
cargo test --locked --test error_contract
cargo test --locked --test config_v2_foundation
cargo test --locked --test automation_domain
cargo test --locked --test management_service
cargo test --locked --test migration_core
cargo test --locked --test migration_cli
cargo test --locked --test migration_locking
cargo test --locked --test migration_recovery
cargo test --locked --test v01_migration_compat
cargo test --locked --test branding_contract
cargo test --locked --test runner_contract
cargo test --locked --features test-fixtures --test native_vendor_contract
cargo test --locked --test tui_pty
cargo test --locked --features test-fixtures --test setup_token_pty
```

On Windows, also run `cargo test --locked --test migration_windows` for the native junction/reparse-point contract. `runner_contract` and `setup_token_pty` contain no tests on Windows because those files are Unix-only. Do not treat those empty results as Windows runner or setup-token terminal coverage; the native fake-vendor, migration, and CLI suites still run there.

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

For commit `d28a8a7` on macOS arm64 on 2026-08-21, the exact command above used Rust 1.97.1 and `cargo-llvm-cov` 0.9.0, ran 159 tests, and recorded 79.47% region coverage, 63.81% function coverage, and 76.59% line coverage. The enforced floors are 75%, 60%, and 70%, respectively. Platform gating changes the test count and compiled lines on Windows and Linux. Use the hosted CI and coverage reports for the exact published revision as final release evidence.

Coverage is a map of exercised Rust code, not a security score or a provider compatibility claim. Host-only reports do not include code compiled only for another operating system. Record the revision, OS, architecture, Rust version, command, and tool version with every final published measurement. Stable Rust region instrumentation does not provide a reliable branch percentage, so do not present an empty branch column as complete branch coverage.

## What remains private or manual

The public automated suite must stay offline and credential-free. The following evidence requires a protected qualification environment:

| Area | Required qualification |
| --- | --- |
| Live Claude and Codex | login, status, one harmless request, logout, and re-login with approved official CLI versions and disposable test identities |
| Native OS keyring | store, read, delete, missing item, locked store, consent prompt, and access control on each supported OS |
| Claude WIF | real identity-provider issuance, official Claude exchange and refresh, expiry, rotation, denied exchange, and upstream revocation |
| Codex WIF | first implement the native runtime boundary; then qualify token-file race resistance, official version, identity and workspace verification, exchange/refresh, expiry, rotation, denial, and revocation |
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
- Keep guided-login tests synthetic: prove initialization, the exact setup-token process call, wrapped-paste normalization, and malformed-input rejection without storing a real credential.
- Use the native fake vendor when executable discovery, stdin/stdout, environment, state, or exit status is part of the contract.
- Use a PTY only for terminal behavior. Always set a short timeout and verify terminal restoration.
- Keep TUI CRUD rules in deterministic form and metadata-store tests. Add only a small real-PTY journey, and claim it only after it passes on the native CI targets.
- Add native platform coverage for platform-gated behavior. A cross-compile check cannot prove runtime permissions or process behavior.
- Test the refusal path before the credential-access or vendor-spawn marker.
- Assert that diagnostics, records, and debug output do not contain the synthetic secret.

Changes to vendor contracts should also update [Compatibility and validation status](compatibility.md) and state which live qualification must be repeated.
