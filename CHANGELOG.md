# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/) once releases are tagged.

## Unreleased

### Added

- Added interactive dashboard forms for profile, context, and binding metadata. Use `a` to add, `e` to edit, `R` or `F2` to rename a profile or context or edit a binding path, and `d` to remove.
- Published closed Phase-0 JSON schemas and matching Rust wire contracts for signed work-order authorization, identity-lease requests and responses, readiness, stable refusal codes, and credential-isolation classification.
- Added pure, controller-neutral automation policy-intersection and identity-lease lifecycle domains, covering no-widening authority checks, replay binding, deadlines, fencing, renewal acknowledgement, and terminal-state invariants. These library APIs perform no persistence, credential access, process management, or service startup.
- Added configuration schema v2 with immutable non-secret installation and profile UIDs, retired-profile UID tracking, and a validated per-profile automation policy that defaults to `eligible = false`. Valid config-schema-v1 stores are upgraded under the coordinated metadata locks.
- Added strict Codex WIF CLI metadata enrollment and pure config-shape validation; the dashboard does not expose its enrollment or authority fields. CLI enrollment checks Git-worktree ancestry without opening the token, explicit credential diagnostics own availability checks, and doctor skips the token probe. This is enrollment only: `login`, `logout`, `run`, and runtime readiness remain fail-closed before token-path traversal until a native Codex WIF runtime is implemented and qualified.
- Added a sealed, crate-internal SQLite lease-store and recovery-gate foundation on Linux and macOS. It atomically records initial requests, replay bindings, refusals, and append-only audit events, but it is not a service and does not yet activate leases, manage processes, or claim production recovery. Windows refuses this store boundary before filesystem access.

### Changed

- Moved the Homebrew, Claude Code, and Codex first-run paths to the top of the README and clarified the v0.1 migration and verified release evidence.
- Aligned package, command-help, and dashboard positioning around local account isolation.
- Added exact selected-profile recovery hints for missing credentials without exposing opaque keyring handles.
- Completed argument descriptions and copyable examples on the remaining high-value CLI help surfaces.
- Added the automation identity-plane architecture, authority matrix, platform boundary, fencing and renewal rules, fixed-harness boundary, and seven-day audited-retention contract. The current binary remains explicitly unqualified for production automation.
- Profile Rename now preserves private vendor state and the secret reference while updating context links. Context Rename refuses a name change while the context is active; otherwise it updates default and directory-binding references. Binding Edit can change both path and context.
- Clarified that ordinary CLI/TUI account switching and supported local vendor workflows remain standalone, with no service, controller, MCP, ASF, or Runmill dependency. No lease-service, controller, or automation-MCP runtime ships in this tranche; ASF and Runmill are optional future-integration examples only.
- Added standalone boundary regressions that run ordinary CLI and real dashboard PTY flows beside a deliberately invalid would-be lease database and prove it is neither opened nor changed.
- Doctor now reports disabled/eligible automation policy, warns when either explicit exception is acknowledged, and reduces environment, role, and caller scopes to counts. This is policy visibility, not lease readiness.

### Security

- Kept dashboard forms metadata-only. They never read or delete keyring credentials and never start a vendor CLI. Dashboard profile removal retains its keyring credential and leaves immutable managed vendor state detached in place without automatic reuse or cleanup.
- Made `profile remove --delete-secret` restore profile metadata when keyring cleanup fails and rollback succeeds; a rollback failure reports both failures explicitly.
- Defined the signed work-order and lease wire surfaces so credentials, credential paths, vendor homes, reconstructed environments, prompts, source, tool input, and model output cannot appear as contract fields.
- Bound profile lifecycle and vendor-home locking to immutable profile UIDs across renames, and retire removed UIDs so they cannot be reused.
- Refused `ctxlane env` for contexts selecting Codex WIF so an exported `CODEX_HOME` cannot bypass the unqualified native-runtime boundary.

## 0.2.0 - 2026-08-21

### Changed

- Renamed the package, library, executable, platform application identity, new keyring service, shell selector, release artifacts, and documentation from `aictx` to `ctxlane` for version 0.2.0.
- Added explicit copy-only `ctxlane migrate aictx` and recovery commands. Legacy metadata, vendor state, and credential references remain unchanged; advisory lock files may be created or normalized while coordinating the copy.
- Added `ctxlane init --fresh` and `ctxlane init --guided --fresh` for users who intentionally want a separate empty store when v0.1 metadata is detected.
- Reframed public product language around account selection and profile separation while keeping `profile` as the CLI and configuration object.

## 0.1.0 - 2026-08-20

### Added

- Initial Rust implementation of the `aictx` CLI.
- Versioned profile, context, active-state, and canonical directory-binding metadata.
- Claude subscription setup-token, API-key, and WIF profile modes.
- Codex isolated ChatGPT OAuth, API-key, and managed-workspace access-token profile modes.
- Native OS-keyring storage for static credentials.
- Clean child-environment construction, direct argument forwarding, profile locks, atomic metadata writes, and owner/permission checks.
- Billing-domain banners and confirmation on context changes.
- Ratatui terminal dashboard for context selection, profile and binding inspection, and safe active-context changes.
- Status, credential availability, doctor, shell shims, non-secret environment selectors, and shell completion generation.
- Provider-neutral `--auth subscription` profile creation while preserving vendor-native configuration and compatibility auth spellings.
- Guided first-run setup for the `claude:personal` subscription profile through `aictx init --guided`.
- Homebrew installation through the `mikigraf/tap` third-party tap.
- Actionable error hints, close-name suggestions, command help examples, and machine-readable `doctor --json` readiness reports.
- Unit, CLI lifecycle, native fake-vendor, Unix runner, and PTY contract tests plus coverage-gated cross-platform CI and release scaffolding.

### Security

- Reject credential/endpoint routing and repository command hooks that could defeat profile selection or exfiltrate a credential.
- Reject insecure/symlinked sensitive paths on supported Unix checks, executable self-recursion, and repository-local bare executable resolution.
- Refuse static-secret and cached Codex OAuth use when inherited GitHub event metadata identifies a pull-request workflow, and require an explicit trusted-runner assertion for long-lived subscription/OAuth/access-token automation in CI/non-interactive execution.
- Produce keyless Sigstore bundles, checksums, an SBOM, and GitHub provenance for release assets, and scan repository history for committed secrets in CI.
- Bound local vendor version and authentication-status preflights so a broken executable cannot block diagnostics or a run indefinitely.
- Normalize safe line wrapping and indentation in raw setup-token pastes, reject shell-style or ambiguous input before keyring storage, and never execute pasted credential text.
- Distinguish local Claude authentication-route evidence from remote validity, which begins with a successful model request.
