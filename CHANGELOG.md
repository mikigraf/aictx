# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/) once releases are tagged.

## Unreleased

### Added

- Added interactive dashboard forms for profile, context, and binding metadata. Use `a` to add, `e` to edit, `R` or `F2` to rename a profile or context or edit a binding path, and `d` to remove.

### Changed

- Moved the Homebrew, Claude Code, and Codex first-run paths to the top of the README and clarified the v0.1 migration and verified release evidence.
- Aligned package, command-help, and dashboard positioning around local account isolation.
- Added exact selected-profile recovery hints for missing credentials without exposing opaque keyring handles.
- Completed argument descriptions and copyable examples on the remaining high-value CLI help surfaces.
- Profile Rename now preserves private vendor state and the secret reference while updating context links. Context Rename refuses a name change while the context is active; otherwise it updates default and directory-binding references. Binding Edit can change both path and context.

### Security

- Kept dashboard forms metadata-only. They never read or delete keyring credentials and never start a vendor CLI. Dashboard profile removal retains its keyring credential and leaves immutable managed vendor state detached in place without automatic reuse or cleanup.
- Made `profile remove --delete-secret` restore profile metadata when keyring cleanup fails and rollback succeeds; a rollback failure reports both failures explicitly.

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
