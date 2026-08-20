# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/) once releases are tagged.

## Unreleased

No changes yet.

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
