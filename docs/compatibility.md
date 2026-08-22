# Compatibility and validation status

This document distinguishes implemented behavior from evidence still required in each deployment. It does not promise compatibility with every past or future Claude Code or Codex release.

## Build baseline

| Area | Declared baseline | Repository validation |
| --- | --- | --- |
| Rust | MSRV 1.89; edition 2024 | CI compiles/tests 1.89 on Linux and pinned Rust 1.97.1 on Linux, macOS, and Windows |
| Metadata | config schema v2; mutable-state schema v1 | strict locked config-v1-to-v2 upgrade; unknown versions/fields and invalid relationships are rejected |
| Linux | current GitHub-hosted Ubuntu image | unit, CLI, Unix runner, native fake-vendor, and PTY tests in CI |
| macOS | current GitHub-hosted macOS image | unit, CLI, Unix runner, native fake-vendor, and PTY tests in CI |
| Windows | current GitHub-hosted Windows image | unit, CLI, native fake-vendor, and PTY tests in CI; Unix shell-fixture contracts are disabled |
| Automation store | SQLite WAL on an owner-private local filesystem; Linux service target and macOS development only | sealed internal schema/replay/recovery-gate tests on Linux/macOS; Windows rejects before filesystem access; NFS and other network filesystems are unqualified |
| Terminal UI | Ratatui with Crossterm | renderer/state tests plus native PTY resize, exit, refusal, and restoration checks; deployment terminals still need qualification |
| Coverage | regions/functions/lines | CI floors are 75%/60%/70%; see [Testing](testing.md) for the measured baseline and interpretation |

CI configuration is an intended validation matrix, not proof that a given commit has passed until its workflow run is green. The OS matrix uses native GitHub-hosted runners. It does not qualify every architecture, distribution, terminal host, or vendor release. See [Testing](testing.md) for exact commands and test-layer limits.

The config-v2 automation policy is operator-owned foundation and defaults to `eligible = false`. This release has no supported lease service, automation MCP server, or controller runtime. It contains a crate-internal Linux/macOS SQLite store foundation for initial request, refusal, replay, audit, and recovery-gate work only; it is not opened by ordinary commands and is not a production-recovery claim. Ordinary CLI/TUI account switching and supported local vendor workflows remain standalone, with no ASF, Runmill, service, controller, MCP, or lease-store dependency.

## Evidence classes

- **Automated contract evidence** uses temporary state, synthetic credentials, and fake vendor programs. It is safe for public CI.
- **Revision evidence** is a green CI and release run for the exact commit or tag being evaluated.
- **Deployment qualification** uses approved real accounts, native OS services, and release identities. Keep this evidence in a protected system.

The compiled native fake-vendor suite is process-level E2E evidence for the wrapper. It is not a live Claude or Codex test.

### v0.2.0 release evidence

The source CI and release workflow passed for the commit tagged as [v0.2.0](https://github.com/mikigraf/ctxlane/releases/tag/v0.2.0). The published platform archives, checksums, CycloneDX SBOM, Sigstore bundles, and GitHub provenance attestations were verified against that release. Authenticode, Apple Developer ID signing, and macOS notarization remain separate deployment requirements where an organization needs them.

## Vendor contracts

`ctxlane` intentionally relies on documented public process contracts rather than pinning guessed vendor CLI versions:

| Contract | Automated coverage | Production qualification still required |
| --- | --- | --- |
| direct argument forwarding and exit-code propagation | fake executable tests | current official binaries on each deployment OS |
| competing credential/base-URL/loader removal and trusted child `PATH` | environment construction and fake executable/interpreter tests | validate billing/account using vendor-supported status UI/command |
| Claude `CLAUDE_CONFIG_DIR` isolation | fake executable tests | Linux/Windows official Claude behavior; native macOS subscription login is excluded |
| Guided Claude setup, setup-token capture, and auth-route preflight | CLI/native fake-vendor, input-validation, static environment, and `auth status` contract tests | official setup-token generation, native keyring behavior, first remote model request, expiry/rotation, feature limitations |
| Claude API key and auth-route preflight | environment and `auth status` contract tests | real API account, remote validity, billing attribution, and whether optional org pins expose `orgId`/`orgName` |
| Claude WIF selectors/identity-token file | unit tests/private-file checks | real IdP federation and official client exchange/refresh |
| isolated Codex `CODEX_HOME` | fake executable/config tests | browser and device OAuth on each deployment OS |
| Codex forced login/workspace/credential-store config | config tests | managed workspace enforcement in the organization's current Codex CLI |
| Codex API key stdin login and secret-free main child | runner contract tests | real API account, vendor credential-store behavior, and billing attribution |
| Codex access-token stdin login and CI refusal policy | runner policy/contract tests | eligible managed workspace (currently documented for ChatGPT Enterprise) and private runner |
| Codex WIF enrollment metadata and fail-closed boundary | pure model/config validation, CLI ancestry/persistence, login/logout/run/env refusal, explicit credential-file checks, and doctor runtime-unqualified tests | native Codex WIF runtime is not implemented; after implementation, qualify identity/workspace binding, token-file safety, official version, exchange, refresh, expiry, and revocation |
| native OS keyring | reference parsing, injected-secret routing, fail-before-access policy, and diagnostics | real store/read/delete, locked-store behavior, consent UI, and ACLs on each OS |

On Windows, configured Claude and Codex executables must resolve to native `.exe` files. `.bat` and `.cmd` launchers are refused because Windows executes them through `cmd.exe`, which cannot preserve the wrapper's no-shell argument boundary.

The implementation does not parse token claims or undocumented credential-cache formats. Account labels are masked configured hints. Claude organization pins are compared with fields exposed by the official local auth-status command, and Codex workspace pins are forced through official configuration; neither is independent cryptographic or remote-service verification. A successful Claude auth-status result is local route evidence only. The first successful model request is the remote credential check at that point in time.

## Known boundaries

### Claude on macOS

`CLAUDE_CONFIG_DIR` is set for every Claude profile, but full switching of native Claude subscription logins stored by Claude in the macOS Keychain is not implemented or claimed. Use setup-token/API/WIF profiles, or separate OS identities when complete native-login separation is required.

### Codex keyring and auto modes

Distinct `CODEX_HOME` directories provide explicit file-store separation. With `cli_auth_credentials_store = "keyring"` or `"auto"`, credential namespacing and isolation remain vendor/OS-defined. Qualify these modes before using multiple sensitive identities on one account.

### Interactive keyrings

Native keyrings may prompt for unlock or consent. `--non-interactive` therefore refuses credential reads, writes, and deletes in the keyring instead of assuming they will be silent. Headless Claude jobs should use WIF where it is available.

### Guided setup

`ctxlane init --guided` supports the exact `claude:personal` subscription-token path. It validates existing metadata, refuses incompatible profile reuse, invokes the official setup-token process, applies bounded input-safety checks without depending on an undocumented token prefix or length, and stores the captured credential in the OS keyring. It does not create a context. Public tests use synthetic input and a native fake vendor; they do not run a live Claude login, write to the host keyring, or make a model request.

### Repository settings

To prevent a selected credential from being rerouted or exfiltrated, runs reject competing credential/endpoint settings and inspected startup repository command hooks. This can make a repository that intentionally uses a custom provider, MCP command, hook, or notification incompatible with `ctxlane run`. There is no bypass in `0.2.0`. Claude may still discover descendant `.claude` definitions after navigating or editing deeper paths during a live session; blocked `--add-dir` and subprocess credential scrubbing mitigate but do not eliminate that residual code-execution surface.

### Schema migration

The current configuration schema is version `2`; `state.toml` remains version `1`. On the first coordinated normal load or mutation, a valid config-schema-v1 file is upgraded under the exclusive metadata/config locks and replaced atomically. The upgrade creates one immutable installation UID, derives immutable profile UIDs from that installation UID, the provider, and each immutable managed state leaf identity, and adds a validated automation policy with `eligible = false` to every profile. A diagnostic-only read can validate a non-authoritative in-memory projection without writing it. Unknown schema versions and invalid or unknown fields fail closed.

This is a one-way format transition: there is no config-v2-to-v1 downgrade, and an older binary that only understands config schema v1 must not be used after the upgrade. The explicit copy-only `ctxlane migrate aictx` application-store flow is separate; see [Migration from v0.1](migration-from-v0.1.md). Legacy metadata and vendor state remain in the source store for rollback, and migration coordination may create or normalize advisory profile lock files there.

## Qualification checklist

Before enabling a new OS/vendor version combination:

1. Install official vendor CLIs through your approved channel.
2. Run interactive `ctxlane doctor --json` and record the reviewed report without recording secrets. In `--non-interactive` mode, static OS-keyring reads are skipped with a warning; this is not static-credential readiness evidence.
3. Exercise login, status, one harmless request, logout, and re-login for each runnable supported auth mode. Codex WIF is enrollment-only and must remain excluded until its native runtime is implemented and qualified.
4. Confirm the expected vendor account/workspace and billing domain using vendor-supported status/account controls.
5. Seed deliberately conflicting parent environment variables and verify the selected identity still wins.
6. Test a locked native keyring and a missing or denied keyring item.
7. Run two distinct profiles concurrently and verify their state does not cross.
8. Validate remote revocation and employee/offboarding procedures outside `ctxlane`.
9. For CI, prove fork/untrusted triggers cannot enter the credential-bearing job.
10. On Windows, test the installed native vendor `.exe`, user ACLs, console/PTY restoration, and process exit behavior.
11. For a release, verify checksums, SBOM, Sigstore bundle, and provenance. Qualify Authenticode, Apple signing, and macOS notarization separately where required.

Record the tested vendor version and date in deployment evidence rather than hard-coding a speculative compatibility range here.

## Upstream references

- [Claude Code authentication and credential precedence](https://code.claude.com/docs/en/authentication)
- [Anthropic Workload Identity Federation reference](https://platform.claude.com/docs/en/manage-claude/wif-reference)
- [OpenAI Codex authentication and credential storage](https://developers.openai.com/codex/auth/)
- [OpenAI Codex developer commands](https://developers.openai.com/codex/cli/reference/)
- [OpenAI Codex configuration reference](https://developers.openai.com/codex/config-reference/)
