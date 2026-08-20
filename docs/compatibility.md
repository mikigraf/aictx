# Compatibility and validation status

This document distinguishes implemented behavior from evidence still required in each deployment. It does not promise compatibility with every past or future Claude Code or Codex release.

## Build baseline

| Area | Declared baseline | Repository validation |
| --- | --- | --- |
| Rust | MSRV 1.89; edition 2024 | CI compiles/tests 1.89 on Linux and pinned Rust 1.97.1 on Linux, macOS, and Windows |
| Metadata | schema version 1 | unknown versions/fields and invalid relationships are rejected |
| Linux | current GitHub-hosted Ubuntu image | unit and fake-vendor contract tests in CI |
| macOS | current GitHub-hosted macOS image | unit and fake-vendor contract tests in CI |
| Windows | current GitHub-hosted Windows image | unit/CLI workflow tests and compile coverage in CI; Unix-only fake-vendor contracts are not exercised |
| Terminal UI | Ratatui with Crossterm | renderer, navigation, no-secret display, activation, and non-terminal refusal tests; native Windows terminal use still needs deployment validation |

CI configuration is an intended validation matrix, not proof that a given commit has passed until its workflow run is green. Local development to date validates the host runtime plus compile checks for Linux and Windows targets.

## Vendor contracts

`aictx` intentionally relies on documented public process contracts rather than pinning guessed vendor CLI versions:

| Contract | Automated coverage | Production qualification still required |
| --- | --- | --- |
| direct argument forwarding and exit-code propagation | fake executable tests | current official binaries on each deployment OS |
| competing credential/base-URL/loader removal and trusted child `PATH` | environment construction and fake executable/interpreter tests | validate billing/account using vendor-supported status UI/command |
| Claude `CLAUDE_CONFIG_DIR` isolation | fake executable tests | Linux/Windows official Claude behavior; native macOS subscription login is excluded |
| Claude setup-token injection and auth-route preflight | fake/static environment and `auth status` contract tests | official setup-token generation, remote validity, expiry/rotation, feature limitations |
| Claude API key and auth-route preflight | environment and `auth status` contract tests | real API account, remote validity, billing attribution, and whether optional org pins expose `orgId`/`orgName` |
| Claude WIF selectors/identity-token file | unit tests/private-file checks | real IdP federation and official client exchange/refresh |
| isolated Codex `CODEX_HOME` | fake executable/config tests | browser and device OAuth on each deployment OS |
| Codex forced login/workspace/credential-store config | config tests | managed workspace enforcement in the organization's current Codex CLI |
| Codex API key stdin login and secret-free main child | runner contract tests | real API account, vendor credential-store behavior, and billing attribution |
| Codex access-token stdin login and CI refusal policy | runner policy/contract tests | eligible managed workspace (currently documented for ChatGPT Enterprise) and private runner |
| native OS keyring | library integration plus diagnostics | store/read/delete, locked-store behavior, consent UI, and ACLs on each OS |

On Windows, configured Claude and Codex executables must resolve to native `.exe` files. `.bat` and `.cmd` launchers are refused because Windows executes them through `cmd.exe`, which cannot preserve the wrapper's no-shell argument boundary.

The implementation does not parse token claims or undocumented credential-cache formats. Account labels are masked configured hints. Claude organization pins are compared with fields exposed by the official local auth-status command, and Codex workspace pins are forced through official configuration; neither is independent cryptographic or remote-service verification.

## Known boundaries

### Claude on macOS

`CLAUDE_CONFIG_DIR` is set for every Claude profile, but full switching of native Claude subscription logins stored by Claude in the macOS Keychain is not implemented or claimed. Use setup-token/API/WIF profiles, or separate OS identities when complete native-login separation is required.

### Codex keyring and auto modes

Distinct `CODEX_HOME` directories provide explicit file-store separation. With `cli_auth_credentials_store = "keyring"` or `"auto"`, credential namespacing and isolation remain vendor/OS-defined. Qualify these modes before using multiple sensitive identities on one account.

### Interactive keyrings

Native keyrings may prompt for unlock or consent. `--non-interactive` therefore refuses credential reads, writes, and deletes in the keyring instead of assuming they will be silent. Headless Claude jobs should use WIF where it is available.

### Repository settings

To prevent a selected credential from being rerouted or exfiltrated, runs reject competing credential/endpoint settings and inspected startup repository command hooks. This can make a repository that intentionally uses a custom provider, MCP command, hook, or notification incompatible with `aictx run`. There is no bypass in `0.1.0`. Claude may still discover descendant `.claude` definitions after navigating or editing deeper paths during a live session; blocked `--add-dir` and subprocess credential scrubbing mitigate but do not eliminate that residual code-execution surface.

### Schema migration

Only schema `1` is supported. There is no downgrade or migration command yet. Back up metadata before upgrading across a release that announces a schema change.

## Qualification checklist

Before enabling a new OS/vendor version combination:

1. Install official vendor CLIs through your approved channel.
2. Run `aictx doctor` and record version output without recording secrets.
3. Exercise login, status, one harmless request, logout, and re-login for each supported auth mode.
4. Confirm the expected vendor account/workspace and billing domain using vendor-supported status/account controls.
5. Seed deliberately conflicting parent environment variables and verify the selected identity still wins.
6. Test a locked native keyring and a missing or denied keyring item.
7. Run two distinct profiles concurrently and verify their state does not cross.
8. Validate remote revocation and employee/offboarding procedures outside `aictx`.
9. For CI, prove fork/untrusted triggers cannot enter the credential-bearing job.

Record the tested vendor version and date in deployment evidence rather than hard-coding a speculative compatibility range here.

## Upstream references

- [Claude Code authentication and credential precedence](https://code.claude.com/docs/en/authentication)
- [Anthropic Workload Identity Federation reference](https://platform.claude.com/docs/en/manage-claude/wif-reference)
- [OpenAI Codex authentication and credential storage](https://developers.openai.com/codex/auth/)
- [OpenAI Codex developer commands](https://developers.openai.com/codex/cli/reference/)
- [OpenAI Codex configuration reference](https://developers.openai.com/codex/config-reference/)
