# ctxlane

**Use the right AI coding account, every time.**

`ctxlane` switches and isolates personal, work, and CI accounts for Claude Code and Codex.

In `ctxlane`, a profile represents one Claude or Codex account or authentication path. Each profile gets a separate vendor state directory. A context can switch both tools together or bind the selection to a project directory.

At launch, `ctxlane` removes known competing selectors and refuses inspected repository settings that could change the selected route. Wrapper-managed static secrets stay in the native OS credential store, outside repository files and shell configuration. The official vendor CLIs still handle login and model traffic; `ctxlane` adds no API proxy or remote credential service.

The ordinary CLI, terminal dashboard, and local account switching are standalone. They do not start or require an automation service, controller, MCP server, lease store, or automation-authority file, and they have no ASF or Runmill dependency.

## Quick start

```bash
brew install mikigraf/tap/ctxlane
```

> Used version 0.1? Follow [Migration from v0.1](docs/migration-from-v0.1.md) before setup. `ctxlane` does not import the old local store automatically.

Install at least one supported vendor CLI: [Claude Code](https://code.claude.com/docs/en/quickstart) or [Codex CLI](https://developers.openai.com/codex/cli/).

### Claude Code

```bash
ctxlane init --guided
ctxlane run --profile claude:personal claude -- \
  -p "explain this repository"
```

The guided command initializes `ctxlane`, creates or reuses `claude:personal`, runs the official `claude setup-token` flow, safely accepts wrapped paste input, and stores the token in the native OS credential store.

### Codex

```bash
ctxlane init
ctxlane profile add codex personal --auth subscription
ctxlane login codex:personal
ctxlane run --profile codex:personal codex -- \
  exec "explain this repository"
```

`ctxlane login` opens the official ChatGPT OAuth flow in Codex.

## Add subscription profiles manually

When you create profiles manually, both providers accept the same neutral option:

```bash
ctxlane profile add claude personal --auth subscription
ctxlane profile add codex personal --auth subscription
```

For Codex, the compatibility command below is an alternative to the second command above. Both create the same saved `chatgpt-oauth` mode:

```bash
ctxlane profile add codex personal --auth subscription-token
```

## Use Claude Code and Codex together

Create one context after both account profiles exist:

```bash
ctxlane context add personal \
  --claude claude:personal \
  --codex codex:personal
ctxlane use personal

ctxlane run claude -- -p "explain this repository"
ctxlane run codex -- exec "run the tests"
```

After a context is active, you do not need `--profile` on every run.

Run `ctxlane` with no subcommand to open the terminal context picker.

## Why ctxlane

Claude Code and Codex normally use a default login and state directory. On a machine with personal, company, customer, or CI accounts, a normal command can reuse the wrong cached login or charge the wrong billing destination.

`ctxlane` reduces the risk of accidental account and billing crossover on the same machine. For managed accounts, confirm the final billing destination through the vendor's account controls.

```text
personal project  -> personal Claude + personal Codex
company project   -> work Claude     + work Codex
CI runner         -> CI account      + separate state
```

- **Separate account state:** each profile gets its own `CLAUDE_CONFIG_DIR` or `CODEX_HOME`.
- **One context across tools:** switch Claude Code and Codex accounts together.
- **Directory-aware selection:** bind the right context to a project tree.
- **Keyring-backed secrets:** wrapper-managed static credentials stay in the native OS credential store, outside repository files and shell configuration.
- **Clean vendor launch:** known competing selectors are removed, and inspected project settings that can override routing or load commands are refused.
- **Official vendor CLIs:** Claude Code and Codex still handle login, refresh, and model requests.
- **Local-only design:** `ctxlane` has no API proxy or remote credential service. The vendor CLIs still contact Anthropic or OpenAI.

## Install or update from source

Source builds need Rust 1.89 or newer. From an existing checkout:

```bash
git pull --ff-only
cargo install --path . --locked --force
```

From a new checkout:

```bash
git clone https://github.com/mikigraf/ctxlane.git
cd ctxlane
cargo install --path . --locked
```

## Why Claude and Codex authenticate differently

Claude and Codex expose different subscription login flows:

- `claude setup-token` prints a token but does not save it for `ctxlane`. The token is needed on later runs, so `ctxlane` stores it in Keychain on macOS, Credential Manager on Windows, or Secret Service on Linux. The `ctxlane` configuration stores only a `keyring://...` reference.
- Codex subscription login is browser OAuth managed by Codex. With the default `file` credential-store policy, Codex keeps its login state inside that profile's private `CODEX_HOME`. The `keyring` and `auto` policies remain vendor- and OS-defined. `ctxlane` does not ask you to paste or store a ChatGPT OAuth token.

This is why the shared command uses `--auth subscription`. The saved provider modes remain `subscription-token` for Claude and `chatgpt-oauth` for Codex.

For API keys, WIF, managed access tokens, custom profile names, and other options, see [Authentication support](#authentication-support) and the [Command reference](docs/command-reference.md).

`ctxlane` refuses recognized options and inspected startup settings that can change the selected route, bypass isolated state, or load repository commands. This startup policy is not a sandbox.

## Interactive mode

After `ctxlane init`, run `ctxlane` by itself to open the terminal dashboard, built with [Ratatui](https://ratatui.rs/):

```bash
ctxlane
```

The dashboard shows contexts, active and default selection, directory resolution, profile IDs, authentication modes, and billing domains. You can also manage the selected panel:

| Key | Action |
| --- | --- |
| `a` | Add a profile, context, or binding |
| `e` | Edit the selected item |
| `R` or `F2` | Rename a profile or context; edit a binding path |
| `d` | Remove the selected item after confirmation |

Use the arrow keys or `j` and `k` to move. In a form, use `Tab` to change fields, the arrow keys or Space to change a choice, `Enter` to save, and `Esc` to cancel. Press `Enter` on a context to activate it, `r` to reload, `?` for help, and `q` or `Esc` to leave. By default, changing any selected provider profile opens a confirmation dialog before state is written, even when both profiles use the same billing type.

Dashboard forms change local metadata only. They never read or delete an OS-keyring credential, and they never start Claude Code or Codex. Use the CLI commands `ctxlane login`, `ctxlane logout`, and `ctxlane run` for authentication and vendor work.

Renaming a profile keeps its private vendor state and secret reference, then updates every context that uses it. A context whose name would change cannot be renamed while it is active; switch to another context first. A permitted context rename updates the default context when applicable and every directory binding that uses the old name.

Dashboard profile removal deletes the profile metadata but retains its OS-keyring credential and leaves its immutable vendor-state directory detached at the same path. The directory is not reused automatically, and `ctxlane` does not automatically clean it up. A private `p-*` name does not distinguish a configured directory from a detached one, so never delete one based on its name alone; first verify that no configured profile references the exact path. The CLI option `profile remove --delete-secret` also attempts to delete the wrapper-held keyring item. If that cleanup fails, `ctxlane` attempts to restore the profile metadata; a successful rollback leaves the profile configured, while a rollback failure is reported explicitly and the metadata may already be absent. A binding can still be removed after its directory has been deleted.

The dashboard opens only when standard input and output are terminals. Bare `ctxlane --non-interactive` and redirected use fail instead of entering raw terminal mode. `Ctrl-C` restores the terminal and exits with status `130`. Non-interactive commands remain available for scripts, while browser login, terminal prompts, and native-keyring access fail closed when interaction is disabled.

## Context resolution

The CLI uses these terms:

| Term | Meaning |
| --- | --- |
| Account | A Claude or Codex identity that you use for model requests |
| Profile | One provider account or authentication path configured in `ctxlane` |
| Context | A named selection containing a Claude profile, a Codex profile, or both |
| Binding | The context selected for a directory tree |
| Vendor home | The separate login and configuration state directory for a profile |
| Installation UID | The immutable, non-secret identity generated for one v2 metadata store |
| Profile UID | The immutable, non-secret identity that stays with a profile when its display ID is renamed |
| Billing domain | The subscription, workspace, or API route that `ctxlane` intends to select. Vendor account controls remain authoritative |

Configuration schema v2 adds the installation and profile UIDs. Removing a profile retires its UID, and neither that UID nor its detached vendor home is reused automatically. New and upgraded profiles also receive an operator-owned automation-policy record with `eligible = false`; it is reserved foundation and does not turn an ordinary local profile into an automation identity.

A context can point to one Claude profile, one Codex profile, or both:

```text
personal -> claude:personal + codex:personal
work     -> claude:work     + codex:work
```

For each run, `ctxlane` uses the first available choice in this order:

1. `--profile`
2. `--context`
3. the nearest directory binding
4. the active context
5. the default context

`ctxlane use work` updates only the small mutable state file. It does not copy credentials or rewrite vendor homes. The result shows the selected global context and, when a directory binding takes precedence, the different context and provider profiles effective in the current directory.

Bind a directory tree when one checkout should always use the same context. This example assumes that `claude:work` and `codex:work` already exist:

```bash
ctxlane context add work \
  --claude claude:work \
  --codex codex:work
ctxlane bind . work
ctxlane bindings
```

Bindings live in global user metadata. Repository `.ctxlane.toml` files are ignored.

## Authentication support

Use `--auth subscription` when creating either a Claude or Codex subscription profile. For Claude, `subscription-token` is the provider-native alternative and is the saved mode. For Codex, `chatgpt-oauth` is the provider-native alternative, while `subscription-token` remains a compatibility alias. Codex saves all three accepted subscription spellings as `chatgpt-oauth`.

| Provider | Mode | Configured billing domain | Credential handling |
| --- | --- | --- | --- |
| Claude | `subscription-token` | Claude subscription | native OS keyring, with optional official `setup-token` generation |
| Claude | `api-key` | Anthropic API | native OS keyring |
| Claude | `wif` | Anthropic API | upstream identity-token file, with exchange and refresh owned by Claude |
| Codex | `chatgpt-oauth` | ChatGPT subscription or workspace | official login inside an isolated `CODEX_HOME` |
| Codex | `api-key` | OpenAI API | native OS keyring, then official stdin login into the isolated vendor store |
| Codex | `access-token` | ChatGPT subscription or workspace | native OS keyring, then official stdin login, with workspace and trusted-runner rules |
| Codex | `wif` | ChatGPT workspace | strict enrollment and config validation only; no native login or run support in this release |

Codex WIF enrollment records the complete closed metadata shape, but does not authenticate or start Codex:

```bash
ctxlane profile add codex ci \
  --auth wif \
  --federation-rule-id idpm_production \
  --identity-token-file /run/ctxlane/codex-identity.jwt \
  --workspace chatgpt-workspace:engineering \
  --principal service-account:ctxlane-ci \
  --environment production \
  --minimum-codex-version 0.148.0
```

The dashboard neither exposes this enrollment flow nor edits Codex WIF authority fields. Config loading validates the closed metadata shape, including absolute path syntax, without probing the configured file or its filesystem location. CLI enrollment separately rejects an identity-token path beneath Git-worktree ancestry, without opening the token. `ctxlane login`, `ctxlane logout`, and `ctxlane run` then refuse an enrolled Codex WIF profile before inspecting token-path-derived metadata, preparing vendor state, or starting Codex. An explicit `credential check` may inspect file availability, but that is not native runtime qualification. `doctor` skips the Codex WIF token probe and reports the profile as runtime-unqualified rather than ready.

Static secrets managed by `ctxlane` are stored in the native OS keyring. Configuration contains only a reference:

```text
keyring://service/account
```

Paste only the raw Claude setup token. The hidden prompt accepts wrapped paste input, rejects common shell wrappers and ambiguous whitespace or control characters, and never executes pasted text. Secrets are never accepted as ordinary command-line arguments.

If Claude rejects a stored token, replace the local copy:

```bash
ctxlane logout claude:personal
ctxlane init --guided
```

If Claude creates a setup token but capture or keyring storage fails, revoke that remote token in your Claude account settings under **Settings > Claude Code** before retrying. Local replacement or logout does not revoke an already-created remote token.

Codex API-key and access-token login can store a second vendor-owned credential copy. With the default `file` policy, that copy is plaintext inside the private, isolated `CODEX_HOME`. Treat configured and detached Codex state as credential-bearing data. Other Codex store policies follow vendor and operating-system behavior.

Read [Configuration](docs/configuration.md) for every supported profile field and auth combination.

## Common commands

| Command | Purpose |
| --- | --- |
| `ctxlane init --guided` | Set up the personal Claude subscription profile and credential |
| `ctxlane` | Open the interactive dashboard and manage local metadata |
| `ctxlane status --verbose` | Show resolved profiles and non-secret identity metadata |
| `ctxlane current` | Print the context selected for the current directory |
| `ctxlane use <context>` | Change the global active context |
| `ctxlane profile list` | List provider profiles |
| `ctxlane context list` | List contexts |
| `ctxlane credential check --all` | Check credential availability without printing values |
| `ctxlane doctor [--provider <provider>] [--json]` | Check metadata, permissions, binaries, unsafe settings, and per-profile authentication readiness |
| `ctxlane logout <profile>` | Clear supported local authentication state |

See the full [Command reference](docs/command-reference.md).

Wrapper errors keep stable exit categories and print a short `Hint:` line when a safe recovery action is known. During profile or context resolution, a close misspelling also prints a safe `did you mean ...?` suggestion. The installed binary is authoritative. Use `ctxlane --help` and `ctxlane <command> --help` for current syntax and examples.

If setup fails before a login or token prompt appears, run `ctxlane doctor --provider claude` or `ctxlane doctor --provider codex`. `ctxlane` refuses vendor executables on unsafe writable paths; reinstall the official CLI or correct the reported permissions instead of bypassing that check.

Interactive `doctor` may inspect configured static credentials through the OS keyring and check vendor-owned login state. It always reports a successful local Claude route check as a warning because it neither makes nor records model requests. A successful model request is separate remote-validity evidence. With `--non-interactive`, doctor skips static OS-keyring reads and reports a warning instead of risking an unlock or consent prompt. It also reports each profile's automation policy as disabled or eligible, reduces environment, role, and caller scopes to counts, and warns when either explicit exception is acknowledged. That is configuration visibility, not lease or runtime readiness. `--json` returns a top-level `ok` value and a `checks` array. Every check has `level`, `name`, and `detail`. Warnings alone do not make `ok` false.

## Shell integration

Install small forwarding functions so `claude` and `codex` still run through `ctxlane`:

```bash
# Bash
eval "$(ctxlane shell-init bash)"

# Zsh
eval "$(ctxlane shell-init zsh)"

# Fish
ctxlane shell-init fish | source
```

PowerShell:

```powershell
Invoke-Expression (& ctxlane shell-init powershell | Out-String)
```

Review generated shell code before adding it to a startup file. The shims pin the canonical `ctxlane` path and any explicit `--root`. Regenerate them after either path moves.

For supported runnable profiles, `ctxlane env` emits non-secret selectors only. It refuses a resolved context that selects Codex WIF: exporting `CODEX_HOME` would prepare an unsupported execution path outside the native-runtime refusal. Running a vendor directly after evaluating any successful output bypasses environment cleaning, repository checks, lifecycle locks, workspace setup, and static-secret delivery. Use `ctxlane run` or a generated shim for authenticated work.

## Automation

Every config-v2 profile carries a validated automation policy, but it is disabled by default with `eligible = false`. This release has no supported lease service, automation MCP server, controller runtime, or policy-editing command, and changing metadata by hand does not create those capabilities. The Phase-0 schemas and architecture documents define a possible controller-neutral future boundary; ASF and Runmill appear only as optional integration examples.

The Rust library exposes pure, controller-neutral policy-evaluation and lease-lifecycle domains. Those domains remain inert building blocks for a future trusted service: they do not persist leases, access credentials, start processes, or connect the CLI or dashboard to a controller.

A separate sealed checkpoint now provides crate-internal authority loading, strict Ed25519 work-order verification primitives, and platform-specific caller evidence. Its read-only loader recognizes only a closed version-1, owner-private regular `config/automation-authority.toml` of at most 1 MiB, binds it to the installation and configured host identity, and prepares exact service limits plus controller key, tenant, profile, provider, environment, role, repository, workspace, lifetime, exception, rate, and capacity limits. Keys and signatures use strict canonical encodings, weak Ed25519 public keys are refused, and all proof failures are redacted. This is an internal contract only: no supported command creates, edits, displays, or consumes the file, and the verifier is not a public library or CLI API.

On macOS, the internal adapter is explicitly opt-in, restricted to the exact `local-development` environment, and always classified as unqualified development evidence. On Linux, the adapter requires kernel `SO_PEERPIDFD` support (upstream Linux 6.5 or a qualified backport), retains the live pidfd, and checks peer credentials, process identity, the allowlisted native executable and digest, and protected unified-cgroup/systemd placement. That result is deliberately only connection-origin evidence. It is verifier-ineligible because a Unix stream can be written through a delegated file descriptor; a future listener must enable `SO_PASSCRED` and require matching per-frame `SCM_CREDENTIALS` before any Linux request can become authority. Windows and other unsupported targets refuse this authority boundary before deriving or reading its filesystem path.

An internal, sealed lease-store foundation is available only to future service code on Linux and macOS. It uses an owner-private SQLite journal for atomic request, replay, refusal, and audit records, and it refuses readiness when unresolved state requires recovery. It does not yet activate or renew leases, reconcile processes, prune history, authenticate a controller, or expose a public service API. Windows and other unsupported targets reject this store boundary before filesystem access. The journal is qualified only for a local owner-controlled filesystem; network filesystems such as NFS are not supported or claimed safe.

Ordinary commands and the terminal dashboard never discover, create, or open either sealed boundary. Their standalone tests deliberately place invalid bytes at both the would-be authority path and database path and prove normal CLI and TUI behavior succeeds without changing, locking, repairing, or depending on either file.

No listener, authenticated request-framing gate, lease-authority integration, or provider harness is connected to these foundations. Linux deployment also still depends on a protected local filesystem and kernel/procfs/cgroup/systemd environment, a trusted operator configuration and signing-key system, and a qualified controller executable. The current process evidence does not attest dynamic loaders or libraries, environment or arguments, in-memory mutation or ptrace, unusual filesystem semantics, or writers using a delegated connected descriptor. These assumptions must be narrowed and qualified before any production claim.

The direct CLI controls below predate that future identity plane. Neither `--non-interactive` nor `--trusted-runner` changes `eligible`, creates a lease, or grants production automation authority.

Use `--non-interactive` in CI. It fails before a browser, prompt, terminal dashboard, or OS-keyring unlock can appear. Static credential reads from the native keyring are unavailable in this mode. Prefer WIF for Claude where your Anthropic account supports it. A pre-authorized Codex OAuth profile may be used only on a controlled private runner.

Long-lived Claude subscription tokens, cached Codex OAuth, and Codex access tokens require `--trusted-runner` in CI or non-interactive mode. Static-token profiles still cannot read the native keyring in `--non-interactive` mode. For example, a pre-authorized Codex OAuth profile can run on a controlled private runner:

```bash
ctxlane --non-interactive run \
  --profile codex:ci \
  --trusted-runner \
  codex -- exec "review this change"
```

`--trusted-runner` records an operator assertion. It does not attest the runner. The GitHub pull-request environment check is an extra refusal layer, while workflow permissions and secret gating remain the security boundary.

Read [CI and automation](docs/ci.md) before adding credentials to a workflow.

## Security boundary

`ctxlane` keeps secret values out of wrapper metadata, command arguments, normal status output, and shell startup files. It reconstructs the vendor child environment, rejects repository-local executables, applies platform-specific path checks, and scans supported repository settings before credentials reach a vendor process.

The boundary has limits:

- Local logout clears supported local state. It does not prove remote revocation.
- Switching Claude's own native macOS Keychain login state is outside version `0.2.0`. This does not refer to setup tokens that `ctxlane` stores in Keychain.
- Codex `keyring` and `auto` store isolation is defined by Codex and the operating system.
- Startup repository checks are not a sandbox. Claude can discover some descendant `.claude` definitions later in an interactive session.
- Same-user malware, a compromised vendor CLI, and administrator or root access are outside the protection boundary.
- Windows vendor executables must be native `.exe` files. Script launchers such as `.cmd` and `.bat` are refused.

Static Claude checks use the official local `claude auth status --json` output to verify the selected method and optional organization evidence. This is local routing evidence. It does not make a model request or prove remote validity, expiry, or revocation. The first successful model request is the remote validity check at that point in time. WIF is passed to the official Claude client through documented selectors. `ctxlane` does not exchange or refresh WIF tokens.

Codex WIF metadata validation is not equivalent to that Claude runtime path. Codex WIF `login`, `logout`, and `run` remain fail-closed before configured token-path traversal until the official native flow and its identity, workspace, token-file, and version checks are implemented and qualified.

Read the [Threat model](THREAT_MODEL.md) and [Security policy](SECURITY.md) before an enterprise rollout.

## Validation status

> [!IMPORTANT]
> The local wrapper flow is tested end to end with compiled native fake-vendor executables. These tests cover context selection, state isolation, argument forwarding, credential routing, policy refusals, and exit codes without contacting Claude or Codex. Live accounts, Claude WIF, native keyrings, billing, Windows deployments, and platform-native code signing still need deployment qualification. Codex WIF has enrollment tests only because its native runtime is not implemented. See [Testing](docs/testing.md) and [Compatibility and validation status](docs/compatibility.md).

Local and CI checks are layered: unit tests, public CLI lifecycle tests, Unix runner contracts, native fake-vendor E2E tests, PTY tests, MSRV checks, and native Linux/macOS/Windows jobs. CI also checks formatting, Clippy, documentation, dependency policy, secret history, packaging, and coverage with region/function/line floors of 75%/60%/70%. A configured workflow is evidence only after it runs successfully on a committed revision.

For [v0.2.0](https://github.com/mikigraf/ctxlane/releases/tag/v0.2.0), the source and release workflows passed for the tagged commit. The published archives, checksums, CycloneDX SBOM, Sigstore bundles, and GitHub provenance attestations were verified against that release.

These checks still need real deployment evidence:

- Claude and Codex login, one harmless request, logout, and re-login with approved versions
- Claude WIF exchange and refresh against the real identity provider
- Codex WIF native integration and qualification after that runtime is implemented
- Billing and workspace identity for managed accounts
- Native keyring behavior, including locked stores and consent prompts
- Native Windows ACL and `.exe` launcher behavior
- Linux 6.5-or-newer (or qualified-backport) `SO_PEERPIDFD`, protected procfs/cgroup v2/systemd placement, and the future per-frame credential gate before automation authority is enabled
- Authenticode, Apple code signing, and macOS notarization where required

Read [Testing](docs/testing.md) for the exact automated layers, commands, coverage method, and evidence boundary. The deployment checklist is in [Compatibility and validation status](docs/compatibility.md).

`ctxlane` remains fully standalone. Normal CLI, TUI, login, profile, context,
and supported run workflows neither start nor require ASF, Runmill, MCP, an
automation service, or any controller. The automation identity-plane material
describes a controller-neutral capability that is not yet supported. ASF and
Runmill are examples only; no integration with either ships in the current
binary.

## Project documentation

- [Configuration](docs/configuration.md)
- [Command reference](docs/command-reference.md)
- [CI and automation](docs/ci.md)
- [Automation identity plane (Phase-0 contract)](docs/automation-identity-plane.md)
- [Automation JSON schemas](schemas/README.md)
- [Testing](docs/testing.md)
- [Compatibility and validation status](docs/compatibility.md)
- [Migration from v0.1](docs/migration-from-v0.1.md)
- [Threat model](THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo test --doc --locked
```

The committed lockfile is part of the application build. Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change. Report security issues through [SECURITY.md](SECURITY.md), not a public issue.

The full test architecture and focused commands are in [Testing](docs/testing.md). Automated tests use temporary state and synthetic vendor fixtures. They never need a real account or host keyring.

## License

Apache-2.0. See [LICENSE](LICENSE).
