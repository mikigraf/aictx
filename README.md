# ctxlane

**Use the right AI coding account, every time.**

Switch between Claude Code and Codex accounts with isolated local state. `ctxlane` is a local account launcher for personal, work, and CI identities. It runs the official vendor CLIs without adding a proxy.

Each profile gets its own vendor state directory and configured authentication route. Select a profile directly or through a directory binding, then `ctxlane` applies that configuration when it starts Claude Code or Codex.

```text
personal project  -> personal Claude + personal Codex
company project   -> work Claude     + work Codex
CI runner         -> CI profile      + separate state
```

In the CLI, a **profile** represents one configured provider account or authentication route. A **context** groups a Claude profile, a Codex profile, or both.

## Why ctxlane

Claude Code and Codex normally use a default login and state directory. On a machine with personal, company, customer, or CI accounts, a normal command can reuse the wrong cached login or charge the wrong billing destination.

`ctxlane` reduces the risk of accidental account and billing crossover on the same machine. For managed accounts, confirm the final billing destination through the vendor's account controls.

- **Separate profile state:** each profile gets its own `CLAUDE_CONFIG_DIR` or `CODEX_HOME`.
- **One context across tools:** switch Claude Code and Codex accounts together.
- **Directory-aware selection:** bind the right context to a project tree.
- **Keyring-backed secrets:** wrapper-managed static credentials stay in the native OS credential store, outside repository files and shell configuration.
- **Clean vendor launch:** known competing selectors are removed, and inspected project settings that can override routing or load commands are refused.
- **Official vendor CLIs:** Claude Code and Codex still handle login, refresh, and model requests.
- **Local-only design:** `ctxlane` has no API proxy or remote credential service. The vendor CLIs still contact Claude or OpenAI.

## Quick start

### Install

```bash
brew install mikigraf/tap/ctxlane
```

Install at least one supported vendor CLI: Claude Code or Codex.

If you used version 0.1, follow [Migration from v0.1](docs/migration-from-v0.1.md) before normal setup. Homebrew users must first rename and upgrade the formula as described there. `ctxlane` does not import the old local store automatically.

### Claude Code

```bash
ctxlane init --guided
ctxlane run --profile claude:personal claude -- \
  -p "explain this repository"
```

Guided setup initializes `ctxlane`, creates or reuses the `claude:personal` account profile, runs the official `claude setup-token` flow, and stores the pasted token in the native OS credential store.

### Codex

```bash
ctxlane init
ctxlane profile add codex personal --auth subscription
ctxlane login codex:personal
ctxlane run --profile codex:personal codex -- \
  exec "explain this repository"
```

Codex uses its vendor-managed ChatGPT OAuth flow. The compatibility spelling below selects the same saved `chatgpt-oauth` mode:

```bash
ctxlane profile add codex personal --auth subscription-token
```

### Switch both together

Create one context after both profiles exist:

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

This is why the shared command uses `--auth subscription`, while the saved provider modes remain `subscription-token` for Claude and `chatgpt-oauth` for Codex.

For API keys, WIF, managed access tokens, custom profile names, and other options, see [Authentication support](#authentication-support) and the [Command reference](docs/command-reference.md).

`ctxlane` refuses recognized options and inspected startup settings that can change the selected route, bypass isolated state, or load repository commands. This startup policy is not a sandbox.

## Interactive mode

After `ctxlane init`, run `ctxlane` by itself to open the terminal dashboard, built with [Ratatui](https://ratatui.rs/):

```bash
ctxlane
```

The dashboard shows contexts, active and default selection, directory resolution, profile IDs, authentication modes, and billing domains. It never reads secret values or starts a vendor login. Profile creation, login, logout, and vendor runs stay in the explicit CLI commands.

Use the arrow keys or `j` and `k` to move. Press `Enter` to activate a context, `r` to reload, `?` for help, and `q` or `Esc` to leave. Changing any selected provider profile opens a confirmation dialog before state is written, even when both profiles use the same billing type.

The dashboard opens only when standard input and output are terminals. Bare `ctxlane --non-interactive` and redirected use fail instead of entering raw terminal mode. Non-interactive commands remain available for scripts, while browser login, terminal prompts, and native-keyring access fail closed when interaction is disabled.

## Context resolution

A profile configures one provider authentication route and its intended billing domain. A context can point to one Claude profile, one Codex profile, or both:

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

Bind a directory tree when one checkout should always use the same context:

```bash
ctxlane bind "$HOME/src/company" work
ctxlane bindings
```

Bindings live in global user metadata. Repository `.ctxlane.toml` files are ignored.

## Authentication support

Use `--auth subscription` when creating either a Claude or Codex subscription profile. The compatibility spellings `subscription-token` and `chatgpt-oauth` remain accepted. Configuration is normalized to the vendor-native mode shown below.

| Provider | Mode | Configured billing domain | Credential handling |
| --- | --- | --- | --- |
| Claude | `subscription-token` | Claude subscription | native OS keyring, with optional official `setup-token` generation |
| Claude | `api-key` | Anthropic API | native OS keyring |
| Claude | `wif` | Anthropic API | upstream identity-token file, with exchange and refresh owned by Claude |
| Codex | `chatgpt-oauth` | ChatGPT subscription or workspace | official login inside an isolated `CODEX_HOME` |
| Codex | `api-key` | OpenAI API | native OS keyring, then official stdin login into the isolated vendor store |
| Codex | `access-token` | ChatGPT subscription or workspace | native OS keyring, then official stdin login, with workspace and trusted-runner rules |

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

Codex API-key and access-token login can store a second vendor-owned credential copy. With the default `file` policy, that copy is plaintext inside the private, isolated `CODEX_HOME`. Treat current and retired Codex state as credential-bearing data. Other Codex store policies follow vendor and operating-system behavior.

Read [Configuration](docs/configuration.md) for every supported profile field and auth combination.

## Common commands

| Command | Purpose |
| --- | --- |
| `ctxlane init --guided` | Set up the personal Claude subscription profile and credential |
| `ctxlane` | Open the interactive context dashboard |
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

Interactive `doctor` may inspect configured static credentials through the OS keyring and check vendor-owned login state. It always reports a successful local Claude route check as a warning because it neither makes nor records model requests. A successful model request is separate remote-validity evidence. With `--non-interactive`, doctor skips static OS-keyring reads and reports a warning instead of risking an unlock or consent prompt. `--json` returns a top-level `ok` value and a `checks` array. Every check has `level`, `name`, and `detail`. Warnings alone do not make `ok` false.

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

`ctxlane env` emits non-secret selectors only. Running a vendor directly after evaluating that output bypasses environment cleaning, repository checks, lifecycle locks, workspace setup, and static-secret delivery. Use `ctxlane run` or a generated shim for authenticated work.

## Automation

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

Read the [Threat model](THREAT_MODEL.md) and [Security policy](SECURITY.md) before an enterprise rollout.

## Validation status

> [!IMPORTANT]
> The local wrapper flow is tested end to end with compiled native fake-vendor executables. These tests cover context selection, state isolation, argument forwarding, credential routing, policy refusals, and exit codes without contacting Claude or Codex. Live accounts, WIF, native keyrings, billing, Windows deployments, and release signing still need deployment qualification. See [Testing](docs/testing.md) and [Compatibility and validation status](docs/compatibility.md).

Local and CI checks are layered: unit tests, public CLI lifecycle tests, Unix runner contracts, native fake-vendor E2E tests, PTY tests, MSRV checks, and native Linux/macOS/Windows jobs. CI also checks formatting, Clippy, documentation, dependency policy, secret history, packaging, and coverage with region/function/line floors of 75%/60%/70%. A configured workflow is evidence only after it runs successfully on a committed revision.

These checks still need real deployment evidence:

- Claude and Codex login, one harmless request, logout, and re-login with approved versions
- WIF exchange and refresh against the real identity provider
- Billing and workspace identity for managed accounts
- Native keyring behavior, including locked stores and consent prompts
- Native Windows ACL and `.exe` launcher behavior
- Live GitHub OIDC, Sigstore, provenance, and release publishing
- Authenticode, Apple code signing, and macOS notarization where required

Read [Testing](docs/testing.md) for the exact automated layers, commands, coverage method, and evidence boundary. The deployment checklist is in [Compatibility and validation status](docs/compatibility.md).

## Project documentation

- [Configuration](docs/configuration.md)
- [Command reference](docs/command-reference.md)
- [CI and automation](docs/ci.md)
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
