# aictx

Switch between personal and work profiles in Codex, Claude Code and more.

## Quick start

### 1. Install

```bash
brew install mikigraf/tap/aictx
```

You also need the official `claude` CLI.

### 2. Set up Claude

```bash
aictx init --guided
```

This initializes `aictx`, creates or reuses `claude:personal`, runs the official `claude setup-token` flow, and stores the pasted token in the OS credential store.

### 3. Run Claude

```bash
aictx run --profile claude:personal claude -- \
  -p "reply with exactly: Claude subscription works"
```

A successful reply confirms the token works.

## Add Codex

Install the official `codex` CLI, then run:

```bash
aictx init
aictx profile add codex personal --auth subscription
aictx login codex:personal
aictx run --profile codex:personal codex -- exec "explain this repository"
```

Codex opens its browser login and keeps the OAuth session inside the profile's isolated `CODEX_HOME`.

The compatibility spelling also works:

```bash
aictx profile add codex personal --auth subscription-token
```

For Codex, both spellings select its native `chatgpt-oauth` mode.

## Switch both tools together

Create one context after both profiles exist:

```bash
aictx context add personal \
  --claude claude:personal \
  --codex codex:personal
aictx use personal

aictx run claude -- -p "explain this repository"
aictx run codex -- exec "run the tests"
```

After a context is active, you do not need `--profile` on every run.

Run `aictx` with no subcommand to open the terminal context picker.

## Install or update from source

Source builds need Rust 1.89 or newer. From an existing checkout:

```bash
git pull --ff-only
cargo install --path . --locked --force
```

From a new checkout:

```bash
git clone https://github.com/mikigraf/aictx.git
cd aictx
cargo install --path . --locked
```

## Why aictx is different

Claude Code and Codex normally reuse their default home directory and current login. That is simple for one account, but it becomes unclear when personal, work, and CI identities share a machine.

`aictx` keeps those choices explicit:

- Every profile gets an isolated `CLAUDE_CONFIG_DIR` or `CODEX_HOME`.
- A context can select one Claude profile, one Codex profile, or both.
- Static secrets stay out of project files, shell startup files, and command arguments.
- The official Claude and Codex binaries still own API calls, browser login, refresh, and vendor state.
- `aictx` removes known competing environment selectors and refuses inspected repository settings that can change the selected account or endpoint.

`aictx` is a local launcher and profile manager. It is not an API proxy and does not replace either vendor CLI.

## Why Claude uses the OS credential store

Claude and Codex expose different subscription login flows:

- `claude setup-token` prints a token but does not save it for `aictx`. The token is needed on later runs, so `aictx` stores it in Keychain on macOS, Credential Manager on Windows, or Secret Service on Linux. The `aictx` configuration stores only a `keyring://...` reference.
- Codex subscription login is browser OAuth managed by Codex. Codex stores its login state inside that profile's isolated `CODEX_HOME`. `aictx` does not ask you to paste or store a ChatGPT OAuth token.

This is why the shared command uses `--auth subscription`, while the saved provider modes remain `subscription-token` for Claude and `chatgpt-oauth` for Codex.

For API keys, WIF, managed access tokens, custom profile names, and other options, see [Authentication support](#authentication-support) and the [Command reference](docs/command-reference.md).

Options that could change the selected identity, bypass isolated state, or load unsafe repository commands are refused.

## Interactive mode

After `aictx init`, run `aictx` by itself to open the terminal dashboard, built with [Ratatui](https://ratatui.rs/):

```bash
aictx
```

The dashboard shows contexts, active and default selection, directory resolution, profile IDs, authentication modes, and billing domains. It never reads secret values or starts a vendor login. Profile creation, login, logout, and vendor runs stay in the explicit CLI commands.

Use the arrow keys or `j` and `k` to move. Press `Enter` to activate a context, `r` to reload, `?` for help, and `q` or `Esc` to leave. A billing-domain change opens a confirmation dialog before state is written.

The dashboard opens only when standard input and output are terminals. Bare `aictx --non-interactive` and redirected use fail instead of entering raw terminal mode. Every CLI subcommand remains available for scripts.

## Context resolution

A profile describes one provider identity and billing path. A context can point to one Claude profile, one Codex profile, or both:

```text
personal -> claude:personal + codex:personal
work     -> claude:work     + codex:work
```

For each run, `aictx` uses the first available choice in this order:

1. `--profile`
2. `--context`
3. the nearest directory binding
4. the active context
5. the default context

`aictx use work` updates only the small mutable state file. It does not copy credentials or rewrite vendor homes.

Bind a directory tree when one checkout should always use the same context:

```bash
aictx bind "$HOME/src/company" work
aictx bindings
```

Bindings live in global user metadata. Repository `.aictx.toml` files are ignored.

## Authentication support

Use `--auth subscription` when creating either a Claude or Codex subscription profile. The compatibility spellings `subscription-token` and `chatgpt-oauth` remain accepted. Configuration is normalized to the vendor-native mode shown below.

| Provider | Mode | Billing path | Credential handling |
| --- | --- | --- | --- |
| Claude | `subscription-token` | Claude subscription | native OS keyring, with optional official `setup-token` generation |
| Claude | `api-key` | Anthropic API | native OS keyring |
| Claude | `wif` | Anthropic API | upstream identity-token file, with exchange and refresh owned by Claude |
| Codex | `chatgpt-oauth` | ChatGPT subscription or workspace | official login inside an isolated `CODEX_HOME` |
| Codex | `api-key` | OpenAI API | native OS keyring, then official stdin login into the isolated vendor store |
| Codex | `access-token` | ChatGPT subscription or workspace | native OS keyring, then official stdin login, with workspace and trusted-runner rules |

Static secrets are stored in the native OS keyring. Configuration contains only a reference:

```text
keyring://service/account
```

Paste only the raw Claude setup token. The hidden prompt accepts wrapped paste input, rejects shell commands and unsafe whitespace or control characters, and never executes pasted text. Secrets are never accepted as ordinary command-line arguments.

If Claude rejects a stored token, replace the local copy:

```bash
aictx logout claude:personal
aictx init --guided
```

If Claude creates a setup token but capture or keyring storage fails, revoke that remote token in your Claude account settings under **Settings > Claude Code** before retrying. Local replacement or logout does not revoke an already-created remote token.

Codex API-key and access-token login can store a second vendor-owned credential copy. With the default `file` policy, that copy is plaintext inside the private, isolated `CODEX_HOME`. Treat current and retired Codex state as credential-bearing data. Other Codex store policies follow vendor and operating-system behavior.

Read [Configuration](docs/configuration.md) for every supported profile field and auth combination.

## Common commands

| Command | Purpose |
| --- | --- |
| `aictx init --guided` | Set up the personal Claude subscription profile and credential |
| `aictx` | Open the interactive context dashboard |
| `aictx status --verbose` | Show resolved profiles and non-secret identity metadata |
| `aictx current` | Print the context selected for the current directory |
| `aictx use <context>` | Change the global active context |
| `aictx profile list` | List provider profiles |
| `aictx context list` | List contexts |
| `aictx credential check --all` | Check credential availability without printing values |
| `aictx doctor [--provider <provider>] [--json]` | Check metadata, permissions, binaries, unsafe settings, and per-profile authentication readiness |
| `aictx logout <profile>` | Clear supported local authentication state |

See the full [Command reference](docs/command-reference.md).

Wrapper errors keep stable exit categories and print a short `Hint:` line when a safe recovery action is known. During profile or context resolution, a close misspelling also prints a safe `did you mean ...?` suggestion. The installed binary is authoritative. Use `aictx --help` and `aictx <command> --help` for current syntax and examples.

Interactive `doctor` may inspect configured static credentials through the OS keyring and check vendor-owned login state. It always reports a successful local Claude route check as a warning because it neither makes nor records model requests. A successful model request is separate remote-validity evidence. With `--non-interactive`, doctor skips static OS-keyring reads and reports a warning instead of risking an unlock or consent prompt. `--json` returns a top-level `ok` value and a `checks` array. Every check has `level`, `name`, and `detail`. Warnings alone do not make `ok` false.

## Shell integration

Install small forwarding functions so `claude` and `codex` still run through `aictx`:

```bash
# Bash
eval "$(aictx shell-init bash)"

# Zsh
eval "$(aictx shell-init zsh)"

# Fish
aictx shell-init fish | source
```

PowerShell:

```powershell
Invoke-Expression (& aictx shell-init powershell | Out-String)
```

Review generated shell code before adding it to a startup file. The shims pin the canonical `aictx` path and any explicit `--root`. Regenerate them after either path moves.

`aictx env` emits non-secret selectors only. Running a vendor directly after evaluating that output bypasses environment cleaning, repository checks, lifecycle locks, workspace setup, and static-secret delivery. Use `aictx run` or a generated shim for authenticated work.

## Automation

Use `--non-interactive` in CI. It fails before a browser, prompt, terminal dashboard, or OS-keyring unlock can appear. Static credential reads from the native keyring are unavailable in this mode. Prefer WIF for Claude where your Anthropic account supports it. A pre-authorized Codex OAuth profile may be used only on a controlled private runner.

Long-lived Claude subscription tokens, cached Codex OAuth, and Codex access tokens require `--trusted-runner` in CI or non-interactive mode. Static-token profiles still cannot read the native keyring in `--non-interactive` mode. For example, a pre-authorized Codex OAuth profile can run on a controlled private runner:

```bash
aictx --non-interactive run \
  --profile codex:ci \
  --trusted-runner \
  codex -- exec "review this change"
```

`--trusted-runner` records an operator assertion. It does not attest the runner. The GitHub pull-request environment check is an extra refusal layer, while workflow permissions and secret gating remain the security boundary.

Read [CI and automation](docs/ci.md) before adding credentials to a workflow.

## Security boundary

`aictx` keeps secret values out of wrapper metadata, command arguments, normal status output, and shell startup files. It reconstructs the vendor child environment, rejects unsafe executable paths, and scans supported repository settings before credentials reach a vendor process.

The boundary has limits:

- Local logout clears supported local state. It does not prove remote revocation.
- Native Claude subscription switching through the macOS Keychain is outside version `0.1.0`.
- Codex `keyring` and `auto` store isolation is defined by Codex and the operating system.
- Startup repository checks are not a sandbox. Claude can discover some descendant `.claude` definitions later in an interactive session.
- Same-user malware, a compromised vendor CLI, and administrator or root access are outside the protection boundary.
- Windows vendor executables must be native `.exe` files. Script launchers such as `.cmd` and `.bat` are refused.

Static Claude checks use the official local `claude auth status --json` output to verify the selected method and optional organization evidence. This is local routing evidence. It does not make a model request or prove remote validity, expiry, or revocation. The first successful model request is the remote validity check at that point in time. WIF is passed to the official Claude client through documented selectors. `aictx` does not exchange or refresh WIF tokens.

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
