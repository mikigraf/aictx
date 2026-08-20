# aictx

Run the official Claude Code and Codex CLIs under clear personal, work, or CI identities.

`aictx` keeps each provider profile in its own vendor state directory. Contexts group one Claude profile and one Codex profile, so you can switch both tools together without copying credentials into shell files or repository config.

## Quick start

Initialize the user-scoped configuration:

```bash
aictx init
```

Add one profile for each provider:

```bash
aictx profile add claude personal --auth subscription-token
aictx profile add codex personal --auth chatgpt-oauth
```

Authenticate through the official flows:

```bash
aictx login claude:personal --generate
aictx login codex:personal
```

Create a context and select it:

```bash
aictx context add personal \
  --claude claude:personal \
  --codex codex:personal

aictx use personal
```

Run the vendor CLIs:

```bash
aictx run claude -- -p "explain this repository"
aictx run codex -- exec "run the tests"
```

Arguments after `--` are passed as an argument vector. A shell never parses them. Options that could change the selected identity, bypass isolated state, or load unsafe repository commands are refused.

> [!IMPORTANT]
> The local wrapper flow is tested end to end with fake vendor executables. The tests cover context selection, state isolation, argument forwarding, credential routing, policy refusals, and exit codes. Production rollout still requires live-account tests for Claude, Codex, WIF, native keyrings, Windows, and the release-signing workflow. See [Compatibility and validation status](docs/compatibility.md).

## What aictx gives you

- A terminal dashboard when you run `aictx` with no subcommand
- Named contexts such as `personal`, `work`, and `ci`
- Separate `CLAUDE_CONFIG_DIR` and `CODEX_HOME` state for every profile
- Native OS-keyring storage for static secrets
- Direct argument forwarding to official vendor CLIs without a shell
- Clean child environments that remove competing credentials and routing settings
- Directory bindings stored in user-owned metadata, outside the repository
- Billing-change confirmation and CI guardrails for long-lived credentials

`aictx` stays at the process boundary. Claude Code and Codex still own browser login, device login, API calls, token refresh, and their private state formats.

## Install

You need:

- Rust 1.89 or newer
- the official `claude` and/or `codex` CLI

Install from a source checkout:

```bash
cargo install --path . --locked
```

When release archives are published, they include the binary, shell completions, license, and project documentation. Each archive and SBOM has a SHA-256 file. The release workflow also creates Sigstore bundles and GitHub build provenance. These files do not replace native Authenticode or Apple code signing, and macOS notarization remains a separate release step.

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

The secret value is entered through a hidden prompt or standard input during login. It is never accepted as an ordinary command-line argument.

Codex API-key and access-token login can store a second vendor-owned credential copy. With the default `file` policy, that copy is plaintext inside the private, isolated `CODEX_HOME`. Treat current and retired Codex state as credential-bearing data. Other Codex store policies follow vendor and operating-system behavior.

Read [Configuration](docs/configuration.md) for every supported profile field and auth combination.

## Common commands

| Command | Purpose |
| --- | --- |
| `aictx` | Open the interactive context dashboard |
| `aictx status --verbose` | Show resolved profiles and non-secret identity metadata |
| `aictx current` | Print the context selected for the current directory |
| `aictx use <context>` | Change the global active context |
| `aictx profile list` | List provider profiles |
| `aictx context list` | List contexts |
| `aictx credential check --all` | Check credential availability without printing values |
| `aictx doctor` | Check metadata, permissions, binaries, the OS keyring, and unsafe settings |
| `aictx logout <profile>` | Clear supported local authentication state |

See the full [Command reference](docs/command-reference.md).

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

Static Claude checks use the official local `claude auth status --json` output to verify the selected method and optional organization evidence. This check does not make a model request or prove remote validity, expiry, or revocation. WIF is passed to the official Claude client through documented selectors. `aictx` does not exchange or refresh WIF tokens.

Read the [Threat model](THREAT_MODEL.md) and [Security policy](SECURITY.md) before an enterprise rollout.

## Validation status

Local automated checks cover Rust 1.89 and the pinned development toolchain, unit tests, CLI workflows, fake-vendor contracts, formatting, Clippy, documentation, dependency policy, packaging, and cross-target compilation. A configured GitHub workflow is evidence only after it runs successfully on a committed revision.

These checks still need real deployment evidence:

- Claude and Codex login, one harmless request, logout, and re-login with approved versions
- WIF exchange and refresh against the real identity provider
- Billing and workspace identity for managed accounts
- Native keyring behavior, including locked stores and consent prompts
- Native Windows ACL and `.exe` launcher behavior
- Live GitHub OIDC, Sigstore, provenance, and release publishing
- Authenticode, Apple code signing, and macOS notarization where required

The detailed checklist is in [Compatibility and validation status](docs/compatibility.md).

## Project documentation

- [Configuration](docs/configuration.md)
- [Command reference](docs/command-reference.md)
- [CI and automation](docs/ci.md)
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

## License

Apache-2.0. See [LICENSE](LICENSE).
