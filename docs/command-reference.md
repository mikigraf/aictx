# Command reference

This page summarizes the `0.1.0` command surface. The installed binary is authoritative; use `aictx --help` and `aictx <command> --help` for parser-generated details.

Global options can be supplied with subcommands:

- `--root <ABSOLUTE_PATH>`: use an isolated application root outside the current repository;
- `--claude-bin`, `--codex-bin`: explicitly select a trusted absolute executable outside the current repository for one invocation;
- `--non-interactive`: fail instead of opening a browser, prompting, or unlocking/consenting to an OS keyring;
- `--quiet`: suppress informational banners, but not security warnings or errors;
- `--help`, `--version`.

## Interactive dashboard

```text
aictx
```

After initialization, running `aictx` without a subcommand opens the terminal dashboard. It lists contexts, profiles, and directory bindings without reading credentials or starting a vendor CLI. The header shows the global active context, the default context, and the context resolved for the current directory as separate values.

Use the arrow keys or `j` and `k` to move, `Tab` to change panels, `Enter` or `u` to activate a context, `r` to reload metadata, `?` or `h` for help, and `q` or `Esc` to exit. Context changes use the same locked update and billing-confirmation policy as `aictx use`.

Interactive mode requires terminal input and output. Bare `aictx --non-interactive`, piped input, or redirected output fails with exit code `14` before enabling terminal raw mode. `Ctrl-C` restores the terminal and exits with `130`.

## Initialization and OS keyring

```text
aictx init
```

`init` creates versioned metadata and secure application directories. Re-running it does not replace existing metadata. Static secrets use the native OS keyring.

## Profiles

```text
aictx profile add <claude|codex> <name> --auth <mode> [options]
aictx profile list
aictx profile show <provider:name>
aictx profile remove <provider:name> [--delete-secret]
```

Profile options:

- `--secret-ref <keyring://service/account>`
- `--account <label>`
- `--organization <label-or-id>` for Claude
- `--workspace <id>` for Codex or optional Claude WIF workspace selection
- Claude WIF: `--organization-id`, `--federation-rule-id`, `--service-account-id`, `--identity-token-file`
- Codex: `--codex-credential-store <file|keyring|auto>`

Valid auth names are `subscription-token`, `api-key`, and `wif` for Claude; `chatgpt-oauth`, `api-key`, and `access-token` for Codex. Cross-provider options and incomplete WIF/access-token metadata are rejected.

A profile still referenced by a context cannot be removed. Under a per-profile lock, removal drops its metadata and moves its managed vendor directory to a private `.retired-*` sibling so recreating the name starts with fresh state; profile creation also retires any orphaned active directory left by an interrupted removal. The archive remains available for deliberate recovery and may contain vendor-cached credentials, so protect or deliberately remove it when no longer needed. Remote credentials are not revoked. `--delete-secret` first deletes only that profile's wrapper-held keyring credential, so a keyring error leaves the profile metadata intact.

## Contexts and selection

```text
aictx context add <name> [--claude claude:name] [--codex codex:name]
aictx context list
aictx context show <name>
aictx context remove <name>
aictx use <name> [--yes]
aictx current
```

At least one provider is required when adding a context. An active or directory-bound context cannot be removed. `use` asks for confirmation if the configured billing domain changes; `--yes` is required for that change in non-interactive use. `current` prints the resolved context for the current directory.

## Authentication

```text
aictx login <provider:name> [--device] [--generate] [--trusted-runner]
aictx logout <provider:name>
```

- Claude subscription token: `--generate` first invokes official `claude setup-token`, then reads the displayed token through a hidden prompt/stdin. Without it, login only reads/stores the supplied secret.
- Claude API key: reads/stores the key through the selected secret reference.
- Codex API key: reads/stores the key, then sends it to official `codex login --with-api-key` over stdin so both interactive and `exec` modes use the isolated vendor login state.
- Claude WIF: validates that the configured identity-token file is available; there is no browser login or static secret.
- Codex ChatGPT OAuth: invokes official `codex login` in the isolated profile home; `--device` uses its device authorization option.
- Codex access token: reads the token and sends it to official `codex login --with-access-token` over stdin.

When inherited `GITHUB_EVENT_NAME` identifies `pull_request` or `pull_request_target`, static-credential and cached Codex OAuth login/use is refused before credential access. This is defense-in-depth, not reliable event attestation; workflow/job permissions and secret gating remain the security boundary. Non-interactive Claude subscription-token, Codex OAuth, and Codex access-token login also require `--trusted-runner`, with the same private-runner assertion and limitations as `run`.

`logout` invokes official Codex logout for OAuth, API-key, and access-token profiles and removes a wrapper-held OS-keyring item when applicable. It refuses WIF because the identity source is external. Disable or revoke WIF identity sources upstream. Local logout is not proof of server-side revocation.

## Run

```text
aictx run [--context <name> | --profile <provider:name>] [--trusted-runner] <claude|codex> -- [vendor arguments...]
```

The selected profile must match the provider argument. Arguments after `--` are forwarded as operating-system arguments, not assembled into a shell command. Before spawning, `aictx` rejects vendor options that can replace endpoints/configuration, load executable plugins/MCP definitions, extend the inspected Claude project root, change Codex project roots, activate repository hooks, ignore the forced isolated config, or detach work beyond the lifecycle lock. This includes Codex `--config`/`-c`, `--enable`, `--disable`, `--profile`/`-p`, `--cd`/`-C`, hook-trust bypass and remote/local-provider controls; and Claude `--settings`, `--add-dir`, MCP/plugin loaders, `--debug`, `--remote-control`, `--bg`/`--background`/`--tmux`, and `agents`. Leading vendor options are parsed with a fail-closed allowlist, so a newly introduced option can be refused until its argument grammar is requalified. The official vendor process otherwise inherits stdin/stdout/stderr and its exit status is propagated.

`--trusted-runner` applies to long-lived Claude subscription-token, cached Codex OAuth, and Codex access-token automation. It asserts that the runner is private and trusted; it cannot override the defense-in-depth refusal when the inherited GitHub event variable identifies `pull_request` or `pull_request_target`. It is not attestation and must be backed by external workflow/job and secret policy.

## Status and diagnostics

```text
aictx status [--context <name>] [--verbose]
aictx credential check <provider:name>
aictx credential check --all
aictx doctor [--provider claude|codex] [--json]
```

Normal status shows profiles, authentication, billing, masked account/identity pins, and setup-token limitations. `--verbose` additionally shows state directories, secret references (never values), and availability. In non-interactive mode, an OS-keyring-backed availability check fails with exit `14` instead of risking an unlock or consent prompt.

`credential check` exits `11` when any requested credential is unavailable and `13` when the selected managed identity cannot be confirmed. Claude API-key and setup-token profiles invoke official `claude auth status --json` with only the selected credential and require the expected first-party auth method; an optional `--organization` pin must match the reported `orgId` or `orgName`. If the deployed Claude build omits both fields, a pinned profile fails closed and must not be treated as verified. This local routing preflight also gates `run`, but does not make a model API request or prove remote validity, expiry, or revocation. Codex API keys and WIF identity files remain availability checks; Codex subscription/access-token checks use official login status and forced configuration.

`doctor` checks the same per-profile authentication readiness in addition to metadata, permissions, binaries, keyring availability, and unsafe settings. A requested provider with no configured profile is not ready. Interactive checks may read configured static credentials through the OS keyring. With `--non-interactive`, static keyring reads are skipped and reported as warnings. `--json` emits an `ok` boolean and a `checks` array whose entries contain `level`, `name`, and `detail`; review paths and identifiers before sharing a report. The command exits `1` when it reports a failure, otherwise `0`; warnings alone do not fail it, and it never repairs the layout.

## Directory bindings

```text
aictx bind <existing-directory> <context>
aictx unbind <existing-directory>
aictx bindings
```

Targets are canonicalized and must already be directories. Rebinding a path replaces its previous context.

## Shell support

```text
aictx env [--context <name>] --shell <bash|zsh|fish|powershell>
aictx shell-init <bash|zsh|fish|powershell>
aictx completions <bash|elvish|fish|powershell|zsh>
```

`env` emits quoted, non-secret selectors only. It does not apply run-time environment, repository, lock, workspace, or credential policy; invoking a vendor directly after evaluating it bypasses those protections. `shell-init` emits forwarding functions pinned to the current canonical `aictx` path and any explicit global `--root`; regenerate them after moving either. `completions` writes static completion definitions to stdout.

## Exit codes

Wrapper-originated errors use these stable categories:

| Code | Meaning |
| ---: | --- |
| `0` | success |
| `2` | usage, invalid configuration, local I/O/locking, cancellation, or another general wrapper error |
| `10` | profile or context not found |
| `11` | credential store unavailable |
| `12` | credential expired (reserved by the current error model) |
| `13` | authentication route or organization/workspace identity is unverified/mismatched |
| `14` | interaction required |
| `15` | security policy refused execution |
| `16` | vendor CLI unavailable/incompatible or could not be spawned |

For `run` and vendor-owned login/logout flows, a successfully started vendor CLI can return its own exit code. On Unix, a signal termination is represented as `128 + signal`.
