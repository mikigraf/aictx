# Command reference

This page summarizes the current command surface. The installed binary is authoritative; use `ctxlane --help` and `ctxlane <command> --help` for parser-generated details.

This command surface is fully standalone. Normal CLI and dashboard operations, local profile/context switching, authentication, and supported vendor runs do not start or require a service, controller, MCP server, ASF, or Runmill. The current binary exposes no lease-service or automation-MCP command.

Global options can be supplied with subcommands:

- `--root <ABSOLUTE_PATH>`: use an isolated application root outside the current repository;
- `--claude-bin`, `--codex-bin`: explicitly select a trusted absolute executable outside the current repository for one invocation;
- `--non-interactive`: fail instead of opening a browser, prompting, or unlocking/consenting to an OS keyring;
- `--quiet`: suppress informational banners, but not security warnings or errors;
- `--help`, `--version`.

## Interactive dashboard

```text
ctxlane
```

After initialization, running `ctxlane` without a subcommand opens the terminal dashboard. It lists contexts, profiles, and directory bindings without reading credentials or starting a vendor CLI. The header shows the global active context, the default context, and the context resolved for the current directory as separate values.

Use these keys on a dashboard panel:

| Key | Action |
| --- | --- |
| `a` | Add an item |
| `e` | Edit the selected item |
| `R` or `F2` | Rename the selected profile or context; open binding Edit with the path selected |
| `d` | Remove the selected item after confirmation |
| `Enter` or `u` | Activate the selected context |
| `r` | Reload metadata |
| `Tab`, Left, or Right | Change panels |
| `?` or `h` | Show help |
| `q` or `Esc` | Exit |

In a form, use `Tab` or `Shift-Tab` to change fields, Left and Right or Space to change a choice, `Enter` to save, and `Esc` to cancel. Text fields support normal cursor, Home, End, Backspace, and Delete keys. A form stays open when validation fails.

The forms are metadata-only. They never read or delete a keyring credential and never start a vendor CLI. Profile Add records the chosen authentication mode and, when needed, a generated keyring reference; it does not store a credential. Profile Edit changes non-secret account or organization/workspace metadata and the Codex credential-store policy. Provider, authentication mode, private vendor state, and secret reference stay unchanged. The dashboard neither enrolls Codex WIF nor edits its authority fields. Use `ctxlane login`, `ctxlane logout`, and `ctxlane run` outside the dashboard.

Profile Rename keeps the existing private vendor-state directory and secret reference, and rewrites every context reference to the new profile ID. Dashboard profile removal retains its keyring credential and leaves its immutable managed vendor state detached at the same path. A profile still used by a context cannot be removed.

Context Edit changes its Claude and Codex profile choices. A changed account selection uses the same confirmation policy as `ctxlane use`. A context whose name would change cannot be renamed while it is active; after switching away, Context Rename rewrites the default context when applicable and every directory binding that uses the old name. An active or bound context still cannot be removed.

Binding Edit can change both the directory path and context. The new path must exist so it can be canonicalized. Binding removal uses the saved canonical path and still works when the directory no longer exists.

Interactive mode requires terminal input and output. Bare `ctxlane --non-interactive`, piped input, or redirected output fails with exit code `14` before enabling terminal raw mode. `Ctrl-C` works from the dashboard and its forms or dialogs, restores the terminal, and exits with `130`.

## Initialization and OS keyring

```text
ctxlane init [--guided] [--fresh]
```

`init` creates config-schema-v2 metadata, mutable-state-schema-v1 metadata, and secure application directories. Version 2 assigns one immutable installation UID, an immutable UID to each profile, and a default-disabled automation policy to each profile. A coordinated normal load upgrades a valid config-schema-v1 file in place; other configuration versions are refused. Re-running `init` does not replace existing metadata. Static secrets use the native OS keyring.

`ctxlane init --guided` is the shortest setup path for a personal Claude subscription. It performs these steps in one invocation:

1. Initialize or validate the existing metadata.
2. Create `claude:personal` with `subscription-token` authentication, or reuse it only when it is already compatible.
3. Run the official `claude setup-token` process.
4. Read the pasted token and store it in the profile's OS-keyring item.
5. Print an explicit `ctxlane run --profile claude:personal ...` command.

Guided setup requires terminal input and output and does not create or change a context. It refuses malformed metadata, an incompatible or case-conflicting `claude:personal` profile, and redirected or `--non-interactive` use without overwriting existing state. If the vendor or credential step is interrupted, the compatible profile remains so the same command can be run again. When a wrapper-held credential already exists, `ctxlane` asks before replacing it and does not revoke the prior remote token.

When legacy v0.1 metadata exists at the default platform path and no target store exists, ordinary startup refuses automatic import. Use the migration commands below or pass `--fresh` to make a separate empty store. `--guided --fresh` is the explicit fresh guided path. An explicit global `--root` never auto-detects another store.

## Migration from v0.1

```text
ctxlane migrate aictx [--dry-run]
ctxlane migrate recover
ctxlane --root <NEW_ROOT> migrate aictx --from-root <OLD_ROOT> [--dry-run]
ctxlane --root <NEW_ROOT> migrate recover --from-root <OLD_ROOT>
```

Migration is copy-only and explicit. `--dry-run` validates the complete source and reports non-secret counts without creating target files. A completed migration rewrites managed profile state paths but preserves existing keyring references. Profile metadata, vendor state, and credentials are not moved or deleted; migration may create or normalize private advisory profile locks in the old state directory. A preserved keyring reference addresses the same OS credential from both tools, so later credential changes in `ctxlane` can affect rollback through the old tool. Explicit target roots require `--from-root`.

If a journal remains after interruption, every ordinary command refuses to use the target. `migrate recover` rolls back transaction-owned partial data or finalizes an already verified target. See [Migration from v0.1](migration-from-v0.1.md).

## Profiles

```text
ctxlane profile add <claude|codex> <name> --auth <mode> [options]
ctxlane profile list
ctxlane profile show <provider:name>
ctxlane profile remove <provider:name> [--delete-secret]
```

Profile options:

- `--secret-ref <keyring://service/account>`
- `--account <label>`
- `--organization <label-or-id>` for Claude
- `--workspace <id>` for Codex or optional Claude WIF workspace selection
- Claude WIF: `--organization-id`, `--federation-rule-id`, `--service-account-id`, `--identity-token-file`
- Codex WIF required fields: `--federation-rule-id`, `--identity-token-file`, `--workspace`, `--principal`, one or more `--environment`, and `--minimum-codex-version`
- Codex WIF optional attribution and constraints: repeatable `--workload-label <KEY=VALUE>`, `--workload-instance-id`, `--workload-display-name`, and repeatable `--workload-context-label <KEY=VALUE>`
- Codex: `--codex-credential-store <file|keyring|auto>`

Use the provider-neutral `subscription` auth name for either Claude or Codex. `subscription-token` remains accepted for both providers, including the equivalent Codex command, and `chatgpt-oauth` remains accepted for Codex. Profiles persist the vendor-native mode: `subscription-token` for Claude and `chatgpt-oauth` for Codex. `api-key` and `wif` have provider-specific forms for both providers; `access-token` is Codex-only. Cross-provider options and incomplete WIF/access-token metadata are rejected.

Codex WIF is enrollment-only in this release. The following command validates and persists the closed metadata record; it does not authenticate or qualify the Codex runtime:

```text
ctxlane profile add codex ci --auth wif \
  --federation-rule-id idpm_production \
  --identity-token-file /run/ctxlane/codex-identity.jwt \
  --workspace chatgpt-workspace:engineering \
  --principal service-account:ctxlane-ci \
  --environment production \
  --minimum-codex-version 0.148.0
```

`--workspace` must use `chatgpt-workspace:<id>`, `--principal` must use `user:<id>` or `service-account:<id>`, and the minimum version must be canonical `x.y.z` at or above `0.148.0`. Repeat `--environment` and either label option as needed. The optional display name and context labels require `--workload-instance-id`. Config loading checks path syntax without probing the configured filesystem location. CLI enrollment separately rejects a supplied identity-token path beneath Git-worktree ancestry without opening the token file. The dashboard does not expose this specialized enrollment form or edit its authority fields. Login, logout, and run remain unavailable as described below.

A profile ID such as `codex:personal` is renameable, but its non-secret `profile_uid` is immutable. Rename preserves that UID, its vendor home, and its secret reference. A profile still referenced by a context cannot be removed. Under a per-profile lock, removal drops its metadata, retires its UID, and leaves its immutable managed vendor directory detached at the same path. Profile creation allocates a new UID and private state directory, so recreating a name does not reuse detached state. Detached state may contain vendor-cached credentials; protect it until you deliberately remove it. `ctxlane` does not perform automated orphan cleanup. A private `p-*` leaf does not distinguish configured state from detached state, so never delete one by name alone: verify that no configured profile references the exact path first. Remote credentials are not revoked.

Profile edit, rename, and removal refuse while the profile has a durable unresolved automation fence. The same per-profile signal gates commands that would use, export, migrate, or perform credential/vendor-state inspection against its vendor home. Recovery may retain the marker's representative alias plus validated same-provider current or historical aliases, all exclusively until the UID is clear. This check uses the existing profile-lock directory and never opens or starts an automation service, authority file, or lease database. Metadata-only `profile list`/`profile show`, ordinary status, context listing and `use`, and unrelated profiles remain available.

Without `--delete-secret`, removal retains any wrapper-held OS-keyring item. With `--delete-secret`, `ctxlane` also attempts to delete that item. If keyring cleanup fails, it attempts to restore the profile metadata; when rollback succeeds, the profile remains configured and the command returns the cleanup error. If rollback also fails, the command reports both failures and the metadata may already be absent. For a profile with a wrapper-held keyring reference, `--non-interactive` refuses this cleanup before changing metadata.

New and config-v1-upgraded profiles carry an operator-owned automation policy with `eligible = false`. No current command edits that policy, and this release has no lease service, automation MCP server, or controller runtime. Its presence adds no service dependency to ordinary local CLI/TUI switching, and changing it by hand does not enable automation.

## Contexts and selection

```text
ctxlane context add <name> [--claude claude:name] [--codex codex:name]
ctxlane context list
ctxlane context show <name>
ctxlane context remove <name>
ctxlane use <name> [--yes]
ctxlane current
```

At least one provider is required when adding a context. An active or directory-bound context cannot be removed. `use` asks for confirmation whenever an exact provider-profile selection changes, even when the old and new profiles use the same billing domain; `--yes` is required for that change in non-interactive use. Its receipt separates the global selection from any directory binding effective in the current directory. `current` prints the resolved context for the current directory.

## Authentication

```text
ctxlane login <provider:name> [--device] [--generate] [--trusted-runner]
ctxlane logout <provider:name>
```

- Claude subscription token: `--generate` requires a terminal, invokes official `claude setup-token`, then reads the raw token through a hidden prompt. Paste only the token, not an `export` command, label, quoted value, or other shell text. The parser does not depend on an undocumented vendor prefix, length, or character set. For a line-wrapped paste, ASCII spaces and tabs at each line edge are removed and the nonblank lines are joined. Blank or ambiguous lines, interior whitespace or controls, common labels or shell wrappers, and extra queued input are rejected before keyring storage. Pasted text is never executed. Without `--generate`, login reads from the hidden prompt or standard input. If the keyring item already exists, interactive login asks before replacing it; replacement does not revoke the prior remote credential. If token generation succeeds but capture or keyring storage fails, revoke the generated token in your Claude account settings under **Settings > Claude Code** before retrying.
- Claude API key: reads/stores the key through the selected secret reference.
- Codex API key: reads/stores the key, then sends it to official `codex login --with-api-key` over stdin so both interactive and `exec` modes use the isolated vendor login state.
- Claude WIF: validates that the configured identity-token file is available; there is no browser login or static secret.
- Codex WIF: if a validated config-v2 enrollment record is present, refuses before token-path-derived filesystem inspection or vendor-state preparation because native runtime qualification is not enabled.
- Codex ChatGPT OAuth: invokes official `codex login` in the isolated profile home; `--device` uses its device authorization option.
- Codex access token: reads the token and sends it to official `codex login --with-access-token` over stdin.

When inherited `GITHUB_EVENT_NAME` identifies `pull_request` or `pull_request_target`, static-credential and cached Codex OAuth login/use is refused before credential access. This is defense-in-depth, not reliable event attestation; workflow/job permissions and secret gating remain the security boundary. Non-interactive Claude subscription-token, Codex OAuth, and Codex access-token login also require `--trusted-runner`, with the same private-runner assertion and limitations as `run`.

`logout` invokes official Codex logout for OAuth, API-key, and access-token profiles and removes a wrapper-held OS-keyring item when applicable. It refuses WIF because the identity source is external. Disable or revoke WIF identity sources upstream. Local logout is not proof of server-side revocation.

## Run

```text
ctxlane run [--context <name> | --profile <provider:name>] [--trusted-runner] <claude|codex> -- [vendor arguments...]
```

The selected profile must match the provider argument. Arguments after `--` are forwarded as operating-system arguments, not assembled into a shell command. Before spawning, `ctxlane` rejects vendor options that can replace endpoints/configuration, load executable plugins/MCP definitions, extend the inspected Claude project root, change Codex project roots, activate repository hooks, ignore the forced isolated config, or detach work beyond the lifecycle lock. This includes Codex `--config`/`-c`, `--enable`, `--disable`, `--profile`/`-p`, `--cd`/`-C`, hook-trust bypass and remote/local-provider controls; and Claude `--settings`, `--add-dir`, MCP/plugin loaders, `--debug`, `--remote-control`, `--bg`/`--background`/`--tmux`, and `agents`. Leading vendor options are parsed with a fail-closed allowlist, so a newly introduced option can be refused until its argument grammar is requalified. The official vendor process otherwise inherits stdin/stdout/stderr and its exit status is propagated.

For a configured Codex WIF profile, `run` fails closed before token-path-derived filesystem inspection, vendor-home preparation, executable resolution, or Codex launch. Persisted enrollment metadata is not evidence of a qualified native runtime.

`--trusted-runner` applies to long-lived Claude subscription-token, cached Codex OAuth, and Codex access-token automation. It asserts that the runner is private and trusted; it cannot override the defense-in-depth refusal when the inherited GitHub event variable identifies `pull_request` or `pull_request_target`. It is not attestation, does not change a profile's `eligible` policy, creates no lease, and grants no production automation authority. It must be backed by external workflow/job and secret policy.

## Status and diagnostics

```text
ctxlane status [--context <name>] [--verbose]
ctxlane credential check <provider:name>
ctxlane credential check --all
ctxlane doctor [--provider claude|codex] [--json]
```

Normal status shows profiles, authentication, billing, masked account/identity pins, and setup-token limitations. `--verbose` additionally shows state directories, secret references (never values), and availability. In non-interactive mode, an OS-keyring-backed availability check fails with exit `14` instead of risking an unlock or consent prompt.

`credential check` exits `11` when a requested credential is unavailable. Claude API-key and setup-token profiles invoke official `claude auth status --json` with only the selected credential and require the expected first-party auth method; an optional `--organization` pin must match the reported `orgId` or `orgName`. If the deployed Claude build omits both fields, a pinned profile fails closed. Even when this local route check succeeds, the Claude credential remains `unverified` and `credential check` exits `13`, because no model request was made. The same local route check gates `run`; treat the first successful model request as remote validity evidence at that point in time. It does not prove future expiry or revocation state. Codex API keys remain availability checks; Codex subscription/access-token checks use official login status and forced configuration. Explicitly checking a Codex WIF profile rechecks the repository-location/private-file boundary and reports only availability; it never qualifies the missing native runtime.

`doctor` checks per-profile authentication readiness in addition to metadata, permissions, binaries, keyring availability, and unsafe settings. A requested provider with no configured profile is not ready. For Codex WIF, doctor deliberately skips token-path/file probing and reports the native runtime as unqualified; use the explicit `credential check` command when file availability alone is needed. For each profile, doctor reports disabled automation as `PASS` or eligible metadata as `WARN`, with environment, role, and caller scopes shown only as counts. It emits a separate `WARN` when either the authentication or isolation exception is acknowledged. This policy display is configuration visibility and never asserts lease or runtime readiness. Interactive checks may read configured static credentials through the OS keyring. When a static Claude credential is stored and its local route matches, `doctor` always reports `WARN`, not `FAIL`, because it neither makes nor records model requests. With `--non-interactive`, static keyring reads are skipped and also reported as warnings. `--json` emits an `ok` boolean and a `checks` array whose entries contain `level`, `name`, and `detail`; review paths and identifiers before sharing a report. The command exits `1` when it reports a failure, otherwise `0`; warnings alone do not fail it, and it never repairs the layout.

## Directory bindings

```text
ctxlane bind <existing-directory> <context>
ctxlane unbind <existing-directory>
ctxlane bindings
```

Targets are canonicalized and must already be directories. Rebinding a path replaces its previous context.

## Shell support

```text
ctxlane env [--context <name>] --shell <bash|zsh|fish|powershell>
ctxlane shell-init <bash|zsh|fish|powershell>
ctxlane completions <bash|elvish|fish|powershell|zsh>
```

For supported runnable profiles, `env` emits quoted, non-secret selectors only. It refuses a resolved context that selects Codex WIF, because exporting `CODEX_HOME` would create an unsupported execution-preparation bypass around the native-runtime refusal. Successful output does not apply run-time environment, repository, lock, workspace, or credential policy; invoking a vendor directly after evaluating it bypasses those protections. `shell-init` emits forwarding functions pinned to the current canonical `ctxlane` path and any explicit global `--root`; regenerate them after moving either. `completions` writes static completion definitions to stdout.

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
