# Configuration

`ctxlane` keeps versioned metadata, mutable selection state, vendor state, and credentials separate.

## Location discovery

By default, platform application directories are discovered for the `dev.Cloudsail.ctxlane` application identity. Exact paths therefore follow the operating system and user environment rather than being hard-coded.

The v0.1 application identity uses different platform directories. `ctxlane` never imports those directories during ordinary startup. Use the explicit commands in [Migration from v0.1](migration-from-v0.1.md), or `ctxlane init --fresh` to create an unrelated target store.

The global `--root <ABSOLUTE_PATH>` option relocates the complete layout under `config/`, `data/`, and `state/`. It is useful for isolated tests and ephemeral automation. Repository-local roots are rejected; keep the directory in user-owned or runner-temporary storage and never commit its metadata. A command-line option is used deliberately because inherited environment is not a trusted control plane.

On Unix, directories must be owned by the current user and inaccessible to group/other users (mode `0700`); sensitive files must be regular, non-symlink files owned by the current user with mode `0600` or stricter. Symlinked or writable ancestor chains are rejected, and missing sensitive directories are created one component at a time. Writes are atomic and coordinated by per-file locks plus a cross-file `state/metadata.lock`. Windows relies on user-profile storage and platform ACL semantics; validate them in the target environment.

## Metadata and state

`config.toml` contains no secret values. It stores:

- schema version;
- the default context;
- settings and trusted executable paths;
- profile metadata and OS-keyring references;
- contexts and canonical directory bindings.

`state.toml` contains the active context. `ctxlane use` changes this file only.

Unknown fields are rejected. The current schema version is `1`; this build does not silently migrate other versions.

The no-subcommand terminal dashboard reads the same validated `config.toml` and `state.toml`. Moving through its lists does not write metadata, access the OS keyring, or contact a vendor. Activating a context updates `state.toml` through the same metadata lock and fresh billing-policy check used by `ctxlane use`.

Dashboard Add, Edit, Rename, and Remove forms write through the normal metadata locks and validation. They are metadata-only: they never read or delete an OS-keyring credential and never start Claude Code or Codex. Authentication and vendor work remain in `ctxlane login`, `ctxlane logout`, and `ctxlane run`.

An illustrative generated configuration is shown below. Paths are absolute in a real file and should be managed through CLI commands whenever possible.

```toml
version = 1
default_context = "personal"

[settings]
require_billing_confirmation_on_change = true
show_run_banner = true
telemetry = false

[binaries]
claude = "/trusted/path/to/claude"
codex = "/trusted/path/to/codex"

[profiles."claude:personal"]
provider = "claude"
billing_domain = "claude-subscription"
auth = "subscription-token"
state_dir = "/absolute/private/data/vendor-state/claude/p-<private-id>"
secret_ref = "keyring://ctxlane/claude-personal-<generation>"

[profiles."codex:personal"]
provider = "codex"
billing_domain = "chatgpt-subscription"
auth = "chatgpt-oauth"
state_dir = "/absolute/private/data/vendor-state/codex/p-<private-id>"
credential_store = "file"
trusted_runners_only = false

[contexts.personal]
claude = "claude:personal"
codex = "codex:personal"

[[bindings]]
path = "/home/example/src/personal"
context = "personal"
```

Do not paste this example wholesale: provider/auth/billing combinations, state paths, references, and context links are validated together.

## Settings

- `require_billing_confirmation_on_change`: when `true`, changing any exact provider-profile selection requires terminal confirmation or `ctxlane use --yes`, including two profiles with the same billing domain. The legacy setting name is kept so version 1 configuration files remain compatible.
- `show_run_banner`: prints the selected context/profile/auth/billing/source before a run unless global `--quiet` is used.
- `telemetry`: must remain `false`. Telemetry is not implemented and validation rejects `true`.

## Executables and overrides

Fresh initialization attempts to anchor discovered `claude` and `codex` executables to absolute paths. Configuration accepts an absolute path or a bare executable name. Any executable that resolves inside the current repository is rejected at run time, as is an executable that resolves back to `ctxlane`.

The following explicit global command-line overrides are available and must be absolute:

- `--claude-bin <ABSOLUTE_PATH>`
- `--codex-bin <ABSOLUTE_PATH>`

No environment-variable executable override is supported. Overrides must resolve to regular trusted executables outside the current Git worktree, with a trusted owner and non-writable ancestor chain on Unix. The child `PATH` is filtered to absolute, existing, trusted directories outside the current repository so an `/usr/bin/env` shebang cannot select a repository-local interpreter. Run `ctxlane doctor` after upgrades or path changes.

## OS keyring

```bash
ctxlane init --guided
```

Guided setup requires terminal input and output. It initializes the layout, creates or reuses the compatible `claude:personal` subscription-token profile, runs official `claude setup-token`, and stores the pasted token in the native OS keyring. It does not create or modify a context. An existing wrapper-held credential is replaced only after confirmation; this local replacement does not revoke the prior remote token. Use the separate `init`, `profile add`, and `login` commands for other authentication modes or profile names.

With no explicit reference, a profile gets a generation-specific `keyring://ctxlane/...` account. Recreating a removed profile therefore cannot silently reconnect to an old wrapper-held secret. Explicit migration preserves existing `keyring://aictx/...` references so they continue to address the same OS-keyring item; it never reads or copies the secret value. Login writes through the native keyring library. Because native stores may display unlock or consent UI, keyring reads and writes fail closed in `--non-interactive` mode.

Static secret values are limited to 1 MiB and must be non-empty UTF-8. They are supplied through a hidden terminal prompt or standard input, then stored in the native OS keyring. For a Claude setup token, supply the raw token without shell syntax or a label. The prompt normalizes line wrapping and ASCII indentation but rejects blank, ambiguous, or unsupported input before storage. Pasted text is handled as data and is never executed. No ordinary secret-valued command-line flag exists.

## Profiles

Profile IDs always have the form `claude:name` or `codex:name`. Each profile receives a unique, absolute mutable state directory. Two profiles cannot share a state directory. The directory leaf is private implementation state and does not need to match the profile name.

The dashboard can add profiles for every supported authentication shape. Profile Edit changes only non-secret identity hints and, for Codex, the credential-store policy. It does not change the provider, authentication mode, private state directory, or secret reference. Empty Edit fields keep existing identity hints; `-` clears the selected hint.

Profile Rename changes the profile ID and every context reference to it. The existing private state directory and `secret_ref` remain unchanged. This keeps the isolated vendor login state and the wrapper-held keyring reference attached to the same local account.

Dashboard profile removal does not read or delete the keyring item. It removes the unreferenced profile metadata and leaves the immutable managed vendor directory detached at the same path. That directory is not reused automatically and can contain vendor-owned credentials. `ctxlane` does not perform automated orphan cleanup. A private `p-*` leaf does not distinguish configured state from detached state, so never delete one based on its name alone; verify that no configured profile references the exact path first.

Use the explicit CLI `profile remove --delete-secret` option when you also intend to delete a wrapper-held keyring credential. If keyring cleanup fails, `ctxlane` attempts to restore the profile metadata. A successful rollback leaves the profile configured; if rollback also fails, the command reports both failures and the metadata may already be absent. Remote credentials are never revoked by local profile removal.

Valid authentication/billing combinations are fixed:

At profile creation, `--auth subscription` is the provider-neutral spelling for both vendors. The compatibility spellings `subscription-token` and `chatgpt-oauth` are also accepted as described in the command reference. Serialized profiles always retain the vendor-native values listed in this table.

| Provider/auth | Required metadata | Static secret |
| --- | --- | --- |
| Claude `subscription-token` | optional `--account`, `--organization` | yes |
| Claude `api-key` | optional `--account`, `--organization` | yes |
| Claude `wif` | `--organization-id`, `--federation-rule-id`, `--service-account-id`, `--identity-token-file`; optional `--workspace` | no |
| Codex `chatgpt-oauth` | optional `--workspace`; optional credential-store policy | no, vendor-managed |
| Codex `api-key` | optional `--account`; optional credential-store policy | yes; also materialized through official Codex login |
| Codex `access-token` | required `--workspace`; optional `--account`; optional credential-store policy | yes; also materialized through official Codex login |

The WIF identity-token file path is made absolute and must be a private regular file when used. `ctxlane` sets Anthropic's documented selector environment for the official client; it does not perform token exchange itself.

For Claude static credentials, `claude auth status --json` checks the local authentication route and any configured organization evidence. It does not make a model request. Treat the first successful model request as the remote validity check; neither local status nor one request proves future expiry or revocation state.

For Codex, `ctxlane` maintains these values in the isolated profile `config.toml`:

- `forced_login_method = "api"` for API keys, otherwise `"chatgpt"`;
- `cli_auth_credentials_store` from the profile;
- `forced_chatgpt_workspace_id` when configured.
- a wrapper-owned `shell_environment_policy` with `inherit = "core"` and default secret exclusions enabled.

Codex API keys and access tokens are sent through the official stdin login flow before a run. Codex therefore caches a second vendor-owned copy according to `cli_auth_credentials_store`; `file` mode stores it in plaintext inside the owner-only isolated `CODEX_HOME`. `keyring` and `auto` are supported, but their storage and isolation semantics remain defined by Codex and the operating system. The static credential is not placed in the main Codex child environment. Treat configured and detached Codex state as credential-bearing material.

## Contexts and bindings

The first context becomes the default. A context must contain at least one provider and may reference only existing profiles of that provider. Dashboard Context Edit changes the provider selections. A context whose name would change cannot be renamed while it is active; switch to another context first. When permitted, Context Rename updates the context key, the default selection when applicable, and every binding that points to the old name.

Bindings are canonical absolute directories. The nearest ancestor binding wins. They are recorded in global metadata through `ctxlane bind` or the dashboard; repository configuration cannot choose a secret reference, executable, or command. Dashboard Binding Edit can replace both the path and context. Its new path must exist. Removal matches the saved path directly, so a binding can still be removed after its directory has been deleted.

## Child environment policy

`ctxlane run` clears the child environment and reconstructs it from inherited variables plus the selected profile. It removes current and legacy wrapper selectors, vendor-prefixed variables, profile/home selectors, process-loader/interpreter injection controls, proxy and custom CA controls, and unsafe `PATH` entries before adding only wrapper-selected inputs. Claude receives its selected authentication input plus subprocess scrubbing; Codex static credentials are delivered through official stdin login and are absent from the main child environment. Configure required corporate routing in a trusted system/vendor installation; arbitrary inherited proxy or CA overrides are intentionally unsupported in `0.2.0`.

The child inherits stdio, and forwarded arguments remain an argument vector. No shell parses them. Vendor exit codes are returned to the caller; Unix signals are mapped to the usual `128 + signal` convention.

Claude project settings (`.claude/settings*.json`, `.mcp.json`), agent/skill/command entrypoint frontmatter and project plugin manifests, Codex project settings (`.codex/config.toml`), and `.codex/hooks.json` are inspected on current-directory ancestors to the Git/home boundary. Credential/endpoint overrides, executable loaders, and startup repository command hooks are refused. Profile-local settings are also inspected for competing credential and routing configuration.

Claude can discover a descendant `.claude` definition after it reads or edits a nested file later in an interactive session. `ctxlane` blocks `--add-dir` and forces Claude's documented subprocess credential scrubbing, but it does not recursively freeze or pre-scan an entire changing repository. Treat later descendant extension discovery as residual repository-code execution risk; do not authorize untrusted tool use merely because startup validation passed.
