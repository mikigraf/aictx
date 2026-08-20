# Threat model

## Security objective

`aictx` reduces accidental account, identity, and billing crossover when one OS user runs the official Claude Code and Codex CLIs for personal, work, or automation. It aims to ensure that only the selected credential and isolated state reach the selected vendor child process.

The primary protected assets are API keys, subscription/setup tokens, Codex access tokens, vendor-managed OAuth state, WIF identity tokens, and the integrity of profile/context selection.

## Trust boundary

Trusted components:

- the local `aictx` binary and its dependencies;
- the selected official vendor executable;
- the operating system, current user account, filesystem/ACL implementation, and native keyring;
- the upstream identity provider and official Claude client for WIF;
- user-owned global `aictx` metadata.

Untrusted or potentially hostile inputs:

- repository contents and project-local Claude/Codex settings;
- inherited environment variables;
- forwarded vendor arguments;
- public/fork CI events;
- malformed metadata, symlinks, loose permissions, and executable search paths;
- vendor output and exit status.

## Threats and mitigations

| Threat | Consequence | Implemented mitigation | Residual risk |
| --- | --- | --- | --- |
| shell history/log/argv disclosure | credential theft | no secret-valued CLI flag; hidden prompt/stdin/keyring; redacted status | vendor output, crash dumps, or user tracing can still disclose child memory/environment |
| stale parent credential wins | wrong account or billing domain | clear and reconstruct child environment; inject one selected mechanism; preflight static Claude auth routing | a future vendor selector not yet known to `aictx` could alter precedence; local auth status is not remote validity proof |
| state crossover | one profile refreshes/uses another profile's cache | unique absolute state directories; per-profile locks; `CODEX_HOME`/`CLAUDE_CONFIG_DIR` selection | native macOS Claude Keychain login is not isolated; vendor keyring namespacing remains vendor-defined |
| malicious repository/config override | credential rerouting or command-hook exfiltration | no repository `aictx` config; inspect project vendor settings; refuse credential/endpoint routing, startup command hooks, and forwarded vendor options that can bypass the inspection or isolated config; scrub Claude subprocess credentials | Claude may discover descendant `.claude` definitions later in a session beyond the startup ancestor scan; vendor behavior outside inspected files can change, and blocking is conservative |
| executable/interpreter path hijack | attacker runs a fake vendor binary or shebang interpreter | initialization anchors discovered paths; validate canonical executable ownership/ancestors; reject repository paths; filter child `PATH` to trusted absolute directories | a trusted executable or installation can later be replaced by an attacker with sufficient local rights |
| symlink/permission attack | metadata or state redirected/read | reject symlinked/writable sensitive path chains; Unix owner/mode validation; component-wise directory creation; atomic writes and coordinated locks | Windows ACL correctness needs deployment validation; advisory checks retain a same-user/privileged TOCTOU window |
| fork PR credential theft | untrusted code prints token | defense-in-depth refusal of static credentials and cached Codex OAuth when inherited GitHub event metadata identifies a PR; long-lived subscription/OAuth/access-token automation requires a trusted-runner assertion in CI/non-interactive mode | a same-user process cannot attest its event environment; workflow/job permissions and secret gating are the real boundary, and the assertion can be misused |
| keyring outage/denial | unavailable credentials or unsafe fallback | fail closed; no plaintext fallback; bounded, non-empty UTF-8 secret input | denial of service remains possible |
| supply-chain compromise | theft of all selected credentials | small adapter surface, Rust safety policy, lockfile, CI lint/test/deny/secret-scan checks, checksums/Sigstore bundles/SBOM/provenance workflow | a compromised dependency/build runner/vendor binary remains a severe threat |
| local logout misunderstood | credential remains usable remotely | explicit warning that local cleanup is not revocation | operator must use vendor/IdP controls |

## Explicit non-goals

`aictx` does not protect against:

- same-user malware, debugger/process-memory access, or an interactive process allowed to read the user's keyring;
- administrator/root/kernel compromise;
- a compromised official vendor executable, identity provider, or vendor service;
- intentional credential disclosure by the user or a command they authorize;
- remote revocation, MFA enforcement, SCIM/offboarding, or vendor-side authorization policy;
- full native Claude subscription-login isolation on macOS;
- arbitrary custom model providers, base URLs, credential helpers, or repository command hooks;
- undocumented OAuth/cache compatibility or independent token verification.

OS keyrings are useful at-rest storage, not a sandbox from code already executing as the same user.

## Secret lifecycle

Static credentials are resolved immediately before a vendor operation and held in a `SecretString`; selected credentials are scoped to the child environment or written to official Codex login stdin. Official Codex login can persist a second copy in the profile's configured vendor credential store. File-backed copies live under the isolated private `CODEX_HOME`; keyring/auto behavior is vendor- and OS-defined. Retired vendor-state archives may therefore remain credential-bearing. The wrapper avoids logging values and drops its local secret objects after use.

This is lifetime minimization, not a claim of perfect memory zeroization. Rust libraries, the OS, vendor child, allocators, or crash facilities may copy data. Disable core dumps and process tracing where the deployment requires it, and prefer short-lived workload identity over static bearer tokens.

## Security invariants

Changes should preserve these invariants:

1. no bearer credential in wrapper config/state, logs, normal status, argv, completion, shell init, or `env` output; vendor-owned isolated auth state is explicitly allowed and treated as sensitive;
2. no shell interpolation for vendor execution;
3. no inherited competing vendor credential, endpoint, or home selector in the child;
4. no shared mutable state directory between profiles;
5. no untrusted repository choice of executable, secret reference, context, or hook;
6. no direct implementation of vendor OAuth or WIF exchange;
7. fail closed on malformed/uninspectable security-sensitive files and unavailable credentials;
8. preserve vendor exit behavior without exposing secrets.

## Review triggers

Revisit this model when a release adds a provider, credential storage mechanism, repository configuration, custom endpoint, OAuth/cache parser, remote service, telemetry, self-update mechanism, or a bypass for repository settings. Also review whenever vendor credential precedence or storage contracts change.
