# Threat model

## Security objective

`ctxlane` reduces accidental account, identity, and billing crossover when one OS user runs the official Claude Code and Codex CLIs for personal, work, or automation. It aims to ensure that only the selected credential and isolated state reach the selected vendor child process.

The primary protected assets are API keys, subscription/setup tokens, Codex access tokens, vendor-managed OAuth state, WIF identity tokens, the integrity of profile/context selection, and the integrity of future automation authority configuration, trust roots, and signed authorizations.

### Automation implementation status

The current code is a local CLI and TUI, not a production automation identity plane. It has no supported identity-lease service, production MCP server, listener or request-framing gate, complete durable lease recovery, or lease-enforced provider harness. A sealed crate-internal authority checkpoint can read and validate a separate operator file, verify canonical Ed25519 work-order proofs, produce explicitly unqualified macOS local-development evidence, and attest the process that opened a Linux connection. A separate sealed schema-v2 SQLite foundation can durably record initial requests, replay bindings, refusals, and audit events; preserve lossless lease clock snapshots; reconstruct every status on exact replay; and enumerate redacted, explicitly non-resumable recovery candidates while prior state blocks readiness. It has no lifecycle writer or reconciler. Neither foundation is wired to the CLI, TUI, a listener, or each other, and neither grants lease, session, execution, or production authority. `--trusted-runner` is an assertion for existing CLI flows; it is not caller attestation and never grants production automation authority.

The authority loader is crate-internal and read-only. It accepts only a closed version-1, owner-private regular `config/automation-authority.toml` of at most 1 MiB, binds the prepared state to the expected installation UID and configured host identity, and requires strict Ed25519 keys plus exact service limits and non-empty controller scopes, authentication/isolation exception permissions, rates, capacities, and lifetime ceilings. No supported command creates, edits, displays, or consumes this file. Ordinary CLI/TUI paths never derive or open it.

[Automation identity plane](docs/automation-identity-plane.md) records the Phase-0 security and architecture contract for later implementation. Until the later service, integration, native-provider, recovery, and negative-security phases pass their release gates, no deployment of the current code may claim production automation isolation on Linux, macOS, or Windows.

## Trust boundary

Trusted components:

- the local `ctxlane` binary and its dependencies;
- the selected official vendor executable;
- the operating system, current user account, filesystem/ACL implementation, and native keyring;
- the upstream identity provider and official Claude client for WIF;
- user-owned global `ctxlane` metadata.

If the sealed automation checkpoint is exercised by future service code, its
trusted computing base also includes the operator-controlled authority file
and signing system and, on Linux, the kernel, procfs, cgroup v2/systemd
deployment, protected local filesystem semantics, and allowlisted controller
executable.

Untrusted or potentially hostile inputs:

- repository contents and project-local Claude/Codex settings;
- inherited environment variables;
- forwarded vendor arguments;
- public/fork CI events;
- malformed metadata, symlinks, loose permissions, and executable search paths;
- malformed or forged work-order proofs and an untrusted or mismatched process attempting to use a future automation channel;
- vendor output and exit status.

## Current threats and mitigations

| Threat | Consequence | Implemented mitigation | Residual risk |
| --- | --- | --- | --- |
| shell history/log/argv disclosure | credential theft | no secret-valued CLI flag; hidden prompt/stdin/keyring; redacted status | vendor output, crash dumps, or user tracing can still disclose child memory/environment |
| stale parent credential wins | wrong account or billing domain | clear and reconstruct child environment; inject one selected mechanism; preflight static Claude auth routing | a future vendor selector not yet known to `ctxlane` could alter precedence; local auth status is not remote validity proof |
| state crossover | one profile refreshes/uses another profile's cache | unique absolute state directories; per-profile locks; `CODEX_HOME`/`CLAUDE_CONFIG_DIR` selection | native macOS Claude Keychain login is not isolated; vendor keyring namespacing remains vendor-defined |
| malicious repository/config override | credential rerouting or command-hook exfiltration | no repository `ctxlane` config; inspect project vendor settings; refuse credential/endpoint routing, startup command hooks, and forwarded vendor options that can bypass the inspection or isolated config; scrub Claude subprocess credentials | Claude may discover descendant `.claude` definitions later in a session beyond the startup ancestor scan; vendor behavior outside inspected files can change, and blocking is conservative |
| executable/interpreter path hijack | attacker runs a fake vendor binary or shebang interpreter | initialization anchors discovered paths; validate canonical executable ownership/ancestors; reject repository paths; filter child `PATH` to trusted absolute directories | a trusted executable or installation can later be replaced by an attacker with sufficient local rights |
| symlink/permission attack | metadata or state redirected/read | reject symlinked/writable sensitive path chains; Unix owner/mode validation; component-wise directory creation; atomic writes and coordinated locks | Windows ACL correctness needs deployment validation; advisory checks retain a same-user/privileged TOCTOU window |
| fork PR credential theft | untrusted code prints token | defense-in-depth refusal of static credentials and cached Codex OAuth when inherited GitHub event metadata identifies a PR; long-lived subscription/OAuth/access-token automation requires a trusted-runner assertion in CI/non-interactive mode | a same-user process cannot attest its event environment; workflow/job permissions and secret gating are the real boundary, and the assertion can be misused |
| keyring outage/denial | unavailable credentials or unsafe fallback | fail closed; no plaintext fallback; bounded, non-empty UTF-8 secret input | denial of service remains possible |
| supply-chain compromise | theft of all selected credentials | small adapter surface, Rust safety policy, lockfile, CI lint/test/deny/secret-scan checks, checksums/Sigstore bundles/SBOM/provenance workflow | a compromised dependency/build runner/vendor binary remains a severe threat |
| local logout misunderstood | credential remains usable remotely | explicit warning that local cleanup is not revocation | operator must use vendor/IdP controls |

## Phase-0 automation threats

The controls in this table are production requirements, not a claim that the current implementation is qualified. The sealed authority code implements strict configuration and signature primitives, macOS development-only evidence, and Linux connection-origin attestation; the sealed store implements only an owner-private transactional journal and conservative recovery gate. There is still no listener, per-frame Linux credential gate, lease-authority integration, process reconciliation, harness isolation, pruning, or native deployment qualification. The detailed authority matrix and release gates are in [Automation identity plane](docs/automation-identity-plane.md).

| Threat | Consequence | Required control before production | Residual risk |
| --- | --- | --- | --- |
| controller impersonation | an unrelated same-user process acquires model-provider authority | Linux private service channel authenticated with atomic `SO_PEERPIDFD`, peer UID/GID, a retained live process identity, trusted executable canonical path/digest/snapshot, and expected protected cgroup v2/systemd membership; every accepted frame must additionally carry exactly matching `SCM_CREDENTIALS` obtained with `SO_PASSCRED` | current code attests only the connection opener and deliberately cannot authorize Linux work orders; descriptor delegation, loader/libraries, environment/arguments, process memory/ptrace, unusual filesystem semantics, root, or compromise of the trusted controller/service manager/kernel remain decisive |
| forged or widened work order | a controller selects a profile, role, repository, or lifetime it was not granted | operator-managed Ed25519 public keys verify the existing canonical signed message with strict encodings and verification; exact local controller and profile policy intersections compute the effective policy digest | the sealed verifier is currently unwired and grants no lease authority; compromise of an authorized signing key or operator policy can grant valid but unwanted authority after integration |
| mutable profile-name confusion | rename, reuse, or stale display metadata redirects a lease to another identity | leases, policies, state ownership, and audit records bind an immutable internal profile UID; the human-readable profile reference is only an alias | incorrect initial profile enrollment or provider-side identity changes still require runtime verification |
| concurrent vendor-home use | two leases race through shared cookies, caches, or refresh state | mutable vendor homes are exclusive; concurrency is refused unless each lease receives independently isolated writable state | vendor-owned storage outside the isolated home may defeat the isolation claim and must be qualified |
| stale harness after renewal | an attached process continues under superseded authority | every renewal rotates the fencing generation; the harness must acknowledge the new generation or the lease is revoked and the harness terminated | termination can be delayed by kernel or process failure, so new access must still be fenced immediately |
| MCP or prompt-injection privilege expansion | an agent edits trust policy, obtains a credential, or launches a host command | production MCP is controller-only and bounded; a future local-operator surface exclusively owns policy editing; the execution gate launches a fixed structured harness and exposes no arbitrary execution | no authority-file or signing-key command exists yet; compromise of the future controller or trusted harness remains inside the trusted computing base |
| audit history hides misuse or grows without bound | attribution is unavailable or the service exhausts storage | append-only lease events are retained for seven days; pruning is transactional, excludes live/unresolved state, and emits its own non-secret audit event | a privileged attacker can tamper with a local-only store unless evidence is exported to an external protected system |
| unsupported host weakens caller identity | deployment silently omits required peer and process binding | Linux with `SO_PEERPIDFD` support is the only production target; macOS evidence is explicit local-development and unqualified; Windows and other unsupported authority loaders fail before path derivation or filesystem access | upstream Linux 6.5 or a qualified backport, host configuration, native process behavior, and the future per-frame credential gate still require protected deployment qualification |

## Explicit non-goals

`ctxlane` does not protect against:

- same-user malware, debugger/process-memory access, or an interactive process allowed to read the user's keyring;
- administrator/root/kernel compromise;
- a compromised official vendor executable, identity provider, or vendor service;
- intentional credential disclosure by the user or a command they authorize;
- remote revocation, MFA enforcement, SCIM/offboarding, or vendor-side authorization policy;
- full native Claude subscription-login isolation on macOS;
- production automation on macOS, Windows, or another unsupported target;
- treating Linux connection-origin attestation as message authentication or lease authority before the future per-frame credential gate exists;
- attesting a Linux controller's dynamic loader or libraries, environment, arguments, in-memory state, ptrace state, or writers using a delegated connected descriptor;
- treating `--trusted-runner`, STDIO parentage, a profile name, or a client-supplied policy digest as production authority;
- scheduling, durable delivery, GitHub/backlog credentials, a general secret vault, or arbitrary execution through automation MCP;
- arbitrary custom model providers, base URLs, credential helpers, or repository command hooks;
- undocumented OAuth/cache compatibility or independent token verification.

OS keyrings are useful at-rest storage, not a sandbox from code already executing as the same user.

The internal automation journal assumes an owner-controlled local filesystem.
Its SQLite WAL, file permissions, integrity checks, and service lock do not make
it tamper-proof against the same user, root, or copied database files, and do
not establish safe operation on NFS or another network filesystem. Ordinary
CLI/TUI paths do not open the journal, so a corrupt or unavailable automation
store must not reduce standalone account-switching availability.

The separate internal authority file has the same standalone boundary. Its
loader validates the private path and bounded file without creating or writing
it, but cannot defend against its owning account, root, kernel compromise, or
filesystem behavior outside the qualified deployment model. On Windows and
other unsupported targets, authority loading refuses before deriving or
reading the path. A corrupt or unavailable authority file must not reduce
ordinary CLI/TUI availability.

## Secret lifecycle

Static credentials are resolved immediately before a vendor operation and held in a `SecretString`; selected credentials are scoped to the child environment or written to official Codex login stdin. Official Codex login can persist a second copy in the profile's configured vendor credential store. File-backed copies live under the isolated private `CODEX_HOME`; keyring/auto behavior is vendor- and OS-defined. Detached vendor-state directories may therefore remain credential-bearing. The wrapper avoids logging values and drops its local secret objects after use.

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

Production automation must additionally preserve these invariants. The sealed
checkpoint enforces parts of items 9 and 10 as non-authoritative evidence, but
the complete invariants remain future service requirements:

9. no production authority from `--trusted-runner`, active contexts, directory bindings, repository input, STDIO parentage, or client-asserted identity/policy fields;
10. no activated or resolved lease authority without an authenticated, operator-trusted Linux controller whose current frame credentials match its retained live identity, a verified signed-work-order authorization, an immutable profile UID, and a server-computed effective policy digest; connection-origin evidence, `REQUESTED`, and `REFUSED` records carry no execution authority;
11. no shared mutable vendor home across concurrent leases and no stale-generation harness after renewal, revocation, or expiration;
12. no credential, credential path, vendor-home path, reconstructed environment, or arbitrary executable returned or selected through MCP;
13. no production harness launch except the operator-configured fixed structured harness, with model-proposed tool execution kept in a controller-owned credential-free sandbox;
14. no silent deletion of the seven-day attribution record and no pruning of active or unresolved lease state.

## Review triggers

Revisit this model when a release adds a provider, credential storage mechanism, repository configuration, custom endpoint, OAuth/cache parser, automation service or transport, controller-authentication mechanism, work-order signature format, lease store, provider harness, telemetry, self-update mechanism, or a bypass for repository settings. Also review whenever vendor credential precedence or storage contracts change.
