# Automation identity plane

## Status and release boundary

This document is the Phase-0 security and architecture contract for evolving `ctxlane` into a local automation identity plane. Phase 0 defines authority, isolation, lifecycle, and integration ownership. The repository contains sealed implementation checkpoints for some contracts, but it does not yet connect or qualify a production authority path.

The current `ctxlane` code remains a local account-isolation CLI and TUI. It does not yet provide a supported production MCP server, authenticated lease service or listener, complete durable lease recovery, or lease-enforced structured provider harness. A sealed crate-internal authority checkpoint validates an operator-owned file, implements strict canonical Ed25519 work-order proof verification, and produces platform-specific caller evidence. A separate sealed SQLite foundation records initial request, replay, refusal, and audit state and enforces a conservative recovery gate on Linux/macOS local filesystems. The two foundations are unwired: neither is a service, neither is reachable from an ordinary command, and neither grants lease, session, execution, or production authority. `--trusted-runner` remains a backwards-compatible assertion for existing CLI flows and never grants production automation authority. Production automation identity-plane use is blocked until the later implementation phases and their Linux-native, controller-integration, failure-injection, recovery, credential-search, and negative-security tests pass.

The production contract is:

> A coding-agent invocation receives exactly the provider identity authorized for its run and role, for no longer than the approved lease, with verifiable attribution and no dependence on global profile state.

The companion [threat model](../THREAT_MODEL.md) distinguishes current mitigations from these future requirements.

## Standalone operation and optional integrations

`ctxlane` is a standalone product. ASF and Runmill are optional integrations,
not runtime, build, configuration, or authentication dependencies.

- **Standalone interactive mode:** `ctxlane init`, profiles, contexts,
  directory bindings, login/logout, `ctxlane run`, and the terminal dashboard
  work without starting the automation service or configuring a controller,
  signer, authority file, lease store, or MCP client.
- **Future standalone automation mode:** any operator-trusted local controller
  may use the future service, execution gate, and MCP contracts when it
  satisfies the same authenticated-channel, signed-work-order, and policy
  requirements. No ASF or Runmill component is required.
- **Optional ASF/Runmill integration:** ASF may produce signed work orders and Runmill
  may act as a trusted controller and credential-free tool executor. This is
  one possible integration of the controller-neutral interfaces; none ships in
  the current binary.

Ordinary standalone commands never discover, auto-start, or depend on the
automation service. Automation state and failures cannot change the selected
account or availability of a normal interactive command.

The authority checkpoint has a separate read-only path,
`config/automation-authority.toml`. Its crate-internal loader is intended solely
for a future explicit service and has no current non-test call site. The loader
accepts only its closed version 1 and at most 1 MiB, requires an owner-private
regular file and trusted path, refuses links and unsafe mutation, binds the
prepared state to the expected installation UID and configured host identity,
and validates strict signing keys plus exact service limits, non-empty
controller scopes, authentication/isolation exception permissions, rates,
capacities, and lifetime ceilings. No supported CLI/TUI command creates, edits,
displays, or consumes this file, and this document intentionally does not
define an operator-facing file syntax.

The internal store foundation preserves that boundary by construction. Only a
future explicit automation-service entry point may create or open
`state/automation/lease-store.sqlite3`; metadata loading, profile and context
commands, login/logout, normal runs, doctor, and the dashboard do not. Its WAL
mode is qualified only for an owner-private local filesystem. NFS and other
network filesystems have no safety claim and must be rejected by future
deployment preflight. On Windows and other unsupported targets, opening the
automation store fails before filesystem access while ordinary interactive
behavior is unchanged.

## Published Phase-0 wire contracts

The closed JSON Schema 2020-12 contracts are published with the source and
release archives:

- [Signed work-order authorization v1](../schemas/ctxlane.work-order-authorization.v1.schema.json)
- [Identity-lease request v1](../schemas/ctxlane.identity-lease-request.v1.schema.json)
- [Identity lease v1](../schemas/ctxlane.identity-lease.v1.schema.json)
- [Automation readiness v1](../schemas/ctxlane.automation-readiness.v1.schema.json)
- [Automation error v1](../schemas/ctxlane.automation-error.v1.schema.json)

[Schema rules](../schemas/README.md) define canonical request hashing, signed
work-order bytes, compatibility, and the secret boundary. Publication makes
the contracts reviewable. The sealed verifier now checks the canonical signed
authorization primitive, but the current binary does not serve these schemas
or turn a verified proof into lease or execution authority.

## Product boundary

### ctxlane owns

- Claude and Codex profile definitions.
- Provider-specific authentication metadata.
- Isolation of provider-owned state.
- Automation eligibility for each profile.
- Caller authentication for identity requests.
- Identity lease issuance, renewal, fencing, revocation, expiration, and closure.
- Safe construction of the trusted provider-harness environment.
- Non-secret identity attribution and audit events.
- Provider identity preflight and runtime identity verification where supported.

### ctxlane does not own

- Backlog intake, task selection, planning, dependencies, or scheduling.
- Repository, GitHub, Linear, deployment, or cloud credentials.
- Agent prompts, tool policy, verification, review, PR creation, merge, or deployment.
- Durable delivery workflows.
- General-purpose secret storage.
- Arbitrary command execution exposed as an MCP tool.
- Model-driven profile creation, login, profile editing, or trust-policy changes.

### Controller-neutral ownership

| Concern | Owner | ctxlane interaction |
| --- | --- | --- |
| Work obligation and closure target | Trusted work-order signer | Included as signed references in a lease request |
| One delivery attempt | Authenticated trusted controller | Requests, uses, renews, and closes identity leases |
| Model-provider identity | ctxlane | Authoritative |
| Repository or delivery credential | Controller or external orchestrator | Never stored or issued by ctxlane |
| Backlog credential | External orchestrator | Never enters ctxlane or an agent process |
| Tool execution sandbox | Controller-owned credential-free executor | Must exclude ctxlane control channels and provider credentials |

For a future optional ASF/Runmill integration, ASF would be the work-order
signer and external orchestrator, while Runmill would be the trusted controller
and tool executor. A standalone deployment would supply those roles
independently.

## Target architecture

```text
Trusted work-order signer
      │ signed Work Order
      ▼
Authenticated local controller
      │ MCP control requests
      ▼
ctxlane MCP adapter ───────► ctxlane lease service
                                  │
                                  ├── secure metadata and lease journal
                                  ├── provider identity validation
                                  └── local execution gate
                                           │
                         fixed trusted provider harness
                                           │ structured tool requests
                                           ▼
                           credential-free tool executor
```

The MCP adapter may run over STDIO for local development and single-host BYOC deployment. The production lease service must have a durable journal and a local authenticated execution channel. On Linux, the preferred channel is a private Unix-domain socket with peer credentials. The socket must not be visible inside the repository sandbox.

The provider harness is trusted and may receive the model-provider credential. Tool execution is separate: model-proposed tool calls go to the controller-owned executor, which runs them in a credential-free sandbox. Runmill could supply that executor in a future optional ASF integration. Existing direct vendor CLI execution remains a local-development backend and is not the production credential-isolation claim.

### Phase-0 topology decisions

- The existing `ctxlane` binary will host the future service and MCP adapter modes. Phase 0 does not introduce a separate service executable.
- One future host service must support multiple independently authenticated controllers. Every controller receives its own caller identity and authorization scope; controller concurrency never falls back to the global active context or directory bindings.
- Linux is the only production automation platform. macOS is supported for local development and contract testing only. Windows and all other unsupported automation service, MCP, lease, and execution entry points must refuse before credential access, harness launch, network activity, or authority-bearing state mutation. Existing interactive behavior remains separate.
- Production STDIO MCP is framing, not authentication. It must use an inherited, already-connected service channel that has passed controller authentication. It must not discover an ambient control socket, trust environment-supplied identity, infer authority from its parent process, or fall back to an unauthenticated in-process lease service.
- The service channel and all provider state remain outside repository and tool-execution sandboxes.

## Authority matrix

This is the target service authority matrix. The current sealed authority and
attestation values are evidence objects only: Linux connection-origin evidence
is explicitly verifier-ineligible, macOS evidence is explicitly development
unqualified, and no listener or lease-authority consumer exists.

| Actor or input | Authentication or trust basis | Permitted authority | Explicitly denied authority |
| --- | --- | --- | --- |
| Platform operator | Local operator identity plus owner-controlled CLI and metadata permissions | Create and maintain profiles; enable automation; edit caller, role, environment, concurrency, harness, and signing-key policy; inspect and revoke leases | Supplying credential values through MCP; delegating policy editing to a model, repository, or coding worker; changing the fixed Phase-0 retention |
| Trusted work-order signer | Signature verifiable by an operator-configured Ed25519 public key | Authorize the canonical work-order digest reference and its bounded tenant, run, attempt, role, repository, profile, and validity claims | Direct service access unless separately authenticated as a controller; widening operator policy; receiving a provider credential |
| Trusted local controller | Authenticated Linux service channel bound to peer UID/GID, trusted executable path and digest, and expected service-manager/cgroup identity | Submit an explicit profile and signed work-order reference; list permitted non-secret profile readiness; acquire, inspect, renew, close, or revoke leases within its scope; start the fixed harness through an opaque execution handle | Editing profiles, policy, signing keys, or credentials; using active context or bindings for selection; receiving secret or vendor-home paths; arbitrary host execution |
| Production STDIO MCP adapter | Inherited already-authenticated service channel; STDIO itself grants nothing | Translate the bounded MCP schemas to the service and return non-secret results | Authenticating a controller, computing policy, opening a service channel for an arbitrary caller, storing credentials, or becoming a lease authority |
| `ctxlane` lease service | Operator-owned configuration, authenticated channels, verified signed references, durable state, and runtime checks | Compute effective policy; issue, fence, renew, revoke, expire, and close leases; gate the fixed harness; resolve the credential internally; emit non-secret attribution | Scheduling work, issuing GitHub/backlog tokens, exposing credentials or paths, accepting client policy as authoritative, or running arbitrary commands |
| Fixed provider harness | Operator-configured executable and structured protocol, launched by the service for one lease and generation | Receive exactly one selected provider identity and its lease-isolated state; communicate with the provider; emit structured tool requests; acknowledge renewal generations | Choosing a profile, editing policy, acquiring another lease, continuing on a stale generation, exposing credentials to tools, or executing arbitrary client-supplied programs |
| Tool sandbox and coding agent | Untrusted workload constrained by the controller-owned executor | Execute structured tool requests under controller policy without provider credentials | Reaching service or execution channels; reading provider credentials or vendor homes; selecting identity; invoking the harness directly; editing ctxlane state |
| Repository content, unsigned request fields, active contexts, and directory bindings | Untrusted or ambient input | Narrow execution only where an operator policy explicitly permits a repository constraint | Granting, selecting, extending, or widening automation identity authority |
| CLI `--trusted-runner` assertion | Human- or workflow-supplied compatibility flag | Satisfy the documented assertion requirement for existing non-production CLI flows | Authenticating a production controller, enabling an automation profile, overriding policy, or authorizing a lease or harness |

Authority requires both authenticated transport identity and authorized workload intent. A valid controller without a valid signed work-order reference is refused; a valid signature arriving through an unauthenticated or mismatched controller is also refused.

## Caller authentication and channel binding

The sealed Linux checkpoint attests the process that opened a Unix stream. It
requires `SO_PEERCRED` and atomic `SO_PEERPIDFD` (upstream Linux 6.5 or a
qualified backport), retains the pidfd, and fails closed when that facility is
unavailable. It verifies the pidfd's kernel-reported PID and liveness; stable
process PID, start time, and all real/effective/saved/filesystem UID/GID values;
the configured canonical native executable path, bounded SHA-256 digest,
device/inode and retained metadata snapshot; one protected unified cgroup v2
path whose final component is the configured systemd service unit; and a stable
boot identity. The authority configuration digest, host, subject, process,
executable, and deployment observations are included in the attestation
binding and revalidated.

That result is named connection-origin attestation, not production caller
authority. A connected Unix-stream descriptor can be inherited or delegated
to another writer. The current verifier therefore rejects Linux connection
evidence. A future listener must enable `SO_PASSCRED`, require exactly one
non-truncated `SCM_CREDENTIALS` record on every accepted frame, match its
PID/UID/GID to the retained still-live peer identity, and reject missing,
duplicate, changed, or ambiguous credentials before making Linux work-order
verification eligible.

Every future production controller channel must additionally satisfy all of
these checks:

1. A private Linux Unix-domain service channel supplies kernel peer credentials whose UID and GID match operator policy.
2. The peer process resolves to the operator-allowlisted canonical executable path, and the executable content matches its trusted digest.
3. The peer process belongs to the expected systemd unit and cgroup recorded for that controller deployment.
4. The socket and inherited channel are absent from the repository and tool sandboxes.

A missing, unreadable, unsupported, or mismatched attribute fails closed. UID/GID alone is insufficient because another same-user process may share it. Path alone is insufficient because content can be replaced. Digest alone is insufficient because a copied executable can run outside the supervised deployment. Connection-origin attestation also does not cover dynamic loaders or libraries, environment or arguments, in-memory mutation or ptrace, unusual or network-filesystem semantics, or a writer using a delegated connected descriptor. Protected deployments must qualify those residual trusted-computing-base assumptions rather than treating this checkpoint as a general process-integrity proof.

The future service must support multiple controllers concurrently. Each allowlist entry has a stable caller subject, independent lease scope, and independent rate and capacity accounting. Client-supplied caller names are diagnostic only and never override the authenticated subject.

For production STDIO, the supervisor starts the adapter with an inherited channel that the service has already authenticated. On Linux, that inherited channel still requires the per-frame credential gate described above; connection-origin evidence alone is insufficient. The adapter refuses when the channel or frame identity is absent or invalid. Stdin and stdout carry MCP frames only; possession of those streams, process parentage, environment variables, and `--trusted-runner` do not authenticate the caller.

## Signed work orders and effective policy

The sealed authority loader stores only prepared operator-approved Ed25519 public verification keys. It requires exact lowercase `ed25519:` public-key encoding, rejects weak keys, requires every unique key ID to be referenced by at least one exact controller scope, and never loads a private signing key. Signing private keys remain with the operator's chosen signing system and never enter `ctxlane`.

A lease request carries a versioned signed work-order digest reference. Its canonical signed envelope binds the signing-key ID, client request ID, tenant, work-order ID and digest, run and attempt IDs, role, provider, immutable profile UID and explicit display alias, repository/workspace identity, environment, validity bounds, maximum TTL/session authority, and schema version. Changing any bound value invalidates the signature. The internal verifier reuses the published canonical signature message, accepts only the canonical 64-byte unpadded base64url signature form, uses strict Ed25519 verification, enforces validity plus every configured authorization key/scope and TTL/session ceiling, and collapses key, signature, and authorization failures into one redacted error. Its unforgeable result remains bound to the current authority configuration, caller evidence, host, assurance, and attestation binding. It is crate-private and unwired, and it cannot itself issue or activate a lease. Today only the explicitly unqualified macOS local-development evidence is verifier-eligible; Linux connection-origin evidence is rejected.

The parsed top-level `client_request_id` is a service-global replay key. After strict decoding and transport authentication, the service looks it up under the global idempotency lock before semantic evaluation. The first request durably records its canonical request digest and authenticated caller, host, and authority binding. An exact retry returns the same lease result only when every recorded value matches. A changed request or cross-caller or cross-host reuse returns the pre-lease `idempotency-conflict` error with no lease ID and no disclosure about an existing request or lease. The signed envelope contains the same ID as an authority gate. A fresh top-level ID paired with an envelope that signs another ID can create a durable `work-order-authorization-mismatch` refusal, but it cannot create additional authority. These rules are controller-neutral and would apply equally to future standalone automation and optional controller integrations.

The signed envelope expresses maximum requested authority; it does not override local policy. Its `expires_at` value bounds all derived lease authority, not only when the request may be presented. Acquisition refuses a requested TTL that would cross that time, and the service sets the lease's maximum expiry to the earlier of the signed expiry and the issued time plus the signed maximum session. Renewal and launch recheck that bound. The service computes the effective policy as the intersection of:

- operator-owned profile and automation policy;
- the authenticated controller's allowlist and host limits;
- the verified signed work-order constraints;
- current service, provider, role, environment, concurrency, TTL, and isolation limits.

The service serializes that result with a versioned canonical encoding and computes the effective policy digest. A successfully resolved lease persists and returns that digest as non-secret attribution, then revalidates it at launch and renewal. `REQUESTED` and `REFUSED` responses keep the field null. A v1 request always includes `policy_digest`: `null` means the client makes no equality assertion, while a non-null digest must match the server-computed value or acquisition is refused. In either form, the client field is never authority and cannot widen effective policy.

The target design permits automation-policy and signing-key edits only through a future local operator surface. No such authority-file or signing-key command exists in the current CLI, and manual creation of the internal file does not enable a listener or service. MCP, repositories, work orders, controllers, and harnesses may not create, edit, enable, or widen a profile's automation policy. Work-order and repository constraints may only narrow authority.

## Stable profile identity and state isolation

Every profile receives an immutable internal profile UID. The human-readable `claude:name` or `codex:name` reference is a renameable alias. Renaming preserves the UID; removal never permits UID reuse. Leases, policy, audit events, provider-state ownership, principal verification, and concurrency accounting bind to the UID and record the display reference only for diagnosis.

After lease support is enabled, profile rename and removal are refused while
that UID has any active, renewing, unresolved, quarantined, or recovery-required
lease state. This future interlock does not add an automation dependency to the
current standalone profile manager.

Mutable vendor homes are exclusive. Only one active lease may use a mutable home unless the execution backend provisions a distinct writable home for every concurrent lease and proves that vendor-owned state outside that home cannot cross leases. A policy value requesting concurrency does not waive this invariant: when per-lease isolation is unavailable or unproven, acquisition is refused.

Per-lease state paths remain internal. MCP and controller responses expose neither a vendor-home path nor a credential path. A terminal lease cannot make its mutable state available to a later lease until cleanup and identity checks complete; detached or quarantined state is never selected by name or silently reused.

## Lease fencing, renewal, and recovery

Each lease binds its immutable profile UID, authenticated caller, signed work-order digest reference, run, attempt, role, repository/workspace, server-computed policy digest, issue and expiry times, maximum lifetime, and fencing generation.

Renewal is a fenced state transition:

1. The service reauthenticates the controller, re-verifies the original signed authority, recomputes current effective policy, and checks the maximum lifetime.
2. It transactionally persists the renewed expiration and a strictly greater generation before returning renewed authority.
3. An attached harness must acknowledge that exact generation over its authenticated execution channel within the bounded acknowledgement window.
4. Until acknowledgement, the renewal is not reported as usable. A missing, late, or mismatched acknowledgement revokes the lease, fences new access immediately, records the reason, and terminates the harness after the bounded grace period.

Once rotation is persisted, the old generation cannot launch, reconnect, or perform another privileged provider operation. Revocation, expiration, service restart, and recovery apply the same fail-closed generation checks. The current sealed store establishes the atomic journal and refuses readiness when unresolved prior-generation state exists, but it does not yet persist these activation/renewal transitions or reconcile a process. The later service implementation must journal intent before returning success and must reconcile every lease and harness before reporting service readiness.

## Fixed structured harness

The production execution gate accepts an opaque lease handle and a bounded structured request for the operator-configured provider harness. It does not accept a shell command, arbitrary executable path, caller-controlled environment, credential reference, vendor-home path, or unrestricted argument vector. Executable selection, canonical path, digest, provider compatibility, and allowed structured fields come from operator-owned policy.

The harness alone may receive the selected model-provider credential. It speaks the provider protocol and emits structured tool requests to the controller-owned executor. That executor runs requests in a credential-free sandbox that cannot reach ctxlane channels or provider state. Runmill could implement this role in a future optional ASF integration. A direct vendor CLI backend or any backend that allows model-controlled subprocesses to inherit provider credentials is development-only and cannot support the production credential-isolation claim.

## Audit retention and pruning

Lease and authority events are append-only during their retention window and exclude credentials, credential paths, prompts, source content, raw model output, and unrestricted command arguments. Events use a monotonic per-lease sequence and include the immutable profile UID, display reference, authenticated caller, work-order digest reference, run, attempt, role, server-computed policy digest, fencing generation, timestamps, outcome, and stable reason code where applicable.

Phase 0 fixes local audit retention at seven days. Replay records have an
independent minimum lifetime: a service must retain idempotency material until
the signed authorization expires, or longer when local policy defines a longer
replay horizon. The audit cutoff never permits earlier deletion of replay
material. Pruning is a service transaction, not filesystem deletion by age or
name. It must:

- use a recorded UTC cutoff;
- preserve active, renewing, unresolved, quarantined, and recovery-required lease/process records regardless of age;
- delete only eligible terminal history and idempotency material whose signed
  authorization and any longer local replay horizon have expired;
- emit an `audit.pruned` event with the cutoff, counts, time range, service generation, actor, and outcome, without including secrets;
- fail atomically and visibly if the prune event cannot be committed.

Local retention is not tamper-proof archival. Deployments requiring longer evidence or protection from a privileged host operator must export non-secret events to an external protected system before the seven-day cutoff; export design is outside Phase 0.

## Platform contract

| Platform | Phase-0 automation status | Required behavior |
| --- | --- | --- |
| Linux | Sealed connection-origin checkpoint; production target only after all later release gates pass | Require upstream Linux 6.5 or a qualified `SO_PEERPIDFD` backport; retain and revalidate peer UID/GID, pidfd/process, executable path/digest/snapshot, and protected systemd/cgroup binding; keep it verifier-ineligible until a future per-frame `SO_PASSCRED`/`SCM_CREDENTIALS` gate exists; then add durable recovery and native provider qualification |
| macOS | Explicit development-only checkpoint | Require both configured acknowledgement and runtime opt-in, restrict authority scope to exact `local-development`, and always report caller and credential isolation as unqualified |
| Windows and other targets | Authority checkpoint unsupported with zero filesystem access | Refuse authority loading before deriving or reading its path; future automation service, MCP, lease, and execution entry points must also refuse before credentials, harness launch, network activity, or authority-bearing mutation |

This matrix does not remove or downgrade supported interactive CLI and TUI behavior on any platform.

## Implementation and qualification gates

This Phase-0 document is complete when the contracts and threat boundaries are reviewable. It does not make the current binary production-ready. The immutable IDs, pure policy/digest contracts, strict canonical verifier primitive, and sealed authority/attestation checkpoint implement part of the first and third items below without wiring them into authority. Later phases must complete and prove, in dependency order:

1. A supported operator surface for automation policy and trust roots, plus service integration of the existing immutable profile UIDs, canonical signed-work-order verifier, stable refusal codes, and server-computed policy digests.
2. The existing-binary Linux service, complete durable transactional lease/audit transitions, fencing, TTL, renewal acknowledgement, revocation, process recovery, retention, and audited pruning. The current sealed store covers only the initial request/refusal/replay/audit and conservative recovery-gate foundation of this item.
3. An authenticated controller listener with the mandatory Linux per-frame credential gate, execution channels, multiple-controller isolation, inherited-channel STDIO MCP, the bounded tool schema, and the fixed structured fake-provider harness. The current platform adapters provide only sealed connection/development evidence.
4. Controller-neutral end-to-end integration proving that coding-agent and tool sandboxes cannot reach service channels, credentials, vendor homes, or unsupported execution surfaces, plus optional Runmill compatibility coverage.
5. Native Claude and Codex provider identity qualification on protected Linux, including principal/workspace verification and per-lease state isolation.
6. Crash-boundary failure injection, clock rollback, replay, signature tamper, caller spoof, executable replacement, cgroup mismatch, stale-generation, renewal-acknowledgement, concurrency, credential-search, pruning, and recovery tests.
7. External security review, operational runbooks, support evidence, and explicit production-readiness sign-off.

Linux production remains refused until every applicable gate passes. macOS remains development-only after those gates, and Windows and all other unsupported automation targets remain refused.
