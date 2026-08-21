# Automation schemas

These JSON Schema 2020-12 documents define the versioned, non-secret public
contracts for the optional ctxlane automation identity plane:

- `ctxlane.work-order-authorization/v1`
- `ctxlane.identity-lease-request/v1`
- `ctxlane.identity-lease/v1`
- `ctxlane.automation-readiness/v1`
- `ctxlane.automation-error/v1`

The contracts are controller-neutral. Runmill, ASF, or another trusted
controller may integrate with them, but none is a dependency of standalone
ctxlane. Existing CLI and TUI use does not require the automation service.

All published v1 objects reject unknown fields and duplicate member names. A
duplicate member is a pre-attribution `invalid-request`; implementations never
choose a first or last value. A server refuses an unknown schema version
instead of guessing how to interpret it. A new field, changed required set,
changed enum meaning, or changed canonicalization uses a new schema identifier;
authority-bearing changes require a new major schema.

## Examples and validation

[`examples/`](examples/) contains complete valid examples for the signed
authorization, lease request, active and refused leases, ready and not-ready
results, the explicit development-exception path, and an automation error.
[`work-order-signing-vector.v1.json`](examples/work-order-signing-vector.v1.json)
contains a public test key, exact canonical message, payload digest, signature,
and canonical request digest. It contains no private key.

From the repository root, validate the schemas, examples, negative invariants,
and signing vector with:

```bash
python3 -m pip install --only-binary=:all: --require-hashes \
  --requirement schemas/tests/requirements.txt
python3 schemas/tests/validate_contracts.py
```

The validator dependencies are exactly pinned. Validation fails if Ed25519
verification is unavailable; CI must not skip the signing-vector check.
For these contracts, `format: date-time` is normative rather than annotation
only. Conforming decoders must assert RFC 3339 calendar validity in addition to
the canonical UTC shape and relational timestamp checks documented below.
Generic annotation-only validation is insufficient; the repository gate
registers its own mandatory calendar checker so validation does not depend on
optional `jsonschema` packages.

## Canonical request digest

The idempotency and authority digest is:

```text
sha256:<lowercase hex SHA-256 of the canonical request JSON bytes>
```

Canonical request JSON follows RFC 8785 (JCS). Numeric fields are schema
integers: a decoder accepts any finite JSON number that is mathematically
integral and within the field bound (`900`, `900.0`, and `9e2` are equivalent),
decodes it exactly without binary floating-point rounding, and serializes the
typed value as an integer token before JCS. Non-integral numbers are invalid.
The digest covers every request field, including `schema`,
`client_request_id`, and `work_order_authorization`. An identical request
therefore has one digest; changing any field changes the digest and makes reuse
of the idempotency key a conflict.

The parsed top-level `client_request_id` is a service-global replay key. The
service strictly decodes and authenticates the transport, then performs the
lookup under the global idempotency lock before semantic evaluation. A first
request durably records its canonical request digest and authenticated
caller/host/authority binding. An exact retry returns the same lease result only
when all of those values match. A changed request or reuse by another caller or
host returns the pre-lease `idempotency-conflict` error with `lease_id: null` and
does not reveal whether a lease exists.

The signed authorization also contains `client_request_id`, and the two values
must match as an authority gate. A fresh top-level ID paired with an envelope
that signs another ID can create a durable
`work-order-authorization-mismatch` refusal, but it cannot create more
authority. The replay record remains until the signed authorization expires, or
longer when local policy sets a longer replay horizon. The seven-day audit
retention period does not shorten this minimum.

`policy_digest` is required on the wire and may be either a digest or `null`.
A non-null value is an equality expectation supplied by the trusted controller;
it never grants policy, and a mismatch is refused. `null` means the client has
no equality precondition, which supports a standalone first acquisition.
ctxlane computes and enforces the effective digest during evaluation. A
successfully resolved lease persists and returns it. `REQUESTED` and `REFUSED`
responses keep `effective_policy_digest` null; a refusal evaluation may compute
the digest internally but does not publish pre-activation policy attribution.
The canonical request digest includes the explicit null or digest value.

## Work-order authorization

P0 accepts only Ed25519 detached signatures from operator-configured public
keys. The signed bytes are the concatenation of:

```text
UTF8("ctxlane.work-order-authorization/v1")
0x00
RFC8785_JCS(work_order_authorization without its signature field)
```

`signature` is the unpadded base64url encoding of a 64-byte Ed25519 signature.
The envelope binds the client request ID, tenant, and work order to the run,
attempt, role, provider, immutable profile UID and display alias, repository,
workspace, environment, validity interval, and maximum TTL/session authority.
Every duplicated top-level request field must match the signed value exactly.

Semantic validation additionally requires `not_before < expires_at`,
`maximum_ttl_seconds <= maximum_session_seconds`, and the authorized maximum
session not to outlive the signed interval. One renewable TTL interval is
capped at 86,400 seconds. Longer work uses fenced renewal while remaining
inside both the signed interval and `maximum_session_seconds`. Acquisition
also requires `issued_at + requested_ttl_seconds <= expires_at`. The service
sets `maximum_expires_at` to the earlier of the signed `expires_at` value and
`issued_at + maximum_session_seconds`; renewal and launch never extend beyond
that bound.

## Normalized references

Lease attribution never copies raw provider or backend output. The service
maps verified values to typed, operator/transport-normalized opaque labels:

| Field | Wire shape |
| --- | --- |
| `caller_subject` | `caller:<opaque-label>` |
| `host_identity` | `host:<opaque-label>` |
| `worker_identity` | `worker:<opaque-label>` or `null` |
| `principal_ref` | `user:<opaque-label>`, `service-account:<opaque-label>`, or `null` |
| `workspace_ref` | `claude-organization:<opaque-label>`, `chatgpt-workspace:<opaque-label>`, or `null` |

An opaque label is 1-128 ASCII alphanumeric, dot, underscore, or hyphen
characters and begins with an alphanumeric character. Paths, backslashes,
embedded colons, `@`, and `+` are not accepted. Claude leases use a Claude
organization reference; Codex leases use a managed ChatGPT workspace reference.

`REQUESTED` and `REFUSED` leases carry the profile UID and alias claimed by the
structurally decoded request/envelope for attribution, but keep `principal_ref`,
`workspace_ref`, `worker_identity`, `auth_mode`, and `isolation` null. A refusal
does not assert that those workload claims were cryptographically verified.
Caller and host identity come from the authenticated transport; pre-activation
workload fields remain request claims. These responses never claim that runtime
identity or isolation was resolved before activation.

Every resolved lease status, including terminal attribution, requires
`issued_at < expires_at <= maximum_expires_at`. `REQUESTED` and `REFUSED`
leases keep both expiry fields null.

## Authentication modes

The provider/authentication matrix is closed in v1:

| Provider | Allowed resolved modes |
| --- | --- |
| Claude | `wif`, `subscription-token`, `api-key` |
| Codex | `wif`, `chatgpt-oauth`, `api-key`, `access-token` |

WIF is the normal unattended path. A non-WIF mode needs no authentication
exception in `local-development`. Outside local development, it can be ready
only under a dedicated, operator-owned authentication exception. This decision
is independent of credential-isolation evidence.

## Isolation classifications

| Value | Meaning |
| --- | --- |
| `credential-isolated` | Provider credentials remain inside the trusted harness and are proven absent from model-controlled tool execution. Mutable vendor state is exclusive while the lease is active. |
| `per-lease-isolated` | The credential boundary above is proven and every concurrent lease has independently isolated writable vendor state. |
| `copied-credential-development` | A credential is copied into a direct vendor backend. It is eligible only for an explicitly acknowledged local-development or PR-review exception. |
| `unproven` | The backend has not proved the credential/state boundary. It is never ready. |

Operator policy cannot upgrade a measured classification. Authentication and
isolation exceptions are reported separately:

- `authentication_exception_acknowledged` applies only to a dedicated non-WIF
  authentication policy exception outside `local-development`; it is false for
  WIF and local development.
- `isolation_exception_acknowledged` applies only to
  `copied-credential-development`; it is always false for proven or unproven
  isolation.

`copied-credential-development` can be `ready: true` only when its isolation
exception is acknowledged and either `environment` is exactly
`local-development` or `role` is exactly `pr-reviewer`. It cannot make a
production implementer or local reviewer ready.

## Readiness checks

Every readiness response contains exactly eight checks. Each check contains
only `status` and a required nullable `reason_code`; there is no free-form
backend text field.

| Check | Passing or non-passing result |
| --- | --- |
| `metadata-valid` | `pass`, or `fail` with `metadata-invalid` / `unsupported-platform` |
| `credential-source-available` | `pass`, or `fail` with `credential-source-unavailable` |
| `identity-token-current` | WIF: `pass` or `fail` with `identity-token-stale`; non-WIF: `not-applicable` with `not-applicable` |
| `harness-trusted` | `pass`, or `fail` with `harness-untrusted` / `unsupported-platform` |
| `provider-principal-verified` | `pass`; `unknown` with `principal-unverified` / `probe-not-run`; or `fail` with `principal-mismatch` / `probe-failed` |
| `expected-tenant-verified` | `pass`; `unknown` with `expected-tenant-unverified` / `probe-not-run`; or `fail` with `organization-mismatch`, `workspace-mismatch`, or `probe-failed` |
| `automation-policy-permits` | `pass`; `fail` with `automation-policy-denied` / `authentication-exception-required`; or `warn` with `authentication-exception-acknowledged` |
| `credential-isolation-proven` | `pass`; `fail` with `isolation-exception-required` / `isolation-unproven`; or `warn` with `isolation-exception-acknowledged` |

A `pass` always has `reason_code: null`. `not-applicable` exists only for the
non-WIF identity-token check and carries the exact `not-applicable` reason.
Warnings exist only for an explicit acknowledged exception.

`ready: true` requires the five unconditional checks to pass, plus:

- WIF: authentication exception is false and identity-token and policy pass;
- non-WIF local development: authentication exception is false, identity-token
  is not applicable, and policy passes;
- non-WIF elsewhere: authentication exception is true, identity-token is not
  applicable, and the authentication-exception warning is present;
- proven isolation: the isolation check passes; or
- copied development isolation: the narrowly scoped isolation-exception
  warning is present.

`ready: false` must not contain a ready-eligible combination. `unproven` is
never ready. The policy check is scoped to static profile eligibility and the
requested role/environment represented in this response. Authenticated caller,
signed repository/workspace, TTL, and atomic capacity are intersected later by
resolve/acquire and are not claimed by this readiness object.

`checked_at` is the oldest observation contributing to the result.
`valid_until` is the server-derived minimum freshness horizon and must be later
than `checked_at`. Clients treat `now >= valid_until` as stale. Readiness is
evidence, never execution authority; acquire and launch revalidate all gates.

All probes are non-interactive (`probe_interactive` is always false) and have a
hard configured bound of 1-30,000 milliseconds. `probe_timeout_milliseconds`
is the bound, not elapsed time. Cost labels mean:

| `probe_cost` | Meaning |
| --- | --- |
| `none` | No provider request was dispatched. |
| `provider-request-possible` | The bounded path may dispatch a provider request and clients must assume it could incur cost. |
| `provider-request-incurred` | A provider request was dispatched and must be treated as cost-incurring. |

## Refusal and error codes

A refusal code describes a terminal `REFUSED` lease after strict parsing,
controller authentication/authorization, and durable request attribution.
Provider work has not started. Failures before truthful lease/caller
attribution use `ctxlane.automation-error/v1` and create no lease.
The Rust request decoder therefore separates structural decoding from semantic
authorization evaluation: a schema-valid signed-field mismatch, invalid signed
limit, or disallowed TTL remains fingerprintable and can receive its stable
refusal, while malformed grammar, an unsupported schema, or a provider/profile
shape violation fails structural decoding.

| Refusal code | Meaning |
| --- | --- |
| `work-order-proof-invalid` | A structurally valid Ed25519 proof fails configured-key, signature, or signed-validity verification. Unsupported algorithms and malformed encodings are pre-attribution automation errors. |
| `work-order-authorization-mismatch` | A top-level selection differs from the signed authorization. |
| `requested-ttl-not-allowed` | Requested TTL exceeds the signed maximum, remaining signed interval, or effective local policy. |
| `policy-digest-mismatch` | Client expectation differs from server-computed effective policy. |
| `profile-not-found` | The immutable UID and alias do not resolve to the same profile. |
| `provider-mismatch` | Provider conflicts with the profile or signed authorization. |
| `profile-not-eligible` | Profile is not enabled for automation. |
| `authentication-exception-required` | The non-WIF mode lacks its dedicated operator exception. |
| `isolation-exception-required` | A copied-credential backend lacks its narrowly scoped operator exception. |
| `environment-not-allowed` | Effective policy excludes the environment. |
| `role-not-allowed` | Effective policy excludes the role. |
| `caller-not-allowed` | Effective policy excludes the authenticated caller. |
| `repository-not-allowed` | Effective policy excludes the signed repository identity. |
| `profile-not-ready` | One or more required readiness gates did not pass. |
| `identity-token-stale` | Runtime-managed workload token is missing or stale. |
| `harness-untrusted` | Fixed harness or deployment identity failed trust validation. |
| `principal-unverified` | Provider principal could not be verified. |
| `principal-mismatch` | Verified principal differs from operator policy. |
| `organization-mismatch` | Verified Claude organization differs from policy. |
| `workspace-mismatch` | Verified managed ChatGPT workspace differs from policy. |
| `isolation-unproven` | Backend does not meet the required isolation classification. |
| `capacity-exceeded` | An atomic profile/provider/caller/host limit would be exceeded. |

The error schema uses stable `operation` and `code` values only. It deliberately
contains no free-form `message` and no potentially contradictory `retryable`
hint. Client behavior is derived from the operation, code, and observed state.
The schema enforces these boundaries:

| Operation group | Non-common errors |
| --- | --- |
| `profile-list`, `service-health` | None |
| `profile-readiness` | Profile not found or provider mismatch |
| `profile-resolve` | Profile, provider, eligibility, exception, role/environment/caller/repository, readiness, identity, harness, principal, tenant, or isolation denial |
| `lease-acquire` | Idempotency conflict only; authenticated policy/readiness/capacity denials are durable `REFUSED` leases |
| `lease-inspect` | Lease not found |
| `lease-renew` | Lease state/binding/generation/session-limit errors |
| `lease-revoke` | Lease not found or not active |
| `lease-close` | Lease state/binding/generation errors |
| `execution-start` | Lease state/binding/generation/session-limit plus runtime readiness/identity/isolation errors |

Common errors may occur on any operation:

| Common code | Meaning |
| --- | --- |
| `invalid-request` | Malformed JSON; a duplicate member; an invalid type or grammar; an unsupported algorithm or malformed proof encoding; or a structural provider/profile violation. |
| `unsupported-schema` | The request has an identifiable but unsupported schema ID or version. |
| `caller-unauthenticated` | Transport identity is absent or cannot be verified. |
| `caller-unauthorized` | An authenticated subject lacks permission for the operation or channel. |
| `rate-limited` | A pre-attribution service or caller rate gate refuses work. |
| `service-recovering` | Durable reconciliation has not completed, so authority cannot be evaluated safely. |
| `unsupported-platform` | The automation operation is unavailable under the platform contract. |
| `store-unavailable` | A required durable read or write cannot be guaranteed. |
| `internal-error` | An unexpected code-only failure closes the operation fail-safe. |

Every common error creates no lease and has `lease_id: null`. Common, profile,
service, and acquire errors have `lease_id: null`; a non-common lease or
execution error carries the syntactically valid lease ID it concerns.
Work-order, policy-digest, profile-policy, readiness, isolation, and capacity
denials during acquire are refusal codes, not automation errors.

## Lifecycle reason codes

`CLOSED` uses `completed` or `worker-failed`. `EXPIRED` uses `lease-expired` or
`maximum-lifetime-reached`. `REVOKED` uses `operator-revoked`, `policy-revoked`,
`principal-mismatch`, `heartbeat-lost`, `process-unverifiable`,
`generation-superseded`, `renewal-acknowledgement-failed`, or
`service-recovery`. Transitional `ERROR` uses `process-unverifiable`,
`service-recovery`, or `internal-error` and must recover to `REVOKED` or
`EXPIRED`; it is not terminal. A refusal code and a lifecycle reason never
appear together.

## Secret boundary

These schemas intentionally have no bearer token, identity-token content,
credential-file path, vendor-home path, keyring reference, reconstructed
environment, free-form backend message/detail, prompt, source code, tool input,
or model output field. Opaque lease and execution IDs are routing references,
not credentials.
