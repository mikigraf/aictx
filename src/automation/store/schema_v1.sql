CREATE TABLE store_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    store_id TEXT NOT NULL UNIQUE CHECK (
        length(store_id) = 32 AND substr(store_id, 1, 6) = 'store_'
        AND substr(store_id, 7, 1) BETWEEN '0' AND '7'
        AND substr(store_id, 7) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    installation_uid TEXT NOT NULL CHECK (
        length(installation_uid) = 39
        AND substr(installation_uid, 1, 13) = 'installation_'
        AND substr(installation_uid, 14, 1) BETWEEN '0' AND '7'
        AND substr(installation_uid, 14) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    created_at_utc TEXT NOT NULL
        CHECK (length(created_at_utc) BETWEEN 20 AND 30 AND substr(created_at_utc, -1) = 'Z'),
    created_at_seconds INTEGER NOT NULL,
    created_at_nanos INTEGER NOT NULL CHECK (created_at_nanos BETWEEN 0 AND 999999999)
) STRICT;

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
    checksum TEXT NOT NULL UNIQUE CHECK (
        length(checksum) = 71 AND substr(checksum, 1, 7) = 'sha256:'
        AND substr(checksum, 8) NOT GLOB '*[^0123456789abcdef]*'
    ),
    applied_at_utc TEXT NOT NULL
        CHECK (length(applied_at_utc) BETWEEN 20 AND 30 AND substr(applied_at_utc, -1) = 'Z'),
    applied_at_seconds INTEGER NOT NULL,
    applied_at_nanos INTEGER NOT NULL CHECK (applied_at_nanos BETWEEN 0 AND 999999999)
) STRICT;

CREATE TABLE service_generations (
    service_generation INTEGER PRIMARY KEY AUTOINCREMENT
        CHECK (service_generation BETWEEN 1 AND 9007199254740991),
    service_instance_id TEXT NOT NULL UNIQUE CHECK (
        length(service_instance_id) = 34 AND substr(service_instance_id, 1, 8) = 'service_'
        AND substr(service_instance_id, 9, 1) BETWEEN '0' AND '7'
        AND substr(service_instance_id, 9) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    boot_identity TEXT CHECK (boot_identity IS NULL OR (
        length(boot_identity) BETWEEN 6 AND 80 AND substr(boot_identity, 1, 5) = 'boot:'
    )),
    start_outcome TEXT NOT NULL CHECK (start_outcome IN ('RECOVERY_INCOMPLETE', 'READY')),
    started_at_utc TEXT NOT NULL
        CHECK (length(started_at_utc) BETWEEN 20 AND 30 AND substr(started_at_utc, -1) = 'Z'),
    started_at_seconds INTEGER NOT NULL,
    started_at_nanos INTEGER NOT NULL CHECK (started_at_nanos BETWEEN 0 AND 999999999),
    recovery_completed_at_utc TEXT,
    recovery_completed_at_seconds INTEGER,
    recovery_completed_at_nanos INTEGER CHECK (
        recovery_completed_at_nanos IS NULL OR recovery_completed_at_nanos BETWEEN 0 AND 999999999
    ),
    stopped_at_utc TEXT,
    stopped_at_seconds INTEGER,
    stopped_at_nanos INTEGER CHECK (stopped_at_nanos IS NULL OR stopped_at_nanos BETWEEN 0 AND 999999999),
    stop_outcome TEXT CHECK (stop_outcome IS NULL OR stop_outcome IN ('CLEAN', 'ERROR')),
    CHECK (
        (recovery_completed_at_utc IS NULL AND recovery_completed_at_seconds IS NULL
            AND recovery_completed_at_nanos IS NULL)
        OR (recovery_completed_at_utc IS NOT NULL
            AND length(recovery_completed_at_utc) BETWEEN 20 AND 30
            AND substr(recovery_completed_at_utc, -1) = 'Z'
            AND recovery_completed_at_seconds IS NOT NULL
            AND recovery_completed_at_nanos IS NOT NULL)
    ),
    CHECK ((stopped_at_utc IS NULL) = (stopped_at_seconds IS NULL)
        AND (stopped_at_utc IS NULL) = (stopped_at_nanos IS NULL)),
    CHECK ((stopped_at_utc IS NULL) = (stop_outcome IS NULL)),
    CHECK ((start_outcome = 'READY') = (recovery_completed_at_utc IS NOT NULL))
) STRICT;

CREATE TABLE lease_requests (
    request_record_id TEXT PRIMARY KEY CHECK (
        length(request_record_id) = 34 AND substr(request_record_id, 1, 8) = 'request_'
        AND substr(request_record_id, 9, 1) BETWEEN '0' AND '7'
        AND substr(request_record_id, 9) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    client_request_id TEXT NOT NULL UNIQUE CHECK (length(client_request_id) BETWEEN 1 AND 128),
    canonical_authority_digest TEXT NOT NULL CHECK (
        length(canonical_authority_digest) = 71
        AND substr(canonical_authority_digest, 1, 7) = 'sha256:'
        AND substr(canonical_authority_digest, 8) NOT GLOB '*[^0123456789abcdef]*'
    ),
    canonical_request BLOB NOT NULL CHECK (length(canonical_request) BETWEEN 2 AND 131072),
    authenticated_caller TEXT NOT NULL CHECK (
        length(authenticated_caller) BETWEEN 8 AND 135
        AND substr(authenticated_caller, 1, 7) = 'caller:'
    ),
    host_identity TEXT NOT NULL CHECK (
        length(host_identity) BETWEEN 6 AND 133 AND substr(host_identity, 1, 5) = 'host:'
    ),
    authorization_expires_at_utc TEXT NOT NULL
        CHECK (length(authorization_expires_at_utc) BETWEEN 20 AND 30
            AND substr(authorization_expires_at_utc, -1) = 'Z'),
    authorization_expires_at_seconds INTEGER NOT NULL,
    authorization_expires_at_nanos INTEGER NOT NULL
        CHECK (authorization_expires_at_nanos BETWEEN 0 AND 999999999),
    replay_retain_until_utc TEXT NOT NULL
        CHECK (length(replay_retain_until_utc) BETWEEN 20 AND 30
            AND substr(replay_retain_until_utc, -1) = 'Z'),
    replay_retain_until_seconds INTEGER NOT NULL,
    replay_retain_until_nanos INTEGER NOT NULL
        CHECK (replay_retain_until_nanos BETWEEN 0 AND 999999999),
    recorded_at_utc TEXT NOT NULL
        CHECK (length(recorded_at_utc) BETWEEN 20 AND 30 AND substr(recorded_at_utc, -1) = 'Z'),
    recorded_at_seconds INTEGER NOT NULL,
    recorded_at_nanos INTEGER NOT NULL CHECK (recorded_at_nanos BETWEEN 0 AND 999999999),
    UNIQUE (request_record_id, authenticated_caller, host_identity),
    CHECK (
        replay_retain_until_seconds > authorization_expires_at_seconds
        OR (replay_retain_until_seconds = authorization_expires_at_seconds
            AND replay_retain_until_nanos >= authorization_expires_at_nanos)
    ),
    CHECK (
        replay_retain_until_seconds > recorded_at_seconds + 604800
        OR (replay_retain_until_seconds = recorded_at_seconds + 604800
            AND replay_retain_until_nanos >= recorded_at_nanos)
    )
) STRICT;

CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY CHECK (
        length(lease_id) = 32 AND substr(lease_id, 1, 6) = 'lease_'
        AND substr(lease_id, 7, 1) BETWEEN '0' AND '7'
        AND substr(lease_id, 7) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    request_record_id TEXT NOT NULL UNIQUE
        REFERENCES lease_requests(request_record_id) ON DELETE RESTRICT,
    service_generation INTEGER NOT NULL
        REFERENCES service_generations(service_generation) ON DELETE RESTRICT,
    row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version > 0),
    next_audit_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_audit_sequence > 0),
    status TEXT NOT NULL CHECK (status IN (
        'REQUESTED', 'ACTIVE', 'RENEWING', 'CLOSED', 'REVOKED', 'EXPIRED', 'REFUSED', 'ERROR'
    )),
    recovery_state TEXT NOT NULL DEFAULT 'NONE'
        CHECK (recovery_state IN ('NONE', 'REQUIRED', 'RECONCILING')),
    quarantined INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0, 1)),
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
    work_order_id TEXT NOT NULL CHECK (length(work_order_id) BETWEEN 1 AND 128),
    work_order_digest TEXT NOT NULL CHECK (
        length(work_order_digest) = 71 AND substr(work_order_digest, 1, 7) = 'sha256:'
        AND substr(work_order_digest, 8) NOT GLOB '*[^0123456789abcdef]*'
    ),
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 128),
    attempt_id TEXT NOT NULL CHECK (length(attempt_id) BETWEEN 1 AND 128),
    role TEXT NOT NULL CHECK (role IN ('implementer', 'local-reviewer', 'pr-reviewer')),
    provider TEXT NOT NULL CHECK (provider IN ('claude', 'codex')),
    profile_uid TEXT NOT NULL CHECK (
        length(profile_uid) = 34 AND substr(profile_uid, 1, 8) = 'profile_'
        AND substr(profile_uid, 9, 1) BETWEEN '0' AND '7'
        AND substr(profile_uid, 9) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    profile_ref TEXT NOT NULL CHECK (length(profile_ref) BETWEEN 3 AND 128),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 3 AND 256),
    workspace_id TEXT NOT NULL CHECK (length(workspace_id) BETWEEN 1 AND 128),
    environment TEXT NOT NULL CHECK (length(environment) BETWEEN 1 AND 128),
    authenticated_caller TEXT NOT NULL CHECK (substr(authenticated_caller, 1, 7) = 'caller:'),
    host_identity TEXT NOT NULL CHECK (substr(host_identity, 1, 5) = 'host:'),
    requested_ttl_seconds INTEGER NOT NULL CHECK (requested_ttl_seconds BETWEEN 1 AND 86400),
    requested_policy_digest TEXT CHECK (
        requested_policy_digest IS NULL OR (length(requested_policy_digest) = 71
            AND substr(requested_policy_digest, 1, 7) = 'sha256:'
            AND substr(requested_policy_digest, 8) NOT GLOB '*[^0123456789abcdef]*')
    ),
    effective_policy_digest TEXT CHECK (
        effective_policy_digest IS NULL OR (length(effective_policy_digest) = 71
            AND substr(effective_policy_digest, 1, 7) = 'sha256:'
            AND substr(effective_policy_digest, 8) NOT GLOB '*[^0123456789abcdef]*')
    ),
    fencing_generation INTEGER CHECK (fencing_generation BETWEEN 1 AND 9007199254740991),
    clock_generation INTEGER REFERENCES service_generations(service_generation) ON DELETE RESTRICT,
    execution_handle TEXT UNIQUE CHECK (execution_handle IS NULL OR (
        length(execution_handle) = 31 AND substr(execution_handle, 1, 5) = 'exec_'
        AND substr(execution_handle, 6, 1) BETWEEN '0' AND '7'
        AND substr(execution_handle, 6) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    )),
    worker_identity TEXT CHECK (worker_identity IS NULL OR substr(worker_identity, 1, 7) = 'worker:'),
    principal_ref TEXT,
    workspace_ref TEXT,
    auth_mode TEXT CHECK (auth_mode IS NULL OR auth_mode IN (
        'wif', 'subscription-token', 'api-key', 'chatgpt-oauth', 'access-token'
    )),
    isolation TEXT CHECK (isolation IS NULL OR isolation IN (
        'credential-isolated', 'per-lease-isolated', 'copied-credential-development'
    )),
    issued_at_utc TEXT NOT NULL CHECK (substr(issued_at_utc, -1) = 'Z'),
    issued_at_seconds INTEGER NOT NULL,
    issued_at_nanos INTEGER NOT NULL CHECK (issued_at_nanos BETWEEN 0 AND 999999999),
    issued_monotonic_nanos BLOB NOT NULL CHECK (length(issued_monotonic_nanos) = 16),
    activated_at_utc TEXT,
    activated_at_seconds INTEGER,
    activated_at_nanos INTEGER CHECK (activated_at_nanos IS NULL OR activated_at_nanos BETWEEN 0 AND 999999999),
    renewed_at_utc TEXT,
    renewed_at_seconds INTEGER,
    renewed_at_nanos INTEGER CHECK (renewed_at_nanos IS NULL OR renewed_at_nanos BETWEEN 0 AND 999999999),
    renewal_acknowledged_at_utc TEXT,
    renewal_acknowledged_at_seconds INTEGER,
    renewal_acknowledged_at_nanos INTEGER CHECK (
        renewal_acknowledged_at_nanos IS NULL OR renewal_acknowledged_at_nanos BETWEEN 0 AND 999999999
    ),
    terminal_at_utc TEXT,
    terminal_at_seconds INTEGER,
    terminal_at_nanos INTEGER CHECK (terminal_at_nanos IS NULL OR terminal_at_nanos BETWEEN 0 AND 999999999),
    expires_at_utc TEXT,
    expires_at_seconds INTEGER,
    expires_at_nanos INTEGER CHECK (expires_at_nanos IS NULL OR expires_at_nanos BETWEEN 0 AND 999999999),
    expires_monotonic_nanos BLOB CHECK (expires_monotonic_nanos IS NULL OR length(expires_monotonic_nanos) = 16),
    maximum_expires_at_utc TEXT,
    maximum_expires_at_seconds INTEGER,
    maximum_expires_at_nanos INTEGER CHECK (
        maximum_expires_at_nanos IS NULL OR maximum_expires_at_nanos BETWEEN 0 AND 999999999
    ),
    maximum_expires_monotonic_nanos BLOB
        CHECK (maximum_expires_monotonic_nanos IS NULL OR length(maximum_expires_monotonic_nanos) = 16),
    renewal_ack_deadline_utc TEXT,
    renewal_ack_deadline_seconds INTEGER,
    renewal_ack_deadline_nanos INTEGER CHECK (
        renewal_ack_deadline_nanos IS NULL OR renewal_ack_deadline_nanos BETWEEN 0 AND 999999999
    ),
    renewal_ack_deadline_monotonic_nanos BLOB CHECK (
        renewal_ack_deadline_monotonic_nanos IS NULL OR length(renewal_ack_deadline_monotonic_nanos) = 16
    ),
    refusal_code TEXT CHECK (refusal_code IS NULL OR refusal_code IN (
        'work-order-proof-invalid', 'work-order-authorization-mismatch', 'requested-ttl-not-allowed',
        'policy-digest-mismatch', 'profile-not-found', 'provider-mismatch', 'profile-not-eligible',
        'authentication-exception-required', 'isolation-exception-required', 'environment-not-allowed',
        'role-not-allowed', 'caller-not-allowed', 'repository-not-allowed', 'profile-not-ready',
        'identity-token-stale', 'harness-untrusted', 'principal-unverified', 'principal-mismatch',
        'organization-mismatch', 'workspace-mismatch', 'isolation-unproven', 'capacity-exceeded'
    )),
    reason_code TEXT CHECK (reason_code IS NULL OR reason_code IN (
        'completed', 'worker-failed', 'operator-revoked', 'policy-revoked', 'principal-mismatch',
        'lease-expired', 'maximum-lifetime-reached', 'heartbeat-lost', 'process-unverifiable',
        'generation-superseded', 'renewal-acknowledgement-failed', 'service-recovery', 'internal-error'
    )),
    CHECK ((activated_at_utc IS NULL) = (activated_at_seconds IS NULL)
        AND (activated_at_utc IS NULL) = (activated_at_nanos IS NULL)),
    CHECK ((renewed_at_utc IS NULL) = (renewed_at_seconds IS NULL)
        AND (renewed_at_utc IS NULL) = (renewed_at_nanos IS NULL)),
    CHECK ((renewal_acknowledged_at_utc IS NULL) = (renewal_acknowledged_at_seconds IS NULL)
        AND (renewal_acknowledged_at_utc IS NULL) = (renewal_acknowledged_at_nanos IS NULL)),
    CHECK ((terminal_at_utc IS NULL) = (terminal_at_seconds IS NULL)
        AND (terminal_at_utc IS NULL) = (terminal_at_nanos IS NULL)),
    CHECK ((expires_at_utc IS NULL) = (expires_at_seconds IS NULL)
        AND (expires_at_utc IS NULL) = (expires_at_nanos IS NULL)),
    CHECK ((maximum_expires_at_utc IS NULL) = (maximum_expires_at_seconds IS NULL)
        AND (maximum_expires_at_utc IS NULL) = (maximum_expires_at_nanos IS NULL)),
    CHECK ((renewal_ack_deadline_utc IS NULL) = (renewal_ack_deadline_seconds IS NULL)
        AND (renewal_ack_deadline_utc IS NULL) = (renewal_ack_deadline_nanos IS NULL)),
    CHECK (
        (status = 'REQUESTED' AND refusal_code IS NULL AND reason_code IS NULL)
        OR (status = 'REFUSED' AND refusal_code IS NOT NULL AND reason_code IS NULL)
        OR (status IN ('ACTIVE', 'RENEWING') AND refusal_code IS NULL AND reason_code IS NULL)
        OR (status = 'CLOSED' AND refusal_code IS NULL
            AND reason_code IN ('completed', 'worker-failed'))
        OR (status = 'REVOKED' AND refusal_code IS NULL AND reason_code IN (
            'operator-revoked', 'policy-revoked', 'principal-mismatch', 'heartbeat-lost',
            'process-unverifiable', 'generation-superseded',
            'renewal-acknowledgement-failed', 'service-recovery'
        ))
        OR (status = 'EXPIRED' AND refusal_code IS NULL
            AND reason_code IN ('lease-expired', 'maximum-lifetime-reached'))
        OR (status = 'ERROR' AND refusal_code IS NULL
            AND reason_code IN ('process-unverifiable', 'service-recovery', 'internal-error'))
    ),
    CHECK (
        status != 'REQUESTED' OR (
            effective_policy_digest IS NULL AND fencing_generation IS NULL
            AND clock_generation IS NULL AND execution_handle IS NULL AND worker_identity IS NULL
            AND principal_ref IS NULL AND workspace_ref IS NULL AND auth_mode IS NULL
            AND isolation IS NULL AND activated_at_utc IS NULL AND expires_at_utc IS NULL
            AND expires_monotonic_nanos IS NULL AND maximum_expires_at_utc IS NULL
            AND maximum_expires_monotonic_nanos IS NULL AND renewal_ack_deadline_utc IS NULL
            AND renewal_ack_deadline_monotonic_nanos IS NULL AND terminal_at_utc IS NULL
        )
    ),
    CHECK (
        status != 'REFUSED' OR (
            effective_policy_digest IS NULL AND fencing_generation IS NULL
            AND clock_generation IS NULL AND execution_handle IS NULL AND worker_identity IS NULL
            AND principal_ref IS NULL AND workspace_ref IS NULL AND auth_mode IS NULL
            AND isolation IS NULL AND activated_at_utc IS NULL AND expires_at_utc IS NULL
            AND expires_monotonic_nanos IS NULL AND maximum_expires_at_utc IS NULL
            AND maximum_expires_monotonic_nanos IS NULL AND renewal_ack_deadline_utc IS NULL
            AND renewal_ack_deadline_monotonic_nanos IS NULL AND terminal_at_utc IS NOT NULL
        )
    ),
    CHECK (
        status IN ('REQUESTED', 'REFUSED') OR (
            effective_policy_digest IS NOT NULL AND fencing_generation IS NOT NULL
            AND clock_generation IS NOT NULL AND principal_ref IS NOT NULL
            AND workspace_ref IS NOT NULL AND auth_mode IS NOT NULL AND isolation IS NOT NULL
            AND activated_at_utc IS NOT NULL AND expires_at_utc IS NOT NULL
            AND expires_monotonic_nanos IS NOT NULL AND maximum_expires_at_utc IS NOT NULL
            AND maximum_expires_monotonic_nanos IS NOT NULL
        )
    ),
    CHECK ((status NOT IN ('REQUESTED', 'REFUSED')) = (execution_handle IS NOT NULL)),
    CHECK ((status = 'RENEWING') = (renewal_ack_deadline_utc IS NOT NULL)),
    CHECK ((status = 'RENEWING') = (renewal_ack_deadline_monotonic_nanos IS NOT NULL)),
    CHECK ((status IN ('CLOSED', 'REVOKED', 'EXPIRED', 'REFUSED')) = (terminal_at_utc IS NOT NULL)),
    CHECK (status IN ('REQUESTED', 'REFUSED') OR (
        expires_at_seconds > issued_at_seconds
        OR (expires_at_seconds = issued_at_seconds AND expires_at_nanos > issued_at_nanos)
    )),
    CHECK (status IN ('REQUESTED', 'REFUSED') OR (
        maximum_expires_at_seconds > expires_at_seconds
        OR (maximum_expires_at_seconds = expires_at_seconds
            AND maximum_expires_at_nanos >= expires_at_nanos)
    )),
    CHECK (substr(profile_ref, 1, length(provider) + 1) = provider || ':'),
    CHECK (auth_mode IS NULL OR (provider = 'claude'
        AND auth_mode IN ('wif', 'subscription-token', 'api-key'))
        OR (provider = 'codex' AND auth_mode IN ('wif', 'chatgpt-oauth', 'api-key', 'access-token'))),
    CHECK (workspace_ref IS NULL OR (provider = 'claude'
        AND substr(workspace_ref, 1, 20) = 'claude-organization:')
        OR (provider = 'codex' AND substr(workspace_ref, 1, 18) = 'chatgpt-workspace:')),
    CHECK (isolation != 'copied-credential-development'
        OR environment = 'local-development' OR role = 'pr-reviewer'),
    CHECK (clock_generation IS NULL OR clock_generation = service_generation),
    CHECK (refusal_code != 'organization-mismatch' OR provider = 'claude'),
    CHECK (refusal_code != 'workspace-mismatch' OR provider = 'codex'),
    UNIQUE (lease_id, execution_handle),
    UNIQUE (
        lease_id, provider, profile_uid, authenticated_caller, host_identity, tenant_id
    ),
    FOREIGN KEY (request_record_id, authenticated_caller, host_identity)
        REFERENCES lease_requests(request_record_id, authenticated_caller, host_identity)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE capacity_reservations (
    reservation_id TEXT PRIMARY KEY CHECK (
        length(reservation_id) = 35 AND substr(reservation_id, 1, 9) = 'capacity_'
        AND substr(reservation_id, 10, 1) BETWEEN '0' AND '7'
        AND substr(reservation_id, 10) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    lease_id TEXT NOT NULL REFERENCES leases(lease_id) ON DELETE RESTRICT,
    provider TEXT NOT NULL CHECK (provider IN ('claude', 'codex')),
    profile_uid TEXT NOT NULL CHECK (length(profile_uid) = 34 AND substr(profile_uid, 1, 8) = 'profile_'),
    authenticated_caller TEXT NOT NULL CHECK (substr(authenticated_caller, 1, 7) = 'caller:'),
    host_identity TEXT NOT NULL CHECK (substr(host_identity, 1, 5) = 'host:'),
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
    capacity_dimension TEXT NOT NULL CHECK (capacity_dimension IN (
        'provider', 'profile', 'caller', 'host'
    )),
    capacity_key TEXT NOT NULL CHECK (length(capacity_key) BETWEEN 1 AND 256),
    capacity_limit INTEGER NOT NULL CHECK (capacity_limit BETWEEN 1 AND 4294967295),
    slot INTEGER NOT NULL CHECK (slot > 0),
    state TEXT NOT NULL CHECK (state IN ('HELD', 'RELEASED', 'QUARANTINED', 'RECOVERY_REQUIRED')),
    reserved_at_utc TEXT NOT NULL CHECK (substr(reserved_at_utc, -1) = 'Z'),
    reserved_at_seconds INTEGER NOT NULL,
    reserved_at_nanos INTEGER NOT NULL CHECK (reserved_at_nanos BETWEEN 0 AND 999999999),
    released_at_utc TEXT,
    released_at_seconds INTEGER,
    released_at_nanos INTEGER CHECK (released_at_nanos IS NULL OR released_at_nanos BETWEEN 0 AND 999999999),
    CHECK ((released_at_utc IS NULL) = (released_at_seconds IS NULL)
        AND (released_at_utc IS NULL) = (released_at_nanos IS NULL)),
    CHECK ((state = 'RELEASED') = (released_at_utc IS NOT NULL)),
    CHECK ((capacity_dimension = 'provider' AND capacity_key = provider)
        OR (capacity_dimension = 'profile' AND capacity_key = profile_uid)
        OR (capacity_dimension = 'caller' AND capacity_key = authenticated_caller)
        OR (capacity_dimension = 'host' AND capacity_key = host_identity)),
    FOREIGN KEY (
        lease_id, provider, profile_uid, authenticated_caller, host_identity, tenant_id
    ) REFERENCES leases (
        lease_id, provider, profile_uid, authenticated_caller, host_identity, tenant_id
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE lease_processes (
    process_id TEXT PRIMARY KEY CHECK (
        length(process_id) = 34 AND substr(process_id, 1, 8) = 'process_'
        AND substr(process_id, 9, 1) BETWEEN '0' AND '7'
        AND substr(process_id, 9) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    lease_id TEXT NOT NULL,
    service_generation INTEGER NOT NULL
        REFERENCES service_generations(service_generation) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN (
        'LAUNCH_INTENT', 'STARTING', 'RUNNING', 'STOPPING', 'EXITED', 'QUARANTINED', 'RECOVERY_REQUIRED'
    )),
    process_id_number INTEGER CHECK (process_id_number IS NULL OR process_id_number > 0),
    process_identity TEXT CHECK (process_identity IS NULL OR length(process_identity) BETWEEN 1 AND 256),
    execution_handle TEXT NOT NULL CHECK (length(execution_handle) = 31
        AND substr(execution_handle, 1, 5) = 'exec_'),
    worker_identity TEXT CHECK (worker_identity IS NULL OR substr(worker_identity, 1, 7) = 'worker:'),
    observed_fencing_generation INTEGER NOT NULL
        CHECK (observed_fencing_generation BETWEEN 1 AND 9007199254740991),
    launch_intent_at_utc TEXT NOT NULL CHECK (substr(launch_intent_at_utc, -1) = 'Z'),
    launch_intent_at_seconds INTEGER NOT NULL,
    launch_intent_at_nanos INTEGER NOT NULL CHECK (launch_intent_at_nanos BETWEEN 0 AND 999999999),
    started_at_utc TEXT,
    started_at_seconds INTEGER,
    started_at_nanos INTEGER CHECK (started_at_nanos IS NULL OR started_at_nanos BETWEEN 0 AND 999999999),
    stop_requested_at_utc TEXT,
    stop_requested_at_seconds INTEGER,
    stop_requested_at_nanos INTEGER CHECK (
        stop_requested_at_nanos IS NULL OR stop_requested_at_nanos BETWEEN 0 AND 999999999
    ),
    ended_at_utc TEXT,
    ended_at_seconds INTEGER,
    ended_at_nanos INTEGER CHECK (ended_at_nanos IS NULL OR ended_at_nanos BETWEEN 0 AND 999999999),
    exit_code INTEGER,
    CHECK ((started_at_utc IS NULL) = (started_at_seconds IS NULL)
        AND (started_at_utc IS NULL) = (started_at_nanos IS NULL)),
    CHECK ((stop_requested_at_utc IS NULL) = (stop_requested_at_seconds IS NULL)
        AND (stop_requested_at_utc IS NULL) = (stop_requested_at_nanos IS NULL)),
    CHECK ((ended_at_utc IS NULL) = (ended_at_seconds IS NULL)
        AND (ended_at_utc IS NULL) = (ended_at_nanos IS NULL)),
    CHECK (state IN ('LAUNCH_INTENT', 'STARTING', 'QUARANTINED', 'RECOVERY_REQUIRED')
        OR started_at_utc IS NOT NULL),
    CHECK ((state = 'EXITED') = (ended_at_utc IS NOT NULL)),
    FOREIGN KEY (lease_id, execution_handle)
        REFERENCES leases(lease_id, execution_handle) ON DELETE RESTRICT
) STRICT;

CREATE TABLE audit_events (
    audit_event_id TEXT PRIMARY KEY CHECK (
        length(audit_event_id) = 32 AND substr(audit_event_id, 1, 6) = 'audit_'
        AND substr(audit_event_id, 7, 1) BETWEEN '0' AND '7'
        AND substr(audit_event_id, 7) NOT GLOB '*[^0123456789ABCDEFGHJKMNPQRSTVWXYZ]*'
    ),
    lease_id TEXT REFERENCES leases(lease_id) ON DELETE RESTRICT,
    sequence INTEGER CHECK (sequence IS NULL OR sequence > 0),
    service_generation INTEGER NOT NULL
        REFERENCES service_generations(service_generation) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'lease.requested', 'lease.refused', 'lease.activated', 'lease.renewing',
        'lease.renewed', 'lease.closed', 'lease.revoked', 'lease.expired', 'lease.error',
        'lease.quarantined', 'lease.recovery-required', 'process.launch-intent',
        'process.started', 'process.exited', 'caller.authentication-failed', 'audit.pruned'
    )),
    outcome TEXT NOT NULL CHECK (outcome IN ('recorded', 'succeeded', 'refused', 'failed')),
    lease_status TEXT CHECK (lease_status IS NULL OR lease_status IN (
        'REQUESTED', 'ACTIVE', 'RENEWING', 'CLOSED', 'REVOKED', 'EXPIRED', 'REFUSED', 'ERROR'
    )),
    recovery_state TEXT CHECK (recovery_state IS NULL OR recovery_state IN ('NONE', 'REQUIRED', 'RECONCILING')),
    quarantined INTEGER CHECK (quarantined IS NULL OR quarantined IN (0, 1)),
    event_at_utc TEXT NOT NULL CHECK (substr(event_at_utc, -1) = 'Z'),
    event_at_seconds INTEGER NOT NULL,
    event_at_nanos INTEGER NOT NULL CHECK (event_at_nanos BETWEEN 0 AND 999999999),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 135),
    client_request_id TEXT,
    tenant_id TEXT,
    work_order_id TEXT,
    work_order_digest TEXT CHECK (work_order_digest IS NULL OR (
        length(work_order_digest) = 71 AND substr(work_order_digest, 1, 7) = 'sha256:'
        AND substr(work_order_digest, 8) NOT GLOB '*[^0123456789abcdef]*'
    )),
    run_id TEXT,
    attempt_id TEXT,
    role TEXT CHECK (role IS NULL OR role IN ('implementer', 'local-reviewer', 'pr-reviewer')),
    provider TEXT CHECK (provider IS NULL OR provider IN ('claude', 'codex')),
    profile_uid TEXT,
    profile_ref TEXT,
    repository_id TEXT,
    workspace_id TEXT,
    environment TEXT,
    authenticated_caller TEXT,
    host_identity TEXT,
    fencing_generation INTEGER CHECK (fencing_generation BETWEEN 1 AND 9007199254740991),
    effective_policy_digest TEXT CHECK (effective_policy_digest IS NULL OR (
        length(effective_policy_digest) = 71 AND substr(effective_policy_digest, 1, 7) = 'sha256:'
        AND substr(effective_policy_digest, 8) NOT GLOB '*[^0123456789abcdef]*'
    )),
    refusal_code TEXT CHECK (refusal_code IS NULL OR refusal_code IN (
        'work-order-proof-invalid', 'work-order-authorization-mismatch', 'requested-ttl-not-allowed',
        'policy-digest-mismatch', 'profile-not-found', 'provider-mismatch', 'profile-not-eligible',
        'authentication-exception-required', 'isolation-exception-required', 'environment-not-allowed',
        'role-not-allowed', 'caller-not-allowed', 'repository-not-allowed', 'profile-not-ready',
        'identity-token-stale', 'harness-untrusted', 'principal-unverified', 'principal-mismatch',
        'organization-mismatch', 'workspace-mismatch', 'isolation-unproven', 'capacity-exceeded'
    )),
    reason_code TEXT CHECK (reason_code IS NULL OR reason_code IN (
        'completed', 'worker-failed', 'operator-revoked', 'policy-revoked', 'principal-mismatch',
        'lease-expired', 'maximum-lifetime-reached', 'heartbeat-lost', 'process-unverifiable',
        'generation-superseded', 'renewal-acknowledgement-failed', 'service-recovery', 'internal-error'
    )),
    prune_cutoff_utc TEXT,
    prune_deleted_requests INTEGER CHECK (prune_deleted_requests IS NULL OR prune_deleted_requests >= 0),
    prune_deleted_leases INTEGER CHECK (prune_deleted_leases IS NULL OR prune_deleted_leases >= 0),
    prune_deleted_reservations INTEGER CHECK (
        prune_deleted_reservations IS NULL OR prune_deleted_reservations >= 0
    ),
    prune_deleted_processes INTEGER CHECK (prune_deleted_processes IS NULL OR prune_deleted_processes >= 0),
    prune_deleted_events INTEGER CHECK (prune_deleted_events IS NULL OR prune_deleted_events >= 0),
    prune_oldest_event_utc TEXT,
    prune_oldest_event_seconds INTEGER,
    prune_oldest_event_nanos INTEGER CHECK (
        prune_oldest_event_nanos IS NULL OR prune_oldest_event_nanos BETWEEN 0 AND 999999999
    ),
    prune_newest_event_utc TEXT,
    prune_newest_event_seconds INTEGER,
    prune_newest_event_nanos INTEGER CHECK (
        prune_newest_event_nanos IS NULL OR prune_newest_event_nanos BETWEEN 0 AND 999999999
    ),
    CHECK (actor = 'service' OR substr(actor, 1, 7) = 'caller:'),
    CHECK ((lease_id IS NULL) = (sequence IS NULL)),
    CHECK (lease_id IS NULL OR (
        lease_status IS NOT NULL AND recovery_state IS NOT NULL AND quarantined IS NOT NULL
        AND client_request_id IS NOT NULL AND tenant_id IS NOT NULL AND work_order_id IS NOT NULL
        AND work_order_digest IS NOT NULL AND run_id IS NOT NULL AND attempt_id IS NOT NULL
        AND role IS NOT NULL AND provider IS NOT NULL AND profile_uid IS NOT NULL
        AND profile_ref IS NOT NULL AND repository_id IS NOT NULL AND workspace_id IS NOT NULL
        AND environment IS NOT NULL AND authenticated_caller IS NOT NULL AND host_identity IS NOT NULL
    )),
    CHECK ((prune_oldest_event_utc IS NULL) = (prune_oldest_event_seconds IS NULL)
        AND (prune_oldest_event_utc IS NULL) = (prune_oldest_event_nanos IS NULL)),
    CHECK ((prune_newest_event_utc IS NULL) = (prune_newest_event_seconds IS NULL)
        AND (prune_newest_event_utc IS NULL) = (prune_newest_event_nanos IS NULL)),
    CHECK ((event_type = 'audit.pruned') = (prune_cutoff_utc IS NOT NULL)),
    CHECK (event_type != 'audit.pruned' OR (
        prune_deleted_requests IS NOT NULL AND prune_deleted_leases IS NOT NULL
        AND prune_deleted_reservations IS NOT NULL AND prune_deleted_processes IS NOT NULL
        AND prune_deleted_events IS NOT NULL
    )),
    UNIQUE (lease_id, sequence)
) STRICT;

CREATE INDEX lease_requests_replay_expiry
    ON lease_requests(replay_retain_until_seconds, replay_retain_until_nanos);
CREATE INDEX leases_recovery ON leases(recovery_state, quarantined, status);
CREATE INDEX leases_profile_status ON leases(profile_uid, status);
CREATE INDEX leases_caller_status ON leases(authenticated_caller, status);
CREATE INDEX leases_host_status ON leases(host_identity, status);
CREATE INDEX capacity_reservations_recovery ON capacity_reservations(state, provider, profile_uid);
CREATE UNIQUE INDEX capacity_reservations_one_live_slot
    ON capacity_reservations(capacity_dimension, capacity_key, slot) WHERE state <> 'RELEASED';
CREATE UNIQUE INDEX capacity_reservations_one_dimension_per_lease
    ON capacity_reservations(lease_id, capacity_dimension) WHERE state <> 'RELEASED';
CREATE INDEX lease_processes_recovery ON lease_processes(state, service_generation);
CREATE UNIQUE INDEX lease_processes_one_live ON lease_processes(lease_id) WHERE state <> 'EXITED';
CREATE INDEX audit_events_time ON audit_events(event_at_seconds, event_at_nanos);
CREATE INDEX audit_events_profile_time
    ON audit_events(profile_uid, event_at_seconds, event_at_nanos);

CREATE TRIGGER lease_requests_immutable
BEFORE UPDATE ON lease_requests
BEGIN
    SELECT RAISE(ABORT, 'immutable lease request');
END;

CREATE TRIGGER audit_events_immutable
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'immutable audit event');
END;
