CREATE INDEX capacity_reservations_lease_state
    ON capacity_reservations(lease_id, state);

CREATE INDEX lease_processes_lease_state
    ON lease_processes(lease_id, state);

CREATE TRIGGER capacity_reservations_insert_held
BEFORE INSERT ON capacity_reservations
WHEN NEW.state <> 'HELD'
    OR NEW.released_at_utc IS NOT NULL
    OR NEW.released_at_seconds IS NOT NULL
    OR NEW.released_at_nanos IS NOT NULL
    OR NEW.slot > NEW.capacity_limit
    OR EXISTS(
        SELECT 1 FROM capacity_reservations
        WHERE lease_id = NEW.lease_id
          AND capacity_dimension = NEW.capacity_dimension
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid new capacity reservation');
END;

CREATE TRIGGER capacity_reservations_transition_only
BEFORE UPDATE ON capacity_reservations
WHEN NEW.reservation_id <> OLD.reservation_id
    OR NEW.lease_id <> OLD.lease_id
    OR NEW.provider <> OLD.provider
    OR NEW.profile_uid <> OLD.profile_uid
    OR NEW.authenticated_caller <> OLD.authenticated_caller
    OR NEW.host_identity <> OLD.host_identity
    OR NEW.tenant_id <> OLD.tenant_id
    OR NEW.capacity_dimension <> OLD.capacity_dimension
    OR NEW.capacity_key <> OLD.capacity_key
    OR NEW.capacity_limit <> OLD.capacity_limit
    OR NEW.slot <> OLD.slot
    OR NEW.reserved_at_utc <> OLD.reserved_at_utc
    OR NEW.reserved_at_seconds <> OLD.reserved_at_seconds
    OR NEW.reserved_at_nanos <> OLD.reserved_at_nanos
    OR NOT (
        (OLD.state = 'HELD'
            AND NEW.state IN ('QUARANTINED', 'RECOVERY_REQUIRED')
            AND NEW.released_at_utc IS NULL
            AND NEW.released_at_seconds IS NULL
            AND NEW.released_at_nanos IS NULL)
        OR (OLD.state = 'RECOVERY_REQUIRED'
            AND NEW.state = 'QUARANTINED'
            AND NEW.released_at_utc IS NULL
            AND NEW.released_at_seconds IS NULL
            AND NEW.released_at_nanos IS NULL)
        OR (OLD.state IN ('HELD', 'QUARANTINED', 'RECOVERY_REQUIRED')
            AND NEW.state = 'RELEASED'
            AND NEW.released_at_utc IS NOT NULL
            AND NEW.released_at_seconds IS NOT NULL
            AND NEW.released_at_nanos IS NOT NULL)
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid capacity reservation transition');
END;

CREATE TRIGGER capacity_reservations_delete_released
BEFORE DELETE ON capacity_reservations
WHEN OLD.state <> 'RELEASED'
BEGIN
    SELECT RAISE(ABORT, 'live capacity reservation cannot be deleted');
END;
