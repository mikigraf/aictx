CREATE UNIQUE INDEX leases_generation_identity
    ON leases(lease_id, service_generation);

CREATE TABLE lease_runtime_clocks (
    lease_id TEXT NOT NULL,
    service_generation INTEGER NOT NULL,
    monotonic_high_water_nanos BLOB NOT NULL
        CHECK (length(monotonic_high_water_nanos) = 16),
    interval_anchor_at_utc TEXT,
    interval_anchor_at_seconds INTEGER,
    interval_anchor_at_nanos INTEGER CHECK (
        interval_anchor_at_nanos IS NULL OR interval_anchor_at_nanos BETWEEN 0 AND 999999999
    ),
    interval_anchor_monotonic_nanos BLOB CHECK (
        interval_anchor_monotonic_nanos IS NULL OR length(interval_anchor_monotonic_nanos) = 16
    ),
    row_version INTEGER NOT NULL CHECK (row_version > 0),
    PRIMARY KEY (lease_id, service_generation),
    FOREIGN KEY (lease_id, service_generation)
        REFERENCES leases(lease_id, service_generation) ON DELETE CASCADE,
    CHECK (
        (interval_anchor_at_utc IS NULL) = (interval_anchor_at_seconds IS NULL)
        AND (interval_anchor_at_utc IS NULL) = (interval_anchor_at_nanos IS NULL)
        AND (interval_anchor_at_utc IS NULL) = (interval_anchor_monotonic_nanos IS NULL)
    ),
    CHECK (interval_anchor_at_utc IS NULL OR (
        length(interval_anchor_at_utc) BETWEEN 20 AND 30
        AND substr(interval_anchor_at_utc, -1) = 'Z'
    ))
) STRICT, WITHOUT ROWID;

INSERT INTO lease_runtime_clocks (
    lease_id, service_generation, monotonic_high_water_nanos,
    interval_anchor_at_utc, interval_anchor_at_seconds, interval_anchor_at_nanos,
    interval_anchor_monotonic_nanos, row_version
)
SELECT lease_id, service_generation, issued_monotonic_nanos,
       NULL, NULL, NULL, NULL, 1
FROM leases;

CREATE INDEX lease_runtime_clocks_generation
    ON lease_runtime_clocks(service_generation, lease_id);

CREATE TRIGGER leases_runtime_clock_insert
AFTER INSERT ON leases
BEGIN
    INSERT INTO lease_runtime_clocks (
        lease_id, service_generation, monotonic_high_water_nanos,
        interval_anchor_at_utc, interval_anchor_at_seconds, interval_anchor_at_nanos,
        interval_anchor_monotonic_nanos, row_version
    ) VALUES (
        NEW.lease_id, NEW.service_generation, NEW.issued_monotonic_nanos,
        NULL, NULL, NULL, NULL, 1
    );
END;

CREATE TRIGGER leases_runtime_clock_identity_immutable
BEFORE UPDATE OF lease_id, service_generation, issued_monotonic_nanos ON leases
WHEN NEW.lease_id <> OLD.lease_id
    OR NEW.service_generation <> OLD.service_generation
    OR NEW.issued_monotonic_nanos <> OLD.issued_monotonic_nanos
BEGIN
    SELECT RAISE(ABORT, 'immutable lease clock identity');
END;

CREATE TRIGGER lease_runtime_clocks_advance_only
BEFORE UPDATE ON lease_runtime_clocks
WHEN NEW.lease_id <> OLD.lease_id
    OR NEW.service_generation <> OLD.service_generation
    OR NEW.monotonic_high_water_nanos < OLD.monotonic_high_water_nanos
    OR (OLD.interval_anchor_monotonic_nanos IS NOT NULL
        AND NEW.interval_anchor_monotonic_nanos IS NULL)
    OR (OLD.interval_anchor_monotonic_nanos IS NOT NULL
        AND NEW.interval_anchor_monotonic_nanos < OLD.interval_anchor_monotonic_nanos)
    OR (NEW.interval_anchor_monotonic_nanos IS NOT NULL
        AND NEW.interval_anchor_monotonic_nanos > NEW.monotonic_high_water_nanos)
    OR (NEW.interval_anchor_monotonic_nanos IS NOT NULL
        AND NEW.interval_anchor_monotonic_nanos < (
            SELECT issued_monotonic_nanos
            FROM leases
            WHERE lease_id = NEW.lease_id
              AND service_generation = NEW.service_generation
        ))
    OR NEW.row_version <> OLD.row_version + 1
BEGIN
    SELECT RAISE(ABORT, 'invalid monotonic high-water advance');
END;
