use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{automation::contracts::Sha256Digest, model::InstallationUid};

use super::{
    StoreError,
    ids::{STORE_PREFIX, random_id},
    records::StoredTimestamp,
};

pub(super) const APPLICATION_ID: i32 = 0x4354_584c;
pub(super) const SCHEMA_VERSION: i32 = 2;
pub(super) const MIGRATION_V1_CHECKSUM: &str =
    "sha256:35180e832ffe3110fd4e52b5842828afdaeac4f1947909a8a36bd2f41e4ddba2";
pub(super) const MIGRATION_V2_CHECKSUM: &str =
    "sha256:fc3f0897b18a4dd1d5d8e9edd0d8b536e5e474c0431da4f6f216972679919e84";
const MIGRATION_V1_NAME: &str = "lease-store-v1";
const MIGRATION_V2_NAME: &str = "lease-store-v2-runtime-clocks";
const SCHEMA_V1: &str = include_str!("schema_v1.sql");
const SCHEMA_V2: &str = include_str!("schema_v2.sql");

pub(super) fn migrate_and_bind(
    connection: &mut Connection,
    installation_uid: &InstallationUid,
    now: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    verify_embedded_checksums()?;
    let application_id = pragma_i32(connection, "application_id")?;
    let user_version = pragma_i32(connection, "user_version")?;

    if application_id == 0 && user_version == 0 {
        if !pristine_v0(connection)? {
            return Err(StoreError::DatabaseIdentityMismatch);
        }
        apply_v1(connection, installation_uid, now)?;
    } else {
        if application_id != APPLICATION_ID {
            return Err(StoreError::DatabaseIdentityMismatch);
        }
        if user_version > SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema);
        }
        if user_version < 1 {
            return Err(StoreError::DatabaseIdentityMismatch);
        }
    }

    let user_version = pragma_i32(connection, "user_version")?;
    if user_version == 1 {
        // A legacy database is fully qualified before the first v2 write. A
        // failed check therefore leaves the frozen v1 installation untouched.
        verify_integrity(connection)?;
        verify_existing_version(connection, installation_uid, 1)?;
        apply_v2(connection, installation_uid, now)?;
    }

    if pragma_i32(connection, "user_version")? != SCHEMA_VERSION {
        return Err(StoreError::DatabaseIdentityMismatch);
    }
    verify_integrity(connection)?;
    verify_existing_version(connection, installation_uid, SCHEMA_VERSION)
}

fn pristine_v0(connection: &Connection) -> Result<bool, StoreError> {
    let objects: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE substr(name, 1, 7) <> 'sqlite_'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    Ok(objects == 0)
}

fn apply_v1(
    connection: &mut Connection,
    installation_uid: &InstallationUid,
    now: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    let store_id = random_id(STORE_PREFIX).map_err(|()| StoreError::EntropyUnavailable)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    transaction
        .execute_batch(SCHEMA_V1)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    transaction
        .execute(
            "INSERT INTO store_metadata (
                singleton, store_id, installation_uid,
                created_at_utc, created_at_seconds, created_at_nanos
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                store_id,
                installation_uid.as_str(),
                now.wire,
                now.seconds,
                now.nanos
            ],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    insert_migration(
        &transaction,
        1,
        MIGRATION_V1_NAME,
        MIGRATION_V1_CHECKSUM,
        now,
    )?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    transaction
        .pragma_update(None, "user_version", 1)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    verify_integrity(&transaction)?;
    verify_existing_version(&transaction, installation_uid, 1)?;
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)
}

fn apply_v2(
    connection: &mut Connection,
    installation_uid: &InstallationUid,
    now: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    transaction
        .execute_batch(SCHEMA_V2)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    insert_migration(
        &transaction,
        2,
        MIGRATION_V2_NAME,
        MIGRATION_V2_CHECKSUM,
        now,
    )?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| StoreError::DatabaseUnavailable)?;

    // Qualification belongs to the migration transaction. Any schema,
    // checksum, integrity, or backfill failure rolls the entire v2 step back.
    verify_integrity(&transaction)?;
    verify_existing_version(&transaction, installation_uid, SCHEMA_VERSION)?;
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)
}

fn insert_migration(
    transaction: &Transaction<'_>,
    version: i32,
    name: &str,
    checksum: &str,
    now: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, checksum, applied_at_utc, applied_at_seconds, applied_at_nanos
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![version, name, checksum, now.wire, now.seconds, now.nanos],
        )
        .map(|_| ())
        .map_err(|_| StoreError::DatabaseUnavailable)
}

fn verify_existing_version(
    connection: &Connection,
    installation_uid: &InstallationUid,
    version: i32,
) -> Result<(), StoreError> {
    if pragma_i32(connection, "application_id")? != APPLICATION_ID
        || pragma_i32(connection, "user_version")? != version
    {
        return Err(StoreError::DatabaseIdentityMismatch);
    }
    let stored_uid = connection
        .query_row(
            "SELECT installation_uid FROM store_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .ok_or(StoreError::IntegrityCheckFailed)?;
    if stored_uid != installation_uid.as_str() {
        return Err(StoreError::InstallationMismatch);
    }
    verify_migrations(connection, version)?;
    verify_object_allowlist(connection, version)?;
    if version == 2 {
        verify_runtime_clock_coverage(connection)?;
    }
    Ok(())
}

fn verify_migrations(connection: &Connection, version: i32) -> Result<(), StoreError> {
    let expected = [
        (1, MIGRATION_V1_NAME, MIGRATION_V1_CHECKSUM),
        (2, MIGRATION_V2_NAME, MIGRATION_V2_CHECKSUM),
    ];
    let mut statement = connection
        .prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version")
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let expected = expected[..usize::try_from(version).unwrap_or(0)]
        .iter()
        .map(|(number, name, checksum)| (*number, (*name).to_owned(), (*checksum).to_owned()))
        .collect::<Vec<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(StoreError::MigrationChecksumMismatch)
    }
}

fn verify_object_allowlist(connection: &Connection, version: i32) -> Result<(), StoreError> {
    let reference = Connection::open_in_memory().map_err(|_| StoreError::IntegrityCheckFailed)?;
    reference
        .execute_batch(SCHEMA_V1)
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if version == 2 {
        reference
            .execute_batch(SCHEMA_V2)
            .map_err(|_| StoreError::IntegrityCheckFailed)?;
    }
    if schema_objects(connection)? == schema_objects(&reference)? {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

fn verify_runtime_clock_coverage(connection: &Connection) -> Result<(), StoreError> {
    let invalid: i64 = connection
        .query_row(
            "SELECT
                (SELECT count(*) FROM leases) <> (SELECT count(*) FROM lease_runtime_clocks)
                OR EXISTS(
                    SELECT 1 FROM leases l
                    LEFT JOIN lease_runtime_clocks c
                      ON c.lease_id = l.lease_id
                     AND c.service_generation = l.service_generation
                    WHERE c.lease_id IS NULL
                       OR c.monotonic_high_water_nanos < l.issued_monotonic_nanos
                       OR (c.interval_anchor_monotonic_nanos IS NOT NULL
                           AND c.monotonic_high_water_nanos < c.interval_anchor_monotonic_nanos)
                       OR (c.interval_anchor_monotonic_nanos IS NOT NULL
                           AND c.interval_anchor_monotonic_nanos < l.issued_monotonic_nanos)
                       OR c.row_version < 1
                       OR (l.status NOT IN ('REQUESTED', 'REFUSED')
                           AND c.interval_anchor_at_utc IS NULL)
                       OR (l.status IN ('REQUESTED', 'REFUSED')
                           AND c.interval_anchor_at_utc IS NOT NULL)
                )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if invalid == 0 {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

fn verify_integrity(connection: &Connection) -> Result<(), StoreError> {
    let mut rows = 0_u8;
    let mut ok = true;
    connection
        .pragma_query(None, "quick_check", |row| {
            rows = rows.saturating_add(1);
            ok &= row.get::<_, String>(0)?.eq_ignore_ascii_case("ok");
            Ok(())
        })
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let foreign_key_failure: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if rows == 1 && ok && !foreign_key_failure {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed)
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct SchemaObject {
    kind: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

fn schema_objects(connection: &Connection) -> Result<BTreeSet<SchemaObject>, StoreError> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema")
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    statement
        .query_map([], |row| {
            Ok(SchemaObject {
                kind: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| StoreError::IntegrityCheckFailed)
}

fn verify_embedded_checksums() -> Result<(), StoreError> {
    let valid = [
        (SCHEMA_V1, MIGRATION_V1_CHECKSUM),
        (SCHEMA_V2, MIGRATION_V2_CHECKSUM),
    ]
    .into_iter()
    .all(|(schema, checksum)| Sha256Digest::hash(schema.as_bytes()).to_string() == checksum);
    if valid {
        Ok(())
    } else {
        Err(StoreError::MigrationChecksumMismatch)
    }
}

fn pragma_i32(connection: &Connection, name: &str) -> Result<i32, StoreError> {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .map_err(|_| StoreError::DatabaseUnavailable)
}
