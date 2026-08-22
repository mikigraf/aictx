use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{automation::contracts::Sha256Digest, model::InstallationUid};

use super::{
    StoreError,
    ids::{STORE_PREFIX, random_id},
    records::StoredTimestamp,
};

pub(super) const APPLICATION_ID: i32 = 0x4354_584c;
pub(super) const SCHEMA_VERSION: i32 = 1;
pub(super) const MIGRATION_V1_CHECKSUM: &str =
    "sha256:35180e832ffe3110fd4e52b5842828afdaeac4f1947909a8a36bd2f41e4ddba2";
const MIGRATION_V1_NAME: &str = "lease-store-v1";
const SCHEMA_V1: &str = include_str!("schema_v1.sql");

pub(super) fn migrate_and_bind(
    connection: &mut Connection,
    installation_uid: &InstallationUid,
    now: &StoredTimestamp<'_>,
) -> Result<(), StoreError> {
    verify_embedded_checksum()?;
    let application_id = pragma_i32(connection, "application_id")?;
    let user_version = pragma_i32(connection, "user_version")?;

    if application_id == 0 && user_version == 0 {
        if !pristine_v0(connection, application_id, user_version)? {
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
        if user_version != SCHEMA_VERSION {
            return Err(StoreError::DatabaseIdentityMismatch);
        }
    }

    verify_existing(connection, installation_uid)
}

fn pristine_v0(
    connection: &Connection,
    application_id: i32,
    user_version: i32,
) -> Result<bool, StoreError> {
    if application_id != 0 || user_version != 0 {
        return Ok(false);
    }
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
    transaction
        .execute(
            "INSERT INTO schema_migrations (
                version, name, checksum, applied_at_utc, applied_at_seconds, applied_at_nanos
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                SCHEMA_VERSION,
                MIGRATION_V1_NAME,
                MIGRATION_V1_CHECKSUM,
                now.wire,
                now.seconds,
                now.nanos
            ],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    if pragma_i32(&transaction, "application_id")? != APPLICATION_ID
        || pragma_i32(&transaction, "user_version")? != SCHEMA_VERSION
    {
        return Err(StoreError::DatabaseIdentityMismatch);
    }
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)
}

fn verify_existing(
    connection: &Connection,
    installation_uid: &InstallationUid,
) -> Result<(), StoreError> {
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
    let migration = connection
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = ?1 AND name = ?2",
            params![SCHEMA_VERSION, MIGRATION_V1_NAME],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| StoreError::IntegrityCheckFailed)?
        .ok_or(StoreError::MigrationChecksumMismatch)?;
    if migration != MIGRATION_V1_CHECKSUM {
        return Err(StoreError::MigrationChecksumMismatch);
    }
    let migration_count: i64 = connection
        .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if migration_count != i64::from(SCHEMA_VERSION) {
        return Err(StoreError::MigrationChecksumMismatch);
    }
    verify_object_allowlist(connection)?;
    Ok(())
}

fn verify_object_allowlist(connection: &Connection) -> Result<(), StoreError> {
    let reference = Connection::open_in_memory().map_err(|_| StoreError::IntegrityCheckFailed)?;
    reference
        .execute_batch(SCHEMA_V1)
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    let expected = schema_objects(&reference)?;
    let actual = schema_objects(connection)?;
    if actual == expected {
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

fn verify_embedded_checksum() -> Result<(), StoreError> {
    let actual = Sha256Digest::hash(SCHEMA_V1.as_bytes()).to_string();
    if actual == MIGRATION_V1_CHECKSUM {
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
