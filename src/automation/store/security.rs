use std::{
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{
    Connection, TransactionBehavior,
    config::DbConfig,
    functions::{Context, FunctionFlags},
    hooks::{AuthAction, AuthContext, Authorization},
    params,
};

use crate::{automation::lease::ServiceClockGeneration, config::validate_sensitive_file};

use super::{
    StoreError,
    ids::{COLLISION_RETRIES, SERVICE_PREFIX, random_id},
    records::StoredTimestamp,
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const MAX_SERVICE_GENERATION: u64 = 9_007_199_254_740_991;

pub(super) fn configure_connection(connection: &Connection) -> Result<(), StoreError> {
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    set_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE,
        false,
    )?;
    set_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE,
        false,
    )?;
    set_db_config(
        connection,
        DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        false,
    )?;
    set_db_config(connection, DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    connection
        .pragma_update(None, "fullfsync", true)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    connection
        .pragma_update(None, "checkpoint_fullfsync", true)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    replace_load_extension(connection)?;
    install_authorizer(connection)
}

fn replace_load_extension(connection: &Connection) -> Result<(), StoreError> {
    for arity in [1, 2] {
        connection
            .create_scalar_function(
                "load_extension",
                arity,
                FunctionFlags::SQLITE_UTF8,
                deny_load_extension,
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;
    }
    Ok(())
}

fn deny_load_extension(_: &Context<'_>) -> rusqlite::Result<String> {
    // rusqlite reports a scalar function's text with `sqlite3_result_error`,
    // which normalizes the callback result to SQLITE_ERROR at VDBE step time.
    // The static text is deliberately path- and input-free.
    Err(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_AUTH),
        Some(String::from("ctxlane extension loading disabled")),
    ))
}

fn install_authorizer(connection: &Connection) -> Result<(), StoreError> {
    connection
        .authorizer(Some(|context: AuthContext<'_>| match context.action {
            AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }))
        .map_err(|_| StoreError::DatabaseUnavailable)
}

pub(super) fn enable_wal(connection: &Connection) -> Result<(), StoreError> {
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| StoreError::DatabaseUnavailable)
}

fn set_db_config(
    connection: &Connection,
    setting: DbConfig,
    expected: bool,
) -> Result<(), StoreError> {
    if connection
        .set_db_config(setting, expected)
        .map_err(|_| StoreError::DatabaseUnavailable)?
        != expected
        || connection
            .db_config(setting)
            .map_err(|_| StoreError::DatabaseUnavailable)?
            != expected
    {
        return Err(StoreError::DatabaseUnavailable);
    }
    Ok(())
}

pub(super) fn verify_connection_settings(connection: &Connection) -> Result<(), StoreError> {
    let journal: String = pragma_value(connection, "journal_mode")?;
    let synchronous: i64 = pragma_value(connection, "synchronous")?;
    let foreign_keys: i64 = pragma_value(connection, "foreign_keys")?;
    let trusted_schema: i64 = pragma_value(connection, "trusted_schema")?;
    let fullfsync: i64 = pragma_value(connection, "fullfsync")?;
    let checkpoint_fullfsync: i64 = pragma_value(connection, "checkpoint_fullfsync")?;
    let busy_timeout: i64 = pragma_value(connection, "busy_timeout")?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || fullfsync != 1
        || checkpoint_fullfsync != 1
        || busy_timeout != 5_000
    {
        return Err(StoreError::DatabaseUnavailable);
    }
    Ok(())
}

fn pragma_value<T: rusqlite::types::FromSql>(
    connection: &Connection,
    name: &str,
) -> Result<T, StoreError> {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .map_err(|_| StoreError::DatabaseUnavailable)
}

pub(super) fn verify_integrity(connection: &Connection) -> Result<(), StoreError> {
    let mut quick_rows = 0_u8;
    let mut quick_ok = true;
    connection
        .pragma_query(None, "quick_check", |row| {
            quick_rows = quick_rows.saturating_add(1);
            quick_ok &= row.get::<_, String>(0)?.eq_ignore_ascii_case("ok");
            Ok(())
        })
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if quick_rows != 1 || !quick_ok {
        return Err(StoreError::IntegrityCheckFailed);
    }
    let mut statement = connection
        .prepare("SELECT 1 FROM pragma_foreign_key_check LIMIT 1")
        .map_err(|_| StoreError::IntegrityCheckFailed)?;
    if statement
        .exists([])
        .map_err(|_| StoreError::IntegrityCheckFailed)?
    {
        return Err(StoreError::IntegrityCheckFailed);
    }
    Ok(())
}

pub(super) fn insert_service_generation(
    connection: &mut Connection,
    now: &StoredTimestamp<'_>,
) -> Result<ServiceClockGeneration, StoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    let service_id = allocate_service_id(&transaction)?;
    transaction
        .execute(
            "INSERT INTO service_generations (
                service_instance_id, boot_identity, start_outcome,
                started_at_utc, started_at_seconds, started_at_nanos
             ) VALUES (?1, NULL, 'RECOVERY_INCOMPLETE', ?2, ?3, ?4)",
            params![service_id, now.wire, now.seconds, now.nanos],
        )
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    let raw = transaction.last_insert_rowid();
    let generation = u64::try_from(raw)
        .ok()
        .filter(|value| (1..=MAX_SERVICE_GENERATION).contains(value))
        .ok_or(StoreError::IntegrityCheckFailed)?;
    transaction
        .commit()
        .map_err(|_| StoreError::DatabaseUnavailable)?;
    Ok(ServiceClockGeneration::from_value(generation))
}

fn allocate_service_id(transaction: &rusqlite::Transaction<'_>) -> Result<String, StoreError> {
    for _ in 0..COLLISION_RETRIES {
        let candidate = random_id(SERVICE_PREFIX).map_err(|()| StoreError::EntropyUnavailable)?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM service_generations WHERE service_instance_id = ?1)",
                [&candidate],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::DatabaseUnavailable)?;
        if !exists {
            return Ok(candidate);
        }
    }
    Err(StoreError::IdentifierCollision)
}

pub(super) fn open_private_file(path: &Path) -> Result<(File, bool), StoreError> {
    for _ in 0..2 {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                validate_store_file(path)?;
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .map_err(|_| StoreError::UnsafeStorage)?;
                validate_store_file(path)?;
                return Ok((file, false));
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                {
                    Ok(file) => {
                        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                            .map_err(|_| StoreError::UnsafeStorage)?;
                        file.sync_all().map_err(|_| StoreError::UnsafeStorage)?;
                        if let Some(parent) = path.parent() {
                            sync_directory(parent)?;
                        }
                        validate_store_file(path)?;
                        return Ok((file, true));
                    }
                    Err(source) if source.kind() == ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(StoreError::UnsafeStorage),
                }
            }
            Err(_) => return Err(StoreError::UnsafeStorage),
        }
    }
    Err(StoreError::UnsafeStorage)
}

pub(super) fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StoreError::UnsafeStorage)
}

pub(super) fn validate_existing_sidecars(database_path: &Path) -> Result<(), StoreError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_store_file(&sidecar)?,
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::UnsafeStorage),
        }
    }
    Ok(())
}

pub(super) fn validate_store_file(path: &Path) -> Result<(), StoreError> {
    validate_sensitive_file(path).map_err(|_| StoreError::UnsafeStorage)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::UnsafeStorage)?;
    if metadata.nlink() != 1 {
        return Err(StoreError::UnsafeStorage);
    }
    Ok(())
}
