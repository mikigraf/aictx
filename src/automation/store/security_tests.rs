use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use rusqlite::Connection;
use tempfile::TempDir;

use crate::{
    automation::{
        contracts::UtcTimestamp,
        store::{RecoveringStore, StoreError},
    },
    config::{AppPaths, ensure_secure_directory},
    model::InstallationUid,
};

struct Fixture {
    temporary: TempDir,
    paths: AppPaths,
    installation: InstallationUid,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temporary
            .path()
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical tempdir: {error}"));
        Self {
            paths: AppPaths::for_root(root.join("ctxlane")),
            installation: InstallationUid::generate()
                .unwrap_or_else(|error| panic!("installation: {error}")),
            temporary,
        }
    }

    fn open(&self) -> Result<RecoveringStore, StoreError> {
        RecoveringStore::open(&self.paths, &self.installation, &stamp())
    }

    fn initialize(&self) {
        let recovering = self
            .open()
            .unwrap_or_else(|error| panic!("initialize open: {error:?}"));
        drop(
            recovering
                .into_ready(&stamp())
                .unwrap_or_else(|error| panic!("initialize ready: {error:?}")),
        );
    }

    fn external(&self, name: &str) -> PathBuf {
        self.temporary.path().join(name)
    }
}

fn stamp() -> UtcTimestamp {
    "2026-08-22T10:00:00Z"
        .parse()
        .unwrap_or_else(|error| panic!("timestamp: {error:?}"))
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("set mode: {error}"));
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|error| panic!("create private file: {error}"));
    file.write_all(bytes)
        .unwrap_or_else(|error| panic!("write private file: {error}"));
    file.sync_all()
        .unwrap_or_else(|error| panic!("sync private file: {error}"));
}

fn sidecar(database: PathBuf, suffix: &str) -> PathBuf {
    let mut value = database.into_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn assert_unsafe(fixture: &Fixture) {
    assert!(matches!(fixture.open(), Err(StoreError::UnsafeStorage)));
}

#[test]
fn unsafe_directory_file_and_sidecar_modes_fail_closed() {
    let directory = Fixture::new();
    let automation = directory.paths.automation_state_dir();
    ensure_secure_directory(
        automation
            .parent()
            .unwrap_or_else(|| panic!("automation path must have a parent")),
    )
    .unwrap_or_else(|error| panic!("state parent: {error}"));
    fs::create_dir(&automation).unwrap_or_else(|error| panic!("automation dir: {error}"));
    set_mode(&automation, 0o755);
    assert_unsafe(&directory);

    for select in ["database", "lock"] {
        let fixture = Fixture::new();
        fixture.initialize();
        let path = if select == "database" {
            fixture.paths.automation_lease_store()
        } else {
            fixture.paths.automation_service_lock()
        };
        set_mode(&path, 0o644);
        assert_unsafe(&fixture);
    }

    let sidecar_fixture = Fixture::new();
    sidecar_fixture.initialize();
    let journal = sidecar(sidecar_fixture.paths.automation_lease_store(), "-journal");
    private_file(&journal, b"hostile journal");
    set_mode(&journal, 0o644);
    assert_unsafe(&sidecar_fixture);
}

#[test]
fn symlinks_and_hard_links_never_mutate_external_targets() {
    let directory = Fixture::new();
    let automation = directory.paths.automation_state_dir();
    ensure_secure_directory(
        automation
            .parent()
            .unwrap_or_else(|| panic!("automation path must have a parent")),
    )
    .unwrap_or_else(|error| panic!("state parent: {error}"));
    let external_directory = directory.external("external-directory");
    ensure_secure_directory(&external_directory)
        .unwrap_or_else(|error| panic!("external directory: {error}"));
    let marker = external_directory.join("marker");
    private_file(&marker, b"directory sentinel");
    symlink(&external_directory, &automation)
        .unwrap_or_else(|error| panic!("directory symlink: {error}"));
    assert_unsafe(&directory);
    assert_eq!(
        fs::read(&marker).unwrap_or_else(|error| panic!("read marker: {error}")),
        b"directory sentinel"
    );

    for link_kind in ["symlink", "hardlink"] {
        for leaf in ["lock", "database", "journal"] {
            let fixture = Fixture::new();
            ensure_secure_directory(&fixture.paths.automation_state_dir())
                .unwrap_or_else(|error| panic!("automation directory: {error}"));
            let external = fixture.external(&format!("{link_kind}-{leaf}"));
            private_file(&external, b"external sentinel");
            let hostile = match leaf {
                "lock" => fixture.paths.automation_service_lock(),
                "database" => fixture.paths.automation_lease_store(),
                _ => sidecar(fixture.paths.automation_lease_store(), "-journal"),
            };
            if link_kind == "symlink" {
                symlink(&external, &hostile)
                    .unwrap_or_else(|error| panic!("file symlink: {error}"));
            } else {
                fs::hard_link(&external, &hostile)
                    .unwrap_or_else(|error| panic!("hard link: {error}"));
            }
            assert_unsafe(&fixture);
            assert_eq!(
                fs::read(&external).unwrap_or_else(|error| panic!("read external target: {error}")),
                b"external sentinel"
            );
        }
    }
}

#[test]
fn corrupt_identity_and_unknown_objects_fail_with_redacted_categories() {
    let corrupt = Fixture::new();
    ensure_secure_directory(&corrupt.paths.automation_state_dir())
        .unwrap_or_else(|error| panic!("automation directory: {error}"));
    private_file(
        &corrupt.paths.automation_lease_store(),
        b"not a sqlite database",
    );
    assert_eq!(corrupt.open().err(), Some(StoreError::DatabaseUnavailable));

    let wrong_application = Fixture::new();
    wrong_application.initialize();
    let connection = Connection::open(wrong_application.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("wrong application raw open: {error}"));
    connection
        .pragma_update(None, "application_id", 1234)
        .unwrap_or_else(|error| panic!("wrong application id: {error}"));
    drop(connection);
    assert_eq!(
        wrong_application.open().err(),
        Some(StoreError::DatabaseIdentityMismatch)
    );

    let lower_version = Fixture::new();
    lower_version.initialize();
    let connection = Connection::open(lower_version.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("lower version raw open: {error}"));
    connection
        .pragma_update(None, "user_version", 0)
        .unwrap_or_else(|error| panic!("lower version: {error}"));
    drop(connection);
    assert_eq!(
        lower_version.open().err(),
        Some(StoreError::DatabaseIdentityMismatch)
    );

    let extra_object = Fixture::new();
    extra_object.initialize();
    let connection = Connection::open(extra_object.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("extra object raw open: {error}"));
    connection
        .execute_batch("CREATE TABLE unexpected_object(value INTEGER) STRICT;")
        .unwrap_or_else(|error| panic!("extra object: {error}"));
    let generations_before: i64 = connection
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("generation count before rejection: {error}"));
    drop(connection);
    assert_eq!(
        extra_object.open().err(),
        Some(StoreError::IntegrityCheckFailed)
    );
    let database = extra_object.paths.automation_lease_store();
    let connection = Connection::open(&database)
        .unwrap_or_else(|error| panic!("inspect rejected database: {error}"));
    let generations_after: i64 = connection
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("generation count after rejection: {error}"));
    assert_eq!(generations_after, generations_before);
    drop(connection);
    for suffix in ["-journal", "-wal", "-shm"] {
        assert!(!sidecar(database.clone(), suffix).exists());
    }

    let extra_view = Fixture::new();
    extra_view.initialize();
    let database = extra_view.paths.automation_lease_store();
    let connection =
        Connection::open(&database).unwrap_or_else(|error| panic!("extra view raw open: {error}"));
    connection
        .execute_batch("CREATE VIEW unexpected_view AS SELECT singleton FROM store_metadata;")
        .unwrap_or_else(|error| panic!("extra view: {error}"));
    let generations_before: i64 = connection
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("view generation count before: {error}"));
    drop(connection);
    assert_eq!(
        extra_view.open().err(),
        Some(StoreError::IntegrityCheckFailed)
    );
    let connection = Connection::open(&database)
        .unwrap_or_else(|error| panic!("inspect rejected view database: {error}"));
    let generations_after: i64 = connection
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("view generation count after: {error}"));
    assert_eq!(generations_after, generations_before);

    let altered_object = Fixture::new();
    altered_object.initialize();
    let database = altered_object.paths.automation_lease_store();
    let connection = Connection::open(&database)
        .unwrap_or_else(|error| panic!("altered object raw open: {error}"));
    connection
        .execute_batch(
            "DROP INDEX leases_recovery;
             CREATE INDEX leases_recovery ON leases(status);",
        )
        .unwrap_or_else(|error| panic!("alter expected object: {error}"));
    let generations_before: i64 = connection
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("altered generation count before: {error}"));
    drop(connection);
    assert_eq!(
        altered_object.open().err(),
        Some(StoreError::IntegrityCheckFailed)
    );
    let connection = Connection::open(&database)
        .unwrap_or_else(|error| panic!("inspect altered database: {error}"));
    let generations_after: i64 = connection
        .query_row("SELECT count(*) FROM service_generations", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("altered generation count after: {error}"));
    assert_eq!(generations_after, generations_before);
}

#[test]
fn check_and_foreign_key_corruption_are_detected_on_reopen() {
    let check = Fixture::new();
    check.initialize();
    let connection = Connection::open(check.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("check raw open: {error}"));
    connection
        .execute_batch(
            "PRAGMA ignore_check_constraints=ON;
             UPDATE store_metadata SET created_at_nanos = -1;",
        )
        .unwrap_or_else(|error| panic!("inject check corruption: {error}"));
    drop(connection);
    assert_eq!(check.open().err(), Some(StoreError::IntegrityCheckFailed));

    let foreign_key = Fixture::new();
    foreign_key.initialize();
    let connection = Connection::open(foreign_key.paths.automation_lease_store())
        .unwrap_or_else(|error| panic!("foreign key raw open: {error}"));
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap_or_else(|error| panic!("disable foreign keys for corruption injection: {error}"));
    connection
        .execute(
            "INSERT INTO audit_events (
                audit_event_id, lease_id, sequence, service_generation, event_type,
                outcome, event_at_utc, event_at_seconds, event_at_nanos, actor
             ) VALUES (
                'audit_00000000000000000000000000', NULL, NULL, 999,
                'caller.authentication-failed', 'failed',
                '2026-08-22T10:00:00Z', 1787392800, 0, 'service'
             )",
            [],
        )
        .unwrap_or_else(|error| panic!("inject foreign key orphan: {error}"));
    drop(connection);
    assert_eq!(
        foreign_key.open().err(),
        Some(StoreError::IntegrityCheckFailed)
    );
}

#[test]
fn installation_mismatch_does_not_change_database_or_leave_sidecars() {
    let fixture = Fixture::new();
    fixture.initialize();
    let database = fixture.paths.automation_lease_store();
    let before = fs::read(&database).unwrap_or_else(|error| panic!("read before: {error}"));
    let other = InstallationUid::generate().unwrap_or_else(|error| panic!("other uid: {error}"));
    assert!(matches!(
        RecoveringStore::open(&fixture.paths, &other, &stamp()),
        Err(StoreError::InstallationMismatch)
    ));
    assert_eq!(
        fs::read(&database).unwrap_or_else(|error| panic!("read after: {error}")),
        before
    );
    for suffix in ["-journal", "-wal", "-shm"] {
        assert!(!sidecar(database.clone(), suffix).exists());
    }
}
