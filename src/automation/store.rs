//! Opt-in durable storage for the automation lease service.
//!
//! Merely constructing or using ordinary metadata paths does not open this
//! store. The automation directory and database are touched only by
//! [`RecoveringStore::open`].

mod ids;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod load;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod load_parse;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod migrations;
mod records;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod recovery;
mod recovery_types;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod security;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod sqlite;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;

pub(crate) use records::BeginAcquireResult;
// Kept available on unsupported targets so the sealed service seam is source-compatible.
#[allow(unused_imports)]
pub(crate) use records::PersistedAcquireOutcome;
#[allow(unused_imports)]
pub(crate) use recovery_types::{RecoveryCursor, RecoveryPage, RecoveryPageRequest};
use thiserror::Error;

/// Redacted, stable failure categories for the automation store boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum StoreError {
    #[error("automation lease storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("the automation lease service is already running")]
    ServiceBusy,
    #[error("automation storage permissions or ownership are unsafe")]
    UnsafeStorage,
    #[error("the automation lease database is unavailable")]
    DatabaseUnavailable,
    #[error("the automation lease database identity is invalid")]
    DatabaseIdentityMismatch,
    #[error("the automation lease database belongs to another installation")]
    InstallationMismatch,
    #[error("the automation lease database schema is newer than this build")]
    UnsupportedSchema,
    #[error("the automation lease database migration identity is invalid")]
    MigrationChecksumMismatch,
    #[error("the automation lease database failed an integrity check")]
    IntegrityCheckFailed,
    #[error("automation lease recovery is required before serving requests")]
    RecoveryRequired,
    #[error("the automation lease request is invalid")]
    InvalidRequest,
    #[error("the client request ID was already used for different authority")]
    IdempotencyConflict,
    #[error("operating-system randomness is unavailable")]
    EntropyUnavailable,
    #[error("could not allocate a unique automation identifier")]
    IdentifierCollision,
    #[error("the persisted lease cannot make that transition")]
    InvalidTransition,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unused_imports)]
pub(crate) use sqlite::{ReadyStore, RecoveringStore};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(unused_imports)]
pub(crate) use unsupported::{ReadyStore, RecoveringStore};

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod audit_recovery_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod load_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod migration_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod recovery_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod security_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod semantic_refusal_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;
