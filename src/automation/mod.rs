//! Versioned, secret-free contracts for local automation clients.

pub mod contracts;
pub mod lease;
pub mod policy;
// The controller/service integration intentionally does not call this foundation yet.
#[allow(dead_code)]
pub(crate) mod store;
