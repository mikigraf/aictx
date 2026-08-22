//! Versioned, secret-free contracts for local automation clients.

pub mod contracts;
pub mod lease;
pub mod policy;
// These authority boundaries are consumed only by future explicit service entry points.
#[allow(dead_code)]
pub(crate) mod attestation;
#[allow(dead_code)]
pub(crate) mod authority;
// The controller/service integration intentionally does not call this foundation yet.
#[allow(dead_code)]
pub(crate) mod store;
