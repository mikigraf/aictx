use std::{fmt::Debug, str::FromStr};

use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            CallerSubject, HostIdentity, IdentityLeaseRequest, ProfileRef, RefusalCode,
            RequestedTtlSeconds, Sha256Digest, UtcTimestamp,
        },
        lease::{ClockSample, MonotonicMoment},
        store::{PersistedAcquireOutcome, ReadyStore, RecoveringStore},
    },
    config::AppPaths,
    model::InstallationUid,
};

struct Fixture {
    _temporary: TempDir,
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
            _temporary: temporary,
        }
    }

    fn ready(&self) -> ReadyStore {
        RecoveringStore::open(
            &self.paths,
            &self.installation,
            &stamp("2026-08-22T10:00:00Z"),
        )
        .unwrap_or_else(|error| panic!("open: {error:?}"))
        .into_ready(&stamp("2026-08-22T10:00:01Z"))
        .unwrap_or_else(|error| panic!("ready: {error:?}"))
    }
}

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    value
        .parse()
        .unwrap_or_else(|error| panic!("parse {value}: {error:?}"))
}

fn stamp(value: &str) -> UtcTimestamp {
    parsed(value)
}

fn request() -> IdentityLeaseRequest {
    let mut request: IdentityLeaseRequest = serde_json::from_str(include_str!(
        "../../../schemas/examples/identity-lease-request.v1.json"
    ))
    .unwrap_or_else(|error| panic!("request fixture: {error}"));
    request.work_order_authorization.not_before = stamp("2026-08-22T09:00:00Z");
    request.work_order_authorization.expires_at = stamp("2026-08-23T14:00:00Z");
    request
}

fn caller() -> CallerSubject {
    parsed("caller:local-controller")
}

fn host() -> HostIdentity {
    parsed("host:runner-01")
}

fn clock(ready: &ReadyStore, monotonic: u128) -> ClockSample {
    ClockSample::new(
        stamp("2026-08-22T10:00:02Z"),
        MonotonicMoment::from_nanoseconds(monotonic),
        ready.service_clock_generation(),
    )
}

#[test]
fn semantic_failures_remain_durable_requested_and_refused_replay_outcomes() {
    let mut authorization_mismatch = request();
    authorization_mismatch.profile_ref = parsed::<ProfileRef>("codex:different-profile");
    let mut ttl_exceeded = request();
    ttl_exceeded.requested_ttl_seconds =
        RequestedTtlSeconds::from_seconds(901).unwrap_or_else(|error| panic!("ttl: {error:?}"));
    let mut not_yet_valid = request();
    not_yet_valid.work_order_authorization.not_before = stamp("2026-08-22T11:00:00Z");
    let mut policy_mismatch = request();
    policy_mismatch.policy_digest = Some(parsed::<Sha256Digest>(
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ));

    for (request, refusal) in [
        (
            authorization_mismatch,
            RefusalCode::WorkOrderAuthorizationMismatch,
        ),
        (ttl_exceeded, RefusalCode::RequestedTtlNotAllowed),
        (not_yet_valid, RefusalCode::WorkOrderProofInvalid),
        (policy_mismatch, RefusalCode::PolicyDigestMismatch),
    ] {
        let fixture = Fixture::new();
        let mut ready = fixture.ready();
        let begun = ready
            .begin_acquire(&request, &caller(), &host(), &clock(&ready, 10))
            .unwrap_or_else(|error| panic!("begin {refusal:?}: {error:?}"));
        assert!(matches!(
            begun.outcome(),
            PersistedAcquireOutcome::Requested { .. }
        ));
        let requested_replay = ready
            .begin_acquire(&request, &caller(), &host(), &clock(&ready, 11))
            .unwrap_or_else(|error| panic!("requested replay {refusal:?}: {error:?}"));
        assert!(requested_replay.replayed());
        assert_eq!(requested_replay.outcome(), begun.outcome());

        ready
            .refuse_requested(
                begun.outcome().lease_id(),
                refusal,
                &stamp("2026-08-22T10:00:03Z"),
            )
            .unwrap_or_else(|error| panic!("refuse {refusal:?}: {error:?}"));
        let expected = ready
            .begin_acquire(&request, &caller(), &host(), &clock(&ready, 12))
            .unwrap_or_else(|error| panic!("refused replay {refusal:?}: {error:?}"))
            .outcome()
            .clone();
        assert!(matches!(
            expected,
            PersistedAcquireOutcome::Refused {
                refusal_code,
                ..
            } if refusal_code == refusal
        ));
        drop(ready);

        let mut reopened = RecoveringStore::open(
            &fixture.paths,
            &fixture.installation,
            &stamp("2026-08-22T10:01:00Z"),
        )
        .unwrap_or_else(|error| panic!("reopen {refusal:?}: {error:?}"))
        .into_ready(&stamp("2026-08-22T10:01:01Z"))
        .unwrap_or_else(|error| panic!("ready again {refusal:?}: {error:?}"));
        let replay = reopened
            .begin_acquire(&request, &caller(), &host(), &clock(&reopened, 13))
            .unwrap_or_else(|error| panic!("reopen replay {refusal:?}: {error:?}"));
        assert!(replay.replayed());
        assert_eq!(replay.outcome(), &expected);
    }
}
