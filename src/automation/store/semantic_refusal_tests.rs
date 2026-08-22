use std::{fmt::Debug, str::FromStr};

use tempfile::TempDir;

use crate::{
    automation::{
        contracts::{
            CallerSubject, HostIdentity, IdentityLeaseRequest, RefusalCode, RequestedTtlSeconds,
            Sha256Digest, UtcTimestamp,
        },
        lease::{ClockSample, MonotonicMoment},
        store::{
            AuthenticatedRequestControl, PersistedAcquireOutcome, ReadyStore, RecoveringStore,
        },
    },
    config::AppPaths,
    model::InstallationUid,
};

use super::lifecycle_types::NonCapacityRefusal;
use super::test_support::TestAutomationProfile;

struct Fixture {
    _temporary: TempDir,
    paths: AppPaths,
    installation: InstallationUid,
    profile: TestAutomationProfile,
}

impl Fixture {
    fn new() -> Self {
        let temporary = TempDir::new().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let root = temporary
            .path()
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical tempdir: {error}"));
        let paths = AppPaths::for_root(root.join("ctxlane"));
        let profile = TestAutomationProfile::install(&paths);
        Self {
            paths,
            installation: profile.installation.clone(),
            profile,
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

    fn request(&self) -> IdentityLeaseRequest {
        let mut request = request();
        self.profile.bind_request(&mut request);
        request
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

fn policy_refusal(code: RefusalCode) -> NonCapacityRefusal {
    NonCapacityRefusal::from_evaluation(code)
        .unwrap_or_else(|| panic!("capacity denial is activation-owned"))
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
    for (case, refusal) in [
        (0, RefusalCode::WorkOrderAuthorizationMismatch),
        (1, RefusalCode::RequestedTtlNotAllowed),
        (2, RefusalCode::WorkOrderProofInvalid),
        (3, RefusalCode::PolicyDigestMismatch),
    ] {
        let fixture = Fixture::new();
        let mut request = fixture.request();
        match case {
            0 => request.work_order_id = parsed("wo_01ARZ3NDEKTSV4RRFFQ69G5FB0"),
            1 => {
                request.requested_ttl_seconds = RequestedTtlSeconds::from_seconds(901)
                    .unwrap_or_else(|error| panic!("ttl: {error:?}"));
            }
            2 => {
                request.work_order_authorization.not_before = stamp("2026-08-22T11:00:00Z");
            }
            3 => {
                request.policy_digest = Some(parsed::<Sha256Digest>(
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                ));
            }
            _ => unreachable!(),
        }
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

        let authenticated_caller = caller();
        let authenticated_host = host();
        let control = AuthenticatedRequestControl::new(
            begun.outcome().lease_id(),
            begun.row_version(),
            &authenticated_caller,
            &authenticated_host,
        );
        ready
            .refuse_requested(
                &control,
                policy_refusal(refusal),
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
