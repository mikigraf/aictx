use core::str::FromStr;

use crate::{
    automation::{
        contracts::{
            CallerSubject, HostIdentity, IdentityLeaseRequest, IsolationClassification,
            LeaseStatus, ProfileRef, ProfileUid, RefusalCode,
        },
        policy::test_support::effective_policy,
        store::AuthenticatedRequestControl,
    },
    config::MetadataStore,
    management::{ProfileDraft, add_profile},
    model::{AutomationConcurrencyMode, CodexAuth, CodexCredentialStore, Name},
};

use super::activation_lifecycle_tests::{Fixture, caller, clock, control, host, resolution};

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: core::fmt::Debug,
{
    value
        .parse()
        .unwrap_or_else(|error| panic!("parse {value}: {error:?}"))
}

fn additional_profile(fixture: &Fixture) -> (ProfileRef, ProfileUid) {
    let store = MetadataStore::new(fixture.paths.clone());
    let receipt = add_profile(
        &store,
        ProfileDraft::Codex {
            name: Name::parse("automation-secondary")
                .unwrap_or_else(|error| panic!("secondary profile name: {error}")),
            auth: CodexAuth::ChatgptOauth,
            secret_ref: None,
            account_hint: None,
            expected_workspace_id: None,
            credential_store: CodexCredentialStore::File,
            trusted_runners_only: false,
            wif: None,
        },
    )
    .unwrap_or_else(|error| panic!("secondary profile: {error}"));
    (
        ProfileRef::from_str(&receipt.id.to_string())
            .unwrap_or_else(|error| panic!("secondary profile ref: {error:?}")),
        receipt.profile_uid,
    )
}

fn bind_profile(request: &mut IdentityLeaseRequest, binding: &(ProfileRef, ProfileUid)) {
    request.profile_ref = binding.0.clone();
    request.profile_uid = binding.1.clone();
    request.work_order_authorization.profile_ref = binding.0.clone();
    request.work_order_authorization.profile_uid = binding.1.clone();
}

fn begin_as(
    store: &mut super::ReadyStore,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    monotonic: u128,
) -> (crate::automation::contracts::LeaseId, u64) {
    let result = store
        .begin_acquire(
            request,
            caller,
            host,
            &clock(store, "2026-08-22T10:00:02Z", monotonic),
        )
        .unwrap_or_else(|error| panic!("capacity begin: {error:?}"));
    (result.outcome().lease_id().clone(), result.row_version())
}

fn activate(
    store: &mut super::ReadyStore,
    request: &IdentityLeaseRequest,
    caller: &CallerSubject,
    host: &HostIdentity,
    limits: [u32; 4],
    suffix: char,
    monotonic: u128,
) -> (
    crate::automation::contracts::LeaseId,
    super::CommittedMutation<()>,
) {
    let (lease_id, row_version) = begin_as(store, request, caller, host, monotonic);
    let control = AuthenticatedRequestControl::new(&lease_id, row_version, caller, host);
    let result = store
        .activate_requested(
            &control,
            &effective_policy(
                request,
                caller,
                host,
                AutomationConcurrencyMode::Exclusive,
                IsolationClassification::CredentialIsolated,
                None,
                limits,
            ),
            resolution(suffix, IsolationClassification::CredentialIsolated),
            &clock(store, "2026-08-22T10:00:03Z", monotonic + 1),
        )
        .unwrap_or_else(|error| panic!("capacity activation: {error:?}"));
    (lease_id, result)
}

type ReservationRow = (String, String, String, String, i64, i64, String, String);

fn reservations(store: &super::ReadyStore) -> Vec<ReservationRow> {
    let mut statement = store
        .test_connection()
        .prepare(
            "SELECT reservation_id, lease_id, capacity_dimension, capacity_key,
                    capacity_limit, slot, state, reserved_at_utc
             FROM capacity_reservations ORDER BY reservation_id",
        )
        .unwrap_or_else(|error| panic!("reservation statement: {error}"));
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })
        .unwrap_or_else(|error| panic!("reservation query: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("reservation rows: {error}"))
}

#[derive(Clone, Copy, Debug)]
enum SaturatedDimension {
    Profile,
    Provider,
    Caller,
    Host,
}

#[test]
fn each_capacity_dimension_is_recounted_and_refuses_without_partial_claims() {
    for (index, dimension) in [
        SaturatedDimension::Profile,
        SaturatedDimension::Provider,
        SaturatedDimension::Caller,
        SaturatedDimension::Host,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        let secondary = additional_profile(&fixture);
        let mut store = fixture.ready();
        let shared_caller = parsed::<CallerSubject>("caller:capacity-shared");
        let owner_caller = parsed::<CallerSubject>("caller:capacity-owner");
        let target_caller = if matches!(dimension, SaturatedDimension::Caller) {
            shared_caller.clone()
        } else {
            parsed("caller:capacity-target")
        };
        let shared_host = parsed::<HostIdentity>("host:capacity-shared");
        let owner_host = parsed::<HostIdentity>("host:capacity-owner");
        let target_host = if matches!(dimension, SaturatedDimension::Host) {
            shared_host.clone()
        } else {
            parsed("host:capacity-target")
        };
        let owner_caller = if matches!(dimension, SaturatedDimension::Caller) {
            &shared_caller
        } else {
            &owner_caller
        };
        let owner_host = if matches!(dimension, SaturatedDimension::Host) {
            &shared_host
        } else {
            &owner_host
        };
        let owner = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FG{index}"));
        let mut target = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FH{index}"));
        if matches!(
            dimension,
            SaturatedDimension::Provider | SaturatedDimension::Caller | SaturatedDimension::Host
        ) {
            bind_profile(&mut target, &secondary);
        }
        let (_owner_id, owner_result) = activate(
            &mut store,
            &owner,
            owner_caller,
            owner_host,
            [10, 10, 10, 10],
            '5',
            100,
        );
        assert_eq!(
            owner_result
                .successful_response()
                .map(|response| response.status),
            Some(LeaseStatus::Active)
        );
        let before = reservations(&store);
        let limits = match dimension {
            SaturatedDimension::Profile => [1, 10, 10, 10],
            SaturatedDimension::Provider => [10, 1, 10, 10],
            SaturatedDimension::Caller => [10, 10, 1, 10],
            SaturatedDimension::Host => [10, 10, 10, 1],
        };
        let (denied_id, denied) = activate(
            &mut store,
            &target,
            &target_caller,
            &target_host,
            limits,
            '6',
            200,
        );
        assert_eq!(
            denied
                .successful_response()
                .map(|response| (response.status, response.refusal_code)),
            Some((LeaseStatus::Refused, Some(RefusalCode::CapacityExceeded)))
        );
        assert_eq!(reservations(&store), before, "{dimension:?}");
        assert_eq!(
            store
                .test_connection()
                .query_row(
                    "SELECT c.monotonic_high_water_nanos,
                            (SELECT count(*) FROM capacity_reservations r
                             WHERE r.lease_id = l.lease_id),
                            (SELECT count(*) FROM audit_events a
                             WHERE a.lease_id = l.lease_id),
                            l.refusal_code
                     FROM leases l JOIN lease_runtime_clocks c USING (lease_id)
                     WHERE l.lease_id = ?1",
                    [denied_id.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .unwrap_or_else(|error| panic!("denied projection: {error}")),
            (
                201_u128.to_be_bytes().to_vec(),
                0,
                2,
                "capacity-exceeded".to_owned(),
            ),
            "{dimension:?}"
        );
    }
}

#[test]
fn renewal_requires_exact_retained_limits_for_each_capacity_dimension() {
    let dimensions = ["profile", "provider", "caller", "host"];
    for (index, (dimension, delta)) in dimensions
        .into_iter()
        .flat_map(|dimension| [(dimension, -1_i32), (dimension, 1_i32)])
        .enumerate()
    {
        let fixture = Fixture::new();
        let mut store = fixture.ready();
        let request = fixture.request(&format!("01ARZ3NDEKTSV4RRFFQ69G5FJ{index}"));
        let authenticated_caller = caller();
        let authenticated_host = host();
        let base_limits = [4, 5, 6, 7];
        let suffix = char::from_digit(u32::try_from(index).unwrap_or(0), 10)
            .unwrap_or_else(|| panic!("renewal suffix"));
        let (lease_id, activated) = activate(
            &mut store,
            &request,
            &authenticated_caller,
            &authenticated_host,
            base_limits,
            suffix,
            100,
        );
        let row_version = activated
            .successful_row_version()
            .unwrap_or_else(|| panic!("activated row version"));
        let before = reservations(&store);
        let mut changed_limits = base_limits;
        let changed = match dimension {
            "profile" => &mut changed_limits[0],
            "provider" => &mut changed_limits[1],
            "caller" => &mut changed_limits[2],
            "host" => &mut changed_limits[3],
            _ => unreachable!(),
        };
        *changed = u32::try_from(i64::from(*changed) + i64::from(delta))
            .unwrap_or_else(|_| panic!("changed limit"));
        let policy = effective_policy(
            &request,
            &authenticated_caller,
            &authenticated_host,
            AutomationConcurrencyMode::Exclusive,
            IsolationClassification::CredentialIsolated,
            None,
            changed_limits,
        );
        let lease_control = control(&request, &authenticated_caller, &authenticated_host, 1);
        let denied = store
            .begin_renewal(
                &lease_id,
                row_version,
                &lease_control,
                &policy,
                &clock(&store, "2026-08-22T10:00:04Z", 102),
            )
            .unwrap_or_else(|error| panic!("renewal {dimension} {delta}: {error:?}"));
        assert_eq!(
            denied.domain_result(),
            &Err(crate::automation::lease::LeaseDomainError::PolicyBindingMismatch)
        );
        assert_eq!(reservations(&store), before, "{dimension} {delta}");
        assert_eq!(
            store
                .test_connection()
                .query_row(
                    "SELECT l.status, l.row_version, l.next_audit_sequence,
                            c.monotonic_high_water_nanos,
                            (SELECT count(*) FROM audit_events a WHERE a.lease_id = l.lease_id)
                     FROM leases l JOIN lease_runtime_clocks c USING (lease_id)
                     WHERE l.lease_id = ?1",
                    [lease_id.as_str()],
                    |row| Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    )),
                )
                .unwrap_or_else(|error| panic!("renewal projection: {error}")),
            (
                "ACTIVE".to_owned(),
                i64::try_from(row_version + 1).unwrap_or(-1),
                3,
                102_u128.to_be_bytes().to_vec(),
                2,
            ),
            "{dimension} {delta}"
        );
    }
}
