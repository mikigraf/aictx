use std::str::FromStr;

use super::{
    super::{
        CallerSubject, ClientRequestId, DetachedSignature, DurationSeconds, ExecutionHandle,
        FencingGeneration, HostIdentity, LeaseId, MaximumTtlSeconds, PrincipalRef,
        ProbeTimeoutMilliseconds, ProfileRef, ProfileUid, RepositoryId, RequestedTtlSeconds,
        Sha256Digest, UtcTimestamp, WorkerIdentity, WorkspaceRef,
    },
    fixtures::{parsed, valid},
};

#[test]
fn log_safe_ids_match_the_wire_alphabet_and_bounds() {
    let accepted = valid(ClientRequestId::parse("Request_1:@+.-"));
    assert_eq!(accepted.as_str(), "Request_1:@+.-");
    assert!(ClientRequestId::parse("x".repeat(128)).is_ok());
    for invalid in ["", " leading", "a/b", "a\\b", "é", "a\nsecret"] {
        assert!(
            ClientRequestId::parse(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
    assert!(ClientRequestId::parse("x".repeat(129)).is_err());
}

#[test]
fn repository_ids_are_namespaced_and_segmented_unambiguously() {
    for accepted in [
        "github:acme/payments",
        "gitlab.example:group/sub_group/repo+mirror",
        "local:Owner@host/Repo.Name",
    ] {
        assert!(RepositoryId::parse(accepted).is_ok(), "rejected {accepted}");
    }
    for rejected in [
        "github",
        "github:",
        ":repo",
        "github:/repo",
        "github:repo/",
        "github:acme//repo",
        "github:./repo",
        "github:../repo",
        "github:acme/..",
        "github:acme:payments",
        "github:acme\\payments",
        "github:acme payments",
    ] {
        assert!(
            RepositoryId::parse(rejected).is_err(),
            "accepted {rejected}"
        );
    }
}

#[test]
fn profile_refs_preserve_existing_name_compatibility() {
    for accepted in ["claude:Personal", "codex:work_profile", "codex:A-1"] {
        assert!(ProfileRef::parse(accepted).is_ok(), "rejected {accepted}");
    }
    for rejected in [
        "other:personal",
        "codex:",
        "codex:-personal",
        "codex:personal.name",
        "Codex:personal",
    ] {
        assert!(ProfileRef::parse(rejected).is_err(), "accepted {rejected}");
    }
}

#[test]
fn opaque_service_ids_enforce_real_ulid_overflow_and_alphabet_rules() {
    assert!(LeaseId::parse("lease_01ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());
    assert!(ProfileUid::parse("profile_71ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());
    assert!(ExecutionHandle::parse("exec_01ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());
    for rejected in [
        "lease_81ARZ3NDEKTSV4RRFFQ69G5FAV",
        "lease_01ARZ3NDEKTSV4RRFFQ69G5FAI",
        "lease_01arz3ndektsv4rrffq69g5fav",
        "lease_01ARZ3NDEKTSV4RRFFQ69G5FA",
        "profile_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ] {
        assert!(LeaseId::parse(rejected).is_err(), "accepted {rejected}");
    }
}

#[test]
fn typed_public_references_reject_raw_backend_and_path_shapes() {
    assert!(CallerSubject::parse("caller:local-controller").is_ok());
    assert!(HostIdentity::parse("host:runner_01").is_ok());
    assert!(WorkerIdentity::parse("worker:process.1").is_ok());
    assert!(PrincipalRef::parse("user:alice").is_ok());
    assert!(PrincipalRef::parse("service-account:automation-worker").is_ok());
    assert!(WorkspaceRef::parse("claude-organization:company").is_ok());
    assert!(WorkspaceRef::parse("chatgpt-workspace:company").is_ok());

    for rejected in [
        "caller:raw/token",
        "caller:key@host",
        "caller:value+scope",
        "caller:nested:value",
        "caller:../keyring",
        "service-account:token\\file",
    ] {
        assert!(CallerSubject::parse(rejected).is_err());
        assert!(PrincipalRef::parse(rejected).is_err());
    }
    assert!(WorkspaceRef::parse("workspace:company").is_err());
}

#[test]
fn timestamps_are_real_canonical_utc_calendar_values() {
    for accepted in [
        "2024-02-29T23:59:59Z",
        "2026-08-21T10:00:00.1Z",
        "2026-08-21T10:00:00.123456789Z",
    ] {
        assert!(UtcTimestamp::parse(accepted).is_ok(), "rejected {accepted}");
    }
    for rejected in [
        "0000-01-01T00:00:00Z",
        "2023-02-29T10:00:00Z",
        "2026-13-01T10:00:00Z",
        "2016-12-31T23:59:60Z",
        "2026-08-21t10:00:00Z",
        "2026-08-21T10:00:00z",
        "2026-08-21T10:00:00+00:00",
        "2026-08-21T10:00:00.1234567890Z",
        "2026-08-21T10:00:00.Z",
    ] {
        assert!(
            UtcTimestamp::parse(rejected).is_err(),
            "accepted {rejected}"
        );
    }
}

#[test]
fn signatures_require_canonical_64_byte_unpadded_base64url_shape() {
    for tail in ['A', 'Q', 'g', 'w'] {
        let mut signature = "A".repeat(85);
        signature.push(tail);
        assert!(DetachedSignature::parse(signature).is_ok());
    }
    for tail in ['E', 'I', 'M', 'U', '0', '8'] {
        let mut signature = "A".repeat(85);
        signature.push(tail);
        assert!(DetachedSignature::parse(signature).is_err());
    }
    assert!(DetachedSignature::parse("A".repeat(85)).is_err());
    assert!(DetachedSignature::parse(format!("{}=", "A".repeat(85))).is_err());
}

#[test]
fn digests_are_lowercase_sha256_only() {
    let digest = Sha256Digest::hash(b"contract");
    let encoded = digest.to_string();
    assert_eq!(Sha256Digest::from_str(&encoded), Ok(digest));
    assert!(Sha256Digest::from_str(&encoded.to_uppercase()).is_err());
    assert!(Sha256Digest::from_str(&format!("sha256:{}", "0".repeat(63))).is_err());
}

#[test]
fn numeric_wire_types_enforce_exact_bounds() {
    assert!(RequestedTtlSeconds::from_seconds(1).is_ok());
    assert!(RequestedTtlSeconds::from_seconds(86_400).is_ok());
    assert!(RequestedTtlSeconds::from_seconds(0).is_err());
    assert!(RequestedTtlSeconds::from_seconds(86_401).is_err());

    assert!(MaximumTtlSeconds::from_seconds(86_400).is_ok());
    assert!(MaximumTtlSeconds::from_seconds(86_401).is_err());
    assert!(DurationSeconds::from_seconds(u64::from(u32::MAX)).is_ok());
    assert!(DurationSeconds::from_seconds(u64::from(u32::MAX) + 1).is_err());

    let maximum = valid(FencingGeneration::from_value(FencingGeneration::MAXIMUM));
    assert_eq!(maximum.get(), 9_007_199_254_740_991);
    assert!(FencingGeneration::from_value(0).is_err());
    assert!(FencingGeneration::from_value(FencingGeneration::MAXIMUM + 1).is_err());
}

#[test]
fn primitive_json_deserialization_applies_the_same_validation() {
    assert!(serde_json::from_str::<LeaseId>("\"lease_81ARZ3NDEKTSV4RRFFQ69G5FAV\"").is_err());
    assert!(serde_json::from_str::<UtcTimestamp>("\"2026-02-30T00:00:00Z\"").is_err());
    assert!(serde_json::from_str::<FencingGeneration>("9007199254740992").is_err());
    let timestamp: UtcTimestamp = parsed("2026-08-21T10:00:00Z");
    assert_eq!(
        valid(serde_json::to_string(&timestamp)),
        "\"2026-08-21T10:00:00Z\""
    );
}

#[test]
fn bounded_integer_wires_accept_all_integral_json_number_forms_canonically() {
    for wire in ["900", "900.0", "9e2", "9E+2", "90.00e1", "9000e-1"] {
        let ttl: RequestedTtlSeconds = valid(serde_json::from_str(wire));
        assert_eq!(ttl.get(), 900);
        assert_eq!(valid(serde_json::to_string(&ttl)), "900");
    }

    let maximum_ttl: MaximumTtlSeconds = valid(serde_json::from_str("8.64e4"));
    assert_eq!(maximum_ttl.get(), 86_400);
    assert_eq!(valid(serde_json::to_string(&maximum_ttl)), "86400");

    let duration: DurationSeconds = valid(serde_json::from_str("4.294967295e9"));
    assert_eq!(duration.get(), u64::from(u32::MAX));
    assert_eq!(valid(serde_json::to_string(&duration)), "4294967295");

    let generation: FencingGeneration = valid(serde_json::from_str("9.007199254740991e15"));
    assert_eq!(generation.get(), FencingGeneration::MAXIMUM);
    assert_eq!(
        valid(serde_json::to_string(&generation)),
        "9007199254740991"
    );

    let timeout: ProbeTimeoutMilliseconds = valid(serde_json::from_str("5e3"));
    assert_eq!(timeout.get(), 5_000);
    assert_eq!(valid(serde_json::to_string(&timeout)), "5000");
}

#[test]
fn bounded_integer_wires_reject_fractional_negative_and_out_of_range_numbers() {
    for rejected in [
        "900.5",
        "9.001e2",
        "900.0000000000000000000000001",
        "-900",
        "-0",
        "0",
        "86401",
        "1e400",
        "\"900\"",
        "true",
        "{\"$serde_json::private::Number\":\"900\"}",
    ] {
        assert!(
            serde_json::from_str::<RequestedTtlSeconds>(rejected).is_err(),
            "accepted {rejected}"
        );
    }
    assert!(
        serde_json::from_str::<DurationSeconds>("4.294967296e9").is_err(),
        "accepted a duration above u32::MAX"
    );
    assert!(
        serde_json::from_str::<FencingGeneration>("9.007199254740992e15").is_err(),
        "accepted a fencing generation above the JSON exact-integer ceiling"
    );
    assert!(serde_json::from_str::<ProbeTimeoutMilliseconds>("30000.1").is_err());
}
