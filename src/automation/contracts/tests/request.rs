use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};

use super::{
    super::{
        ContractValidationError, DurationSeconds, IdentityLeaseRequest, MaximumTtlSeconds,
        Provider, RequestedTtlSeconds, Sha256Digest, UtcTimestamp, WorkOrderAuthorization,
    },
    fixtures::{authorization, parsed, request, valid},
};

#[test]
fn request_and_authorization_round_trip_strictly() {
    let request = request();
    let encoded = valid(serde_json::to_vec(&request));
    let decoded: IdentityLeaseRequest = valid(serde_json::from_slice(&encoded));
    assert_eq!(decoded, request);

    let mut unknown: Value = valid(serde_json::from_slice(&encoded));
    unknown["caller_subject"] = json!("caller:injected");
    assert!(serde_json::from_value::<IdentityLeaseRequest>(unknown).is_err());

    let mut nested_unknown: Value = valid(serde_json::from_slice(&encoded));
    nested_unknown["work_order_authorization"]["credential"] = json!("secret-canary");
    assert!(serde_json::from_value::<IdentityLeaseRequest>(nested_unknown).is_err());

    let mut missing_nullable: Value = valid(serde_json::from_slice(&encoded));
    let removed = missing_nullable
        .as_object_mut()
        .and_then(|object| object.remove("policy_digest"));
    assert!(removed.is_some());
    assert!(serde_json::from_value::<IdentityLeaseRequest>(missing_nullable).is_err());

    let mut missing_signed_replay_key: Value = valid(serde_json::from_slice(&encoded));
    let removed = missing_signed_replay_key["work_order_authorization"]
        .as_object_mut()
        .and_then(|object| object.remove("client_request_id"));
    assert!(removed.is_some());
    assert!(serde_json::from_value::<IdentityLeaseRequest>(missing_signed_replay_key).is_err());
}

#[test]
fn major_versions_are_refused_at_both_contract_layers() {
    let mut request_value = valid(serde_json::to_value(request()));
    request_value["schema"] = json!("ctxlane.identity-lease-request/v2");
    assert!(serde_json::from_value::<IdentityLeaseRequest>(request_value).is_err());

    let mut authorization_value = valid(serde_json::to_value(authorization()));
    authorization_value["schema"] = json!("ctxlane.work-order-authorization/v2");
    assert!(serde_json::from_value::<WorkOrderAuthorization>(authorization_value).is_err());
}

#[test]
fn every_duplicated_authority_mismatch_decodes_then_returns_an_exact_semantic_error() {
    let base = valid(serde_json::to_value(request()));
    let cases = [
        ("client_request_id", json!("request-other")),
        ("tenant_id", json!("tenant-other")),
        ("work_order_id", json!("wo_other")),
        (
            "work_order_digest",
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
        ),
        ("run_id", json!("run_other")),
        ("attempt_id", json!("attempt_02")),
        ("role", json!("pr-reviewer")),
        ("profile_ref", json!("codex:other")),
        ("profile_uid", json!("profile_01ARZ3NDEKTSV4RRFFQ69G5FB0")),
        ("repository", json!("github:acme/other")),
        ("workspace_id", json!("workspace_other")),
        ("environment", json!("staging")),
    ];
    for (field, value) in cases {
        let mut changed = base.clone();
        changed[field] = value;
        let decoded: IdentityLeaseRequest = valid(serde_json::from_value(changed));
        assert_eq!(
            decoded.validate_authorization_binding(),
            Err(ContractValidationError::WorkOrderAuthorizationMismatch { field }),
            "field {field} did not return its stable semantic error"
        );
    }

    let mut provider = base;
    provider["provider"] = json!("claude");
    provider["profile_ref"] = json!("claude:automation-production");
    let decoded: IdentityLeaseRequest = valid(serde_json::from_value(provider));
    assert_eq!(
        decoded.validate_authorization_binding(),
        Err(ContractValidationError::WorkOrderAuthorizationMismatch { field: "provider" })
    );
}

#[test]
fn top_level_replay_key_is_canonical_before_the_signed_binding_gate() {
    let mut encoded = valid(serde_json::to_value(request()));
    encoded["client_request_id"] = json!("request-other");

    let decoded: IdentityLeaseRequest = valid(serde_json::from_value(encoded));
    let digest = valid(decoded.authority_digest());
    assert_ne!(digest, valid(request().authority_digest()));
    assert_eq!(decoded.client_request_id.to_string(), "request-other");
    assert_eq!(
        decoded.validate_authorization_binding(),
        Err(ContractValidationError::WorkOrderAuthorizationMismatch {
            field: "client_request_id",
        })
    );
}

#[test]
fn semantic_authorization_failures_remain_reachable_after_strict_decode() {
    let base = valid(serde_json::to_value(request()));

    let mut invalid_interval = base.clone();
    invalid_interval["work_order_authorization"]["expires_at"] = json!("2026-08-21T09:59:59Z");
    let invalid_interval: IdentityLeaseRequest = valid(serde_json::from_value(invalid_interval));
    assert_eq!(
        invalid_interval.validate_authorization_binding(),
        Err(ContractValidationError::InvalidAuthorizationValidity)
    );
    assert!(
        invalid_interval
            .work_order_authorization
            .signature_message()
            .is_ok()
    );
    assert!(invalid_interval.authority_digest().is_ok());

    let mut invalid_limits = base.clone();
    invalid_limits["work_order_authorization"]["maximum_ttl_seconds"] = json!(901);
    invalid_limits["work_order_authorization"]["maximum_session_seconds"] = json!(900);
    let invalid_limits: IdentityLeaseRequest = valid(serde_json::from_value(invalid_limits));
    assert_eq!(
        invalid_limits.validate_authorization_binding(),
        Err(ContractValidationError::InvalidAuthorizationLimits)
    );

    let mut over_ttl = base;
    over_ttl["requested_ttl_seconds"] = json!(901);
    let over_ttl: IdentityLeaseRequest = valid(serde_json::from_value(over_ttl));
    assert_eq!(
        over_ttl.validate_authorization_binding(),
        Err(ContractValidationError::RequestedTtlExceedsAuthorization)
    );
    assert!(over_ttl.authority_digest().is_ok());
}

#[test]
fn schema_level_provider_profile_conditionals_remain_decode_errors() {
    let mut top_level = valid(serde_json::to_value(request()));
    top_level["provider"] = json!("claude");
    assert!(serde_json::from_value::<IdentityLeaseRequest>(top_level).is_err());

    let mut signed = valid(serde_json::to_value(request()));
    signed["work_order_authorization"]["provider"] = json!("claude");
    assert!(serde_json::from_value::<IdentityLeaseRequest>(signed).is_err());

    let mut authorization = valid(serde_json::to_value(authorization()));
    authorization["provider"] = json!("claude");
    assert!(serde_json::from_value::<WorkOrderAuthorization>(authorization).is_err());
}

#[test]
fn invalid_constructed_contracts_cannot_be_serialized() {
    let mut mismatched = request();
    mismatched.profile_uid = parsed("profile_01ARZ3NDEKTSV4RRFFQ69G5FB0");
    assert!(serde_json::to_value(&mismatched).is_err());

    let mut invalid_provider = authorization();
    invalid_provider.provider = Provider::Claude;
    assert!(serde_json::to_value(&invalid_provider).is_err());

    let mut inverted = authorization();
    inverted.expires_at = inverted.not_before.clone();
    assert!(serde_json::to_value(&inverted).is_err());

    let mut ttl_exceeds_session = authorization();
    ttl_exceeds_session.maximum_ttl_seconds = valid(MaximumTtlSeconds::from_seconds(901));
    ttl_exceeds_session.maximum_session_seconds = valid(DurationSeconds::from_seconds(900));
    assert!(serde_json::to_value(&ttl_exceeds_session).is_err());

    let mut session_exceeds_window = authorization();
    session_exceeds_window.maximum_session_seconds = valid(DurationSeconds::from_seconds(14_401));
    assert!(serde_json::to_value(&session_exceeds_window).is_err());

    let mut request_ttl_exceeds_session = request();
    request_ttl_exceeds_session.requested_ttl_seconds =
        valid(RequestedTtlSeconds::from_seconds(901));
    request_ttl_exceeds_session
        .work_order_authorization
        .maximum_session_seconds = valid(DurationSeconds::from_seconds(900));
    request_ttl_exceeds_session
        .work_order_authorization
        .maximum_ttl_seconds = valid(MaximumTtlSeconds::from_seconds(900));
    assert!(serde_json::to_value(&request_ttl_exceeds_session).is_err());
}

#[test]
fn authorization_validity_is_half_open_and_covers_the_session_limit() {
    let request = request();
    let before: UtcTimestamp = parsed("2026-08-21T09:59:59.999999999Z");
    let start: UtcTimestamp = parsed("2026-08-21T10:00:00Z");
    let end: UtcTimestamp = parsed("2026-08-21T14:00:00Z");
    assert!(request.validate_authorization(&before).is_err());
    assert!(request.validate_authorization(&start).is_ok());
    assert!(request.validate_authorization(&end).is_err());

    let exact_ttl_boundary: UtcTimestamp = parsed("2026-08-21T13:45:00Z");
    let just_inside_ttl_boundary: UtcTimestamp = parsed("2026-08-21T13:45:00.000000001Z");
    assert!(request.validate_authorization(&exact_ttl_boundary).is_ok());
    assert!(
        request
            .validate_authorization(&just_inside_ttl_boundary)
            .is_err()
    );

    let mut maximum_calendar_request = request.clone();
    maximum_calendar_request.work_order_authorization.not_before = parsed("9999-12-31T00:00:00Z");
    maximum_calendar_request.work_order_authorization.expires_at = parsed("9999-12-31T23:59:59Z");
    let near_calendar_limit: UtcTimestamp = parsed("9999-12-31T23:59:58Z");
    assert!(
        maximum_calendar_request
            .validate_authorization(&near_calendar_limit)
            .is_err()
    );

    let mut exact_fractional_window = authorization();
    exact_fractional_window.not_before = parsed("2026-08-21T10:00:00.5Z");
    exact_fractional_window.expires_at = parsed("2026-08-21T10:00:01.5Z");
    exact_fractional_window.maximum_ttl_seconds = valid(MaximumTtlSeconds::from_seconds(1));
    exact_fractional_window.maximum_session_seconds = valid(DurationSeconds::from_seconds(1));
    assert!(exact_fractional_window.validate().is_ok());

    exact_fractional_window.expires_at = parsed("2026-08-21T10:00:01.499999999Z");
    assert!(exact_fractional_window.validate().is_err());
}

#[test]
fn signature_message_matches_the_published_golden_vector() {
    let vector: Value = valid(serde_json::from_str(include_str!(
        "../../../../schemas/examples/work-order-signing-vector.v1.json"
    )));
    let canonical = concat!(
        "{\"algorithm\":\"ed25519\",\"attempt_id\":\"attempt_01\",",
        "\"client_request_id\":\"01ARZ3NDEKTSV4RRFFQ69G5FAV\",",
        "\"environment\":\"production\",\"expires_at\":\"2026-08-21T14:00:00Z\",",
        "\"key_id\":\"key-controller-2026-08\",\"maximum_session_seconds\":14400,",
        "\"maximum_ttl_seconds\":900,\"not_before\":\"2026-08-21T10:00:00Z\",",
        "\"profile_ref\":\"codex:automation-production\",",
        "\"profile_uid\":\"profile_01ARZ3NDEKTSV4RRFFQ69G5FAV\",",
        "\"provider\":\"codex\",\"repository\":\"github:acme/payments\",",
        "\"role\":\"implementer\",\"run_id\":\"run_01ARZ3NDEKTSV4RRFFQ69G5FAV\",",
        "\"schema\":\"ctxlane.work-order-authorization/v1\",\"tenant_id\":\"tenant-acme\",",
        "\"work_order_digest\":\"sha256:a36dbc1704725260b0896399529c16a86acabb6849bb1c9abeb251d7ffd16e6c\",",
        "\"work_order_id\":\"wo_01ARZ3NDEKTSV4RRFFQ69G5FAV\",",
        "\"workspace_id\":\"workspace_01ARZ3NDEKTSV4RRFFQ69G5FAV\"}"
    );
    assert_eq!(
        canonical,
        vector_string(&vector, "canonical_authorization_without_signature")
    );
    let mut expected = b"ctxlane.work-order-authorization/v1\0".to_vec();
    expected.extend_from_slice(canonical.as_bytes());
    let actual = valid(authorization().signature_message());
    assert_eq!(actual, expected);
    assert_eq!(
        Sha256Digest::hash(&actual).to_string(),
        format!(
            "sha256:{}",
            vector_string(&vector, "signing_payload_sha256_hex")
        )
    );

    let public_key = decode_hex_public_key(vector_string(&vector, "public_key_hex"));
    let verifying_key = valid(VerifyingKey::from_bytes(&public_key));
    let published_signature = vector_string(&vector, "signature_base64url_unpadded");
    assert_eq!(authorization().signature.as_str(), published_signature);
    let signature_bytes = decode_base64url_signature(published_signature);
    let signature = Signature::from_bytes(&signature_bytes);
    assert!(verifying_key.verify(&actual, &signature).is_ok());
}

fn vector_string<'a>(vector: &'a Value, field: &str) -> &'a str {
    match vector.get(field).and_then(Value::as_str) {
        Some(value) => value,
        None => panic!("published signing vector is missing string field {field}"),
    }
}

fn decode_hex_public_key(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "published public key must be 32 bytes");
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = valid(u8::from_str_radix(&value[start..start + 2], 16));
    }
    output
}

fn decode_base64url_signature(value: &str) -> [u8; 64] {
    let mut output = Vec::with_capacity(64);
    let mut accumulator = 0_u32;
    let mut bit_count = 0_u8;
    for byte in value.bytes() {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("golden signature is not base64url"),
        };
        accumulator = (accumulator << 6) | u32::from(sextet);
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((accumulator >> bit_count).to_be_bytes()[3]);
            accumulator &= (1_u32 << bit_count) - 1;
        }
    }
    match output.try_into() {
        Ok(bytes) => bytes,
        Err(value) => panic!("golden signature decoded to {} bytes", value.len()),
    }
}

#[test]
fn canonical_request_digest_is_stable_and_sensitive() {
    let request = request();
    let canonical = valid(request.canonical_authority_json());
    let as_text = valid(String::from_utf8(canonical.clone()));
    assert_eq!(canonical, valid(request.canonical_authority_json()));
    assert!(as_text.contains("\"policy_digest\":null"));
    assert!(as_text.contains("\"profile_uid\":\"profile_01ARZ3NDEKTSV4RRFFQ69G5FAV\""));
    assert!(as_text.contains("\"signature\":\"jLtlv6wV"));

    let baseline = valid(request.authority_digest());
    assert_eq!(baseline, Sha256Digest::hash(as_text.as_bytes()));
    assert_eq!(
        baseline.to_string(),
        "sha256:c2e97e1730562837f58c1a0745026b1a377afa60a8d2d58254d078be6e7dcb4c"
    );
    let vector: Value = valid(serde_json::from_str(include_str!(
        "../../../../schemas/examples/work-order-signing-vector.v1.json"
    )));
    assert_eq!(
        baseline.to_string(),
        vector_string(&vector, "canonical_request_digest")
    );

    let mut mismatched_client = request.clone();
    mismatched_client.client_request_id = parsed("request-other");
    assert_ne!(valid(mismatched_client.authority_digest()), baseline);

    let mut new_signed_client = request.clone();
    new_signed_client.client_request_id = parsed("request-other");
    new_signed_client.work_order_authorization.client_request_id =
        new_signed_client.client_request_id.clone();
    assert!(new_signed_client.validate_authorization_binding().is_ok());
    assert_ne!(
        valid(
            new_signed_client
                .work_order_authorization
                .signature_message()
        ),
        valid(request.work_order_authorization.signature_message())
    );
    assert_ne!(valid(new_signed_client.authority_digest()), baseline);

    let mut policy = request.clone();
    policy.policy_digest = Some(parsed(
        "sha256:bb42590da6d8c5c0c0103b67572979c60d3c44a5a5a2cfa74f469e8cd7cf3d12",
    ));
    assert_ne!(valid(policy.authority_digest()), baseline);

    let mut ttl = request.clone();
    ttl.requested_ttl_seconds = valid(RequestedTtlSeconds::from_seconds(899));
    assert_ne!(valid(ttl.authority_digest()), baseline);

    let mut key = request.clone();
    key.work_order_authorization.key_id = parsed("key-controller-2026-09");
    assert_ne!(valid(key.authority_digest()), baseline);

    let mut signature = request;
    signature.work_order_authorization.signature =
        valid(super::super::DetachedSignature::parse("A".repeat(86)));
    assert_ne!(valid(signature.authority_digest()), baseline);
}
