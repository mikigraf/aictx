#!/usr/bin/env python3
"""Validate ctxlane's published Phase-0 schemas, examples, and golden vector."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource
except ImportError as error:  # pragma: no cover - environment setup failure
    raise SystemExit(
        "install schemas/tests/requirements.txt before validating contracts"
    ) from error

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as error:  # pragma: no cover - environment setup failure
    raise SystemExit(
        "install schemas/tests/requirements.txt before validating contracts"
    ) from error


SCHEMA_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_ROOT = SCHEMA_ROOT / "examples"

EXAMPLE_SCHEMAS = {
    "work-order-authorization.v1.json": "ctxlane.work-order-authorization.v1.schema.json",
    "identity-lease-request.v1.json": "ctxlane.identity-lease-request.v1.schema.json",
    "identity-lease-active.v1.json": "ctxlane.identity-lease.v1.schema.json",
    "identity-lease-refused.v1.json": "ctxlane.identity-lease.v1.schema.json",
    "automation-readiness-ready.v1.json": "ctxlane.automation-readiness.v1.schema.json",
    "automation-readiness-not-ready.v1.json": "ctxlane.automation-readiness.v1.schema.json",
    "automation-readiness-development-exception.v1.json": "ctxlane.automation-readiness.v1.schema.json",
    "automation-error.v1.json": "ctxlane.automation-error.v1.schema.json",
}

AUTHORIZATION_BINDINGS = (
    "client_request_id",
    "tenant_id",
    "work_order_id",
    "work_order_digest",
    "run_id",
    "attempt_id",
    "role",
    "provider",
    "profile_uid",
    "profile_ref",
    "repository",
    "workspace_id",
    "environment",
)

COMMON_ERROR_CODES = frozenset(
    {
        "invalid-request",
        "unsupported-schema",
        "caller-unauthenticated",
        "caller-unauthorized",
        "rate-limited",
        "service-recovering",
        "unsupported-platform",
        "store-unavailable",
        "internal-error",
    }
)

NONCOMMON_ERROR_CODES = {
    "profile-list": frozenset(),
    "profile-readiness": frozenset({"profile-not-found", "provider-mismatch"}),
    "profile-resolve": frozenset(
        {
            "profile-not-found",
            "provider-mismatch",
            "profile-not-eligible",
            "authentication-exception-required",
            "isolation-exception-required",
            "environment-not-allowed",
            "role-not-allowed",
            "caller-not-allowed",
            "repository-not-allowed",
            "profile-not-ready",
            "identity-token-stale",
            "harness-untrusted",
            "principal-unverified",
            "principal-mismatch",
            "organization-mismatch",
            "workspace-mismatch",
            "isolation-unproven",
        }
    ),
    "lease-acquire": frozenset({"idempotency-conflict"}),
    "lease-inspect": frozenset({"lease-not-found"}),
    "lease-renew": frozenset(
        {
            "lease-not-found",
            "lease-not-active",
            "lease-expired",
            "lease-revoked",
            "generation-mismatch",
            "run-mismatch",
            "role-mismatch",
            "tenant-mismatch",
            "host-mismatch",
            "session-limit-reached",
        }
    ),
    "lease-revoke": frozenset({"lease-not-found", "lease-not-active"}),
    "lease-close": frozenset(
        {
            "lease-not-found",
            "lease-not-active",
            "lease-expired",
            "lease-revoked",
            "generation-mismatch",
            "run-mismatch",
            "role-mismatch",
            "tenant-mismatch",
            "host-mismatch",
        }
    ),
    "service-health": frozenset(),
    "execution-start": frozenset(
        {
            "lease-not-found",
            "lease-not-active",
            "lease-expired",
            "lease-revoked",
            "generation-mismatch",
            "run-mismatch",
            "role-mismatch",
            "tenant-mismatch",
            "host-mismatch",
            "session-limit-reached",
            "profile-not-ready",
            "identity-token-stale",
            "harness-untrusted",
            "principal-unverified",
            "principal-mismatch",
            "organization-mismatch",
            "workspace-mismatch",
            "isolation-unproven",
        }
    ),
}

NONCOMMON_ERRORS_REQUIRE_LEASE_ID = frozenset(
    {"lease-inspect", "lease-renew", "lease-revoke", "lease-close", "execution-start"}
)


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key}")
        value[key] = member
    return value


def reject_non_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def strict_json_loads(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=reject_duplicate_members,
        parse_constant=reject_non_json_constant,
    )


def load_json(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def canonical_json(value: Any) -> bytes:
    """RFC 8785 equivalent for the fixture's string/integer-only value domain."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def utc_nanoseconds(value: str) -> int:
    body = value.removesuffix("Z")
    whole, separator, fraction = body.partition(".")
    instant = datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc
    )
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = instant - epoch
    whole_seconds = delta.days * 86_400 + delta.seconds
    fractional_nanoseconds = int(fraction.ljust(9, "0")) if separator else 0
    return whole_seconds * 1_000_000_000 + fractional_nanoseconds


def contract_format_checker() -> FormatChecker:
    """Build the mandatory, dependency-independent v1 format checker."""
    checker = FormatChecker()

    @checker.checks("date-time")
    def strict_date_time(value: object) -> bool:
        if not isinstance(value, str):
            return True
        try:
            utc_nanoseconds(value)
        except (TypeError, ValueError):
            return False
        return True

    return checker


def validate_request_semantics(request: dict[str, Any]) -> None:
    authorization = request["work_order_authorization"]
    for field in AUTHORIZATION_BINDINGS:
        if request[field] != authorization[field]:
            raise AssertionError(f"request field {field!r} does not match authorization")
    if request["requested_ttl_seconds"] > authorization["maximum_ttl_seconds"]:
        raise AssertionError("requested TTL exceeds signed maximum TTL")
    if authorization["maximum_ttl_seconds"] > authorization["maximum_session_seconds"]:
        raise AssertionError("signed maximum TTL exceeds signed maximum session")
    signed_interval_nanoseconds = utc_nanoseconds(
        authorization["expires_at"]
    ) - utc_nanoseconds(authorization["not_before"])
    if signed_interval_nanoseconds <= 0:
        raise AssertionError("signed authorization interval is empty or reversed")
    if (
        authorization["maximum_session_seconds"] * 1_000_000_000
        > signed_interval_nanoseconds
    ):
        raise AssertionError("signed maximum session outlives signed authorization interval")


def validate_readiness_semantics(readiness: dict[str, Any]) -> None:
    if utc_nanoseconds(readiness["checked_at"]) >= utc_nanoseconds(
        readiness["valid_until"]
    ):
        raise AssertionError("readiness valid_until must be later than checked_at")


def validate_resolved_lease_semantics(lease: dict[str, Any]) -> None:
    if lease["status"] not in {"active", "renewing", "closed", "expired", "revoked", "error"}:
        return
    if not (
        utc_nanoseconds(lease["issued_at"])
        < utc_nanoseconds(lease["expires_at"])
        <= utc_nanoseconds(lease["maximum_expires_at"])
    ):
        raise AssertionError("resolved lease timestamps are not monotonic")


def expect_invalid(
    validator: Draft202012Validator,
    value: dict[str, Any],
    description: str,
) -> None:
    if validator.is_valid(value):
        raise AssertionError(f"expected schema rejection: {description}")


def expect_semantic_invalid(check: Callable[[], None], description: str) -> None:
    try:
        check()
    except AssertionError:
        return
    raise AssertionError(f"expected semantic rejection: {description}")


def expect_strict_json_invalid(text: str, description: str) -> None:
    try:
        strict_json_loads(text)
    except ValueError:
        return
    raise AssertionError(f"expected strict JSON rejection: {description}")


def main() -> None:
    expect_strict_json_invalid(
        '{"schema":"ctxlane.identity-lease-request/v1",'
        '"run_id":"run_one","run_id":"run_two"}',
        "duplicate root request member",
    )
    expect_strict_json_invalid(
        '{"work_order_authorization":{"profile_uid":"profile_one",'
        '"profile_uid":"profile_two"}}',
        "duplicate nested authorization member",
    )

    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        schema = load_json(path)
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema
        resources.append((schema["$id"], Resource.from_contents(schema)))

    registry = Registry().with_resources(resources)
    format_checker = contract_format_checker()
    validators = {
        name: Draft202012Validator(
            schema,
            registry=registry,
            format_checker=format_checker,
        )
        for name, schema in schemas.items()
    }

    examples: dict[str, dict[str, Any]] = {}
    for example_name, schema_name in EXAMPLE_SCHEMAS.items():
        value = load_json(EXAMPLE_ROOT / example_name)
        validators[schema_name].validate(value)
        examples[example_name] = value

    request = examples["identity-lease-request.v1.json"]
    authorization = examples["work-order-authorization.v1.json"]
    if request["work_order_authorization"] != authorization:
        raise AssertionError("request does not embed the published authorization example")
    validate_request_semantics(request)
    validate_readiness_semantics(examples["automation-readiness-ready.v1.json"])
    validate_readiness_semantics(examples["automation-readiness-not-ready.v1.json"])
    validate_readiness_semantics(
        examples["automation-readiness-development-exception.v1.json"]
    )
    validate_resolved_lease_semantics(examples["identity-lease-active.v1.json"])

    vector = load_json(EXAMPLE_ROOT / "work-order-signing-vector.v1.json")
    if any("private" in key.lower() or "seed" in key.lower() for key in vector):
        raise AssertionError("signing vector must not publish private-key material")
    unsigned = copy.deepcopy(authorization)
    signature_text = unsigned.pop("signature")
    canonical_authorization = canonical_json(unsigned)
    if canonical_authorization.decode("utf-8") != vector["canonical_authorization_without_signature"]:
        raise AssertionError("authorization canonicalization differs from golden vector")
    domain = vector["domain_separator_utf8"].encode("utf-8")
    if not domain.endswith(b"\0"):
        raise AssertionError("signing-vector domain separator does not end in NUL")
    signing_payload = domain + canonical_authorization
    if hashlib.sha256(signing_payload).hexdigest() != vector["signing_payload_sha256_hex"]:
        raise AssertionError("signing payload digest differs from golden vector")
    if signature_text != vector["signature_base64url_unpadded"]:
        raise AssertionError("authorization signature differs from golden vector")
    signature = base64.urlsafe_b64decode(signature_text + "==")
    if len(signature) != 64:
        raise AssertionError("golden Ed25519 signature is not 64 bytes")
    request_digest = "sha256:" + hashlib.sha256(canonical_json(request)).hexdigest()
    if request_digest != vector["canonical_request_digest"]:
        raise AssertionError("canonical request digest differs from golden vector")

    public_key = bytes.fromhex(vector["public_key_hex"])
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signing_payload)

    auth_validator = validators["ctxlane.work-order-authorization.v1.schema.json"]
    integral = copy.deepcopy(authorization)
    integral["maximum_ttl_seconds"] = 900.0
    auth_validator.validate(integral)
    invalid = copy.deepcopy(authorization)
    invalid["maximum_ttl_seconds"] = 900.5
    expect_invalid(auth_validator, invalid, "fractional maximum TTL")
    for field in [
        "tenant_id",
        "profile_ref",
        "profile_uid",
        "repository",
        "work_order_digest",
        "not_before",
        "signature",
    ]:
        invalid = copy.deepcopy(authorization)
        invalid[field] += "\n"
        expect_invalid(auth_validator, invalid, f"newline-suffixed authorization {field}")
    invalid = copy.deepcopy(authorization)
    invalid["profile_ref"] = "claude:automation-production"
    expect_invalid(auth_validator, invalid, "authorization provider/profile mismatch")
    invalid = copy.deepcopy(authorization)
    del invalid["client_request_id"]
    expect_invalid(auth_validator, invalid, "authorization without signed replay key")
    invalid = copy.deepcopy(authorization)
    invalid["expires_at"] = "2026-08-21T14:00:00+00:00"
    expect_invalid(auth_validator, invalid, "authorization timestamp without canonical Z")
    invalid = copy.deepcopy(authorization)
    invalid["not_before"] = "0000-01-01T00:00:00Z"
    expect_invalid(auth_validator, invalid, "authorization timestamp with year zero")
    invalid = copy.deepcopy(authorization)
    invalid["not_before"] = "2016-12-31T23:59:60Z"
    expect_invalid(auth_validator, invalid, "authorization leap-second timestamp")
    invalid = copy.deepcopy(authorization)
    invalid["not_before"] = "2023-02-29T00:00:00Z"
    expect_invalid(auth_validator, invalid, "authorization invalid calendar date")
    invalid = copy.deepcopy(authorization)
    invalid["signature"] = invalid["signature"][:-1] + "B"
    expect_invalid(auth_validator, invalid, "noncanonical Ed25519 base64url tail")
    invalid = copy.deepcopy(authorization)
    invalid["maximum_ttl_seconds"] = 901
    invalid["maximum_session_seconds"] = 900
    expect_semantic_invalid(
        lambda: validate_request_semantics(
            {**request, "requested_ttl_seconds": 901, "work_order_authorization": invalid}
        ),
        "maximum TTL greater than maximum session",
    )
    invalid = copy.deepcopy(authorization)
    invalid["not_before"] = "2026-08-21T10:00:00.000000001Z"
    invalid["expires_at"] = "2026-08-21T10:00:01Z"
    invalid["maximum_ttl_seconds"] = 1
    invalid["maximum_session_seconds"] = 1
    expect_semantic_invalid(
        lambda: validate_request_semantics(
            {**request, "requested_ttl_seconds": 1, "work_order_authorization": invalid}
        ),
        "signed interval one nanosecond shorter than the session maximum",
    )

    request_validator = validators["ctxlane.identity-lease-request.v1.schema.json"]
    integral_request_text = (
        EXAMPLE_ROOT / "identity-lease-request.v1.json"
    ).read_text(encoding="utf-8").replace(
        '"requested_ttl_seconds": 900', '"requested_ttl_seconds": 9e2', 1
    )
    integral_request = strict_json_loads(integral_request_text)
    request_validator.validate(integral_request)
    validate_request_semantics(integral_request)
    invalid = copy.deepcopy(request)
    invalid["repository"] = "github:../secrets"
    expect_invalid(request_validator, invalid, "repository traversal")
    invalid = copy.deepcopy(request)
    invalid["provider"] = "claude"
    expect_invalid(request_validator, invalid, "request provider/profile mismatch")
    invalid = copy.deepcopy(request)
    invalid["unexpected"] = True
    expect_invalid(request_validator, invalid, "unknown request field")
    invalid = copy.deepcopy(request)
    invalid["run_id"] = "run_other"
    expect_semantic_invalid(
        lambda: validate_request_semantics(invalid),
        "request/authorization binding mismatch",
    )
    invalid = copy.deepcopy(request)
    invalid["client_request_id"] = "request-other"
    expect_semantic_invalid(
        lambda: validate_request_semantics(invalid),
        "request/signed replay-key mismatch",
    )

    lease_validator = validators["ctxlane.identity-lease.v1.schema.json"]
    active = examples["identity-lease-active.v1.json"]
    refused = examples["identity-lease-refused.v1.json"]
    for field in [
        "lease_id",
        "execution_handle",
        "caller_subject",
        "host_identity",
        "principal_ref",
        "workspace_ref",
        "effective_policy_digest",
        "issued_at",
    ]:
        invalid = copy.deepcopy(active)
        invalid[field] += "\n"
        expect_invalid(lease_validator, invalid, f"newline-suffixed lease {field}")
    invalid = copy.deepcopy(active)
    invalid["caller_subject"] = "caller:path/segment"
    expect_invalid(lease_validator, invalid, "path-like caller subject")
    invalid = copy.deepcopy(active)
    invalid["provider"] = "claude"
    invalid["profile_ref"] = "claude:automation-production"
    invalid["workspace_ref"] = "claude-organization:org_automation"
    invalid["auth_mode"] = "access-token"
    expect_invalid(lease_validator, invalid, "Claude access-token mode")
    invalid = copy.deepcopy(refused)
    invalid["principal_ref"] = "service-account:unverified"
    expect_invalid(lease_validator, invalid, "refused lease runtime principal claim")
    invalid = copy.deepcopy(refused)
    invalid["worker_identity"] = "worker:unverified"
    expect_invalid(lease_validator, invalid, "refused lease runtime worker claim")
    invalid = copy.deepcopy(refused)
    invalid["refusal_code"] = "organization-mismatch"
    expect_invalid(lease_validator, invalid, "Claude organization code on Codex lease")
    claude_refusal = copy.deepcopy(refused)
    claude_refusal["provider"] = "claude"
    claude_refusal["profile_ref"] = "claude:automation-production"
    claude_refusal["refusal_code"] = "organization-mismatch"
    lease_validator.validate(claude_refusal)
    invalid = copy.deepcopy(claude_refusal)
    invalid["refusal_code"] = "workspace-mismatch"
    expect_invalid(lease_validator, invalid, "Codex workspace code on Claude lease")
    invalid = copy.deepcopy(active)
    invalid["expires_at"] = invalid["issued_at"]
    expect_semantic_invalid(
        lambda: validate_resolved_lease_semantics(invalid),
        "non-increasing active lease timestamps",
    )
    invalid = copy.deepcopy(active)
    invalid["status"] = "closed"
    invalid["execution_handle"] = None
    invalid["reason_code"] = "completed"
    invalid["expires_at"] = invalid["issued_at"]
    lease_validator.validate(invalid)
    expect_semantic_invalid(
        lambda: validate_resolved_lease_semantics(invalid),
        "non-increasing terminal resolved lease timestamps",
    )
    invalid = copy.deepcopy(active)
    invalid["isolation"] = "unproven"
    expect_invalid(lease_validator, invalid, "active lease with unproven isolation")
    invalid = copy.deepcopy(active)
    invalid["isolation"] = "copied-credential-development"
    expect_invalid(
        lease_validator,
        invalid,
        "copied-credential production implementer lease",
    )
    allowed_copied_review = copy.deepcopy(invalid)
    allowed_copied_review["role"] = "pr-reviewer"
    lease_validator.validate(allowed_copied_review)

    readiness_validator = validators["ctxlane.automation-readiness.v1.schema.json"]
    ready = examples["automation-readiness-ready.v1.json"]
    development = examples["automation-readiness-development-exception.v1.json"]
    nanosecond_ready = copy.deepcopy(ready)
    nanosecond_ready["checked_at"] = "2026-08-21T10:00:00.000000001Z"
    nanosecond_ready["valid_until"] = "2026-08-21T10:00:00.000000002Z"
    readiness_validator.validate(nanosecond_ready)
    validate_readiness_semantics(nanosecond_ready)
    invalid = copy.deepcopy(ready)
    invalid["ready"] = False
    expect_invalid(readiness_validator, invalid, "false result with all ready gates")
    invalid = copy.deepcopy(ready)
    invalid["checks"]["metadata-valid"] = {
        "status": "fail",
        "reason_code": "metadata-invalid",
    }
    expect_invalid(readiness_validator, invalid, "true result with failed core gate")
    invalid = copy.deepcopy(ready)
    invalid["checks"]["metadata-valid"]["reason_code"] = "metadata-invalid"
    expect_invalid(readiness_validator, invalid, "pass with non-null reason")
    invalid = copy.deepcopy(ready)
    invalid["checks"]["metadata-valid"] = {
        "status": "not-applicable",
        "reason_code": "not-applicable",
    }
    expect_invalid(readiness_validator, invalid, "not-applicable outside token check")
    invalid = copy.deepcopy(ready)
    invalid["ready"] = False
    invalid["checks"]["metadata-valid"] = {
        "status": "warn",
        "reason_code": "metadata-invalid",
    }
    expect_invalid(readiness_validator, invalid, "warning metadata-invalid status")
    invalid = copy.deepcopy(ready)
    invalid["ready"] = False
    invalid["checks"]["credential-source-available"] = {
        "status": "unknown",
        "reason_code": "credential-source-unavailable",
    }
    expect_invalid(readiness_validator, invalid, "unknown credential-source status")
    invalid = copy.deepcopy(ready)
    invalid["ready"] = False
    invalid["checks"]["provider-principal-verified"] = {
        "status": "warn",
        "reason_code": "probe-failed",
    }
    expect_invalid(readiness_validator, invalid, "warning probe-failed status")
    invalid = copy.deepcopy(ready)
    invalid["authentication_exception_acknowledged"] = True
    expect_invalid(readiness_validator, invalid, "WIF authentication exception")
    invalid = copy.deepcopy(ready)
    invalid["checks"]["identity-token-current"] = {
        "status": "not-applicable",
        "reason_code": "not-applicable",
    }
    expect_invalid(readiness_validator, invalid, "WIF token marked not applicable")
    invalid = copy.deepcopy(ready)
    invalid["isolation"] = "unproven"
    invalid["checks"]["credential-isolation-proven"] = {
        "status": "fail",
        "reason_code": "isolation-unproven",
    }
    expect_invalid(readiness_validator, invalid, "unproven isolation marked ready")
    invalid = copy.deepcopy(ready)
    invalid["ready"] = False
    invalid["checks"]["expected-tenant-verified"] = {
        "status": "fail",
        "reason_code": "organization-mismatch",
    }
    expect_invalid(readiness_validator, invalid, "Claude organization code on Codex readiness")
    invalid = copy.deepcopy(development)
    invalid["environment"] = "production"
    invalid["role"] = "implementer"
    expect_invalid(readiness_validator, invalid, "copied production implementer")
    allowed_pr_exception = copy.deepcopy(development)
    allowed_pr_exception["environment"] = "production"
    allowed_pr_exception["role"] = "pr-reviewer"
    allowed_pr_exception["authentication_exception_acknowledged"] = True
    allowed_pr_exception["checks"]["automation-policy-permits"] = {
        "status": "warn",
        "reason_code": "authentication-exception-acknowledged",
    }
    readiness_validator.validate(allowed_pr_exception)
    stale = copy.deepcopy(ready)
    stale["valid_until"] = stale["checked_at"]
    expect_semantic_invalid(
        lambda: validate_readiness_semantics(stale),
        "readiness with empty freshness interval",
    )
    invalid = copy.deepcopy(ready)
    invalid["probe_interactive"] = True
    expect_invalid(readiness_validator, invalid, "interactive readiness probe")

    error_validator = validators["ctxlane.automation-error.v1.schema.json"]
    error = examples["automation-error.v1.json"]
    invalid = copy.deepcopy(error)
    invalid["message"] = "backend response"
    expect_invalid(error_validator, invalid, "free-form automation error message")
    invalid = copy.deepcopy(error)
    invalid["retryable"] = True
    expect_invalid(error_validator, invalid, "arbitrary retryable hint")
    invalid = copy.deepcopy(error)
    invalid["code"] = "profile-not-ready"
    expect_invalid(error_validator, invalid, "refusal-only code on lease acquire")
    invalid = {
        "schema": "ctxlane.automation-error/v1",
        "operation": "lease-renew",
        "code": "generation-mismatch",
        "client_request_id": None,
        "lease_id": None,
    }
    expect_invalid(error_validator, invalid, "lease mutation error without lease ID")
    invalid["lease_id"] = active["lease_id"]
    error_validator.validate(invalid)
    invalid = copy.deepcopy(error)
    invalid["lease_id"] = active["lease_id"]
    expect_invalid(error_validator, invalid, "common error with lease ID")

    declared_operations = set(
        schemas["ctxlane.automation-error.v1.schema.json"]["properties"]["operation"]["enum"]
    )
    if declared_operations != set(NONCOMMON_ERROR_CODES):
        raise AssertionError("automation error operation enum differs from matrix")
    declared_codes = set(
        schemas["ctxlane.automation-error.v1.schema.json"]["properties"]["code"]["enum"]
    )
    expected_codes = COMMON_ERROR_CODES.union(*NONCOMMON_ERROR_CODES.values())
    if declared_codes != expected_codes:
        raise AssertionError("automation error code enum differs from matrix")
    for operation, operation_codes in NONCOMMON_ERROR_CODES.items():
        allowed_codes = COMMON_ERROR_CODES | operation_codes
        for code in declared_codes:
            for lease_id in (None, active["lease_id"]):
                candidate = {
                    "schema": "ctxlane.automation-error/v1",
                    "operation": operation,
                    "code": code,
                    "client_request_id": None,
                    "lease_id": lease_id,
                }
                expected_lease_id = (
                    active["lease_id"]
                    if code in operation_codes
                    and operation in NONCOMMON_ERRORS_REQUIRE_LEASE_ID
                    else None
                )
                should_be_valid = code in allowed_codes and lease_id == expected_lease_id
                if error_validator.is_valid(candidate) != should_be_valid:
                    raise AssertionError(
                        "automation error operation/code/lease_id matrix mismatch: "
                        f"{operation}/{code}/{lease_id!r}"
                    )

    print(
        f"validated {len(schemas)} schemas, {len(examples)} examples, "
        f"negative invariants, and signing vector"
    )


if __name__ == "__main__":
    main()
