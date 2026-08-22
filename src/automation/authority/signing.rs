use ed25519_dalek::{Signature, VerifyingKey};

use crate::automation::{
    attestation::AuthenticatedMessage,
    contracts::{Sha256Digest, UtcTimestamp, WorkOrderAuthorization},
};

use super::{AuthorityError, PreparedAuthority, ProofError, VerifiedWorkOrder};

pub(super) struct VerifiedClaims {
    key_id: crate::automation::contracts::KeyId,
    signed_message_digest: Sha256Digest,
}

impl PreparedAuthority {
    /// Verify an authorization parsed from this exact authenticated payload.
    ///
    /// This primitive binds and authenticates bytes; it does not prove that a
    /// separately supplied authorization came from them. A future service must
    /// parse `WorkOrderAuthorization` from `message.payload()` and pass that
    /// same value here. Supplying authorization from any other source would be
    /// a confused-deputy bug.
    pub(crate) fn verify_work_order(
        &self,
        message: &AuthenticatedMessage<'_>,
        authorization: &WorkOrderAuthorization,
        now: &UtcTimestamp,
    ) -> Result<VerifiedWorkOrder, ProofError> {
        if !message.assurance().permits_work_order_verification() {
            return Err(ProofError::WorkOrderProofInvalid);
        }
        message
            .revalidate(self)
            .map_err(|_| ProofError::WorkOrderProofInvalid)?;
        if message.host_identity() != &self.host_identity {
            return Err(ProofError::WorkOrderProofInvalid);
        }
        let controller = self
            .controllers
            .iter()
            .find(|value| value.subject == *message.subject())
            .filter(|value| *value == message.controller())
            .ok_or(ProofError::WorkOrderProofInvalid)?;
        let claims = self.verify_claims(controller, authorization, now)?;
        message
            .revalidate(self)
            .map_err(|_| ProofError::WorkOrderProofInvalid)?;
        Ok(VerifiedWorkOrder {
            caller_subject: message.subject().clone(),
            host_identity: message.host_identity().clone(),
            assurance: message.assurance(),
            attestation_binding: message.attestation_binding(),
            configuration_digest: self.configuration_digest(),
            key_id: claims.key_id,
            signed_message_digest: claims.signed_message_digest,
            authorization: authorization.clone(),
        })
    }

    pub(super) fn verify_claims(
        &self,
        controller: &super::PreparedController,
        authorization: &WorkOrderAuthorization,
        now: &UtcTimestamp,
    ) -> Result<VerifiedClaims, ProofError> {
        let key = self
            .signing_keys
            .iter()
            .find(|value| {
                value.key_id == authorization.key_id
                    && controller.signing_key_ids.contains(&value.key_id)
            })
            .ok_or(ProofError::WorkOrderProofInvalid)?;
        let message = authorization
            .signature_message()
            .map_err(|_| ProofError::WorkOrderProofInvalid)?;
        let signature = decode_signature(authorization.signature.as_str())?;
        key.verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| ProofError::WorkOrderProofInvalid)?;
        authorization
            .validate()
            .map_err(|_| ProofError::WorkOrderProofInvalid)?;
        if now.is_before(&authorization.not_before) || !now.is_before(&authorization.expires_at) {
            return Err(ProofError::WorkOrderProofInvalid);
        }
        if !controller.tenant_ids.contains(&authorization.tenant_id)
            || !controller.profile_uids.contains(&authorization.profile_uid)
            || !controller.providers.contains(&authorization.provider)
            || !controller.environments.contains(&authorization.environment)
            || !controller.roles.contains(&authorization.role)
            || !controller.repositories.contains(&authorization.repository)
            || !controller
                .workspace_ids
                .contains(&authorization.workspace_id)
            || authorization.maximum_ttl_seconds.get() > controller.maximum_ttl_seconds
            || authorization.maximum_session_seconds.get() > controller.maximum_session_seconds
        {
            return Err(ProofError::WorkOrderProofInvalid);
        }
        Ok(VerifiedClaims {
            key_id: authorization.key_id.clone(),
            signed_message_digest: Sha256Digest::hash(message),
        })
    }
}

pub(super) fn parse_verifying_key(value: &str) -> Result<VerifyingKey, AuthorityError> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or(AuthorityError::InvalidConfiguration)?;
    if encoded.len() != 64 {
        return Err(AuthorityError::InvalidConfiguration);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| AuthorityError::InvalidConfiguration)?;
    if key.is_weak() {
        return Err(AuthorityError::InvalidConfiguration);
    }
    Ok(key)
}

fn hex_nibble(value: u8) -> Result<u8, AuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityError::InvalidConfiguration),
    }
}

fn decode_signature(value: &str) -> Result<Signature, ProofError> {
    if value.len() != 86 {
        return Err(ProofError::WorkOrderProofInvalid);
    }
    let mut bytes = [0_u8; 64];
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let mut output = 0_usize;
    for byte in value.bytes() {
        let decoded = decode_base64url(byte).ok_or(ProofError::WorkOrderProofInvalid)?;
        accumulator = (accumulator << 6) | u32::from(decoded);
        bits = bits.saturating_add(6);
        while bits >= 8 {
            bits -= 8;
            if output >= bytes.len() {
                return Err(ProofError::WorkOrderProofInvalid);
            }
            bytes[output] =
                u8::try_from(accumulator >> bits).map_err(|_| ProofError::WorkOrderProofInvalid)?;
            output += 1;
            accumulator &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if output != bytes.len() || bits != 4 || accumulator != 0 {
        return Err(ProofError::WorkOrderProofInvalid);
    }
    Ok(Signature::from_bytes(&bytes))
}

const fn decode_base64url(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_keys_and_noncanonical_text_encodings_are_rejected() {
        for value in [
            "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
            "ed25519:3E7AC95170AC322C7CBD342E12E5E0AF36F21375ED128C33372E73810D05BFF9",
            "3e7ac95170ac322c7cbd342e12e5e0af36f21375ed128c33372e73810d05bff9",
            "ed25519:00",
        ] {
            assert_eq!(
                parse_verifying_key(value),
                Err(AuthorityError::InvalidConfiguration)
            );
        }
    }

    #[test]
    fn published_signature_decodes_exactly() {
        let value = "jLtlv6wVNme_sIhGEIcT25hnhY4YrkAwOolb60L22TWa9DRkudNgfEAxrBSrCm3YXjvFIRsujAKizOeO7wjrAw";
        assert!(decode_signature(value).is_ok());
        let mut changed = value.to_owned();
        changed.replace_range(85..86, "B");
        assert_eq!(
            decode_signature(&changed),
            Err(ProofError::WorkOrderProofInvalid)
        );
    }
}
