const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub(super) const AUDIT_PREFIX: &str = "audit_";
pub(super) const LEASE_PREFIX: &str = "lease_";
pub(super) const REQUEST_PREFIX: &str = "request_";
pub(super) const SERVICE_PREFIX: &str = "service_";
pub(super) const STORE_PREFIX: &str = "store_";
pub(super) const COLLISION_RETRIES: usize = 16;

pub(super) fn random_id(prefix: &str) -> Result<String, ()> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    Ok(format!("{prefix}{}", encode_crockford(bytes)))
}

fn encode_crockford(bytes: [u8; 16]) -> String {
    let mut value = u128::from_be_bytes(bytes);
    let mut encoded = [b'0'; 26];
    for byte in encoded.iter_mut().rev() {
        *byte = CROCKFORD[(value & 0x1f) as usize];
        value >>= 5;
    }
    encoded.into_iter().map(char::from).collect()
}

#[cfg(test)]
mod tests {
    use super::{LEASE_PREFIX, encode_crockford, random_id};

    #[test]
    fn crockford_encoding_is_fixed_width_and_canonical() {
        assert_eq!(encode_crockford([0; 16]), "00000000000000000000000000");
        assert_eq!(
            encode_crockford([u8::MAX; 16]),
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
        );
        let generated = random_id(LEASE_PREFIX).unwrap_or_else(|()| panic!("randomness"));
        assert_eq!(generated.len(), 32);
        assert!(generated.starts_with(LEASE_PREFIX));
    }
}
