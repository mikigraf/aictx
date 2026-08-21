use serde::Deserialize;

pub(super) fn deserialize_bounded_u64<'de, D>(
    deserializer: D,
    minimum: u64,
    maximum: u64,
) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    parse_unsigned_integral(raw.get().trim(), maximum)
        .filter(|value| *value >= minimum)
        .ok_or_else(|| {
            serde::de::Error::custom(format_args!(
                "expected an integral JSON number between {minimum} and {maximum}"
            ))
        })
}

fn parse_unsigned_integral(value: &str, maximum: u64) -> Option<u64> {
    if value.starts_with('-') {
        return None;
    }
    let (mantissa, exponent) = match value.find(['e', 'E']) {
        Some(index) => (&value[..index], value[index + 1..].parse::<i128>().ok()?),
        None => (value, 0),
    };
    let (whole, fraction) = match mantissa.split_once('.') {
        Some(parts) => parts,
        None => (mantissa, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut digits = String::with_capacity(whole.len() + fraction.len());
    digits.push_str(whole);
    digits.push_str(fraction);
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Some(0);
    }

    let fraction_len = i128::try_from(fraction.len()).ok()?;
    let scale = exponent.checked_sub(fraction_len)?;
    if scale >= 0 {
        let zeroes = usize::try_from(scale).ok()?;
        if significant.len().checked_add(zeroes)? > 20 {
            return None;
        }
        let value = parse_digits(significant, maximum)?;
        multiply_by_power_of_ten(value, zeroes, maximum)
    } else {
        let removed = usize::try_from(scale.checked_neg()?).ok()?;
        if removed >= significant.len() {
            return None;
        }
        let split = significant.len() - removed;
        if !significant.as_bytes()[split..]
            .iter()
            .all(|byte| *byte == b'0')
        {
            return None;
        }
        parse_digits(&significant[..split], maximum)
    }
}

fn parse_digits(digits: &str, maximum: u64) -> Option<u64> {
    let mut value = 0_u64;
    for digit in digits.bytes() {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
        if value > maximum {
            return None;
        }
    }
    Some(value)
}

fn multiply_by_power_of_ten(mut value: u64, zeroes: usize, maximum: u64) -> Option<u64> {
    for _ in 0..zeroes {
        value = value.checked_mul(10)?;
        if value > maximum {
            return None;
        }
    }
    Some(value)
}
