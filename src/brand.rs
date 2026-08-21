//! Stable product labels used during the `aictx` to `ctxlane` transition.

pub(crate) const LEGACY_PRODUCT_LABEL: &str = "aictx";
pub(crate) const TARGET_PRODUCT_LABEL: &str = "ctxlane";
pub(crate) const CURRENT_PRODUCT_LABEL: &str = TARGET_PRODUCT_LABEL;

pub(crate) const LEGACY_ENVIRONMENT_PREFIX: &str = "AICTX_";
pub(crate) const TARGET_ENVIRONMENT_PREFIX: &str = "CTXLANE_";

pub(crate) fn is_wrapper_environment_key(key: &str) -> bool {
    [LEGACY_ENVIRONMENT_PREFIX, TARGET_ENVIRONMENT_PREFIX]
        .iter()
        .any(|prefix| {
            key.get(..prefix.len())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        })
}

#[cfg(test)]
mod tests {
    use super::is_wrapper_environment_key;

    #[test]
    fn wrapper_environment_prefixes_cover_current_target_and_future_keys() {
        for (key, expected) in [
            ("AICTX_PROFILE", true),
            ("AICTX_FUTURE_SELECTOR", true),
            ("aictx_lowercase_future", true),
            ("CTXLANE_CONTEXT", true),
            ("CTXLANE_FUTURE_SELECTOR", true),
            ("ctxlane_lowercase_future", true),
            ("AICTX", false),
            ("CTXLANE", false),
            ("NOT_AICTX_PROFILE", false),
            ("LANG", false),
        ] {
            assert_eq!(is_wrapper_environment_key(key), expected, "key={key}");
        }
    }
}
