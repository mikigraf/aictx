use crate::{
    automation::contracts::IsolationClassification, model::SharedStateIsolationRequirement,
};

pub(super) const fn valid_shared_resource_isolation(
    isolation: IsolationClassification,
    shared: Option<SharedStateIsolationRequirement>,
) -> bool {
    matches!(
        (isolation, shared),
        (
            IsolationClassification::CredentialIsolated,
            Some(SharedStateIsolationRequirement::Stateless)
        ) | (
            IsolationClassification::PerLeaseIsolated,
            Some(SharedStateIsolationRequirement::PerLeaseIsolated)
        )
    )
}
