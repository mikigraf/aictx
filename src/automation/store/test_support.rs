use core::str::FromStr;

use crate::{
    automation::contracts::{IdentityLeaseRequest, ProfileRef},
    config::{AppPaths, MetadataStore},
    management::{ProfileDraft, add_profile},
    model::{CodexAuth, CodexCredentialStore, InstallationUid, Name, ProfileUid},
};

pub(super) struct TestAutomationProfile {
    pub(super) installation: InstallationUid,
    pub(super) profile_uid: ProfileUid,
    profile_ref: ProfileRef,
}

impl TestAutomationProfile {
    pub(super) fn install(paths: &AppPaths) -> Self {
        let store = MetadataStore::new(paths.clone());
        store
            .initialize()
            .unwrap_or_else(|error| panic!("metadata initialize: {error}"));
        let receipt = add_profile(
            &store,
            ProfileDraft::Codex {
                name: Name::parse("automation-production")
                    .unwrap_or_else(|error| panic!("profile name: {error}")),
                auth: CodexAuth::ChatgptOauth,
                secret_ref: None,
                account_hint: None,
                expected_workspace_id: None,
                credential_store: CodexCredentialStore::File,
                trusted_runners_only: false,
                wif: None,
            },
        )
        .unwrap_or_else(|error| panic!("add profile: {error}"));
        let installation = store
            .load_config()
            .unwrap_or_else(|error| panic!("load metadata: {error}"))
            .installation_uid;
        let profile_ref = ProfileRef::from_str(&receipt.id.to_string())
            .unwrap_or_else(|error| panic!("profile ref: {error:?}"));
        Self {
            installation,
            profile_uid: receipt.profile_uid,
            profile_ref,
        }
    }

    pub(super) fn bind_request(&self, request: &mut IdentityLeaseRequest) {
        request.profile_ref = self.profile_ref.clone();
        request.profile_uid = self.profile_uid.clone();
        request.work_order_authorization.profile_ref = self.profile_ref.clone();
        request.work_order_authorization.profile_uid = self.profile_uid.clone();
    }
}
