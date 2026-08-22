use crate::automation::contracts::{LeaseStatus, UtcTimestamp};

use crate::automation::store::StoreError;

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum ProcessAuditProjection {
    None,
    LaunchIntent {
        launch_intent_at: UtcTimestamp,
        observed_fence: u64,
    },
    Started {
        launch_intent_at: UtcTimestamp,
        started_at: UtcTimestamp,
        observed_fence: u64,
    },
}

impl ProcessAuditProjection {
    pub(crate) fn transition(
        &self,
        event_type: &str,
        prior_status: LeaseStatus,
        event_at: &UtcTimestamp,
        fencing_generation: Option<u64>,
    ) -> Result<Self, StoreError> {
        let fence = || fencing_generation.ok_or(StoreError::IntegrityCheckFailed);
        match (event_type, self) {
            ("process.launch-intent", Self::None) if prior_status == LeaseStatus::Active => {
                Ok(Self::LaunchIntent {
                    launch_intent_at: event_at.clone(),
                    observed_fence: fence()?,
                })
            }
            (
                "process.started",
                Self::LaunchIntent {
                    launch_intent_at,
                    observed_fence,
                },
            ) if prior_status == LeaseStatus::Active
                && Some(*observed_fence) == fencing_generation =>
            {
                Ok(Self::Started {
                    launch_intent_at: launch_intent_at.clone(),
                    started_at: event_at.clone(),
                    observed_fence: *observed_fence,
                })
            }
            ("process.exited", Self::LaunchIntent { .. } | Self::Started { .. }) => Ok(Self::None),
            ("lease.renewing", Self::LaunchIntent { .. }) => Err(StoreError::IntegrityCheckFailed),
            (
                "lease.renewed",
                Self::Started {
                    launch_intent_at,
                    started_at,
                    ..
                },
            ) => Ok(Self::Started {
                launch_intent_at: launch_intent_at.clone(),
                started_at: started_at.clone(),
                observed_fence: fence()?,
            }),
            ("process.launch-intent" | "process.started" | "process.exited", _) => {
                Err(StoreError::IntegrityCheckFailed)
            }
            _ => Ok(self.clone()),
        }
    }
}
