use crate::error::ReedeError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LeaseId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialLease {
    pub id: LeaseId,
    pub task_id: Uuid,
    pub secret_ref: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

impl CredentialLease {
    pub fn is_active(&self) -> bool {
        !self.revoked && Utc::now() < self.expires_at
    }
}

#[async_trait]
pub trait LeaseManager: Send + Sync {
    async fn issue(
        &self,
        task_id: Uuid,
        secret_ref: &str,
        ttl: Duration,
    ) -> Result<CredentialLease, ReedeError>;

    async fn check(&self, lease_id: LeaseId) -> Result<CredentialLease, ReedeError>;

    async fn revoke(&self, lease_id: LeaseId) -> Result<(), ReedeError>;

    async fn revoke_all_for_task(&self, task_id: Uuid) -> Result<u32, ReedeError>;
}

pub struct InMemoryLeaseManager {
    leases: Mutex<HashMap<LeaseId, CredentialLease>>,
}

impl InMemoryLeaseManager {
    pub fn new() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryLeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LeaseManager for InMemoryLeaseManager {
    async fn issue(
        &self,
        task_id: Uuid,
        secret_ref: &str,
        ttl: Duration,
    ) -> Result<CredentialLease, ReedeError> {
        let now = Utc::now();
        let chrono_ttl = chrono::Duration::from_std(ttl).map_err(|e| ReedeError::LeaseExpired {
            task_id: task_id.to_string(),
            secret_ref: format!("Invalid TTL duration: {e}"),
        })?;

        let lease = CredentialLease {
            id: LeaseId(Uuid::new_v4()),
            task_id,
            secret_ref: secret_ref.to_string(),
            issued_at: now,
            expires_at: now + chrono_ttl,
            revoked: false,
        };

        let mut leases = self.leases.lock().unwrap();
        leases.insert(lease.id, lease.clone());
        Ok(lease)
    }

    async fn check(&self, lease_id: LeaseId) -> Result<CredentialLease, ReedeError> {
        let leases = self.leases.lock().unwrap();
        let lease = leases
            .get(&lease_id)
            .ok_or_else(|| ReedeError::LeaseExpired {
                task_id: "unknown".to_string(),
                secret_ref: format!("LeaseId {:?} not found", lease_id.0),
            })?;

        if lease.revoked {
            return Err(ReedeError::LeaseRevoked {
                task_id: lease.task_id.to_string(),
                secret_ref: lease.secret_ref.clone(),
            });
        }

        if Utc::now() >= lease.expires_at {
            return Err(ReedeError::LeaseExpired {
                task_id: lease.task_id.to_string(),
                secret_ref: lease.secret_ref.clone(),
            });
        }

        Ok(lease.clone())
    }

    async fn revoke(&self, lease_id: LeaseId) -> Result<(), ReedeError> {
        let mut leases = self.leases.lock().unwrap();
        let lease = leases
            .get_mut(&lease_id)
            .ok_or_else(|| ReedeError::LeaseExpired {
                task_id: "unknown".to_string(),
                secret_ref: format!("LeaseId {:?} not found", lease_id.0),
            })?;

        lease.revoked = true;
        Ok(())
    }

    async fn revoke_all_for_task(&self, task_id: Uuid) -> Result<u32, ReedeError> {
        let mut leases = self.leases.lock().unwrap();
        let mut count = 0u32;
        for lease in leases.values_mut() {
            if lease.task_id == task_id && !lease.revoked {
                lease.revoked = true;
                count += 1;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lease_lifecycle_both_directions() {
        let mgr = InMemoryLeaseManager::new();
        let task_id = Uuid::new_v4();

        // 1. Issue lease with 1 hour TTL
        let lease = mgr
            .issue(task_id, "api_key_db", Duration::from_secs(3600))
            .await
            .unwrap();

        // 2. Check active lease passes
        let checked = mgr.check(lease.id).await.unwrap();
        assert_eq!(checked.secret_ref, "api_key_db");
        assert!(checked.is_active());

        // 3. Revoke lease mid-run causes next check to fail closed
        mgr.revoke(lease.id).await.unwrap();
        let err = mgr.check(lease.id).await.unwrap_err();
        assert!(matches!(err, ReedeError::LeaseRevoked { .. }));

        // 4. Issue lease with zero TTL (expired immediately)
        let expired_lease = mgr
            .issue(task_id, "short_token", Duration::from_millis(0))
            .await
            .unwrap();
        let err2 = mgr.check(expired_lease.id).await.unwrap_err();
        assert!(matches!(err2, ReedeError::LeaseExpired { .. }));
    }
}
