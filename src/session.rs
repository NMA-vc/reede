use crate::error::ReedeError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    pub id: Uuid,
    pub agent_spec_id: String,
    pub tenant_id: String,
    pub state: SessionState,
    pub tasks: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Session {
    pub fn new(agent_spec_id: impl Into<String>, tenant_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            agent_spec_id: agent_spec_id.into(),
            tenant_id: tenant_id.into(),
            state: SessionState::Active,
            tasks: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[async_trait]
pub trait SessionManager: Send + Sync {
    async fn create_session(
        &self,
        agent_spec_id: &str,
        tenant_id: &str,
    ) -> Result<Session, ReedeError>;
    async fn get_session(&self, session_id: Uuid) -> Result<Session, ReedeError>;
    async fn suspend_session(&self, session_id: Uuid) -> Result<(), ReedeError>;
    async fn terminate_session(&self, session_id: Uuid) -> Result<(), ReedeError>;
}
