//! Producer contract and watermark store.
//!
//! A producer is a small component that emits normalized `Signal`s,
//! so adding a feedback source never touches the store, the reducers, or the
//! envelope. Every producer is *push*: it is handed a `Signal` (webhook, UI
//! event, a human's decision) and it lands.
//!
//! An earlier cleanup deleted the rest of what this module used to hold: the
//! `ProducerRegistry` (binding table, poll scheduler, backoff, telemetry), its
//! `run_scheduler_forever` loop, the *poll* mode and `PollBatch`, and `FnProducer`.
//! Nothing outside Reede ever called them, and the only poll producer
//! (`AnalyticsPoller`) had no `AnalyticsSource` implementation anywhere, so the
//! scheduler had nothing to drive. If a poll producer is ever bound for real, write
//! the loop beside the thing that needs it.
//!
//! This module is host-independent (Reede stays standalone). The concrete producers that
//! know host domain events implement `SignalProducer` in the host runtime
//! (which already depends on Reede), inverting the dependency per the Reede
//! one-way rule: Reede defines the trait, the host implements it.

use crate::error::ReedeError;
use crate::signal::Signal;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

/// A watermark lookup key: (producer, tenant, agent, capability).
type WatermarkKey = (String, String, String, String);

/// The one contract a feedback source implements to become a producer.
#[async_trait]
pub trait SignalProducer: Send + Sync {
    /// Stable, unique producer id (the `source` stamped on every `Signal` it
    /// emits, e.g. `rating`, `diff-capture`, `nakiek`).
    fn id(&self) -> &str;

    /// Schema version stamped as `source_version` on emitted signals.
    fn source_version(&self) -> &str;

    /// Push entry point: the producer is handed a signal.
    async fn push(&self, signal: Signal) -> Result<(), ReedeError>;
}

/// Persists "how far has this consumer got" per `(producer, tenant, agent, capability)`, so a
/// re-run is safe. The reduction tick books its progress here (see
/// [`crate::reducer::REDUCER_WATERMARK_ID`]).
#[async_trait]
pub trait WatermarkStore: Send + Sync {
    /// The last persisted watermark for a `(producer, tenant, agent, capability)`.
    async fn get(
        &self,
        producer_id: &str,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<DateTime<Utc>>, ReedeError>;

    /// Persist a watermark (monotonic up).
    async fn put(
        &self,
        producer_id: &str,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        watermark: DateTime<Utc>,
    ) -> Result<(), ReedeError>;
}

/// In-memory watermark persistence.
pub struct InMemoryWatermarkStore {
    map: Mutex<HashMap<WatermarkKey, DateTime<Utc>>>,
}

impl InMemoryWatermarkStore {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryWatermarkStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WatermarkStore for InMemoryWatermarkStore {
    async fn get(
        &self,
        producer_id: &str,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<DateTime<Utc>>, ReedeError> {
        let map = self.map.lock().unwrap();
        Ok(map
            .get(&(
                producer_id.to_string(),
                tenant_id.to_string(),
                agent_id.to_string(),
                capability.to_string(),
            ))
            .copied())
    }

    async fn put(
        &self,
        producer_id: &str,
        tenant_id: &str,
        agent_id: &str,
        capability: &str,
        watermark: DateTime<Utc>,
    ) -> Result<(), ReedeError> {
        let mut map = self.map.lock().unwrap();
        map.insert(
            (
                producer_id.to_string(),
                tenant_id.to_string(),
                agent_id.to_string(),
                capability.to_string(),
            ),
            watermark,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_watermark_is_scoped_to_its_producer_tenant_agent_and_capability() {
        let store = InMemoryWatermarkStore::new();
        let at = Utc::now();
        assert!(store
            .get("reducer", "t1", "a1", "c1")
            .await
            .unwrap()
            .is_none());

        store.put("reducer", "t1", "a1", "c1", at).await.unwrap();

        assert_eq!(
            store.get("reducer", "t1", "a1", "c1").await.unwrap(),
            Some(at)
        );
        assert!(store
            .get("reducer", "t2", "a1", "c1")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get("reducer", "t1", "a1", "c2")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get("poller", "t1", "a1", "c1")
            .await
            .unwrap()
            .is_none());
    }
}
