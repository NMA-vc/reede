use crate::error::ReedeError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ReservationId(pub Uuid);

#[derive(Debug, Clone)]
pub struct ReservationRecord {
    pub id: ReservationId,
    pub task_id: Uuid,
    pub tenant_id: String,
    pub amount: i64,
    pub created_at: Instant,
    pub settled: bool,
}

#[async_trait]
pub trait Ledger: Send + Sync {
    async fn reserve(
        &self,
        task_id: Uuid,
        tenant_id: &str,
        amount: i64,
    ) -> Result<ReservationId, ReedeError>;

    async fn deduct(&self, reservation: ReservationId, actual: i64) -> Result<(), ReedeError>;

    async fn release(&self, reservation: ReservationId) -> Result<(), ReedeError>;

    async fn balance(&self, tenant_id: &str) -> Result<i64, ReedeError>;

    async fn recover_stranded(
        &self,
        older_than: Duration,
    ) -> Result<Vec<ReservationId>, ReedeError>;
}

/// Thread-safe in-memory ledger implementation for open-core runtime and unit testing.
pub struct InMemoryLedger {
    balances: Mutex<HashMap<String, i64>>,
    reservations: Mutex<HashMap<ReservationId, ReservationRecord>>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self {
            balances: Mutex::new(HashMap::new()),
            reservations: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_balance(&self, tenant_id: &str, balance: i64) {
        let mut balances = self.balances.lock().unwrap();
        balances.insert(tenant_id.to_string(), balance);
    }
}

impl Default for InMemoryLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Ledger for InMemoryLedger {
    async fn reserve(
        &self,
        task_id: Uuid,
        tenant_id: &str,
        amount: i64,
    ) -> Result<ReservationId, ReedeError> {
        if amount <= 0 {
            return Err(ReedeError::LedgerFailed {
                reason: format!("reserve amount must be positive, got {amount}"),
            });
        }
        let mut balances = self.balances.lock().unwrap();
        let mut reservations = self.reservations.lock().unwrap();

        let current_balance = balances.get(tenant_id).copied().unwrap_or(0);
        if current_balance < amount {
            return Err(ReedeError::BudgetExhausted {
                spent_eur: format!("{:.2}", amount as f64 / 100.0),
                ceiling_eur: format!("{:.2}", current_balance as f64 / 100.0),
            });
        }

        // Atomic check and reserve
        balances.insert(tenant_id.to_string(), current_balance - amount);

        let res_id = ReservationId(Uuid::new_v4());
        reservations.insert(
            res_id,
            ReservationRecord {
                id: res_id,
                task_id,
                tenant_id: tenant_id.to_string(),
                amount,
                created_at: Instant::now(),
                settled: false,
            },
        );

        Ok(res_id)
    }

    async fn deduct(&self, reservation: ReservationId, actual: i64) -> Result<(), ReedeError> {
        if actual < 0 {
            return Err(ReedeError::LedgerFailed {
                reason: format!("deduct actual must not be negative, got {actual}"),
            });
        }
        let mut balances = self.balances.lock().unwrap();
        let mut reservations = self.reservations.lock().unwrap();

        let record =
            reservations
                .get_mut(&reservation)
                .ok_or_else(|| ReedeError::LedgerFailed {
                    reason: format!("ReservationId {:?} not found", reservation.0),
                })?;

        if record.settled {
            return Err(ReedeError::LedgerFailed {
                reason: format!("ReservationId {:?} is already settled", reservation.0),
            });
        }

        record.settled = true;
        let diff = record.amount - actual;

        // Refund any unused reserved credits back to the tenant's balance
        let current_balance = balances.get(&record.tenant_id).copied().unwrap_or(0);
        balances.insert(record.tenant_id.clone(), current_balance + diff);

        Ok(())
    }

    async fn release(&self, reservation: ReservationId) -> Result<(), ReedeError> {
        let mut balances = self.balances.lock().unwrap();
        let mut reservations = self.reservations.lock().unwrap();

        let record =
            reservations
                .get_mut(&reservation)
                .ok_or_else(|| ReedeError::LedgerFailed {
                    reason: format!("ReservationId {:?} not found", reservation.0),
                })?;

        if record.settled {
            return Err(ReedeError::LedgerFailed {
                reason: format!("ReservationId {:?} is already settled", reservation.0),
            });
        }

        record.settled = true;

        // Refund full reservation back to balance
        let current_balance = balances.get(&record.tenant_id).copied().unwrap_or(0);
        balances.insert(record.tenant_id.clone(), current_balance + record.amount);

        Ok(())
    }

    async fn balance(&self, tenant_id: &str) -> Result<i64, ReedeError> {
        let balances = self.balances.lock().unwrap();
        Ok(balances.get(tenant_id).copied().unwrap_or(0))
    }

    async fn recover_stranded(
        &self,
        older_than: Duration,
    ) -> Result<Vec<ReservationId>, ReedeError> {
        let mut balances = self.balances.lock().unwrap();
        let mut reservations = self.reservations.lock().unwrap();
        let now = Instant::now();

        let mut recovered = Vec::new();
        for record in reservations.values_mut() {
            if !record.settled && now.duration_since(record.created_at) >= older_than {
                record.settled = true;
                let current_balance = balances.get(&record.tenant_id).copied().unwrap_or(0);
                balances.insert(record.tenant_id.clone(), current_balance + record.amount);
                recovered.push(record.id);
            }
        }

        Ok(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reserve_rejects_non_positive_amounts() {
        let ledger = InMemoryLedger::new();
        ledger.set_balance("t", 100);
        for amount in [0, -50] {
            let err = ledger
                .reserve(Uuid::new_v4(), "t", amount)
                .await
                .unwrap_err();
            assert!(
                matches!(err, ReedeError::LedgerFailed { .. }),
                "{amount}: {err:?}"
            );
            assert_eq!(ledger.balance("t").await.unwrap(), 100, "no credits minted");
        }
        ledger
            .reserve(Uuid::new_v4(), "t", 1)
            .await
            .expect("one credit reserves");
        assert_eq!(ledger.balance("t").await.unwrap(), 99);
    }

    #[tokio::test]
    async fn deduct_rejects_negative_actual_and_charges_overrun() {
        let ledger = InMemoryLedger::new();
        ledger.set_balance("t", 100);
        let res = ledger.reserve(Uuid::new_v4(), "t", 40).await.unwrap();
        let err = ledger.deduct(res, -10).await.unwrap_err();
        assert!(matches!(err, ReedeError::LedgerFailed { .. }));
        assert_eq!(
            ledger.balance("t").await.unwrap(),
            60,
            "refused deduct changed nothing"
        );
        // The reservation is still live, and an overrun is charged in full (trait contract).
        ledger.deduct(res, 55).await.expect("overrun settles");
        assert_eq!(ledger.balance("t").await.unwrap(), 45);
        let res = ledger.reserve(Uuid::new_v4(), "t", 5).await.unwrap();
        ledger.deduct(res, 0).await.expect("zero is a valid spend");
        assert_eq!(ledger.balance("t").await.unwrap(), 45);
    }

    #[tokio::test]
    async fn test_ledger_both_directions() {
        let ledger = InMemoryLedger::new();
        let tenant = "tenant-test";
        let task_id = Uuid::new_v4();

        // 1. Initial balance 100 credits
        ledger.set_balance(tenant, 100);
        assert_eq!(ledger.balance(tenant).await.unwrap(), 100);

        // 2. Reserve succeeds with sufficient balance
        let res_id = ledger.reserve(task_id, tenant, 40).await.unwrap();
        assert_eq!(ledger.balance(tenant).await.unwrap(), 60);

        // 3. Reserve fails without sufficient balance
        let err = ledger.reserve(task_id, tenant, 70).await.unwrap_err();
        assert!(matches!(err, ReedeError::BudgetExhausted { .. }));

        // 4. Deduct actual spend (30 out of 40 reserved, 10 refunded)
        ledger.deduct(res_id, 30).await.unwrap();
        assert_eq!(ledger.balance(tenant).await.unwrap(), 70);

        // 5. Double deduct fails
        let err2 = ledger.deduct(res_id, 10).await.unwrap_err();
        assert!(matches!(err2, ReedeError::LedgerFailed { .. }));
    }

    #[tokio::test]
    async fn test_ledger_release_and_recovery() {
        let ledger = InMemoryLedger::new();
        let tenant = "tenant-recover";
        let task_id = Uuid::new_v4();

        ledger.set_balance(tenant, 100);

        // Reserve 50
        let res1 = ledger.reserve(task_id, tenant, 50).await.unwrap();
        assert_eq!(ledger.balance(tenant).await.unwrap(), 50);

        // Explicit release refunds 50
        ledger.release(res1).await.unwrap();
        assert_eq!(ledger.balance(tenant).await.unwrap(), 100);

        // Stranded recovery test
        let _res2 = ledger.reserve(task_id, tenant, 30).await.unwrap();
        assert_eq!(ledger.balance(tenant).await.unwrap(), 70);

        // Recover stranded reservations older than 0 seconds
        let recovered = ledger
            .recover_stranded(Duration::from_secs(0))
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(ledger.balance(tenant).await.unwrap(), 100);
    }
}
