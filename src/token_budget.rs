//! Hard per-task token ceilings.
//!
//! A caller must reserve an upper bound before starting a model call and then
//! settle that reservation with the provider-reported input+output usage. The
//! reservation is the concurrency guard: two calls cannot both observe the
//! same remaining capacity and overspend it. An underestimated upper bound is
//! treated as a fail-closed accounting error and marks the budget exhausted.

use crate::error::ReedeError;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBudgetSnapshot {
    pub limit_tokens: u64,
    pub consumed_tokens: u64,
    pub reserved_tokens: u64,
    pub exhausted: bool,
}

#[derive(Debug)]
struct State {
    consumed_tokens: u64,
    reserved_tokens: u64,
    exhausted: bool,
}

/// A task-scoped hard token ceiling.
#[derive(Debug)]
pub struct TokenBudget {
    limit_tokens: u64,
    state: Mutex<State>,
}

impl TokenBudget {
    pub fn new(limit_tokens: u64) -> Self {
        Self {
            limit_tokens,
            state: Mutex::new(State {
                consumed_tokens: 0,
                reserved_tokens: 0,
                exhausted: limit_tokens == 0,
            }),
        }
    }

    /// Reserve the maximum number of tokens a model call may consume.
    ///
    /// This must happen before dispatching the call. The reservation is
    /// released automatically if its guard is dropped without settlement.
    pub fn begin(self: &Arc<Self>, max_tokens: u64) -> Result<TokenReservation, ReedeError> {
        let mut state = self.state.lock().expect("token budget mutex poisoned");
        let available = self
            .limit_tokens
            .saturating_sub(state.consumed_tokens.saturating_add(state.reserved_tokens));

        if state.exhausted || max_tokens > available {
            return Err(self.exhausted_error(max_tokens, &state));
        }

        state.reserved_tokens = state.reserved_tokens.saturating_add(max_tokens);
        Ok(TokenReservation {
            budget: Arc::clone(self),
            max_tokens,
            settled: false,
        })
    }

    /// Consume already-measured usage when no concurrent call reservation is
    /// needed. Callers issuing model requests should prefer [`Self::begin`].
    pub fn consume(&self, tokens: u64) -> Result<(), ReedeError> {
        let mut state = self.state.lock().expect("token budget mutex poisoned");
        let next = state.consumed_tokens.saturating_add(tokens);
        if state.exhausted || next > self.limit_tokens {
            state.exhausted = true;
            state.consumed_tokens = next;
            return Err(self.exhausted_error(tokens, &state));
        }
        state.consumed_tokens = next;
        if next == self.limit_tokens {
            state.exhausted = true;
        }
        Ok(())
    }

    pub fn snapshot(&self) -> TokenBudgetSnapshot {
        let state = self.state.lock().expect("token budget mutex poisoned");
        TokenBudgetSnapshot {
            limit_tokens: self.limit_tokens,
            consumed_tokens: state.consumed_tokens,
            reserved_tokens: state.reserved_tokens,
            exhausted: state.exhausted,
        }
    }

    pub fn remaining_tokens(&self) -> u64 {
        let state = self.state.lock().expect("token budget mutex poisoned");
        self.limit_tokens
            .saturating_sub(state.consumed_tokens.saturating_add(state.reserved_tokens))
    }

    fn settle(&self, max_tokens: u64, actual_tokens: u64) -> Result<(), ReedeError> {
        let mut state = self.state.lock().expect("token budget mutex poisoned");
        state.reserved_tokens = state.reserved_tokens.saturating_sub(max_tokens);
        let next = state.consumed_tokens.saturating_add(actual_tokens);
        state.consumed_tokens = next;

        // A provider response that exceeds its declared reservation is an
        // accounting violation. Record the actual usage and fail closed.
        let exceeded_reservation = actual_tokens > max_tokens;
        let exceeded_limit = next > self.limit_tokens;
        if exceeded_reservation || exceeded_limit {
            state.exhausted = true;
            return Err(self.exhausted_error(actual_tokens, &state));
        }

        if next == self.limit_tokens {
            state.exhausted = true;
        }
        Ok(())
    }

    fn release(&self, max_tokens: u64) {
        let mut state = self.state.lock().expect("token budget mutex poisoned");
        state.reserved_tokens = state.reserved_tokens.saturating_sub(max_tokens);
    }

    fn exhausted_error(&self, requested_tokens: u64, state: &State) -> ReedeError {
        ReedeError::TokenBudgetExhausted {
            consumed_tokens: state.consumed_tokens.saturating_add(state.reserved_tokens),
            limit_tokens: self.limit_tokens,
            requested_tokens,
        }
    }
}

/// Reservation guard for one model call.
#[derive(Debug)]
pub struct TokenReservation {
    budget: Arc<TokenBudget>,
    max_tokens: u64,
    settled: bool,
}

impl TokenReservation {
    pub fn max_tokens(&self) -> u64 {
        self.max_tokens
    }

    /// Settle with the provider's actual input+output token count.
    pub fn commit(mut self, actual_tokens: u64) -> Result<(), ReedeError> {
        self.settled = true;
        self.budget.settle(self.max_tokens, actual_tokens)
    }

    /// Settle directly from the gateway's separate input/output counters.
    pub fn commit_usage(self, tokens_in: u32, tokens_out: u32) -> Result<(), ReedeError> {
        self.commit(u64::from(tokens_in) + u64::from(tokens_out))
    }

    /// Cancel a call before a provider response is received.
    pub fn abort(mut self) {
        self.settled = true;
        self.budget.release(self.max_tokens);
    }
}

impl Drop for TokenReservation {
    fn drop(&mut self) {
        if !self.settled {
            self.budget.release(self.max_tokens);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn clean_usage_stays_under_the_cap() {
        let budget = Arc::new(TokenBudget::new(100));
        let reservation = budget.begin(60).unwrap();
        reservation.commit(40).unwrap();

        assert_eq!(budget.remaining_tokens(), 60);
        assert_eq!(
            budget.snapshot(),
            TokenBudgetSnapshot {
                limit_tokens: 100,
                consumed_tokens: 40,
                reserved_tokens: 0,
                exhausted: false,
            }
        );
    }

    #[test]
    fn reaching_the_cap_refuses_the_next_call() {
        let budget = Arc::new(TokenBudget::new(10));
        budget.begin(10).unwrap().commit(10).unwrap();

        let err = budget.begin(1).unwrap_err();
        assert!(matches!(err, ReedeError::TokenBudgetExhausted { .. }));
        assert!(budget.snapshot().exhausted);
    }

    #[test]
    fn dropped_or_aborted_reservations_release_capacity() {
        let budget = Arc::new(TokenBudget::new(20));
        {
            let _reservation = budget.begin(15).unwrap();
            assert_eq!(budget.remaining_tokens(), 5);
        }
        assert_eq!(budget.remaining_tokens(), 20);

        budget.begin(15).unwrap().abort();
        assert_eq!(budget.remaining_tokens(), 20);
    }

    #[test]
    fn underestimated_call_fails_closed_and_records_actual_usage() {
        let budget = Arc::new(TokenBudget::new(100));
        let err = budget.begin(10).unwrap().commit(11).unwrap_err();
        assert!(matches!(err, ReedeError::TokenBudgetExhausted { .. }));
        let snapshot = budget.snapshot();
        assert_eq!(snapshot.consumed_tokens, 11);
        assert!(snapshot.exhausted);
    }

    #[test]
    fn concurrent_reservations_cannot_overspend() {
        let budget = Arc::new(TokenBudget::new(100));
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let reservation = budget.begin(60);
                if let Ok(reservation) = reservation {
                    reservation.commit(60).unwrap();
                    true
                } else {
                    false
                }
            }));
        }

        barrier.wait();
        let successes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|success| *success)
            .count();

        assert_eq!(successes, 1);
        assert_eq!(budget.snapshot().consumed_tokens, 60);
        assert_eq!(budget.snapshot().reserved_tokens, 0);
    }
}
