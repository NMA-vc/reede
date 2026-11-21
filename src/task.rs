use crate::error::ReedeError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Running,
    Completing,
    Succeeded,
    Failed,
    Killed,
}

impl TaskState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskState::Succeeded | TaskState::Failed | TaskState::Killed
        )
    }

    pub fn can_transition_to(&self, next: TaskState) -> bool {
        if self == &next {
            return true;
        }
        if self.is_terminal() {
            return false;
        }
        match (self, next) {
            (TaskState::Pending, TaskState::Running) => true,
            (TaskState::Running, TaskState::Completing) => true,
            (TaskState::Completing, TaskState::Succeeded) => true,
            (TaskState::Running, TaskState::Failed) => true,
            (TaskState::Completing, TaskState::Failed) => true,
            (_, TaskState::Killed) => true, // Killed reachable from any non-terminal state
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BudgetEnvelope {
    pub ceiling_eur: f64,
    pub reserved_credits: i64,
    pub spent_credits: i64,
}

impl BudgetEnvelope {
    pub fn new(ceiling_eur: f64) -> Self {
        Self {
            ceiling_eur,
            reserved_credits: 0,
            spent_credits: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task {
    pub id: Uuid,
    pub session_id: Uuid,
    pub tenant_id: String,
    pub agent_spec_id: String,
    pub state: TaskState,
    pub budget_envelope: BudgetEnvelope,
    pub lease_id: Option<String>,
    pub receipt_chain_head: Option<String>,
    /// durable subject identity this run's artifact will carry, when the
    /// producing vertical has minted one. `None` for runs that do not yet carry a
    /// subject id. Stamped onto the run's `ExecutionReceipt` by the runner.
    #[serde(default)]
    pub subject_id: Option<String>,
    /// the budget reservation this task holds, when a lifecycle
    /// caller reserved credits at create time (`ReservationId` rendered as its
    /// UUID string, to keep this field ledger-agnostic and JSON-stable). `None`
    /// when the task reserved no budget. Read by the lifecycle API on cancel to
    /// release the outstanding reservation. `#[serde(default)]` keeps older
    /// persisted rows readable.
    #[serde(default)]
    pub reservation_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    /// When a cancel of this task was first requested. A request is not a state: `state` is
    /// written only by the run's own lifecycle and records how it ended, so a run cancelled after
    /// it claimed its completion ends `Succeeded` with the request kept here. `None` when no
    /// cancel was requested; rows written before the field existed read as `None`.
    #[serde(default)]
    pub cancel_requested_at: Option<DateTime<Utc>>,
}

impl Task {
    pub fn new(
        session_id: Uuid,
        tenant_id: impl Into<String>,
        agent_spec_id: impl Into<String>,
        budget_ceiling_eur: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            tenant_id: tenant_id.into(),
            agent_spec_id: agent_spec_id.into(),
            state: TaskState::Pending,
            budget_envelope: BudgetEnvelope::new(budget_ceiling_eur),
            lease_id: None,
            receipt_chain_head: None,
            subject_id: None,
            reservation_id: None,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            cancel_requested_at: None,
        }
    }

    pub fn transition_to(&mut self, next: TaskState) -> Result<(), ReedeError> {
        if !self.state.can_transition_to(next) {
            return Err(ReedeError::TaskStateViolation {
                from: format!("{:?}", self.state),
                to: format!("{:?}", next),
            });
        }

        if self.started_at.is_none() && next == TaskState::Running {
            self.started_at = Some(Utc::now());
        }

        if next.is_terminal() {
            self.finished_at = Some(Utc::now());
        }

        self.state = next;
        Ok(())
    }
}

use crate::isolation::IsolationBackend;
use crate::policy::DerivedPolicy;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

#[async_trait]
pub trait TaskStore: Send + Sync {
    async fn save(&self, task: &Task) -> Result<(), ReedeError>;
    async fn get(&self, id: Uuid) -> Result<Option<Task>, ReedeError>;
    async fn update_state(&self, id: Uuid, state: TaskState) -> Result<(), ReedeError>;
}

pub struct InMemoryTaskStore {
    tasks: Mutex<HashMap<Uuid, Task>>,
}

impl InMemoryTaskStore {
    pub fn new() -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryTaskStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TaskStore for InMemoryTaskStore {
    async fn save(&self, task: &Task) -> Result<(), ReedeError> {
        let mut guard = self.tasks.lock().unwrap();
        guard.insert(task.id, task.clone());
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Task>, ReedeError> {
        let guard = self.tasks.lock().unwrap();
        Ok(guard.get(&id).cloned())
    }

    async fn update_state(&self, id: Uuid, state: TaskState) -> Result<(), ReedeError> {
        let mut guard = self.tasks.lock().unwrap();
        if let Some(task) = guard.get_mut(&id) {
            task.transition_to(state)?;
        } else {
            return Err(ReedeError::TaskNotFound { id: id.to_string() });
        }
        Ok(())
    }
}

/// Executes a task within a sandbox managed by `IsolationBackend`.
/// 1. Creates sandbox via `isolation.create_sandbox(&task, &policy).await`
/// 2. Saves task in `TaskStore` with state `Running`
/// 3. Executes task work
/// 4. Destroys sandbox via `isolation.destroy_sandbox(sandbox_id).await` on completion or failure
pub async fn execute_isolated_task<F, R>(
    task: &mut Task,
    policy: &DerivedPolicy,
    isolation: &dyn IsolationBackend,
    store: &dyn TaskStore,
    work: F,
) -> Result<R, ReedeError>
where
    F: FnOnce() -> Result<R, ReedeError>,
{
    // 1. Create sandbox
    let sandbox_id = isolation.create_sandbox(task, policy).await?;

    // Capture every fallible operation after creation so cleanup runs exactly once
    // on each Result path. Panics and future cancellation remain outside this
    // synchronous FnOnce API's guarantee.
    let execution = async {
        // 2. Transition state and persist
        task.transition_to(TaskState::Running)?;
        store.save(task).await?;

        // 3. Execute task work
        let result = work();

        if result.is_ok() {
            task.transition_to(TaskState::Completing)?;
            task.transition_to(TaskState::Succeeded)?;
        } else {
            let _ = task.transition_to(TaskState::Failed);
        }
        store.save(task).await?;

        result
    }
    .await;

    // Cleanup errors are secondary to any execution error, including a work error.
    let cleanup = isolation.destroy_sandbox(sandbox_id).await;
    match execution {
        Err(error) => Err(error),
        Ok(output) => cleanup.map(|()| output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_state_machine_forward_transitions() {
        let mut task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        assert_eq!(task.state, TaskState::Pending);

        assert!(task.transition_to(TaskState::Running).is_ok());
        assert_eq!(task.state, TaskState::Running);
        assert!(task.started_at.is_some());

        assert!(task.transition_to(TaskState::Completing).is_ok());
        assert_eq!(task.state, TaskState::Completing);

        assert!(task.transition_to(TaskState::Succeeded).is_ok());
        assert_eq!(task.state, TaskState::Succeeded);
        assert!(task.finished_at.is_some());
    }

    #[test]
    fn test_task_state_machine_rejects_backward_transitions() {
        let mut task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        task.transition_to(TaskState::Running).unwrap();
        task.transition_to(TaskState::Completing).unwrap();
        task.transition_to(TaskState::Succeeded).unwrap();

        // Succeeded is terminal, cannot transition anywhere else
        let err = task.transition_to(TaskState::Running).unwrap_err();
        assert!(matches!(err, ReedeError::TaskStateViolation { .. }));
    }

    #[test]
    fn test_task_kill_reachable_from_any_non_terminal() {
        let mut task1 = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        assert!(task1.transition_to(TaskState::Killed).is_ok());

        let mut task2 = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        task2.transition_to(TaskState::Running).unwrap();
        assert!(task2.transition_to(TaskState::Killed).is_ok());
    }

    /// A task written before `cancel_requested_at` existed reads with no request; one that
    /// carries a request round-trips it, and a request does not change the state.
    #[test]
    fn test_task_cancel_request_field_is_optional_and_round_trips() {
        let mut task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        let mut old = serde_json::to_value(&task).unwrap();
        old.as_object_mut().unwrap().remove("cancel_requested_at");
        let parsed: Task = serde_json::from_value(old).unwrap();
        assert_eq!(parsed.cancel_requested_at, None);
        assert_eq!(parsed, task);

        task.transition_to(TaskState::Running).unwrap();
        task.cancel_requested_at = Some(Utc::now());
        let json = serde_json::to_string(&task).unwrap();
        let back: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(back, task);
        assert_eq!(back.state, TaskState::Running);
        assert!(back.cancel_requested_at.is_some());
    }

    #[tokio::test]
    async fn test_execute_isolated_task_success_and_cleanup() {
        use crate::isolation::PassthroughBackend;
        use crate::policy::DerivedPolicy;

        let mut task = Task::new(Uuid::new_v4(), "tenant-test", "spec-isolated", 100.0);
        let policy = DerivedPolicy::default();
        let isolation = PassthroughBackend;
        let store = InMemoryTaskStore::new();

        let res = execute_isolated_task(&mut task, &policy, &isolation, &store, || Ok(42)).await;

        assert_eq!(res.unwrap(), 42);
        assert_eq!(task.state, TaskState::Succeeded);

        let saved = store.get(task.id).await.unwrap().unwrap();
        assert_eq!(saved.state, TaskState::Succeeded);
    }

    #[tokio::test]
    async fn test_execute_isolated_task_failure_and_cleanup() {
        use crate::isolation::PassthroughBackend;
        use crate::policy::DerivedPolicy;

        let mut task = Task::new(Uuid::new_v4(), "tenant-test", "spec-isolated", 100.0);
        let policy = DerivedPolicy::default();
        let isolation = PassthroughBackend;
        let store = InMemoryTaskStore::new();

        let res: Result<(), ReedeError> =
            execute_isolated_task(&mut task, &policy, &isolation, &store, || {
                Err(ReedeError::GatewayError {
                    reason: "Simulated worker failure".to_string(),
                })
            })
            .await;

        assert!(res.is_err());
        assert_eq!(task.state, TaskState::Failed);

        let saved = store.get(task.id).await.unwrap().unwrap();
        assert_eq!(saved.state, TaskState::Failed);
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use crate::isolation::{IsolationBackend, SandboxCommand, SandboxId};
    use crate::policy::DerivedPolicy;
    use async_trait::async_trait;
    use std::process::Output;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RecordingBackend {
        create_calls: AtomicUsize,
        destroy_calls: AtomicUsize,
        create_error: Option<ReedeError>,
        destroy_error: Option<ReedeError>,
    }

    impl RecordingBackend {
        fn new(create_error: Option<ReedeError>, destroy_error: Option<ReedeError>) -> Self {
            Self {
                create_calls: AtomicUsize::new(0),
                destroy_calls: AtomicUsize::new(0),
                create_error,
                destroy_error,
            }
        }
    }

    #[async_trait]
    impl IsolationBackend for RecordingBackend {
        fn name(&self) -> &'static str {
            "recording"
        }

        async fn create_sandbox(
            &self,
            _task: &Task,
            _policy: &DerivedPolicy,
        ) -> Result<SandboxId, ReedeError> {
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = &self.create_error {
                return Err(error.clone());
            }
            Ok(SandboxId(Uuid::from_u128(42)))
        }

        async fn destroy_sandbox(&self, _id: SandboxId) -> Result<(), ReedeError> {
            self.destroy_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = &self.destroy_error {
                return Err(error.clone());
            }
            Ok(())
        }

        async fn exec_in_sandbox(
            &self,
            _id: SandboxId,
            _cmd: SandboxCommand,
        ) -> Result<Output, ReedeError> {
            Err(ReedeError::IsolationFailed {
                reason: "exec is unused by cleanup tests".to_string(),
            })
        }
    }

    struct FailureInjectingStore {
        save_calls: AtomicUsize,
        fail_on_save: Option<usize>,
    }

    impl FailureInjectingStore {
        fn new(fail_on_save: Option<usize>) -> Self {
            Self {
                save_calls: AtomicUsize::new(0),
                fail_on_save,
            }
        }
    }

    #[async_trait]
    impl TaskStore for FailureInjectingStore {
        async fn save(&self, _task: &Task) -> Result<(), ReedeError> {
            let call = self.save_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_on_save == Some(call) {
                return Err(ReedeError::LedgerFailed {
                    reason: format!("save {call} failed"),
                });
            }
            Ok(())
        }

        async fn get(&self, _id: Uuid) -> Result<Option<Task>, ReedeError> {
            Ok(None)
        }

        async fn update_state(&self, _id: Uuid, _state: TaskState) -> Result<(), ReedeError> {
            Ok(())
        }
    }

    fn task() -> Task {
        Task::new(Uuid::new_v4(), "tenant-cleanup", "spec-cleanup", 10.0)
    }

    fn assert_counts(
        backend: &RecordingBackend,
        store: &FailureInjectingStore,
        creates: usize,
        destroys: usize,
        saves: usize,
    ) {
        assert_eq!(backend.create_calls.load(Ordering::SeqCst), creates);
        assert_eq!(backend.destroy_calls.load(Ordering::SeqCst), destroys);
        assert_eq!(store.save_calls.load(Ordering::SeqCst), saves);
    }

    #[tokio::test]
    async fn cleanup_runs_once_and_preserves_success_output() {
        let backend = RecordingBackend::new(None, None);
        let store = FailureInjectingStore::new(None);
        let mut task = task();

        let result = execute_isolated_task(
            &mut task,
            &DerivedPolicy::default(),
            &backend,
            &store,
            || Ok(42),
        )
        .await;

        assert_eq!(result, Ok(42));
        assert_eq!(task.state, TaskState::Succeeded);
        assert_counts(&backend, &store, 1, 1, 2);
    }

    #[tokio::test]
    async fn cleanup_runs_once_when_first_save_fails() {
        let backend = RecordingBackend::new(None, None);
        let store = FailureInjectingStore::new(Some(1));
        let mut task = task();
        let work_calls = AtomicUsize::new(0);

        let result: Result<(), ReedeError> = execute_isolated_task(
            &mut task,
            &DerivedPolicy::default(),
            &backend,
            &store,
            || {
                work_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert_eq!(
            result,
            Err(ReedeError::LedgerFailed {
                reason: "save 1 failed".into()
            })
        );
        assert_eq!(task.state, TaskState::Running);
        assert_eq!(work_calls.load(Ordering::SeqCst), 0);
        assert_counts(&backend, &store, 1, 1, 1);
    }

    #[tokio::test]
    async fn cleanup_runs_once_when_terminal_save_fails() {
        let backend = RecordingBackend::new(None, None);
        let store = FailureInjectingStore::new(Some(2));
        let mut task = task();

        let result = execute_isolated_task(
            &mut task,
            &DerivedPolicy::default(),
            &backend,
            &store,
            || Ok(7),
        )
        .await;

        assert_eq!(
            result,
            Err(ReedeError::LedgerFailed {
                reason: "save 2 failed".into()
            })
        );
        assert_eq!(task.state, TaskState::Succeeded);
        assert_counts(&backend, &store, 1, 1, 2);
    }

    #[tokio::test]
    async fn cleanup_runs_once_when_running_transition_fails() {
        let backend = RecordingBackend::new(None, None);
        let store = FailureInjectingStore::new(None);
        let mut task = task();
        task.state = TaskState::Succeeded;
        let work_calls = AtomicUsize::new(0);

        let result: Result<(), ReedeError> = execute_isolated_task(
            &mut task,
            &DerivedPolicy::default(),
            &backend,
            &store,
            || {
                work_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert!(matches!(result, Err(ReedeError::TaskStateViolation { .. })));
        assert_eq!(work_calls.load(Ordering::SeqCst), 0);
        assert_counts(&backend, &store, 1, 1, 0);
    }

    #[tokio::test]
    async fn work_error_wins_over_secondary_destroy_error() {
        let backend = RecordingBackend::new(
            None,
            Some(ReedeError::IsolationFailed {
                reason: "destroy failed".into(),
            }),
        );
        let store = FailureInjectingStore::new(None);
        let mut task = task();
        let work_error = ReedeError::GatewayError {
            reason: "work failed".into(),
        };

        let result: Result<(), ReedeError> = execute_isolated_task(
            &mut task,
            &DerivedPolicy::default(),
            &backend,
            &store,
            || Err(work_error.clone()),
        )
        .await;

        assert_eq!(result, Err(work_error));
        assert_eq!(task.state, TaskState::Failed);
        assert_counts(&backend, &store, 1, 1, 2);
    }

    #[tokio::test]
    async fn destroy_error_is_returned_after_successful_work() {
        let backend = RecordingBackend::new(
            None,
            Some(ReedeError::IsolationFailed {
                reason: "destroy failed".into(),
            }),
        );
        let store = FailureInjectingStore::new(None);
        let mut task = task();

        let result = execute_isolated_task(
            &mut task,
            &DerivedPolicy::default(),
            &backend,
            &store,
            || Ok(42),
        )
        .await;

        assert_eq!(
            result,
            Err(ReedeError::IsolationFailed {
                reason: "destroy failed".into()
            })
        );
        assert_eq!(task.state, TaskState::Succeeded);
        assert_counts(&backend, &store, 1, 1, 2);
    }

    #[tokio::test]
    async fn failed_create_does_not_attempt_destroy() {
        let create_error = ReedeError::IsolationFailed {
            reason: "create failed".into(),
        };
        let backend = RecordingBackend::new(Some(create_error.clone()), None);
        let store = FailureInjectingStore::new(None);
        let mut task = task();
        let work_calls = AtomicUsize::new(0);

        let result: Result<(), ReedeError> = execute_isolated_task(
            &mut task,
            &DerivedPolicy::default(),
            &backend,
            &store,
            || {
                work_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert_eq!(result, Err(create_error));
        assert_eq!(work_calls.load(Ordering::SeqCst), 0);
        assert_counts(&backend, &store, 1, 0, 0);
    }
}
