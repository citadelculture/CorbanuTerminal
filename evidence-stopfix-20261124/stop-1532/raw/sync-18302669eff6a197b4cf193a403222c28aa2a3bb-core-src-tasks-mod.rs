mod compact;
mod lifecycle;
mod regular;
mod review;
mod user_shell;

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use codex_diagnostics::Gauge;
use codex_exec_server::ExecutorCapabilityDiscoveryV2Cache;
use codex_extension_api::ThreadIdleCause;
use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::select;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;
use tracing::Span;
use tracing::debug;
use tracing::field;
use tracing::info_span;
use tracing::trace;
use tracing::trace_span;
use tracing::warn;

use crate::agent::types::AgentExecutionGuard;
use crate::codex_thread::BackgroundTerminalInfo;
use crate::config::Config;
use crate::context::ContextualUserFragment;
use crate::hook_runtime::run_turn_interrupt_hooks;
use crate::session::TurnInput;
use crate::session::session::Session;
use crate::session::turn::run_hooks_and_record_inputs;
use crate::session::turn::turn_inputs_are_terminal_result_only;
use crate::session::turn::turn_inputs_expect_parent_completion;
use crate::session::turn_context::NewTurnContextOptions;
use crate::session::turn_context::TurnContext;
use crate::state::ActiveTurn;
use crate::state::RunningTask;
use crate::state::TaskKind;
use crate::state::TurnState;
use codex_analytics::TurnProfileFact;
use codex_analytics::TurnTokenUsageFact;
use codex_context_fragments::RenderedFragment;
use codex_otel::SessionTelemetry;
use codex_otel::TURN_E2E_DURATION_METRIC;
use codex_otel::TURN_MEMORY_METRIC;
use codex_otel::TURN_NETWORK_PROXY_METRIC;
use codex_otel::TURN_TOOL_CALL_METRIC;
use codex_otel::TURN_UNIFIED_EXEC_RUNNING_PROCESSES_METRIC;
use codex_otel::auth_storage::AuthStorageOriginator;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::ErrorEvent;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::MultiAgentVersion;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::TokenUsage;
use codex_protocol::protocol::TurnAbortReason;
use codex_protocol::protocol::TurnAbortedEvent;
use codex_protocol::protocol::TurnCompleteEvent;
use codex_protocol::protocol::TurnDiffEvent;
use codex_protocol::protocol::WarningEvent;
use codex_protocol::turn_input::NotSubmittedReason;
use codex_protocol::turn_input::TurnInput as SubmittedTurnInput;
use codex_protocol::turn_input::TurnInputMode;
use codex_protocol::turn_input::TurnInputRequest;
use codex_protocol::turn_input::TurnInputSubmission;
use codex_protocol::turn_input::TurnStartOptions;
use codex_protocol::user_input::UserInput;
use codex_thread_store::PersistContext;

use codex_features::Feature;
use codex_protocol::error::CodexErr;
use codex_protocol::error::CodexErrorDetails;
use codex_protocol::error::Result as CodexResult;
pub(crate) use compact::CompactTask;
pub(crate) use regular::RegularTask;
pub(crate) use review::ReviewTask;
pub(crate) use user_shell::UserShellCommandMode;
pub(crate) use user_shell::UserShellCommandTask;
pub(crate) use user_shell::execute_user_shell_command;

pub(crate) const GRACEFULL_INTERRUPTION_TIMEOUT_MS: u64 = 100;
const TASK_COMPACT_METRIC: &str = "codex.task.compact";
static ACTIVE_TURNS: Gauge = Gauge::new("core.turns.active");

pub(crate) type SessionTaskResult = CodexResult<Option<String>>;

/// The turn error reported when a task panicked (#616). The panic itself is
/// logged by the process panic hook; its payload is not repeated here.
pub(crate) const TURN_PANICKED_MESSAGE: &str =
    "this turn stopped because of an internal error (a panic); the details are in the log";

/// Attempts to submit one refused follow-up input again before it is reported.
const FOLLOW_UP_SUBMIT_ATTEMPTS: usize = 3;

/// How a turn ended, for its mailbox messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MailboxTurnEnd {
    /// The turn ended on its own.
    Completed,
    /// The turn returned an error (a turn-aborted one included); its leftover input is
    /// still recorded or submitted again afterwards.
    Failed,
    /// An interrupt, a replacing turn or a shutdown stopped the turn.
    Aborted,
}

/// How a starting task holds agent execution capacity.
enum ExecutionAdmission {
    /// Admitted when the task registers (upstream's `admit_turn`).
    AtRegistration,
    /// Reserved by the caller before it prepared the turn (pending-work wakes),
    /// so a worker turn never starts without capacity.
    Reserved(Option<AgentExecutionGuard>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterruptedTurnHistoryMarker {
    Disabled,
    ContextualUser,
    Developer,
}

impl InterruptedTurnHistoryMarker {
    pub(crate) fn from_config_and_version(
        config: &Config,
        multi_agent_version: MultiAgentVersion,
    ) -> Self {
        if !config.agent_interrupt_message_enabled {
            return Self::Disabled;
        }
        if multi_agent_version == MultiAgentVersion::V2 {
            Self::Developer
        } else {
            Self::ContextualUser
        }
    }
}

/// Shared model-visible marker used by both the real interrupt path and
/// interrupted fork snapshots.
pub(crate) fn interrupted_turn_history_marker(
    marker: InterruptedTurnHistoryMarker,
) -> Option<ResponseItem> {
    match marker {
        InterruptedTurnHistoryMarker::Disabled => None,
        InterruptedTurnHistoryMarker::ContextualUser => Some(ContextualUserFragment::into(
            crate::context::TurnAborted::new(crate::context::TurnAborted::INTERRUPTED_GUIDANCE),
        )),
        InterruptedTurnHistoryMarker::Developer => {
            let marker = crate::context::TurnAborted::new(
                crate::context::TurnAborted::INTERRUPTED_DEVELOPER_GUIDANCE,
            );
            let (_, content) = marker.render_fragment().into_parts();
            Some(RenderedFragment::new("developer", content).into())
        }
    }
}

fn emit_turn_network_proxy_metric(
    session_telemetry: &SessionTelemetry,
    network_proxy_active: bool,
    tmp_mem: (&str, &str),
) {
    let active = if network_proxy_active {
        "true"
    } else {
        "false"
    };
    session_telemetry.counter(
        TURN_NETWORK_PROXY_METRIC,
        /*inc*/ 1,
        &[("active", active), tmp_mem],
    );
}

fn emit_turn_memory_metric(
    session_telemetry: &SessionTelemetry,
    feature_enabled: bool,
    config_enabled: bool,
    has_citations: bool,
) {
    let read_allowed = feature_enabled && config_enabled;
    session_telemetry.counter(
        TURN_MEMORY_METRIC,
        /*inc*/ 1,
        &[
            ("read_allowed", bool_tag(read_allowed)),
            ("feature_enabled", bool_tag(feature_enabled)),
            ("config_use_memories", bool_tag(config_enabled)),
            ("has_citations", bool_tag(has_citations)),
        ],
    );
}

pub(crate) fn emit_compact_metric(
    session_telemetry: &SessionTelemetry,
    compact_type: &'static str,
    manual: bool,
) {
    session_telemetry.counter(
        TASK_COMPACT_METRIC,
        /*inc*/ 1,
        &[("type", compact_type), ("manual", bool_tag(manual))],
    );
}

fn bool_tag(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Async task that drives a [`Session`] turn.
///
/// Implementations encapsulate a specific Codex workflow (regular chat,
/// reviews, ghost snapshots, etc.). Each task instance is owned by a
/// [`Session`] and executed on a background Tokio task. The trait is
/// intentionally small: implementers identify themselves via
/// [`SessionTask::kind`], perform their work in [`SessionTask::run`], and may
/// release resources in [`SessionTask::abort`].
pub(crate) trait SessionTask: Send + Sync + 'static {
    /// Describes the type of work the task performs so the session can
    /// surface it in telemetry and UI.
    fn kind(&self) -> TaskKind;

    /// Returns the tracing name for a spawned task span.
    fn span_name(&self) -> &'static str;

    /// Executes the task until completion or cancellation.
    ///
    /// Implementations typically stream protocol events using `session` and
    /// `ctx`, returning an optional final agent message when finished. The
    /// provided `cancellation_token` is cancelled when the session requests an
    /// abort; implementers should watch for it and terminate quickly once it
    /// fires. Returning [`Some`] yields a final message that
    /// [`Session::on_task_finished`] will emit to the client. Returning
    /// [`CodexErr::TurnAborted`] completes the task through the aborted-turn
    /// lifecycle instead.
    fn run(
        self: Arc<Self>,
        session: Arc<Session>,
        ctx: Arc<TurnContext>,
        input: Vec<TurnInput>,
        cancellation_token: CancellationToken,
    ) -> impl std::future::Future<Output = SessionTaskResult> + Send;

    /// Gives the task a chance to perform cleanup after an abort.
    ///
    /// The default implementation is a no-op; override this if additional
    /// teardown or notifications are required once
    /// [`Session::abort_all_tasks`] cancels the task.
    fn abort(
        &self,
        session: Arc<Session>,
        ctx: Arc<TurnContext>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let _ = (session, ctx);
        }
    }
}

pub(crate) trait AnySessionTask: Send + Sync + 'static {
    fn kind(&self) -> TaskKind;

    fn span_name(&self) -> &'static str;

    fn run(
        self: Arc<Self>,
        session: Arc<Session>,
        ctx: Arc<TurnContext>,
        input: Vec<TurnInput>,
        cancellation_token: CancellationToken,
    ) -> BoxFuture<'static, SessionTaskResult>;

    fn abort<'a>(&'a self, session: Arc<Session>, ctx: Arc<TurnContext>) -> BoxFuture<'a, ()>;
}

impl<T> AnySessionTask for T
where
    T: SessionTask + Send + Sync + 'static,
{
    fn kind(&self) -> TaskKind {
        SessionTask::kind(self)
    }

    fn span_name(&self) -> &'static str {
        SessionTask::span_name(self)
    }

    fn run(
        self: Arc<Self>,
        session: Arc<Session>,
        ctx: Arc<TurnContext>,
        input: Vec<TurnInput>,
        cancellation_token: CancellationToken,
    ) -> BoxFuture<'static, SessionTaskResult> {
        Box::pin(SessionTask::run(
            self,
            session,
            ctx,
            input,
            cancellation_token,
        ))
    }

    fn abort<'a>(&'a self, session: Arc<Session>, ctx: Arc<TurnContext>) -> BoxFuture<'a, ()> {
        Box::pin(SessionTask::abort(self, session, ctx))
    }
}

impl Session {
    pub async fn spawn_task<T: SessionTask + Send + Sync + 'static>(
        self: &Arc<Self>,
        turn_context: Arc<TurnContext>,
        input: Vec<TurnInput>,
        task: T,
    ) {
        self.abort_all_tasks(TurnAbortReason::Replaced).await;
        self.clear_connector_selection().await;
        self.start_task(turn_context, input, task).await;
    }

    pub(crate) async fn start_task<T: SessionTask>(
        self: &Arc<Self>,
        turn_context: Arc<TurnContext>,
        input: Vec<TurnInput>,
        task: T,
    ) {
        self.start_task_with_admission(
            turn_context,
            input,
            task,
            ExecutionAdmission::AtRegistration,
        )
        .await;
    }

    #[expect(
        clippy::await_holding_invalid_type,
        reason = "record the started turn atomically with task registration"
    )]
    async fn start_task_with_admission<T: SessionTask>(
        self: &Arc<Self>,
        turn_context: Arc<TurnContext>,
        input: Vec<TurnInput>,
        task: T,
        admission: ExecutionAdmission,
    ) {
        // Replace the cache; in-flight acquisitions retain their previous Arc.
        self.services
            .thread_extension_data
            .insert(ExecutorCapabilityDiscoveryV2Cache::default());
        if turn_context
            .config
            .features
            .enabled(Feature::ExecutorCapabilityDiscoveryV2)
        {
            // MCP contributors must project the new inventory even if their other inputs match.
            self.request_mcp_runtime_reprojection();
        }
        self.activate_plugin_selection(&turn_context).await;
        // Inherited or recovered roots are applied before task start. Otherwise this
        // task owns its turn, including background work. Later mail cannot change it.
        turn_context
            .turn_metadata_state
            .set_root_turn_id(turn_context.sub_id.clone());
        let task: Arc<dyn AnySessionTask> = Arc::new(task);
        let task_kind = task.kind();
        let span_name = task.span_name();
        let started_at = Instant::now();
        let turn_started_at_unix_ms = turn_context
            .turn_timing_state
            .mark_turn_started(started_at)
            .await;
        turn_context
            .turn_metadata_state
            .set_turn_started_at_unix_ms(turn_started_at_unix_ms);
        let token_usage_at_turn_start = self.total_token_usage().await.unwrap_or_default();

        let cancellation_token = CancellationToken::new();
        let done = Arc::new(Notify::new());

        // #2033 / #1999 (D485): mail that has crossed a turn boundary only.
        // Match explicit turn admission (#445/#507): a refused task must leave ready mail
        // queued, rather than detach it and race its resubmission against switch-off.
        let pending_items = if Box::pin(crate::session::turn::turn_refusal(self, &turn_context))
            .await
            .is_none()
        {
            self.input_queue
                .get_pending_input_for_task_start(&self.active_turn)
                .await
                .0
        } else {
            Vec::new()
        };
        // Pending-work wakes deliberately start RegularTask with empty explicit input and move
        // mailbox items through InputQueue. Classify the complete admitted task here, after that
        // move, so a terminal-result turn cannot masquerade as fresh operator work.
        let terminal_result_only =
            turn_inputs_are_terminal_result_only(input.iter().chain(pending_items.iter()));
        let parent_completion_expected =
            turn_inputs_expect_parent_completion(input.iter().chain(pending_items.iter()));
        turn_context.parent_completion_expected.store(
            parent_completion_expected,
            std::sync::atomic::Ordering::Release,
        );
        // Sessions start only on Corbanu's local agent backend (D530 (a)), so this is present.
        let native_auto_turn_guard =
            self.services.agent_control.local().map(|control| {
                control.begin_native_agent_turn(self.thread_id, terminal_result_only)
            });
        let turn_state = {
            let mut active = self.active_turn.lock().await;
            let turn = active.get_or_insert_with(ActiveTurn::default);
            debug_assert!(turn.task.is_none());
            turn.finishing = None;
            Arc::clone(&turn.turn_state)
        };
        {
            let mut turn_state = turn_state.lock().await;
            turn_state.token_usage_at_turn_start = token_usage_at_turn_start.clone();
            // #1952 (D485): mail this turn starts with, taken off the mailbox queue above or by
            // the caller.
            turn_state.track_taken_mailbox_messages(input.iter().chain(pending_items.iter()));
        }
        self.input_queue
            .extend_pending_input_for_turn_state(turn_state.as_ref(), pending_items)
            .await;
        self.emit_turn_start_lifecycle(
            turn_context.as_ref(),
            Some(&token_usage_at_turn_start),
            codex_extension_api::TurnStartPhase::BeforeTaskRegistration,
        )
        .await;

        let mut active = self.active_turn.lock().await;
        let turn = active.get_or_insert_with(ActiveTurn::default);
        debug_assert!(turn.task.is_none());
        // Record lineage only when the task starts: settings changes can invalidate a reservation.
        self.record_started_turn(
            &turn_context.sub_id,
            (task_kind == TaskKind::Regular).then(|| turn_context.attribution()),
        )
        .await;
        let agent_execution_guard = match admission {
            ExecutionAdmission::AtRegistration => self.services.agent_control.admit_turn(
                turn_context.multi_agent_version,
                &turn_context.session_source,
            ),
            ExecutionAdmission::Reserved(guard) => guard,
        };
        let done_clone = Arc::clone(&done);
        let session = Arc::clone(self);
        let ctx = Arc::clone(&turn_context);
        let task_for_run = Arc::clone(&task);
        let task_input = input;
        let task_cancellation_token = cancellation_token.child_token();
        // Task-owned turn spans keep a core-owned span open for the
        // full task lifecycle after the submission dispatch span ends.
        let reasoning_effort = turn_context.effective_reasoning_effort_for_tracing();
        let task_span = info_span!(
            "turn",
            otel.name = span_name,
            thread.id = %self.thread_id,
            turn.id = %turn_context.sub_id,
            model = %turn_context.model_info().slug,
            codex.turn.reasoning_effort = %reasoning_effort,
            codex.turn.token_usage.input_tokens = field::Empty,
            codex.turn.token_usage.cached_input_tokens = field::Empty,
            codex.turn.token_usage.cache_write_input_tokens = field::Empty,
            codex.turn.token_usage.non_cached_input_tokens = field::Empty,
            codex.turn.token_usage.output_tokens = field::Empty,
            codex.turn.token_usage.reasoning_output_tokens = field::Empty,
            codex.turn.token_usage.total_tokens = field::Empty,
        );
        let storage_originator = AuthStorageOriginator::from_client_name(&turn_context.originator);
        let task_future = async move {
            let ctx_for_finish = Arc::clone(&ctx);
            // #434: vault values stored since the vault was last read
            // (before this process started, or by another process) are
            // protected before this task produces output.
            let run_session = Arc::clone(&session);
            let run_cancellation_token = task_cancellation_token.clone();
            let run = async move {
                tokio::select! {
                    () = crate::security::disclosure_gate::refresh_vault_values_for_task(
                        &run_session,
                        ctx.as_ref(),
                    ) => {}
                    () = run_cancellation_token.cancelled() => {}
                }
                task_for_run
                    .run(
                        run_session,
                        ctx,
                        task_input,
                        run_cancellation_token.child_token(),
                    )
                    .instrument(trace_span!("session_task.run"))
                    .await
            };
            // #616: a panic inside the task must still finish the turn
            // (with an error), or every client waiting for its end (exec,
            // the TUI) waits forever.
            let task_result = std::panic::AssertUnwindSafe(run)
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Err(CodexErr::Fatal(TURN_PANICKED_MESSAGE.to_string())));
            let sess = Arc::clone(&session);
            // Private reviewers save their transcript together with the terminal event.
            // Errors and cancellation retain their existing save path.
            if (!sess.is_private_guardian_reviewer().await
                || task_cancellation_token.is_cancelled()
                || task_result.is_err())
                && let Err(err) = sess.flush_rollout().await
            {
                warn!("failed to flush rollout before completing turn: {err}");
                sess.send_event(
                    ctx_for_finish.as_ref(),
                    EventMsg::Warning(WarningEvent {
                        message: format!(
                            "Failed to save the conversation transcript; Codex will continue retrying. Error: {err}"
                        ),
                    }),
                )
                .await;
            }
            if !task_cancellation_token.is_cancelled() {
                // Finish uniformly from the spawn site so all tasks share the same lifecycle.
                sess.on_task_finished(Arc::clone(&ctx_for_finish), task_result)
                    .await;
            }
            done_clone.notify_waiters();
        }
        .instrument(task_span);
        let handle = tokio::spawn(storage_originator.scope(task_future));
        let timer = turn_context
            .session_telemetry
            .start_timer(TURN_E2E_DURATION_METRIC, &[])
            .ok();
        let running_task = RunningTask {
            done,
            handle: AbortOnDropHandle::new(handle),
            kind: task_kind,
            task,
            cancellation_token,
            turn_context: Arc::clone(&turn_context),
            _agent_execution_guard: agent_execution_guard,
            _native_auto_turn_guard: native_auto_turn_guard,
            _diagnostics_guard: ACTIVE_TURNS.track(),
            _timer: timer,
        };
        turn.task = Some(running_task);
    }

    /// Returns whether an extension has marked this thread as durably asleep.
    pub(crate) fn has_outstanding_durable_sleep(&self) -> bool {
        self.services
            .thread_extension_data
            .get::<codex_extension_items::sleep::SleepItem>()
            .is_some()
    }

    /// Starts a regular turn when the session is idle and pending work is waiting.
    ///
    /// Mail can request a new task with `trigger_turn`, wake durable sleep, or wake a root with
    /// `wake_on_agent_messages` enabled.
    ///
    /// This helper generates a fresh sub-id for the synthetic turn before delegating to the
    /// explicit-sub-id variant.
    pub(crate) fn maybe_start_turn_for_pending_work(self: &Arc<Self>) -> BoxFuture<'static, ()> {
        let session = Arc::clone(self);
        Box::pin(async move {
            session
                .maybe_start_turn_for_pending_work_with_sub_id(uuid::Uuid::new_v4().to_string())
                .await;
        })
    }

    /// Starts a regular turn with the provided sub-id when pending work should wake an idle
    /// session.
    ///
    /// Starts an idle turn for explicit follow-ups, durable sleep, or enabled message wakes.
    pub(crate) async fn maybe_start_turn_for_pending_work_with_sub_id(
        self: &Arc<Self>,
        sub_id: String,
    ) {
        if !self.input_queue.has_pending_mailbox_items().await {
            return;
        }
        // Issue #445: no turn is started for agent messages while the kill
        // switch is on; they wait until a person turns it off and a turn runs.
        if self.services.model_client().kill_switch_on() {
            return;
        }

        // A busy session cannot start another turn. Avoid preparing a turn and reading its
        // named account here; the locked reservation below still checks for a concurrent start.
        if self.active_turn.lock().await.is_some() {
            return;
        }

        // D663: reserve before preparing auth/refusal state. Interrupt must be able to
        // cancel this wake while discovery is suspended, without consuming its mail.
        let Some((turn_state, previous_options)) = self.reserve_pending_work_turn().await else {
            return;
        };
        let turn_context = self.new_default_turn().await;
        // #1331 (D171): nor while its named account is removed or signed out.
        if let Some(err) = crate::session::turn::turn_refusal(self, &turn_context).await {
            self.clear_reserved_idle_turn(&turn_state).await;
            let message = format!(
                "Agent messages remain queued: {err}. After recovery, send another message or start a turn to retry."
            );
            self.send_event(
                &turn_context,
                EventMsg::Warning(WarningEvent {
                    message: message.clone(),
                }),
            )
            .await;
            if let Some(control) = self.services.agent_control.local()
                && let Err(err) = control
                    .warn_parent_of_held_mailbox(
                        self.thread_id,
                        &turn_context.session_source,
                        message,
                    )
                    .await
            {
                debug!("failed to notify parent of held mailbox: {err}");
            }
            return;
        }
        // D530 (a): capacity is reserved through Corbanu's local backend; any other
        // controller fails closed here.
        let agent_execution_guard = match self
            .services
            .agent_control
            .local_or_unsupported()
            .and_then(|control| {
                control.try_execution_guard(
                    turn_context.multi_agent_version,
                    &turn_context.session_source,
                )
            }) {
            Ok(guard) => guard,
            Err(err) if matches!(err.details(), CodexErrorDetails::AgentLimitReached { .. }) => {
                self.clear_reserved_idle_turn(&turn_state).await;
                if let Some(control) = self.services.agent_control.local().cloned()
                    && self.input_queue.try_schedule_capacity_wait()
                {
                    let session = Arc::clone(self);
                    tokio::spawn(async move {
                        control.wait_for_execution_capacity().await;
                        session.input_queue.finish_capacity_wait();
                        session.submit_pending_work_wake().await;
                    });
                }
                return;
            }
            Err(err) => {
                self.clear_reserved_idle_turn(&turn_state).await;
                warn!(%err, "failed to reserve execution capacity for pending mailbox work");
                return;
            }
        };

        self.services
            .models_manager
            .refresh_after_auth_change(self.get_config().await.http_client_factory())
            .await;
        let session_configuration = if self.enabled(Feature::WakeOnAgentMessages) {
            let Some(configuration) = self.pending_work_turn_configuration(&turn_state).await
            else {
                return;
            };
            Some(configuration)
        } else {
            if self
                .active_turn
                .lock()
                .await
                .as_ref()
                .is_none_or(|turn| !Arc::ptr_eq(&turn.turn_state, &turn_state))
            {
                return;
            }
            None
        };
        let (input, mut start_options) = self
            .input_queue
            .get_pending_input_for_task_start(&self.active_turn)
            .await;
        if !input.iter().any(
            |item| matches!(item, TurnInput::InterAgentCommunication(mail) if mail.trigger_turn),
        ) {
            // Queue-only wakes retain the previous turn context without selecting a new task.
            start_options = previous_options;
            start_options.cyber_access_program = self
                .reference_context_item()
                .await
                .and_then(|context| context.cyber_access_program);
        }
        let options = NewTurnContextOptions {
            final_output_json_schema: start_options.final_output_json_schema,
            cyber_access_program: start_options.cyber_access_program,
        };
        let turn_context = match session_configuration {
            Some(configuration) => {
                self.new_turn_with_configuration(sub_id, configuration, options)
                    .await
            }
            None => self.new_turn_with_default_settings(sub_id, options).await,
        };
        if let Some(trigger) = start_options.turn_trigger {
            turn_context.turn_metadata_state.set_turn_trigger(trigger);
        }
        if let Some(id) = start_options.parent_turn_id {
            if let Some(initiating_agent_path) = input
                .iter()
                .find_map(|item| {
                    let TurnInput::InterAgentCommunication(communication) = item else {
                        return None;
                    };
                    communication
                        .trigger_turn
                        .then(|| communication.author.clone())
                })
                .or(start_options.initiating_agent_path)
            {
                turn_context
                    .turn_metadata_state
                    .set_initiating_agent_path(initiating_agent_path);
            }
            turn_context.turn_metadata_state.set_parent_turn_id(id);
        }
        if let Some(id) = start_options.root_turn_id {
            turn_context.turn_metadata_state.set_root_turn_id(id);
        }
        self.maybe_emit_model_warnings_for_turn(turn_context.as_ref())
            .await;
        // Task completion must still save this mail if pre-turn compaction fails.
        self.input_queue
            .extend_pending_input_for_turn_state(turn_state.as_ref(), input)
            .await;
        // Context construction can outlive an interrupt or replacement. Do not let
        // start_task recreate a turn whose reservation is no longer ours.
        if self
            .active_turn
            .lock()
            .await
            .as_ref()
            .is_none_or(|turn| !Arc::ptr_eq(&turn.turn_state, &turn_state))
        {
            return;
        }
        self.start_task_with_admission(
            turn_context,
            Vec::new(),
            RegularTask::new(),
            ExecutionAdmission::Reserved(agent_execution_guard),
        )
        .await;
    }

    pub async fn abort_all_tasks(self: &Arc<Self>, reason: TurnAbortReason) {
        let mut aborted_turn = false;
        let mut active_turn_to_clear = None;
        if let Some(mut active_turn) = self.take_active_turn(&reason).await {
            let task = active_turn.task.take();
            aborted_turn = task.is_some();
            if let Some(task) = task {
                self.handle_task_abort(
                    task,
                    reason.clone(),
                    &active_turn.turn_state,
                    /*error*/ None,
                )
                .await;
            }
            if aborted_turn {
                active_turn_to_clear = Some(active_turn);
            }
        }

        if let Some(active_turn) = active_turn_to_clear {
            self.finish_turn_mailbox_messages(
                active_turn.turn_state.as_ref(),
                MailboxTurnEnd::Aborted,
            )
            .await;
            // Let interrupted tasks observe cancellation before dropping pending approvals, or an
            // in-flight approval wait can surface as a model-visible rejection before TurnAborted.
            self.input_queue.clear_pending(&active_turn).await;
        }
        if reason == TurnAbortReason::Interrupted && aborted_turn {
            self.maybe_start_turn_for_pending_work().await;
        }
    }

    pub(crate) async fn abort_turn_if_active(
        self: &Arc<Self>,
        turn_id: &str,
        reason: TurnAbortReason,
        error: Option<ErrorEvent>,
    ) -> bool {
        let active_turn = {
            let mut active = self.active_turn.lock().await;
            if active
                .as_ref()
                .and_then(|active_turn| active_turn.task.as_ref())
                .is_some_and(|task| task.turn_context.sub_id == turn_id)
            {
                if matches!(
                    reason,
                    TurnAbortReason::Interrupted | TurnAbortReason::BudgetLimited
                ) {
                    self.mark_interrupted();
                }
                active.take()
            } else {
                None
            }
        };
        let Some(active_turn) = active_turn else {
            return false;
        };

        self.finish_turn_abort(active_turn, reason, error).await;
        true
    }

    pub(crate) async fn finish_turn_abort(
        self: &Arc<Self>,
        mut active_turn: ActiveTurn,
        reason: TurnAbortReason,
        error: Option<ErrorEvent>,
    ) {
        let task = active_turn.task.take();
        if let Some(task) = task {
            self.handle_task_abort(task, reason.clone(), &active_turn.turn_state, error)
                .await;
        }
        self.finish_turn_mailbox_messages(active_turn.turn_state.as_ref(), MailboxTurnEnd::Aborted)
            .await;
        // Let interrupted tasks observe cancellation before dropping pending approvals, or an
        // in-flight approval wait can surface as a model-visible rejection before TurnAborted.
        self.input_queue.clear_pending(&active_turn).await;

        if reason == TurnAbortReason::Interrupted {
            self.maybe_start_turn_for_pending_work().await;
        }
    }

    pub async fn on_task_finished(
        self: &Arc<Self>,
        turn_context: Arc<TurnContext>,
        task_result: SessionTaskResult,
    ) {
        let turn_refused = turn_context
            .turn_refused
            .load(std::sync::atomic::Ordering::Acquire);
        let completed_without_error = turn_context.terminal_error.lock().await.is_none();
        let (last_agent_message, abort_reason, completed_naturally) = match task_result {
            // run_turn reports terminal errors before returning Ok. Only pre-turn refusals
            // retain their existing rejection/follow-up handling (D659, #2443).
            Ok(last_agent_message) => (
                last_agent_message,
                None,
                completed_without_error || turn_refused,
            ),
            Err(err) if matches!(err.details(), CodexErrorDetails::TurnAborted) => {
                (None, Some(TurnAbortReason::Interrupted), false)
            }
            Err(err) => {
                warn!(%err, "session task returned an unexpected error");
                self.emit_turn_error_lifecycle(
                    turn_context.as_ref(),
                    err.to_codex_protocol_error(),
                    err.details(),
                )
                .await;
                self.track_turn_codex_error(turn_context.as_ref(), &err);
                self.send_event(
                    turn_context.as_ref(),
                    EventMsg::Error(err.to_error_event(/*message_prefix*/ None)),
                )
                .await;
                (None, None, false)
            }
        };
        turn_context
            .turn_metadata_state
            .cancel_git_enrichment_task();

        let finishing = CancellationToken::new();
        let finish_recording = finishing.clone().drop_guard();
        let turn_state = {
            let mut active = self.active_turn.lock().await;
            active.as_mut().and_then(|active_turn| {
                let task = active_turn.task.take()?;
                task.handle.detach();
                active_turn.finishing = Some(finishing);
                Some(Arc::clone(&active_turn.turn_state))
            })
        };
        let Some(turn_state) = turn_state else {
            return;
        };
        let pending_input = self
            .input_queue
            .take_pending_input_for_turn_state(turn_state.as_ref())
            .await;
        let (
            turn_had_memory_citation,
            turn_tool_calls,
            token_usage_at_turn_start,
            token_usage_by_model,
        ) = {
            let mut ts = turn_state.lock().await;
            (
                ts.has_memory_citation,
                ts.tool_calls,
                ts.token_usage_at_turn_start.clone(),
                std::mem::take(&mut ts.token_usage_by_model),
            )
        };
        self.finish_turn_mailbox_messages(
            turn_state.as_ref(),
            if completed_naturally {
                MailboxTurnEnd::Completed
            } else {
                MailboxTurnEnd::Failed
            },
        )
        .await;
        // Queue-only mail deliberately does not wake an idle thread or join the immediately
        // following admitted request. Crossing this terminal boundary makes it eligible to join
        // the next human turn without creating a model-only continuation loop.
        self.input_queue.mark_mailbox_ready_for_next_turn().await;
        // A naturally completed turn hands input that should start work to a follow-up turn;
        // the rest is recorded on this turn.
        let mut follow_up_input = Vec::new();
        let mut recorded_input = Vec::new();
        for (pending_input_item, final_output_json_schema) in pending_input {
            // D660: mail taken but not answered is recorded below for the next explicit
            // turn. Re-submitting it would synthesize an automatic continuation.
            if completed_naturally
                && (pending_input_seeds_follow_up(&pending_input_item)
                    || (turn_refused
                        && matches!(pending_input_item, TurnInput::InterAgentCommunication(_))))
            {
                follow_up_input.push((pending_input_item, final_output_json_schema));
            } else {
                recorded_input.push(pending_input_item);
            }
        }
        if let Err(err) = run_hooks_and_record_inputs(
            self,
            &turn_context,
            &turn_context.capture_current_model_info(),
            &recorded_input,
            PersistContext::Standard,
        )
        .await
        {
            self.emit_turn_error_lifecycle(
                turn_context.as_ref(),
                err.to_codex_protocol_error(),
                err.details(),
            )
            .await;
            self.track_turn_codex_error(turn_context.as_ref(), &err);
            self.send_event(
                turn_context.as_ref(),
                EventMsg::Error(err.to_error_event(/*message_prefix*/ None)),
            )
            .await;
        }
        drop(finish_recording);
        let turn_telemetry = &turn_context.session_telemetry;
        // Emit token usage metrics.
        {
            // TODO(jif): drop this
            let tmp_mem = (
                "tmp_mem_enabled",
                if self.enabled(Feature::MemoryTool) {
                    "true"
                } else {
                    "false"
                },
            );
            let network_proxy = self.services.network_proxy.load_full();
            let network_proxy_active = match network_proxy.as_ref() {
                Some(started_network_proxy) => {
                    match started_network_proxy.proxy().current_cfg().await {
                        Ok(config) => config.enabled,
                        Err(err) => {
                            warn!(
                                "failed to read managed network proxy state for turn metrics: {err:#}"
                            );
                            false
                        }
                    }
                }
                None => false,
            };
            emit_turn_network_proxy_metric(turn_telemetry, network_proxy_active, tmp_mem);
            turn_telemetry.histogram(
                TURN_TOOL_CALL_METRIC,
                i64::try_from(turn_tool_calls).unwrap_or(i64::MAX),
                &[tmp_mem],
            );
            let total_token_usage = self.total_token_usage().await.unwrap_or_default();
            let turn_token_usage = TokenUsage {
                input_tokens: (total_token_usage.input_tokens
                    - token_usage_at_turn_start.input_tokens)
                    .max(0),
                cached_input_tokens: (total_token_usage.cached_input_tokens
                    - token_usage_at_turn_start.cached_input_tokens)
                    .max(0),
                cache_write_input_tokens: (total_token_usage.cache_write_input_tokens
                    - token_usage_at_turn_start.cache_write_input_tokens)
                    .max(0),
                output_tokens: (total_token_usage.output_tokens
                    - token_usage_at_turn_start.output_tokens)
                    .max(0),
                reasoning_output_tokens: (total_token_usage.reasoning_output_tokens
                    - token_usage_at_turn_start.reasoning_output_tokens)
                    .max(0),
                total_tokens: (total_token_usage.total_tokens
                    - token_usage_at_turn_start.total_tokens)
                    .max(0),
                codex_rollout_budget_units: None,
            };
            let current_span = Span::current();
            current_span.record(
                "codex.turn.token_usage.input_tokens",
                turn_token_usage.input_tokens,
            );
            current_span.record(
                "codex.turn.token_usage.cached_input_tokens",
                turn_token_usage.cached_input(),
            );
            current_span.record(
                "codex.turn.token_usage.cache_write_input_tokens",
                turn_token_usage.cache_write_input_tokens,
            );
            current_span.record(
                "codex.turn.token_usage.non_cached_input_tokens",
                turn_token_usage.non_cached_input(),
            );
            current_span.record(
                "codex.turn.token_usage.output_tokens",
                turn_token_usage.output_tokens,
            );
            current_span.record(
                "codex.turn.token_usage.reasoning_output_tokens",
                turn_token_usage.reasoning_output_tokens,
            );
            current_span.record(
                "codex.turn.token_usage.total_tokens",
                turn_token_usage.total_tokens,
            );
            self.services
                .analytics_events_client
                .track_turn_token_usage(TurnTokenUsageFact {
                    turn_id: turn_context.sub_id.clone(),
                    thread_id: self.thread_id.to_string(),
                    token_usage: turn_token_usage,
                });
            token_usage_by_model.emit(turn_telemetry, tmp_mem);
        }
        emit_turn_memory_metric(
            turn_telemetry,
            turn_context.config.features.enabled(Feature::MemoryTool),
            turn_context.config.memories.use_memories,
            turn_had_memory_citation,
        );
        turn_telemetry.counter(
            TURN_UNIFIED_EXEC_RUNNING_PROCESSES_METRIC,
            i64::try_from(self.list_background_terminals().await.len()).unwrap_or(i64::MAX),
            &[],
        );
        let started_at = turn_context.turn_timing_state.started_at_unix_secs().await;
        let (completed_at, duration_ms, profile) = turn_context
            .turn_timing_state
            .complete_profile_and_duration_ms()
            .await;
        crate::turn_timing::record_turn_profile_trace(
            self.thread_id,
            &turn_context.sub_id,
            &profile,
        );
        self.services
            .analytics_events_client
            .track_turn_profile(TurnProfileFact {
                turn_id: turn_context.sub_id.clone(),
                profile,
            });
        // #874 (D6): a process an agent command left running may have
        // changed a git folder this session watches since its last look;
        // the person is told before the turn ends.
        if let Some(level) = crate::security::protected_additional::protected_level(self)
            .filter(|level| *level != codex_security_policy::SecurityLevel::Permissive)
        {
            let thread = self.thread_id;
            let level = format!("{level:?}");
            // A failed look is told too.
            let message = tokio::task::spawn_blocking(move || {
                crate::security::git_postcheck::recheck(thread, &level, &[])
            })
            .await
            .map_or_else(
                |_| Some(crate::security::git_postcheck::CHECK_FAILED.to_string()),
                |(message, _)| message,
            );
            if let Some(message) = message {
                self.send_event(
                    turn_context.as_ref(),
                    EventMsg::Warning(codex_protocol::protocol::WarningEvent { message }),
                )
                .await;
            }
        }
        let idle_cause = if matches!(
            abort_reason.as_ref(),
            Some(TurnAbortReason::Interrupted | TurnAbortReason::BudgetLimited)
        ) {
            ThreadIdleCause::Interrupted
        } else if abort_reason.is_none() && turn_context.terminal_error.lock().await.is_some() {
            ThreadIdleCause::Failed
        } else {
            ThreadIdleCause::Completed
        };
        let event = if let Some(reason) = abort_reason {
            if reason == TurnAbortReason::Interrupted {
                run_turn_interrupt_hooks(self, &turn_context, &turn_state).await;
            }
            self.emit_turn_abort_lifecycle(reason.clone(), turn_context.extension_data.as_ref())
                .await;
            EventMsg::TurnAborted(TurnAbortedEvent {
                root_turn_id: Some(turn_context.root_turn_id()),
                turn_id: Some(turn_context.sub_id.clone()),
                reason,
                error: None,
                started_at,
                completed_at,
                duration_ms,
            })
        } else {
            let time_to_first_token_ms = turn_context
                .turn_timing_state
                .time_to_first_token_ms()
                .await;
            let error = turn_context.terminal_error.lock().await.clone();
            self.emit_turn_stop_lifecycle(turn_context.extension_data.as_ref())
                .await;
            EventMsg::TurnComplete(TurnCompleteEvent {
                root_turn_id: Some(turn_context.root_turn_id()),
                turn_id: turn_context.sub_id.clone(),
                last_agent_message,
                error,
                started_at,
                completed_at,
                duration_ms,
                time_to_first_token_ms,
            })
        };
        let saved_guardian_completion =
            matches!(event, EventMsg::TurnComplete(_)) && self.is_private_guardian_reviewer().await;
        if !saved_guardian_completion {
            self.send_event(turn_context.as_ref(), event.clone()).await;
        }

        let cleared_active_turn = {
            let mut active = self.active_turn.lock().await;
            if let Some(active_turn) = active.as_ref()
                && active_turn.task.is_none()
                && Arc::ptr_eq(&active_turn.turn_state, &turn_state)
            {
                *active = None;
                true
            } else {
                false
            }
        };
        if saved_guardian_completion {
            // The parent can request another review as soon as it receives this event.
            self.send_event(turn_context.as_ref(), event).await;
        }
        // D742 (a): report the idle boundary before pending-work discovery, as upstream
        // does, and only here, so a completed turn reports it once. A queue-only wake
        // still reserves before discovery (D663), so Interrupt can cancel it there.
        if cleared_active_turn {
            self.emit_thread_idle_lifecycle_if_idle(idle_cause).await;
        }
        // Private reviewers already flushed the terminal event before delivering it.
        // Other buffering writers still need a barrier for the terminal event.
        if !saved_guardian_completion && let Err(err) = self.flush_rollout().await {
            warn!("failed to flush rollout after emitting terminal turn event: {err}");
        }
        // A completed task owns the pending inputs it detached above. Dispatch them even if a
        // concurrent lifecycle update replaced the active-turn slot while terminal hooks ran;
        // coupling delivery to slot cleanup loses accepted user input during that race.
        if !follow_up_input.is_empty() {
            self.submit_follow_up_input(follow_up_input).await;
            return;
        }
        if cleared_active_turn {
            self.maybe_start_turn_for_pending_work().await;
        }
    }

    async fn finish_turn_mailbox_messages(
        &self,
        turn_state: &tokio::sync::Mutex<crate::state::TurnState>,
        end: MailboxTurnEnd,
    ) {
        let (message_ids, unrecorded_message_ids) = {
            let mut turn_state = turn_state.lock().await;
            let message_ids = turn_state.take_mailbox_message_ids();
            let unrecorded_message_ids =
                turn_state.take_unrecorded_mailbox_message_ids(&message_ids);
            let unrecorded_message_ids = match end {
                MailboxTurnEnd::Aborted => unrecorded_message_ids,
                MailboxTurnEnd::Completed | MailboxTurnEnd::Failed => Vec::new(),
            };
            (message_ids, unrecorded_message_ids)
        };
        if message_ids.is_empty() && unrecorded_message_ids.is_empty() {
            return;
        }
        let Some(state_db) = self.state_db() else {
            return;
        };
        // #1952 (D485): mail the stopped turn took but never recorded is gone from this session
        // (the abort drops the turn's input). Cancel its row, still Submitted under this
        // session, so that reloading the agent does not hand it over again: mailbox recovery
        // requeues a Submitted row of a replaced session, which is meant for a session that
        // died (crash recovery, #1058/#1545) and still is. The transition only moves a row that
        // is still Submitted. A message this session applied to its history is left as it is
        // even when its row is still Submitted (its rollout did not flush, or the abort landed
        // before the row moved on): recovery decides about it, as before.
        for message_id in unrecorded_message_ids {
            if self.has_applied_agent_message_id(&message_id).await {
                continue;
            }
            match state_db
                .transition_agent_message(
                    &message_id,
                    codex_state::AgentMailboxPhase::Submitted,
                    codex_state::AgentMailboxPhase::Cancelled,
                    crate::turn_timing::now_unix_timestamp_ms(),
                )
                .await
            {
                Ok(true) => debug!(
                    %message_id,
                    "cancelled agent mailbox message an interrupted turn took but never recorded"
                ),
                Ok(false) => {}
                Err(err) => warn!(
                    %err,
                    %message_id,
                    "failed to cancel agent mailbox message an interrupted turn never recorded"
                ),
            }
        }
        let completed_naturally = matches!(end, MailboxTurnEnd::Completed);
        for message_id in message_ids {
            let result = if completed_naturally {
                state_db
                    .mark_agent_message_completed(
                        &message_id,
                        crate::turn_timing::now_unix_timestamp_ms(),
                    )
                    .await
            } else {
                state_db
                    .transition_agent_message(
                        &message_id,
                        codex_state::AgentMailboxPhase::ProviderRunning,
                        codex_state::AgentMailboxPhase::UnknownOutcome,
                        crate::turn_timing::now_unix_timestamp_ms(),
                    )
                    .await
            };
            if let Err(err) = result {
                warn!(
                    %err,
                    %message_id,
                    completed_naturally,
                    "failed to finalize agent mailbox message with its turn"
                );
            }
        }
    }

    async fn take_active_turn(&self, reason: &TurnAbortReason) -> Option<ActiveTurn> {
        let mut active = self.active_turn.lock().await;
        if matches!(
            reason,
            TurnAbortReason::Interrupted | TurnAbortReason::BudgetLimited
        ) && active.as_ref().is_some_and(|turn| {
            turn.task.is_some()
                || (self.enabled(Feature::WakeOnAgentMessages) && turn.finishing.is_none())
        }) {
            // Message wakes reserve work before registering a task. With the
            // feature enabled, stopping a reservation must block later mail too.
            // Finishing turns must retain their status until completion is
            // persisted, so capacity eviction cannot close their rollout writer.
            self.mark_interrupted();
        }
        active.take()
    }

    pub(crate) async fn close_unified_exec_processes(&self) {
        self.services
            .unified_exec_manager
            .terminate_all_processes()
            .await;
    }

    pub(crate) async fn list_background_terminals(&self) -> Vec<BackgroundTerminalInfo> {
        self.services.unified_exec_manager.list_processes().await
    }

    pub(crate) async fn terminate_background_terminal(&self, process_id: i32) -> bool {
        self.services
            .unified_exec_manager
            .terminate_process(process_id)
            .await
    }

    async fn submit_follow_up_input(
        self: &Arc<Self>,
        follow_up_input: Vec<(TurnInput, Option<serde_json::Value>)>,
    ) {
        // User input waiting for admission's answer, settled in submission order.
        let mut awaiting_admission = Vec::new();
        for (input, final_output_json_schema) in follow_up_input {
            let submitted = match &input {
                TurnInput::UserInput { .. } => {
                    match self
                        .submit_follow_up_user_input(&input, final_output_json_schema.clone())
                        .await
                    {
                        Ok(reply_rx) => {
                            awaiting_admission.push((reply_rx, input, final_output_json_schema));
                            Ok(())
                        }
                        Err(err) => Err(err),
                    }
                }
                TurnInput::InterAgentCommunication(communication) => {
                    let delivery = communication.delivery.clone();
                    let mut communication = (**communication).clone();
                    communication.trigger_turn = true;
                    let op = Op::InterAgentCommunication {
                        communication,
                        start_options: TurnStartOptions {
                            final_output_json_schema,
                            ..Default::default()
                        },
                    };
                    self.submit_internal_follow_up_with_delivery(op, delivery)
                        .await
                }
                // The turn's own items (tool outputs, injected context) do not start work.
                TurnInput::ResponseItem(_) | TurnInput::FunctionCallOutput(_) => {
                    debug!("leftover non-user input after a finished turn is not submitted again");
                    continue;
                }
            };
            if let Err(err) = submitted {
                warn!(%err, "failed to submit follow-up input after task finished");
            }
        }
        if awaiting_admission.is_empty() {
            return;
        }
        // The input left this turn's queue: a refusal must not lose it.
        let session = Arc::clone(self);
        tokio::spawn(async move {
            for (reply_rx, input, final_output_json_schema) in awaiting_admission {
                session
                    .settle_follow_up_input(reply_rx, input, final_output_json_schema)
                    .await;
            }
        });
    }

    /// Submits follow-up user input as a start-or-steer turn input; the receiver gets
    /// admission's answer.
    async fn submit_follow_up_user_input(
        &self,
        input: &TurnInput,
        final_output_json_schema: Option<serde_json::Value>,
    ) -> CodexResult<tokio::sync::oneshot::Receiver<CodexResult<TurnInputSubmission>>> {
        let TurnInput::UserInput {
            content,
            client_id,
            metadata,
        } = input
        else {
            return Err(CodexErr::InvalidRequest(
                "only user input is submitted as turn input".to_string(),
            ));
        };
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let mut request = TurnInputRequest::new(SubmittedTurnInput::UserInput {
            content: content.clone(),
            client_id: client_id.clone(),
        })
        .on_start(TurnStartOptions {
            final_output_json_schema,
            // Keeps a heartbeat's origin (`UserInputOrigin::from_turn_trigger`).
            turn_trigger: (metadata.origin == codex_history::UserInputOrigin::Heartbeat)
                .then(|| "automation_heartbeat_scheduled".to_string()),
            ..Default::default()
        });
        request.user_item_uuid = metadata.response_item_uuid;
        self.submit_internal_follow_up(Op::TurnInput {
            request: Box::new(request),
            mode: TurnInputMode::StartOrSteer,
            reply,
        })
        .await?;
        Ok(reply_rx)
    }

    /// Follow-up user input that admission did not take, typically because another turn is
    /// running that it may not join (D529 (a): another authority, a non-steerable turn, another
    /// output schema): it waits in that turn's deferred input and is admitted again when the
    /// turn ends; with no turn running any more it is submitted again. Anything else is
    /// reported, as for client input.
    #[expect(
        clippy::await_holding_invalid_type,
        reason = "deferring into the running turn must not race its end"
    )]
    async fn settle_follow_up_input(
        &self,
        mut reply_rx: tokio::sync::oneshot::Receiver<CodexResult<TurnInputSubmission>>,
        input: TurnInput,
        final_output_json_schema: Option<serde_json::Value>,
    ) {
        // Each retry follows the end of the turn that refused it; the bound only stops a loop.
        for attempt in 1..=FOLLOW_UP_SUBMIT_ATTEMPTS {
            let reason = match reply_rx.await {
                Ok(Ok(
                    TurnInputSubmission::Started { .. } | TurnInputSubmission::Steered { .. },
                )) => return,
                Ok(Ok(TurnInputSubmission::NotSubmitted { reason })) => reason,
                Ok(Err(err)) => {
                    self.report_unsubmitted_follow_up(&input, &err.to_string())
                        .await;
                    return;
                }
                // The session ended before admission answered.
                Err(_) => return,
            };
            if !matches!(
                reason,
                NotSubmittedReason::AuthorizationChanged
                    | NotSubmittedReason::ActiveTurnNotSteerable { .. }
                    | NotSubmittedReason::ActiveTurnOutputSchemaMismatch
            ) {
                self.report_unsubmitted_follow_up(&input, &not_submitted_reason_text(&reason))
                    .await;
                return;
            }
            {
                // Under the active-turn lock, as every end of a turn takes its input under it:
                // a turn that is ending no longer has a task and never reads its queue again.
                let active = self.active_turn.lock().await;
                if let Some(active_turn) = active.as_ref().filter(|turn| turn.task.is_some()) {
                    active_turn
                        .turn_state
                        .lock()
                        .await
                        .pending_input
                        .defer_with_schema(input, final_output_json_schema);
                    return;
                }
            }
            if attempt == FOLLOW_UP_SUBMIT_ATTEMPTS {
                // Not submitted again: its answer would be read by no one.
                break;
            }
            // The turn that refused it has ended: admission takes it now.
            reply_rx = match self
                .submit_follow_up_user_input(&input, final_output_json_schema.clone())
                .await
            {
                Ok(reply_rx) => reply_rx,
                Err(err) => {
                    self.report_unsubmitted_follow_up(&input, &err.to_string())
                        .await;
                    return;
                }
            };
        }
        self.report_unsubmitted_follow_up(&input, "it was refused repeatedly")
            .await;
    }

    async fn report_unsubmitted_follow_up(&self, input: &TurnInput, reason: &str) {
        warn!(%reason, "follow-up input after a finished turn was not submitted");
        let preview = follow_up_preview(input);
        // A warning, not an error: an error event would end whatever turn runs now.
        self.send_event_raw(Event {
            id: uuid::Uuid::new_v4().to_string(),
            msg: EventMsg::Warning(WarningEvent {
                message: format!(
                    "Input that arrived while a turn was running could not be sent afterwards \
                     ({reason}); please send it again: \"{preview}\""
                ),
            }),
        })
        .await;
    }

    async fn submit_pending_work_wake(&self) {
        if !self.input_queue.has_trigger_turn_mailbox_items().await {
            return;
        }
        if let Err(err) = self.submit_internal_follow_up(Op::WakePendingWork).await {
            warn!(%err, "failed to submit pending-work wake after task finished");
        }
    }

    async fn handle_task_abort(
        self: &Arc<Self>,
        mut task: RunningTask,
        reason: TurnAbortReason,
        turn_state: &Mutex<TurnState>,
        error: Option<ErrorEvent>,
    ) {
        let sub_id = task.turn_context.sub_id.clone();
        if task.cancellation_token.is_cancelled() {
            self.emit_turn_abort_lifecycle(reason, task.turn_context.extension_data.as_ref())
                .await;
            return;
        }

        trace!(task_kind = ?task.kind, sub_id, "aborting running task");
        let cancelled_at = Instant::now();
        task.cancellation_token.cancel();
        if reason == TurnAbortReason::Interrupted
            && task
                .turn_context
                .config
                .features
                .enabled(Feature::CodeModeInterrupt)
        {
            self.services
                .code_mode_service
                .interrupt_active_cells()
                .await;
        }
        task.turn_context
            .turn_metadata_state
            .cancel_git_enrichment_task();
        let session_task = task.task;

        let hard_aborted = select! {
            _ = task.done.notified() => false,
            _ = tokio::time::sleep(Duration::from_millis(GRACEFULL_INTERRUPTION_TIMEOUT_MS)) => {
                warn!("task {sub_id} didn't complete gracefully after {}ms", GRACEFULL_INTERRUPTION_TIMEOUT_MS);
                // Forced teardown can abort independently spawned tool dispatches
                // whose guards are destroyed later. Do not publish complete totals
                // for a dependency graph that has not settled.
                task.turn_context.turn_timing_state.invalidate_critical_path();
                true
            }
        };

        task.handle.abort();
        // Aborting schedules destruction; join before freezing the turn's timing.
        // Joining waits only for the turn's current poll to return, so the turn
        // cannot record an output after the check below. The join is skipped only
        // when the turn task aborts itself; aborts from tasks the turn spawned must
        // run in a detached task (as guardian's does), or the join cancels them.
        if tokio::task::try_id() != Some(task.handle.abort_handle().id()) {
            let _ = (&mut task.handle).await;
        }
        if hard_aborted {
            // The turn did not record its tool outputs in time. Once it has stopped,
            // record each pending call's output, as the turn would have: the tool's
            // own output if it finished (D244), else its abort output (#1467).
            let mut outputs: Vec<ResponseItem> = task
                .turn_context
                .pending_tool_calls
                .take_unrecorded_outputs(cancelled_at)
                .into_iter()
                .collect();
            self.retain_unrecorded_tool_outputs(&mut outputs).await;
            if !outputs.is_empty() {
                self.record_conversation_items(
                    task.turn_context.as_ref(),
                    task.turn_context.model_info(),
                    &outputs,
                )
                .await;
                // A finished call's real output is recorded here instead of by the
                // turn (D244), so apply the turn's external-context check too.
                for output in &outputs {
                    crate::stream_events_utils::mark_thread_memory_mode_polluted_if_external_context(
                        self,
                        task.turn_context.as_ref(),
                        output,
                    )
                    .await;
                }
            }
            // D282: the turn did not reach its end, which sends the turn's
            // file-change summary; send it here.
            if let Some(tracker) = task.turn_context.pending_tool_calls.turn_diff_tracker() {
                let unified_diff = tracker.lock().await.get_unified_diff();
                if let Some(unified_diff) = unified_diff {
                    self.send_event(
                        task.turn_context.as_ref(),
                        EventMsg::TurnDiff(TurnDiffEvent { unified_diff }),
                    )
                    .await;
                }
            }
        }

        session_task
            .abort(Arc::clone(self), Arc::clone(&task.turn_context))
            .await;

        if reason == TurnAbortReason::Interrupted
            && let Some(marker) = interrupted_turn_history_marker(
                InterruptedTurnHistoryMarker::from_config_and_version(
                    task.turn_context.config.as_ref(),
                    task.turn_context.multi_agent_version,
                ),
            )
        {
            self.record_conversation_items_from(
                task.turn_context.as_ref(),
                task.turn_context.model_info(),
                std::slice::from_ref(&marker),
                Some(crate::security::ingress::MessageOrigin::Host),
            )
            .await;
            // Ensure the marker is durably visible before emitting TurnAborted: some clients
            // synchronously re-read the rollout on receipt of the abort event.
            if let Err(err) = self.flush_rollout().await {
                warn!("failed to flush interrupted-turn marker before emitting TurnAborted: {err}");
            }
        }

        if reason == TurnAbortReason::Interrupted {
            run_turn_interrupt_hooks(self, &task.turn_context, turn_state).await;
        }

        let started_at = task
            .turn_context
            .turn_timing_state
            .started_at_unix_secs()
            .await;
        let (completed_at, duration_ms, profile) = task
            .turn_context
            .turn_timing_state
            .complete_profile_and_duration_ms()
            .await;
        crate::turn_timing::record_turn_profile_trace(
            self.thread_id,
            &task.turn_context.sub_id,
            &profile,
        );
        self.services
            .analytics_events_client
            .track_turn_profile(TurnProfileFact {
                turn_id: task.turn_context.sub_id.clone(),
                profile,
            });
        self.emit_turn_abort_lifecycle(reason.clone(), task.turn_context.extension_data.as_ref())
            .await;
        let event = EventMsg::TurnAborted(TurnAbortedEvent {
            root_turn_id: Some(task.turn_context.root_turn_id()),
            turn_id: Some(task.turn_context.sub_id.clone()),
            reason,
            error,
            started_at,
            completed_at,
            duration_ms,
        });
        self.send_event(task.turn_context.as_ref(), event).await;
        // Regular items were flushed before this terminal event was appended; buffering
        // thread writers may not flush it without another explicit barrier.
        if let Err(err) = self.flush_rollout().await {
            warn!("failed to flush rollout after emitting terminal turn event: {err}");
        }
    }
}

/// Plain-language text for a refused follow-up (never a debug dump).
fn not_submitted_reason_text(reason: &NotSubmittedReason) -> String {
    match reason {
        NotSubmittedReason::ServerDraining => "the server is shutting down".to_string(),
        NotSubmittedReason::EmptyInput => "it was empty".to_string(),
        NotSubmittedReason::PendingTriggerTurn => {
            "agent messages were waiting to start a turn first".to_string()
        }
        NotSubmittedReason::Superseded | NotSubmittedReason::NotIdle => {
            "another request took its place".to_string()
        }
        // Not reached for start-or-steer user input; listed so the match stays exhaustive.
        NotSubmittedReason::PlanMode
        | NotSubmittedReason::NoActiveTurn
        | NotSubmittedReason::ExpectedTurnMismatch { .. } => {
            "the thread was not ready for it".to_string()
        }
        // Retried by `settle_follow_up_input`, so reported only after repeated refusals.
        NotSubmittedReason::AuthorizationChanged => {
            "the running turn's permissions changed".to_string()
        }
        NotSubmittedReason::ActiveTurnNotSteerable { .. } => {
            "the running turn does not take new input".to_string()
        }
        NotSubmittedReason::ActiveTurnOutputSchemaMismatch => {
            "the running turn expects another output format".to_string()
        }
        NotSubmittedReason::KillSwitch => "the security kill switch is on".to_string(),
    }
}

/// A short, single-line preview of follow-up text for a report.
fn follow_up_preview(input: &TurnInput) -> String {
    const PREVIEW_CHARS: usize = 80;
    let TurnInput::UserInput { content, .. } = input else {
        return String::new();
    };
    let text = content
        .iter()
        .filter_map(|item| match item {
            UserInput::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > PREVIEW_CHARS {
        format!(
            "{}...",
            text.chars().take(PREVIEW_CHARS).collect::<String>()
        )
    } else {
        text
    }
}

fn pending_input_seeds_follow_up(input: &TurnInput) -> bool {
    match input {
        TurnInput::UserInput { content, .. } => !content.is_empty(),
        TurnInput::InterAgentCommunication(_) => false,
        TurnInput::ResponseItem(_) | TurnInput::FunctionCallOutput(_) => false,
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "idle_lifecycle_tests.rs"]
mod idle_lifecycle_tests;
