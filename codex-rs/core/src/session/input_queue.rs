use super::Session;
use crate::state::ActiveTurn;
use crate::state::MailboxDeliveryPhase;
use crate::state::TurnState;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::InterAgentCommunication;
use codex_protocol::user_input::UserInput;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TurnInput {
    UserInput {
        content: Vec<UserInput>,
        client_id: Option<String>,
    },
    ResponseItem(ResponseItem),
    InterAgentCommunication(InterAgentCommunication),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputQueueActivity {
    Mailbox,
    Steer,
}

/// Turn-local pending input storage owned by the input queue flow.
#[derive(Default)]
pub(crate) struct TurnInputQueue {
    items: Vec<TurnInput>,
    deferred: Vec<(TurnInput, Option<serde_json::Value>)>,
}

/// Session-scoped pending input storage and active-turn mailbox delivery coordination.
pub(crate) struct InputQueue {
    activity_tx: watch::Sender<InputQueueActivity>,
    mailbox_pending_mails: Mutex<VecDeque<PendingMailboxCommunication>>,
    capacity_wait_scheduled: AtomicBool,
    interrupted_deferred_input: Mutex<VecDeque<(TurnInput, Option<serde_json::Value>)>>,
    interrupted_input_ready: tokio::sync::Notify,
}

struct PendingMailboxCommunication {
    communication: InterAgentCommunication,
    parent_turn_id: Option<String>,
    ready_for_admitted_turn: bool,
    deferred_for_turn: Option<String>,
    deferred_turn_state: Option<std::sync::Weak<Mutex<TurnState>>>,
}

impl InputQueue {
    pub(crate) fn new() -> Self {
        let (activity_tx, _) = watch::channel(InputQueueActivity::Mailbox);
        Self {
            activity_tx,
            mailbox_pending_mails: Mutex::new(VecDeque::new()),
            capacity_wait_scheduled: AtomicBool::new(false),
            interrupted_deferred_input: Mutex::new(VecDeque::new()),
            interrupted_input_ready: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn try_schedule_capacity_wait(&self) -> bool {
        self.capacity_wait_scheduled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn finish_capacity_wait(&self) {
        self.capacity_wait_scheduled.store(false, Ordering::Release);
    }

    pub(crate) async fn subscribe_activity(
        &self,
        turn_state: Option<&Mutex<TurnState>>,
    ) -> (
        watch::Receiver<InputQueueActivity>,
        Option<InputQueueActivity>,
    ) {
        let activity_rx = self.activity_tx.subscribe();
        let has_pending_steer = if let Some(turn_state) = turn_state {
            turn_state.lock().await.pending_input.has_user_input()
        } else {
            false
        };
        // Turn-local waiters cannot consume input still waiting for re-admission.
        let has_pending_steer = has_pending_steer
            || (turn_state.is_none() && !self.interrupted_deferred_input.lock().await.is_empty());
        let pending_activity = if has_pending_steer {
            Some(InputQueueActivity::Steer)
        } else if self.mailbox_pending_mails.lock().await.iter().any(|mail| {
            !turn_state.is_some_and(|turn_state| {
                mail.deferred_turn_state
                    .as_ref()
                    .is_some_and(|deferred| std::ptr::eq(deferred.as_ptr(), turn_state))
            })
        }) {
            Some(InputQueueActivity::Mailbox)
        } else {
            None
        };
        (activity_rx, pending_activity)
    }

    #[cfg(test)]
    pub(crate) async fn enqueue_mailbox_communication(
        &self,
        communication: InterAgentCommunication,
        parent_turn_id: Option<String>,
    ) {
        self.mailbox_pending_mails
            .lock()
            .await
            .push_back(PendingMailboxCommunication {
                ready_for_admitted_turn: communication.trigger_turn,
                deferred_for_turn: None,
                deferred_turn_state: None,
                communication,
                parent_turn_id,
            });
        self.activity_tx.send_replace(InputQueueActivity::Mailbox);
    }

    /// Enqueues mailbox delivery relative to the session's actual task boundary.
    ///
    /// Holding `active_turn` while the queue entry is created closes the race with task
    /// completion: mail received after the task has been detached is immediately eligible for
    /// the next admitted human turn, while mail received during the task is advanced by that
    /// task's terminal boundary.
    #[allow(
        clippy::await_holding_invalid_type,
        reason = "active-turn and mailbox admission must remain atomic across both locks"
    )]
    pub(crate) async fn enqueue_mailbox_communication_for_session(
        &self,
        session: &Session,
        communication: InterAgentCommunication,
        parent_turn_id: Option<String>,
    ) {
        let active_turn = session.active_turn.lock().await;
        let state = session.state.lock().await;
        let deferred_for_turn = active_turn
            .as_ref()
            .and_then(|turn| turn.task.as_ref())
            .filter(|task| {
                !Session::authorization_matches(&state.session_configuration, &task.turn_context)
            })
            .map(|task| task.turn_context.sub_id.clone());
        let notify_waiters = deferred_for_turn.is_none();
        let deferred_turn_state = active_turn
            .as_ref()
            .filter(|_| deferred_for_turn.is_some())
            .map(|turn| Arc::downgrade(&turn.turn_state));
        let ready_for_admitted_turn = communication.trigger_turn
            || active_turn
                .as_ref()
                .and_then(|active_turn| active_turn.task.as_ref())
                .is_none();
        self.mailbox_pending_mails
            .lock()
            .await
            .push_back(PendingMailboxCommunication {
                communication,
                parent_turn_id,
                ready_for_admitted_turn,
                deferred_for_turn,
                deferred_turn_state,
            });
        drop(state);
        drop(active_turn);
        // Deferred mail cannot interrupt a waiter in the turn that cannot consume it.
        if notify_waiters {
            self.activity_tx.send_replace(InputQueueActivity::Mailbox);
        }
    }

    pub(crate) async fn has_pending_mailbox_items(&self) -> bool {
        !self.mailbox_pending_mails.lock().await.is_empty()
    }

    pub(crate) async fn has_trigger_turn_mailbox_items(&self) -> bool {
        self.mailbox_pending_mails
            .lock()
            .await
            .iter()
            .any(|mail| mail.communication.trigger_turn)
    }

    #[cfg(test)]
    pub(crate) async fn drain_mailbox_input_items(&self) -> (Vec<TurnInput>, Option<String>) {
        self.drain_mailbox_input_for_turn(/*turn_id*/ None).await
    }

    async fn drain_mailbox_input_for_turn(
        &self,
        turn_id: Option<&str>,
    ) -> (Vec<TurnInput>, Option<String>) {
        let mut pending_mails = self.mailbox_pending_mails.lock().await;
        let (ready, deferred) = pending_mails.drain(..).partition(|mail| {
            mail.deferred_for_turn.is_none() || mail.deferred_for_turn.as_deref() != turn_id
        });
        *pending_mails = deferred;
        Self::mailbox_input_items(ready.into())
    }

    /// Drains only mail that is eligible to join a newly admitted human turn.
    ///
    /// Trigger-turn mail is immediately eligible. Queue-only mail becomes eligible after one
    /// active-turn boundary, which prevents mail queued while idle from being pulled into the
    /// very next request while still allowing it to accompany the following human turn.
    pub(crate) async fn drain_ready_mailbox_input_items(&self) -> (Vec<TurnInput>, Option<String>) {
        let ready_mails = {
            let mut pending_mails = self.mailbox_pending_mails.lock().await;
            let mut ready_mails = Vec::new();
            let mut waiting_mails = VecDeque::new();
            while let Some(mail) = pending_mails.pop_front() {
                if mail.ready_for_admitted_turn {
                    ready_mails.push(mail);
                } else {
                    waiting_mails.push_back(mail);
                }
            }
            *pending_mails = waiting_mails;
            ready_mails
        };
        Self::mailbox_input_items(ready_mails)
    }

    /// Advances queue-only mail across a completed turn boundary without starting a turn.
    pub(crate) async fn mark_mailbox_ready_for_next_turn(&self) {
        for mail in self.mailbox_pending_mails.lock().await.iter_mut() {
            mail.ready_for_admitted_turn = true;
        }
    }

    fn mailbox_input_items(
        pending_mails: Vec<PendingMailboxCommunication>,
    ) -> (Vec<TurnInput>, Option<String>) {
        let parent_turn_id = pending_mails
            .iter()
            .filter(|mail| mail.communication.trigger_turn)
            .map(|mail| mail.parent_turn_id.as_deref())
            .reduce(|expected, candidate| expected.filter(|id| candidate == Some(*id)))
            .and_then(|id| id.filter(|id| !id.trim().is_empty()).map(str::to_string));
        let items = pending_mails
            .into_iter()
            .map(|mail| TurnInput::InterAgentCommunication(mail.communication))
            .collect();
        (items, parent_turn_id)
    }

    pub(crate) async fn turn_state_for_sub_id(
        &self,
        active_turn: &Mutex<Option<ActiveTurn>>,
        sub_id: &str,
    ) -> Option<Arc<Mutex<TurnState>>> {
        let active = active_turn.lock().await;
        active.as_ref().and_then(|active_turn| {
            active_turn
                .task
                .as_ref()
                .is_some_and(|task| task.turn_context.sub_id == sub_id)
                .then(|| Arc::clone(&active_turn.turn_state))
        })
    }

    /// Clear any pending waiters and input buffered for the current turn.
    pub(crate) async fn clear_pending(&self, active_turn: &ActiveTurn) {
        // Release the turn-state lock before taking the interrupted-input lock:
        // holding one tokio mutex guard across another await is disallowed.
        let deferred = {
            let mut turn_state = active_turn.turn_state.lock().await;
            turn_state.clear_pending_waiters();
            turn_state.pending_input.items.clear();
            std::mem::take(&mut turn_state.pending_input.deferred)
        };
        if !deferred.is_empty() {
            self.interrupted_deferred_input
                .lock()
                .await
                .extend(deferred);
            self.interrupted_input_ready.notify_one();
        }
    }

    /// Interrupted input returns to submission admission, never directly to a task's queue.
    pub(crate) async fn next_interrupted_deferred_input(
        &self,
    ) -> (TurnInput, Option<serde_json::Value>) {
        loop {
            let ready = self.interrupted_input_ready.notified();
            if let Some(input) = self.interrupted_deferred_input.lock().await.pop_front() {
                return input;
            }
            ready.await;
        }
    }

    pub(crate) async fn defer_mailbox_delivery_to_next_turn(
        &self,
        active_turn: &Mutex<Option<ActiveTurn>>,
        sub_id: &str,
    ) {
        let turn_state = self.turn_state_for_sub_id(active_turn, sub_id).await;
        let Some(turn_state) = turn_state else {
            return;
        };
        let mut turn_state = turn_state.lock().await;
        // Explicit same-turn work still needs a follow-up. Queue-only child mail does not: keep
        // it pending so task completion records it for the next turn without sampling again.
        if turn_state.pending_input.items.iter().any(|input| {
            !matches!(
                input,
                TurnInput::InterAgentCommunication(communication) if !communication.trigger_turn
            )
        }) {
            return;
        }
        turn_state.set_mailbox_delivery_phase(MailboxDeliveryPhase::NextTurn);
    }

    pub(crate) async fn accept_mailbox_delivery_for_current_turn(
        &self,
        active_turn: &Mutex<Option<ActiveTurn>>,
        sub_id: &str,
    ) {
        let turn_state = self.turn_state_for_sub_id(active_turn, sub_id).await;
        let Some(turn_state) = turn_state else {
            return;
        };
        self.accept_mailbox_delivery_for_turn_state(turn_state.as_ref())
            .await;
    }

    pub(super) async fn accept_mailbox_delivery_for_turn_state(
        &self,
        turn_state: &Mutex<TurnState>,
    ) {
        turn_state
            .lock()
            .await
            .accept_mailbox_delivery_for_current_turn();
    }

    pub(super) async fn extend_pending_input_and_accept_mailbox_delivery_for_turn_state(
        &self,
        turn_state: &Mutex<TurnState>,
        input: Vec<TurnInput>,
    ) {
        {
            let mut turn_state = turn_state.lock().await;
            turn_state.pending_input.items.extend(input);
            turn_state.accept_mailbox_delivery_for_current_turn();
        }
        self.activity_tx.send_replace(InputQueueActivity::Steer);
    }

    pub(crate) async fn extend_pending_input_for_turn_state(
        &self,
        turn_state: &Mutex<TurnState>,
        input: Vec<TurnInput>,
    ) {
        turn_state.lock().await.pending_input.items.extend(input);
    }

    pub(crate) async fn defer_input_for_turn_state(
        &self,
        turn_state: &Mutex<TurnState>,
        input: Vec<TurnInput>,
        final_output_json_schema: Option<serde_json::Value>,
    ) {
        turn_state.lock().await.pending_input.deferred.extend(
            input
                .into_iter()
                .map(|input| (input, final_output_json_schema.clone())),
        );
    }

    pub(crate) async fn take_pending_input_for_turn_state(
        &self,
        turn_state: &Mutex<TurnState>,
    ) -> Vec<(TurnInput, Option<serde_json::Value>)> {
        let mut state = turn_state.lock().await;
        let mut input: Vec<_> = std::mem::take(&mut state.pending_input.items)
            .into_iter()
            .map(|input| (input, None))
            .collect();
        input.append(&mut state.pending_input.deferred);
        input
    }

    /// #2047: tests poll pending input the way a running task does. With no active turn (a
    /// detached task, or an idle session) mailbox mail stays queued, as in production; tests
    /// that inspect queued mail use `drain_mailbox_input_items` or `has_pending_mailbox_items`.
    #[cfg(test)]
    pub(crate) async fn get_pending_input(
        &self,
        active_turn: &Mutex<Option<ActiveTurn>>,
    ) -> (Vec<TurnInput>, Option<String>) {
        self.get_pending_input_for_running_task(active_turn).await
    }

    /// Takes input for an already-running task. A task detached by any stop path must not drain
    /// mailbox mail: it no longer has a turn state that can record its outcome.
    #[allow(
        clippy::await_holding_invalid_type,
        reason = "taking mail off the queue and noting it in the turn state must remain atomic"
    )]
    pub(crate) async fn get_pending_input_for_running_task(
        &self,
        active_turn: &Mutex<Option<ActiveTurn>>,
    ) -> (Vec<TurnInput>, Option<String>) {
        let (pending_input, accepts_mailbox_delivery, turn_id, turn_state) =
            Self::take_turn_pending_input(active_turn).await;
        if !accepts_mailbox_delivery {
            return (pending_input, None);
        }
        let (mailbox_items, parent_turn_id) = match turn_state {
            // #1952 (D485): the turn notes the mail it takes in the same step, with no await
            // between, so an interrupt that stops the turn knows what it took.
            Some(turn_state) => {
                let mut turn_state = turn_state.lock().await;
                let (mailbox_items, parent_turn_id) =
                    self.drain_mailbox_input_for_turn(turn_id.as_deref()).await;
                turn_state.track_taken_mailbox_messages(&mailbox_items);
                (mailbox_items, parent_turn_id)
            }
            // No turn state can note the mail (a detached task or an idle session): it stays
            // queued.
            None => (Vec::new(), None),
        };
        if pending_input.is_empty() {
            (mailbox_items, parent_turn_id)
        } else {
            let mut pending_input = pending_input;
            pending_input.extend(mailbox_items);
            (pending_input, parent_turn_id)
        }
    }

    /// Takes input while admitting a task without bypassing mailbox turn-boundary eligibility.
    ///
    /// A task start may inherit user steering from a reserved active-turn slot, but queue-only
    /// collaboration mail must remain session-pending until it has crossed a completed turn
    /// boundary. Draining the entire mailbox here converts that mail into a same-turn follow-up
    /// and can create a mail-only model turn before the next human prompt.
    pub(crate) async fn get_pending_input_for_task_start(
        &self,
        active_turn: &Mutex<Option<ActiveTurn>>,
    ) -> (Vec<TurnInput>, Option<String>) {
        let (pending_input, accepts_mailbox_delivery, turn_id, _turn_state) =
            Self::take_turn_pending_input(active_turn).await;
        if !accepts_mailbox_delivery {
            return (pending_input, None);
        }
        debug_assert!(
            turn_id.is_none(),
            "task start must precede task installation"
        );
        let (mailbox_items, parent_turn_id) = self.drain_ready_mailbox_input_items().await;
        if pending_input.is_empty() {
            (mailbox_items, parent_turn_id)
        } else {
            let mut pending_input = pending_input;
            pending_input.extend(mailbox_items);
            (pending_input, parent_turn_id)
        }
    }

    #[allow(
        clippy::await_holding_invalid_type,
        reason = "active-turn and turn-state inspection must remain atomic"
    )]
    async fn take_turn_pending_input(
        active_turn: &Mutex<Option<ActiveTurn>>,
    ) -> (
        Vec<TurnInput>,
        bool,
        Option<String>,
        Option<Arc<Mutex<TurnState>>>,
    ) {
        {
            let mut active = active_turn.lock().await;
            match active.as_mut() {
                Some(active_turn) => {
                    let mut turn_state = active_turn.turn_state.lock().await;
                    let accepts_mailbox_delivery =
                        turn_state.accepts_mailbox_delivery_for_current_turn();
                    let pending_input = if accepts_mailbox_delivery {
                        turn_state.pending_input.items.split_off(0)
                    } else {
                        Vec::new()
                    };
                    (
                        pending_input,
                        accepts_mailbox_delivery,
                        active_turn
                            .task
                            .as_ref()
                            .map(|task| task.turn_context.sub_id.clone()),
                        Some(Arc::clone(&active_turn.turn_state)),
                    )
                }
                // `get_pending_input_for_task_start` also uses this helper. It may legitimately
                // start from an idle slot and must still inspect ready mailbox work; the running
                // task path separately refuses to drain without a TurnState (#2010).
                None => (Vec::new(), true, None, None),
            }
        }
    }

    #[expect(
        clippy::await_holding_invalid_type,
        reason = "active turn checks and turn state reads must remain atomic"
    )]
    pub(crate) async fn has_pending_input(&self, active_turn: &Mutex<Option<ActiveTurn>>) -> bool {
        if !self.interrupted_deferred_input.lock().await.is_empty() {
            return true;
        }
        let (has_turn_pending_input, accepts_mailbox_delivery, turn_id) = {
            let active = active_turn.lock().await;
            match active.as_ref() {
                Some(active_turn) => {
                    let turn_state = active_turn.turn_state.lock().await;
                    (
                        !turn_state.pending_input.items.is_empty(),
                        turn_state.accepts_mailbox_delivery_for_current_turn(),
                        active_turn
                            .task
                            .as_ref()
                            .map(|task| task.turn_context.sub_id.clone()),
                    )
                }
                None => (false, true, None),
            }
        };
        if !accepts_mailbox_delivery {
            return false;
        }
        if has_turn_pending_input {
            return true;
        }
        self.mailbox_pending_mails
            .lock()
            .await
            .iter()
            .any(|mail| mail.deferred_for_turn.is_none() || mail.deferred_for_turn != turn_id)
    }
}

impl TurnInputQueue {
    fn has_user_input(&self) -> bool {
        self.items
            .iter()
            .any(|input| matches!(input, TurnInput::UserInput { .. }))
    }

    /// #1952: whether `message_id` waits in input deferred to re-admission, which an interrupt
    /// keeps (`InputQueue::clear_pending`).
    pub(crate) fn defers_mailbox_message(&self, message_id: &str) -> bool {
        self.deferred.iter().any(|(input, _)| {
            matches!(
                input,
                TurnInput::InterAgentCommunication(communication)
                    if communication.message_id.as_deref() == Some(message_id)
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::AgentPath;
    use pretty_assertions::assert_eq;

    fn make_mail(
        author: AgentPath,
        recipient: AgentPath,
        content: &str,
        trigger_turn: bool,
    ) -> InterAgentCommunication {
        InterAgentCommunication::new(
            author,
            recipient,
            Vec::new(),
            content.to_string(),
            trigger_turn,
        )
    }

    #[tokio::test]
    async fn input_queue_notifies_mailbox_subscribers() {
        let input_queue = InputQueue::new();
        let (mut activity_rx, pending_activity) =
            input_queue.subscribe_activity(/*turn_state*/ None).await;
        assert_eq!(pending_activity, None);

        let mail_one = make_mail(
            AgentPath::root(),
            AgentPath::try_from("/root/worker").expect("agent path"),
            "one",
            /*trigger_turn*/ false,
        );
        input_queue
            .enqueue_mailbox_communication(mail_one, /*parent_turn_id*/ None)
            .await;
        let mail_two = make_mail(
            AgentPath::root(),
            AgentPath::try_from("/root/worker").expect("agent path"),
            "two",
            /*trigger_turn*/ false,
        );
        input_queue
            .enqueue_mailbox_communication(mail_two, /*parent_turn_id*/ None)
            .await;

        activity_rx.changed().await.expect("mailbox update");
        assert_eq!(
            *activity_rx.borrow_and_update(),
            InputQueueActivity::Mailbox
        );
    }

    #[tokio::test]
    async fn input_queue_notifies_steer_subscribers() {
        let input_queue = InputQueue::new();
        let turn_state = Mutex::new(TurnState::default());
        let (mut activity_rx, pending_activity) =
            input_queue.subscribe_activity(Some(&turn_state)).await;
        assert_eq!(pending_activity, None);

        input_queue
            .extend_pending_input_and_accept_mailbox_delivery_for_turn_state(
                &turn_state,
                vec![TurnInput::UserInput {
                    content: vec![UserInput::Text {
                        text: "steer".to_string(),
                        text_elements: Vec::new(),
                    }],
                    client_id: None,
                }],
            )
            .await;

        activity_rx.changed().await.expect("steer update");
        assert_eq!(*activity_rx.borrow_and_update(), InputQueueActivity::Steer);
    }

    #[tokio::test]
    async fn input_queue_reports_already_pending_steer() {
        let input_queue = InputQueue::new();
        let turn_state = Mutex::new(TurnState::default());
        input_queue
            .extend_pending_input_and_accept_mailbox_delivery_for_turn_state(
                &turn_state,
                vec![TurnInput::UserInput {
                    content: vec![UserInput::Text {
                        text: "already pending".to_string(),
                        text_elements: Vec::new(),
                    }],
                    client_id: None,
                }],
            )
            .await;

        let (_activity_rx, pending_activity) =
            input_queue.subscribe_activity(Some(&turn_state)).await;

        assert_eq!(pending_activity, Some(InputQueueActivity::Steer));
    }

    #[tokio::test]
    async fn input_queue_drains_mailbox_in_delivery_order() {
        let input_queue = InputQueue::new();
        let mail_one = make_mail(
            AgentPath::root(),
            AgentPath::try_from("/root/worker").expect("agent path"),
            "one",
            /*trigger_turn*/ false,
        );
        let mail_two = make_mail(
            AgentPath::try_from("/root/worker").expect("agent path"),
            AgentPath::root(),
            "two",
            /*trigger_turn*/ true,
        );

        input_queue
            .enqueue_mailbox_communication(mail_one.clone(), /*parent_turn_id*/ None)
            .await;
        input_queue
            .enqueue_mailbox_communication(mail_two.clone(), /*parent_turn_id*/ None)
            .await;

        assert_eq!(
            input_queue.drain_mailbox_input_items().await.0,
            vec![
                TurnInput::InterAgentCommunication(mail_one),
                TurnInput::InterAgentCommunication(mail_two)
            ]
        );
        assert!(!input_queue.has_pending_mailbox_items().await);
    }

    #[tokio::test]
    async fn input_queue_requires_one_unambiguous_trigger_parent() {
        for (pending_mails, expected_parent_turn_id) in [
            (Vec::new(), None),
            (vec![(false, Some("q"))], None),
            (vec![(true, Some(""))], None),
            (vec![(true, Some("   "))], None),
            (vec![(true, None)], None),
            (vec![(true, Some("a")), (true, Some("b"))], None),
            (vec![(true, Some("a")), (true, None)], None),
            (vec![(true, Some("a")), (true, Some("a"))], Some("a")),
            (vec![(false, Some("q")), (true, Some("a"))], Some("a")),
        ] {
            let input_queue = InputQueue::new();
            for (trigger_turn, parent_turn_id) in pending_mails {
                input_queue
                    .enqueue_mailbox_communication(
                        make_mail(AgentPath::root(), AgentPath::root(), "task", trigger_turn),
                        parent_turn_id.map(str::to_string),
                    )
                    .await;
            }
            let (_, parent_turn_id) = input_queue.drain_mailbox_input_items().await;
            assert_eq!(parent_turn_id.as_deref(), expected_parent_turn_id);
        }
    }

    #[tokio::test]
    async fn input_queue_tracks_pending_trigger_turn_mail() {
        let input_queue = InputQueue::new();

        let queued_mail = make_mail(
            AgentPath::root(),
            AgentPath::try_from("/root/worker").expect("agent path"),
            "queued",
            /*trigger_turn*/ false,
        );
        input_queue
            .enqueue_mailbox_communication(queued_mail, /*parent_turn_id*/ None)
            .await;
        assert!(!input_queue.has_trigger_turn_mailbox_items().await);

        let trigger_mail = make_mail(
            AgentPath::root(),
            AgentPath::try_from("/root/worker").expect("agent path"),
            "wake",
            /*trigger_turn*/ true,
        );
        input_queue
            .enqueue_mailbox_communication(trigger_mail, /*parent_turn_id*/ None)
            .await;
        assert!(input_queue.has_trigger_turn_mailbox_items().await);
    }

    #[tokio::test]
    async fn admitted_turn_drain_waits_one_boundary_for_queue_only_mail() {
        let input_queue = InputQueue::new();
        let queued_mail = make_mail(
            AgentPath::try_from("/root/worker").expect("agent path"),
            AgentPath::root(),
            "queued",
            /*trigger_turn*/ false,
        );
        input_queue
            .enqueue_mailbox_communication(queued_mail.clone(), /*parent_turn_id*/ None)
            .await;

        assert_eq!(
            input_queue.drain_ready_mailbox_input_items().await,
            (Vec::new(), None)
        );
        input_queue.mark_mailbox_ready_for_next_turn().await;
        assert_eq!(
            input_queue.drain_ready_mailbox_input_items().await,
            (vec![TurnInput::InterAgentCommunication(queued_mail)], None)
        );
    }

    #[tokio::test]
    async fn idle_session_makes_queue_only_mail_ready_for_next_turn() {
        let (session, _context) = super::super::tests::make_session_and_context().await;
        let input_queue = &session.input_queue;
        let queued_mail = make_mail(
            AgentPath::try_from("/root/worker").expect("agent path"),
            AgentPath::root(),
            "queued while idle",
            /*trigger_turn*/ false,
        );

        input_queue
            .enqueue_mailbox_communication_for_session(
                &session,
                queued_mail.clone(),
                /*parent_turn_id*/ None,
            )
            .await;

        assert_eq!(
            input_queue.drain_ready_mailbox_input_items().await,
            (vec![TurnInput::InterAgentCommunication(queued_mail)], None)
        );
    }

    #[tokio::test]
    async fn admitted_turn_drain_accepts_trigger_mail_immediately() {
        let input_queue = InputQueue::new();
        let trigger_mail = make_mail(
            AgentPath::try_from("/root/worker").expect("agent path"),
            AgentPath::root(),
            "trigger",
            /*trigger_turn*/ true,
        );
        input_queue
            .enqueue_mailbox_communication(trigger_mail.clone(), Some("parent-turn".to_string()))
            .await;

        assert_eq!(
            input_queue.drain_ready_mailbox_input_items().await,
            (
                vec![TurnInput::InterAgentCommunication(trigger_mail)],
                Some("parent-turn".to_string())
            )
        );
    }

    fn mail_with_id(content: &str) -> (InterAgentCommunication, String) {
        let mut mail = make_mail(
            AgentPath::root(),
            AgentPath::try_from("/root/worker").expect("agent path"),
            content,
            /*trigger_turn*/ true,
        );
        let message_id = mail.ensure_message_identity().to_string();
        (mail, message_id)
    }

    #[tokio::test]
    async fn running_turn_notes_the_mail_it_takes() {
        let input_queue = InputQueue::new();
        let active_turn = Mutex::new(Some(ActiveTurn::default()));
        let (mail, message_id) = mail_with_id("taken mid-turn");
        input_queue
            .enqueue_mailbox_communication(mail.clone(), /*parent_turn_id*/ None)
            .await;

        let (input, _) = input_queue.get_pending_input(&active_turn).await;

        assert_eq!(input, vec![TurnInput::InterAgentCommunication(mail)]);
        let turn_state = Arc::clone(
            &active_turn
                .lock()
                .await
                .as_ref()
                .expect("active turn")
                .turn_state,
        );
        assert_eq!(
            turn_state
                .lock()
                .await
                .take_unrecorded_mailbox_message_ids(&[]),
            vec![message_id]
        );
    }

    #[tokio::test]
    async fn stopped_turn_keeps_mailbox_items_for_the_next_turn() {
        let input_queue = InputQueue::new();
        let stopped_turn = Mutex::new(None);
        let (mail, _) = mail_with_id("arrived while stopping");
        input_queue
            .enqueue_mailbox_communication(mail.clone(), /*parent_turn_id*/ None)
            .await;

        // The active slot is removed before shutdown waits for the running task. A stale task
        // reaching its next input poll must leave mail queued rather than silently taking it.
        assert_eq!(
            input_queue
                .get_pending_input_for_running_task(&stopped_turn)
                .await
                .0,
            Vec::new()
        );
        assert!(input_queue.has_pending_mailbox_items().await);

        // A subsequently admitted turn receives the preserved item normally.
        let next_turn = Mutex::new(Some(ActiveTurn::default()));
        assert_eq!(
            input_queue.get_pending_input(&next_turn).await.0,
            vec![TurnInput::InterAgentCommunication(mail)]
        );
        assert!(!input_queue.has_pending_mailbox_items().await);
    }

    #[tokio::test]
    async fn task_start_still_admits_ready_mail_from_an_idle_slot() {
        let input_queue = InputQueue::new();
        let idle_slot = Mutex::new(None);
        let (mail, _) = mail_with_id("normal task start");
        input_queue
            .enqueue_mailbox_communication(mail.clone(), /*parent_turn_id*/ None)
            .await;

        // Control: the task-admission path may begin with no installed active turn and must
        // retain its existing ability to take ready mail.
        assert_eq!(
            input_queue
                .get_pending_input_for_task_start(&idle_slot)
                .await
                .0,
            vec![TurnInput::InterAgentCommunication(mail)]
        );
    }

    #[tokio::test]
    async fn unrecorded_mail_leaves_out_recorded_and_deferred_mail() {
        let input_queue = InputQueue::new();
        let turn_state = Mutex::new(TurnState::default());
        let (recorded, recorded_id) = mail_with_id("recorded");
        let (deferred, _) = mail_with_id("deferred");
        let (lost, lost_id) = mail_with_id("lost");
        let taken = [recorded, deferred.clone(), lost]
            .into_iter()
            .map(TurnInput::InterAgentCommunication)
            .collect::<Vec<_>>();
        turn_state.lock().await.track_taken_mailbox_messages(&taken);
        input_queue
            .defer_input_for_turn_state(
                &turn_state,
                vec![TurnInput::InterAgentCommunication(deferred)],
                /*final_output_json_schema*/ None,
            )
            .await;

        let mut turn_state = turn_state.lock().await;
        assert_eq!(
            turn_state.take_unrecorded_mailbox_message_ids(&[recorded_id]),
            vec![lost_id]
        );
        assert_eq!(
            turn_state.take_unrecorded_mailbox_message_ids(&[]),
            Vec::<String>::new()
        );
    }
}
