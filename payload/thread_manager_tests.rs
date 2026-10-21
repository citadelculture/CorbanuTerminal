use super::*;
use crate::agent::AgentStatus;
use crate::config::test_config;
use crate::init_state_db;
use crate::installation_id::INSTALLATION_ID_FILENAME;
use crate::rollout::RolloutRecorder;
use crate::session::session::SessionSettingsUpdate;
use crate::session::tests::build_world_state_from_turn_context;
use crate::session::tests::make_session_and_context;
use crate::tasks::InterruptedTurnHistoryMarker;
use crate::tasks::interrupted_turn_history_marker;
use assert_matches::assert_matches;
use codex_extension_api::empty_extension_registry;
use codex_models_manager::manager::RefreshStrategy;
use codex_protocol::AgentPath;
use codex_protocol::ResponseItemId;
use codex_protocol::capabilities::CapabilityRootLocation;
use codex_protocol::capabilities::SelectedCapabilityRoot;
use codex_protocol::config_types::ForcedLoginMethod;
use codex_protocol::error::CodexErrorDetails;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ReasoningItemReasoningSummary;
use codex_protocol::models::ResponseItem;
use codex_protocol::openai_models::ModelsResponse;
use codex_protocol::protocol::AgentMessageEvent;
use codex_protocol::protocol::InitialHistory;
use codex_protocol::protocol::InterAgentCommunication;
use codex_protocol::protocol::InternalSessionSource;
use codex_protocol::protocol::ResumedHistory;
use codex_protocol::protocol::SessionMeta;
use codex_protocol::protocol::SessionMetaLine;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::ThreadSource;
use codex_protocol::protocol::TurnStartedEvent;
use codex_protocol::protocol::UserMessageEvent;
use codex_protocol::user_input::UserInput;
use codex_utils_path_uri::PathUri;
use core_test_support::PathBufExt;
use core_test_support::PathExt;
use core_test_support::responses::mount_models_once;
use core_test_support::responses::strip_response_item_ids_from_json;
use pretty_assertions::assert_eq;
use std::time::Duration;
use tempfile::tempdir;
use wiremock::MockServer;

const TEST_INSTALLATION_ID: &str = "11111111-1111-4111-8111-111111111111";

struct FakeAgentGraphStore {
    root_thread_id: ThreadId,
    descendant_thread_ids: Vec<ThreadId>,
}

impl codex_agent_graph_store::AgentGraphStore for FakeAgentGraphStore {
    fn upsert_thread_spawn_edge(
        &self,
        _parent_thread_id: ThreadId,
        _child_thread_id: ThreadId,
        _status: codex_agent_graph_store::ThreadSpawnEdgeStatus,
    ) -> codex_agent_graph_store::AgentGraphStoreFuture<'_, ()> {
        Box::pin(async { panic!("unexpected graph upsert") })
    }

    fn set_thread_spawn_edge_status(
        &self,
        _child_thread_id: ThreadId,
        _status: codex_agent_graph_store::ThreadSpawnEdgeStatus,
    ) -> codex_agent_graph_store::AgentGraphStoreFuture<'_, ()> {
        Box::pin(async { panic!("unexpected graph status update") })
    }

    fn list_thread_spawn_children(
        &self,
        _parent_thread_id: ThreadId,
        _status_filter: Option<codex_agent_graph_store::ThreadSpawnEdgeStatus>,
    ) -> codex_agent_graph_store::AgentGraphStoreFuture<'_, Vec<ThreadId>> {
        Box::pin(async { panic!("unexpected direct-child listing") })
    }

    fn list_thread_spawn_descendants(
        &self,
        root_thread_id: ThreadId,
        status_filter: Option<codex_agent_graph_store::ThreadSpawnEdgeStatus>,
    ) -> codex_agent_graph_store::AgentGraphStoreFuture<'_, Vec<ThreadId>> {
        assert_eq!(root_thread_id, self.root_thread_id);
        assert_eq!(status_filter, None);
        let descendant_thread_ids = self.descendant_thread_ids.clone();
        Box::pin(async move { Ok(descendant_thread_ids) })
    }
}

fn user_msg(text: &str) -> ResponseItem {
    ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::OutputText {
            text: text.to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    }
}
fn assistant_msg(text: &str) -> ResponseItem {
    ResponseItem::Message {
        id: None,
        role: "assistant".to_string(),
        content: vec![ContentItem::OutputText {
            text: text.to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    }
}

fn contextual_user_interrupted_marker() -> ResponseItem {
    interrupted_turn_history_marker(InterruptedTurnHistoryMarker::ContextualUser)
        .expect("contextual-user interrupted marker should be enabled")
}

fn developer_interrupted_marker() -> ResponseItem {
    interrupted_turn_history_marker(InterruptedTurnHistoryMarker::Developer)
        .expect("developer interrupted marker should be enabled")
}

#[test]
fn effective_originator_prefers_thread_scoped_sources_before_env_originator() {
    for (metrics_service_name, persisted_originator, inherited_originator, expected_originator) in [
        (
            Some("codex_work_desktop"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "codex_work_desktop",
        ),
        (
            Some("codex_work_web"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "codex_work_web",
        ),
        (
            Some("codex_work_mobile"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "codex_work_mobile",
        ),
        (
            Some("codex_work_cca"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "codex_work_cca",
        ),
        (
            Some("chatgpt_cca"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "chatgpt_cca",
        ),
        (
            Some("chatgpt_cca_extra"),
            Some("persisted_originator"),
            Some("inherited_originator"),
            "persisted_originator",
        ),
        (
            None,
            Some("persisted_originator"),
            Some("inherited_originator"),
            "persisted_originator",
        ),
        (
            None,
            None,
            Some("inherited_originator"),
            "inherited_originator",
        ),
    ] {
        assert_eq!(
            effective_originator_value(
                metrics_service_name,
                Some("Codex Desktop".to_string()),
                persisted_originator.map(str::to_string),
                inherited_originator.map(str::to_string),
                "codex_cli_rs".to_string(),
            ),
            expected_originator
        );
    }
}

#[test]
fn truncates_before_requested_user_message() {
    let items = [
        user_msg("u1"),
        assistant_msg("a1"),
        assistant_msg("a2"),
        user_msg("u2"),
        assistant_msg("a3"),
        ResponseItem::Reasoning {
            id: Some(ResponseItemId::with_suffix("rs", "1")),
            summary: vec![ReasoningItemReasoningSummary::SummaryText {
                text: "s".to_string(),
            }],
            content: None,
            encrypted_content: None,
            anthropic_content_block: None,
            internal_chat_message_metadata_passthrough: None,
        },
        ResponseItem::FunctionCall {
            id: None,
            call_id: "c1".to_string(),
            name: "tool".to_string(),
            namespace: None,
            arguments: "{}".to_string(),
            encrypted_function_args: None,
            internal_chat_message_metadata_passthrough: None,
        },
        assistant_msg("a4"),
    ];

    let initial: Vec<RolloutItem> = items
        .iter()
        .cloned()
        .map(RolloutItem::ResponseItem)
        .collect();
    let truncated = truncate_before_nth_user_message(
        InitialHistory::Forked(initial),
        /*n*/ 1,
        &SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
    let got_items = truncated.get_rollout_items();
    let expected_items = vec![
        RolloutItem::ResponseItem(items[0].clone()),
        RolloutItem::ResponseItem(items[1].clone()),
        RolloutItem::ResponseItem(items[2].clone()),
    ];
    assert_eq!(
        serde_json::to_value(got_items).unwrap(),
        serde_json::to_value(&expected_items).unwrap()
    );

    let initial2: Vec<RolloutItem> = items
        .iter()
        .cloned()
        .map(RolloutItem::ResponseItem)
        .collect();
    let truncated2 = truncate_before_nth_user_message(
        InitialHistory::Forked(initial2.clone()),
        /*n*/ 2,
        &SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
    assert_eq!(
        serde_json::to_value(truncated2.get_rollout_items()).unwrap(),
        serde_json::to_value(initial2).unwrap()
    );
}

#[test]
fn out_of_range_truncation_drops_only_unfinished_suffix_mid_turn() {
    let items = vec![
        RolloutItem::ResponseItem(user_msg("u1")),
        RolloutItem::ResponseItem(assistant_msg("a1")),
        RolloutItem::ResponseItem(user_msg("u2")),
        RolloutItem::ResponseItem(assistant_msg("partial")),
    ];

    let truncated = truncate_before_nth_user_message(
        InitialHistory::Forked(items.clone()),
        usize::MAX,
        &SnapshotTurnState {
            ends_mid_turn: true,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );

    assert_eq!(
        serde_json::to_value(truncated.get_rollout_items()).unwrap(),
        serde_json::to_value(items[..2].to_vec()).unwrap()
    );
}

#[test]
fn fork_thread_accepts_legacy_usize_snapshot_argument() {
    fn assert_legacy_snapshot_callsite(
        manager: &ThreadManager,
        config: Config,
        path: std::path::PathBuf,
    ) {
        let _future = manager.fork_thread(
            usize::MAX,
            config,
            path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        );
    }

    let _: fn(&ThreadManager, Config, std::path::PathBuf) = assert_legacy_snapshot_callsite;
}

#[test]
fn out_of_range_truncation_drops_pre_user_active_turn_prefix() {
    let items = vec![
        RolloutItem::ResponseItem(user_msg("u1")),
        RolloutItem::ResponseItem(assistant_msg("a1")),
        RolloutItem::EventMsg(EventMsg::TurnStarted(TurnStartedEvent {
            turn_id: "turn-2".to_string(),
            trace_id: None,
            started_at: None,
            model_context_window: None,
            collaboration_mode_kind: Default::default(),
        })),
        RolloutItem::ResponseItem(user_msg("u2")),
        RolloutItem::ResponseItem(assistant_msg("partial")),
    ];

    let snapshot_state = snapshot_turn_state(&InitialHistory::Forked(items.clone()));
    assert_eq!(
        snapshot_state,
        SnapshotTurnState {
            ends_mid_turn: true,
            active_turn_id: Some("turn-2".to_string()),
            active_turn_started_at: None,
            active_turn_start_index: Some(2),
        },
    );

    let truncated = truncate_before_nth_user_message(
        InitialHistory::Forked(items.clone()),
        usize::MAX,
        &snapshot_state,
    );

    assert_eq!(
        serde_json::to_value(truncated.get_rollout_items()).unwrap(),
        serde_json::to_value(items[..2].to_vec()).unwrap()
    );
}

#[tokio::test]
async fn ignores_session_prefix_messages_when_truncating() {
    let (session, turn_context) = make_session_and_context().await;
    let turn_context = Arc::new(turn_context);
    let world_state = build_world_state_from_turn_context(&session, &turn_context).await;
    let mut items = session
        .build_initial_context_with_world_state(&turn_context, &world_state)
        .await;
    items.push(user_msg("feature request"));
    items.push(assistant_msg("ack"));
    items.push(user_msg("second question"));
    items.push(assistant_msg("answer"));

    let rollout_items: Vec<RolloutItem> = items
        .iter()
        .cloned()
        .map(RolloutItem::ResponseItem)
        .collect();

    let truncated = truncate_before_nth_user_message(
        InitialHistory::Forked(rollout_items),
        /*n*/ 1,
        &SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
    let got_items = truncated.get_rollout_items();

    let expected: Vec<RolloutItem> = vec![
        RolloutItem::ResponseItem(items[0].clone()),
        RolloutItem::ResponseItem(items[1].clone()),
        RolloutItem::ResponseItem(items[2].clone()),
        RolloutItem::ResponseItem(items[3].clone()),
    ];

    assert_eq!(
        serde_json::to_value(got_items).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
}

#[tokio::test]
async fn shutdown_all_threads_bounded_submits_shutdown_to_every_thread() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let thread_1 = manager
        .start_thread(StartThreadOptions::new(config.clone()))
        .await
        .expect("start first thread")
        .thread_id;
    let thread_2 = manager
        .start_thread(StartThreadOptions::new(config.clone()))
        .await
        .expect("start second thread")
        .thread_id;

    let report = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;

    let mut expected_completed = vec![thread_1, thread_2];
    expected_completed.sort_by_key(std::string::ToString::to_string);
    assert_eq!(report.completed, expected_completed);
    assert!(report.submit_failed.is_empty());
    assert!(report.timed_out.is_empty());
    assert!(manager.list_thread_ids().await.is_empty());
}

#[tokio::test]
async fn start_thread_refuses_a_missing_named_account() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    config.model_provider = ModelProviderInfo::create_zai_provider();
    config.model_provider.account = Some(codex_model_provider_info::NamedProviderAccount {
        provider_id: "zai".to_string(),
        name: "gone".to_string(),
    });

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let Err(error) = manager.start_thread(StartThreadOptions::new(config)).await else {
        panic!("a missing named account must not start a thread");
    };
    let CodexErrorDetails::InvalidRequest(message) = error.details() else {
        panic!("expected an invalid request, got {error}");
    };
    assert_eq!(
        message,
        &("account `gone` of provider `zai` is not configured; add it with \
         `corbanu account add zai gone` or pick another with `--account` (see `corbanu account list`)"
            .to_string())
    );
}

/// PF-84-S06 (#570): a process whose session runs on a named sign-in account
/// leaves a default login the login restrictions rule out in place (its
/// default-login manager hides it), so a thread that would run on that
/// default login (a switch to the default account, a spawned agent on it, a
/// resumed default thread) is refused with the reason, and the login is not
/// touched. A thread on a named account, a process that enforced at startup,
/// the feature off or no restriction: no check.
#[tokio::test]
async fn start_thread_refuses_a_ruled_out_default_login_without_logging_it_out() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    config
        .features
        .enable(Feature::NamedAccounts)
        .expect("named accounts should be available in tests");
    config.model_provider_id = "openai".to_string();
    config.model_provider = ModelProviderInfo::create_openai_provider(/*base_url*/ None);
    config.configured_forced_login_method = Some(ForcedLoginMethod::Chatgpt);
    config.forced_login_method = Some(ForcedLoginMethod::Chatgpt);
    config.cli_auth_credentials_store_mode = codex_config::types::AuthCredentialsStoreMode::File;
    codex_login::login_with_api_key(
        &config.codex_home,
        "sk-default-570",
        config.cli_auth_credentials_store_mode,
        config.auth_keyring_backend_kind(),
    )
    .expect("seed the default login");
    let auth_file = config.codex_home.join("auth.json");
    let before = std::fs::read(&auth_file).expect("default login");

    let mut named = config.clone();
    named.model_provider.account = Some(codex_model_provider_info::NamedProviderAccount {
        provider_id: "openai".to_string(),
        name: "work".to_string(),
    });
    // The process's default-login manager, built from the named session's
    // config, hides the ruled-out login; one built from a default session's
    // config does not.
    let hiding = AuthManager::shared_from_config(&named, /*enable_codex_api_key_env*/ false).await;
    assert!(hiding.hides_restricted_default_login());
    assert!(hiding.auth_cached().is_none());
    let enforcing =
        AuthManager::shared_from_config(&config, /*enable_codex_api_key_env*/ false).await;
    assert!(!enforcing.hides_restricted_default_login());

    let message = crate::config::default_login_restriction_error(&config, &hiding)
        .expect("an API key breaks a required ChatGPT login");
    assert!(
        message.contains("ChatGPT login is required") && message.contains("left unchanged"),
        "{message}"
    );

    let mut feature_off = config.clone();
    feature_off
        .features
        .disable(Feature::NamedAccounts)
        .expect("named accounts can be turned off");
    // A process without a restriction hides nothing.
    let mut unrestricted = named.clone();
    unrestricted.configured_forced_login_method = None;
    unrestricted.forced_login_method = None;
    let hiding_nothing =
        AuthManager::shared_from_config(&unrestricted, /*enable_codex_api_key_env*/ false).await;
    assert!(hiding_nothing.hides_restricted_default_login());
    assert!(hiding_nothing.auth_cached().is_some());
    for (other, manager) in [
        (&named, &hiding),
        (&feature_off, &hiding),
        (&config, &hiding_nothing),
        (&config, &enforcing),
    ] {
        assert_eq!(
            crate::config::default_login_restriction_error(other, manager),
            None
        );
    }

    let mut manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    Arc::get_mut(&mut manager.state)
        .expect("a fresh manager's state is not shared")
        .auth_manager = hiding;
    let Err(error) = manager.start_thread(StartThreadOptions::new(config)).await else {
        panic!("a ruled-out default login must not start a thread");
    };
    let CodexErrorDetails::InvalidRequest(refusal) = error.details() else {
        panic!("expected an invalid request, got {error}");
    };
    assert_eq!(refusal, &message);
    assert_eq!(
        std::fs::read(&auth_file).expect("default login kept"),
        before
    );
}

/// #425: `--account <other-provider>:<name>` whose account is missing is
/// refused at thread start with the session-provider case's text, instead of
/// running the session on its provider's default account.
#[tokio::test]
async fn start_thread_refuses_a_missing_account_of_another_provider() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    config.model_provider_id = "zai".to_string();
    config.model_provider = ModelProviderInfo::create_zai_provider();
    let mut kimi = ModelProviderInfo::create_zai_provider();
    kimi.account = Some(codex_model_provider_info::NamedProviderAccount {
        provider_id: "kimi-code".to_string(),
        name: "ghost".to_string(),
    });
    config.model_providers.insert("kimi-code".to_string(), kimi);
    config.provider_account_override = Some("kimi-code:ghost".to_string());

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let Err(error) = manager.start_thread(StartThreadOptions::new(config)).await else {
        panic!("a missing account of another provider must not start a thread");
    };
    let CodexErrorDetails::InvalidRequest(message) = error.details() else {
        panic!("expected an invalid request, got {error}");
    };
    assert_eq!(
        message,
        &("account `ghost` of provider `kimi-code` is not configured; add it with \
         `corbanu account add kimi-code ghost` or pick another with `--account` (see `corbanu account list`)"
            .to_string())
    );
}

/// #425: another provider's account that is configured starts the session
/// (it is used by agents on that provider); a spawned agent checks only the
/// account it runs on, and `default` is never refused.
#[tokio::test]
async fn other_provider_account_check_accepts_configured_accounts_and_spawned_agents() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    config.model_provider_id = "zai".to_string();
    config.model_provider = ModelProviderInfo::create_zai_provider();
    codex_vault::Vault::new(config.codex_home.to_path_buf())
        .write_provider_account(
            "kimi-code",
            &codex_vault::ProviderAccountName::parse("alt").expect("name"),
            codex_vault::ProviderAccountKind::ApiKey,
            "canary-kimi-alt",
        )
        .expect("write account");
    let with_kimi = |name: Option<&str>| {
        let mut config = config.clone();
        let mut kimi = ModelProviderInfo::create_zai_provider();
        kimi.account = name.map(|name| codex_model_provider_info::NamedProviderAccount {
            provider_id: "kimi-code".to_string(),
            name: name.to_string(),
        });
        config.model_providers.insert("kimi-code".to_string(), kimi);
        config.provider_account_override = Some(format!("kimi-code:{}", name.unwrap_or("default")));
        config
    };
    let spawned = SessionSource::SubAgent(SubAgentSource::Review);
    assert_eq!(
        [
            thread_start_account_error(&with_kimi(Some("alt")), &SessionSource::Exec),
            thread_start_account_error(&with_kimi(/*name*/ None), &SessionSource::Exec),
            thread_start_account_error(&with_kimi(Some("ghost")), &spawned),
        ],
        [None, None, None]
    );
    assert!(
        thread_start_account_error(&with_kimi(Some("ghost")), &SessionSource::Cli)
            .is_some_and(|message| message.starts_with("account `ghost` of provider `kimi-code`"))
    );
}

#[tokio::test]
async fn code_mode_session_provider_is_shared_across_threads() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let provider: Arc<dyn CodeModeSessionProvider> = Arc::new(DisabledCodeModeSessionProvider);
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    )
    .with_code_mode_session_provider(Arc::clone(&provider));
    let first = manager
        .start_thread(StartThreadOptions::new(config.clone()))
        .await
        .expect("start first thread");
    let second = manager
        .start_thread(StartThreadOptions::new(config))
        .await
        .expect("start second thread");

    let first_provider = first
        .thread
        .session
        .services
        .code_mode_service
        .session_provider();
    let second_provider = second
        .thread
        .session
        .services
        .code_mode_service
        .session_provider();
    assert!(Arc::ptr_eq(&first_provider, &second_provider));
    assert!(Arc::ptr_eq(&first_provider, &provider));
    assert!(Arc::ptr_eq(
        &first_provider,
        &manager.state.code_mode_session_provider
    ));

    let mut completed = vec![first.thread_id, second.thread_id];
    completed.sort_by_key(std::string::ToString::to_string);
    let report = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;
    assert_eq!(
        report,
        ThreadShutdownReport {
            completed,
            submit_failed: Vec::new(),
            timed_out: Vec::new(),
        }
    );
}

#[tokio::test]
async fn mcp_invalidation_refreshes_threads_that_are_still_starting() {
    struct BlockingThreadStartup {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        refreshed: tokio::sync::Notify,
        projections: std::sync::atomic::AtomicUsize,
    }

    impl codex_extension_api::ThreadLifecycleContributor<Config> for BlockingThreadStartup {
        fn on_thread_start<'a>(
            &'a self,
            _input: codex_extension_api::ThreadStartInput<'a, Config>,
        ) -> codex_extension_api::ExtensionFuture<'a, ()> {
            Box::pin(async move {
                self.entered.notify_one();
                self.release.notified().await;
            })
        }
    }

    impl codex_extension_api::McpServerContributor<Config> for BlockingThreadStartup {
        fn id(&self) -> &'static str {
            "starting_mcp_runtime_refresh_test"
        }

        fn contribute<'a>(
            &'a self,
            _context: codex_extension_api::McpServerContributionContext<'a, Config>,
        ) -> codex_extension_api::ExtensionFuture<'a, Vec<codex_extension_api::McpServerContribution>>
        {
            Box::pin(async move {
                if self.projections.fetch_add(1, Ordering::AcqRel) != 0 {
                    self.refreshed.notify_one();
                }
                Vec::new()
            })
        }
    }

    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let observer = Arc::new(BlockingThreadStartup {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        refreshed: tokio::sync::Notify::new(),
        projections: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut extensions = codex_extension_api::ExtensionRegistryBuilder::new();
    extensions.thread_lifecycle_contributor(observer.clone());
    extensions.mcp_server_contributor(observer.clone());
    let auth_manager = AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy"));
    let manager = Arc::new(ThreadManager::new(
        &config,
        Arc::clone(&auth_manager),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        Arc::new(extensions.build()),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    ));
    let starting = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move { manager.start_thread(StartThreadOptions::new(config)).await }
    });

    tokio::time::timeout(Duration::from_secs(5), observer.entered.notified())
        .await
        .expect("thread should enter its startup lifecycle");
    assert!(manager.list_thread_ids().await.is_empty());
    manager.invalidate_mcp_runtimes().await;
    observer.release.notify_one();
    starting
        .await
        .expect("thread startup task should finish")
        .expect("thread should start");
    tokio::time::timeout(Duration::from_secs(5), observer.refreshed.notified())
        .await
        .expect("invalidation during startup should refresh the newly published thread");
    let shutdown = manager
        .shutdown_all_threads_bounded(Duration::from_secs(5))
        .await;
    assert!(shutdown.timed_out.is_empty());
}

#[tokio::test]
async fn start_thread_keeps_internal_threads_hidden_from_normal_lookups() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let thread = manager
        .start_thread(StartThreadOptions {
            session_source: Some(SessionSource::Internal(
                InternalSessionSource::MemoryConsolidation,
            )),
            environments: Some(Vec::new()),
            ..StartThreadOptions::new(config)
        })
        .await
        .expect("internal thread should start");

    assert_eq!(manager.list_thread_ids().await, Vec::new());
    assert!(manager.get_thread(thread.thread_id).await.is_err());

    let report = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;
    assert_eq!(report.completed, vec![thread.thread_id]);
    assert!(report.submit_failed.is_empty());
    assert!(report.timed_out.is_empty());
    assert!(manager.list_thread_ids().await.is_empty());
}

#[tokio::test]
async fn resumed_subagent_rejoins_loaded_parent_control_plane() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let parent = manager
        .start_thread(config.clone())
        .await
        .expect("start parent thread");
    let child_path = AgentPath::try_from("/root/troll_burzum").expect("child path");
    let child_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: parent.thread_id,
        depth: 1,
        agent_path: Some(child_path.clone()),
        agent_nickname: Some("Burzum".to_string()),
        agent_role: Some("troll".to_string()),
        agent_class: None,
    });
    let child = manager
        .start_thread_with_options(StartThreadOptions {
            config: config.clone(),
            allow_provider_model_fallback: false,
            history_mode: None,
            initial_history: InitialHistory::New,
            session_source: Some(child_source.clone()),
            thread_source: Some(ThreadSource::Subagent),
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: Some(Vec::new()),
            thread_extension_init: Default::default(),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("start child thread");

    for (thread, message) in [
        (&parent.thread, "persist parent"),
        (&child.thread, "persist child"),
    ] {
        thread
            .inject_user_message_without_turn(message.to_string())
            .await;
        thread.codex.session.ensure_rollout_materialized().await;
        thread
            .codex
            .session
            .flush_rollout()
            .await
            .expect("flush rollout");
    }
    let parent_rollout = parent.thread.rollout_path().expect("parent rollout path");
    let child_rollout = child.thread.rollout_path().expect("child rollout path");
    let parent_id = parent.thread_id;
    let child_id = child.thread_id;

    let shutdown = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;
    assert!(shutdown.submit_failed.is_empty());
    assert!(shutdown.timed_out.is_empty());

    let resumed_manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let resumed_parent = resumed_manager
        .resume_thread_from_rollout(
            config.clone(),
            parent_rollout,
            auth_manager.clone(),
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume parent first");
    assert_eq!(resumed_parent.thread_id, parent_id);
    let resumed_child = resumed_manager
        .resume_thread_from_rollout(
            config.clone(),
            child_rollout,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume child after parent");
    assert_eq!(resumed_child.thread_id, child_id);

    let parent_control = resumed_parent
        .thread
        .codex
        .session
        .services
        .agent_control
        .clone();
    let child_control = resumed_child
        .thread
        .codex
        .session
        .services
        .agent_control
        .clone();
    assert_eq!(parent_control.session_id(), child_control.session_id());
    assert_eq!(
        parent_control
            .get_agent_metadata_for_path(&child_path)
            .and_then(|metadata| metadata.agent_id),
        Some(child_id)
    );
    assert_eq!(
        child_control
            .get_agent_metadata_for_path(&child_path)
            .and_then(|metadata| metadata.agent_id),
        Some(child_id)
    );

    let duplicate = parent_control
        .spawn_agent(
            config,
            vec![UserInput::Text {
                text: "duplicate work".to_string(),
                text_elements: Vec::new(),
            }],
            Some(child_source),
        )
        .await
        .expect_err("a restored live path must not be replaced");
    assert_matches!(
        duplicate.details(),
        CodexErrorDetails::UnsupportedOperation(message)
            if message.contains("agent path `/root/troll_burzum` already exists")
    );
}

#[tokio::test]
async fn resumed_root_restores_open_descendants_as_unloaded_with_exact_runtime() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    config
        .features
        .enable(Feature::Sqlite)
        .expect("sqlite should be available in tests");
    config
        .features
        .enable(Feature::MultiAgentV2)
        .expect("multi-agent v2 should be available in tests");
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    let state_db = init_state_db(&config).await;

    let manager = ThreadManager::with_models_provider_home_and_state_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        state_db.clone(),
    );
    let parent = manager
        .start_thread(config.clone())
        .await
        .expect("start parent thread");
    let child_path = AgentPath::try_from("/root/troll_burzum").expect("child path");
    let child_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: parent.thread_id,
        depth: 1,
        agent_path: Some(child_path.clone()),
        agent_nickname: Some("Burzum".to_string()),
        agent_role: Some("troll".to_string()),
        agent_class: None,
    });
    let child = manager
        .start_thread_with_options(StartThreadOptions {
            config: config.clone(),
            allow_provider_model_fallback: false,
            history_mode: None,
            initial_history: InitialHistory::New,
            session_source: Some(child_source.clone()),
            thread_source: Some(ThreadSource::Subagent),
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: Some(Vec::new()),
            thread_extension_init: Default::default(),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("start child thread");

    let verifier_path = child_path
        .join("verification_reassign")
        .expect("verifier path");
    let verifier_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: child.thread_id,
        depth: 2,
        agent_path: Some(verifier_path.clone()),
        agent_nickname: Some("Godel".to_string()),
        // This fixture exercises persisted runtime restoration, not role lookup. Keep the role
        // unset so reloading proves the exact stored provider/model without layering an unrelated
        // role config over it.
        agent_role: None,
        agent_class: None,
    });
    let mut verifier_config = config.clone();
    verifier_config.model_provider = verifier_config
        .model_providers
        .get("openrouter")
        .cloned()
        .expect("OpenRouter provider");
    verifier_config.model_provider_id = "openrouter".to_string();
    verifier_config.model = Some("x-ai/grok-4.5".to_string());
    let verifier = manager
        .start_thread_with_options(StartThreadOptions {
            config: verifier_config,
            allow_provider_model_fallback: false,
            history_mode: None,
            initial_history: InitialHistory::New,
            session_source: Some(verifier_source),
            thread_source: Some(ThreadSource::Subagent),
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: Some(Vec::new()),
            thread_extension_init: Default::default(),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("start verifier thread");

    for (thread, message) in [
        (&parent.thread, "persist parent"),
        (&child.thread, "persist child"),
        (&verifier.thread, "persist verifier"),
    ] {
        thread
            .inject_user_message_without_turn(message.to_string())
            .await;
        thread.codex.session.ensure_rollout_materialized().await;
        thread
            .codex
            .session
            .flush_rollout()
            .await
            .expect("flush rollout");
    }
    let stored_verifier = manager
        .update_thread_metadata(
            verifier.thread_id,
            ThreadMetadataPatch {
                model_provider: Some("openrouter".to_string()),
                model: Some("x-ai/grok-4.5".to_string()),
                ..Default::default()
            },
            /*include_archived*/ true,
        )
        .await
        .expect("persist verifier runtime metadata");
    assert_eq!(stored_verifier.model_provider, "openrouter");
    assert_eq!(stored_verifier.model.as_deref(), Some("x-ai/grok-4.5"));
    let parent_rollout = parent.thread.rollout_path().expect("parent rollout path");
    let parent_id = parent.thread_id;
    let child_id = child.thread_id;
    let verifier_id = verifier.thread_id;

    let shutdown = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;
    assert!(shutdown.submit_failed.is_empty());
    assert!(shutdown.timed_out.is_empty());

    let resumed_manager = ThreadManager::with_models_provider_home_and_state_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        state_db,
    );
    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let resumed_parent = resumed_manager
        .resume_thread_from_rollout(
            config.clone(),
            parent_rollout,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume only the root thread");
    assert_eq!(resumed_parent.thread_id, parent_id);

    let control = resumed_parent
        .thread
        .codex
        .session
        .services
        .agent_control
        .clone();
    assert_eq!(
        control
            .get_agent_metadata_for_path(&child_path)
            .and_then(|metadata| metadata.agent_id),
        Some(child_id)
    );
    assert_eq!(
        control
            .get_agent_metadata_for_path(&verifier_path)
            .and_then(|metadata| metadata.agent_id),
        Some(verifier_id)
    );
    assert_eq!(control.get_status(child_id).await, AgentStatus::Unloaded);
    assert_eq!(control.get_status(verifier_id).await, AgentStatus::Unloaded);
    let child_err = resumed_manager
        .get_thread(child_id)
        .await
        .err()
        .expect("unloaded child must not have a live thread");
    assert!(matches!(
        child_err.details(),
        CodexErrorDetails::ThreadNotFound(id) if *id == child_id
    ));
    let verifier_err = resumed_manager
        .get_thread(verifier_id)
        .await
        .err()
        .expect("unloaded verifier must not have a live thread");
    assert!(matches!(
        verifier_err.details(),
        CodexErrorDetails::ThreadNotFound(id) if *id == verifier_id
    ));

    let listed = control
        .list_agents(&SessionSource::Cli, /*path_prefix*/ None)
        .await
        .expect("list restored descendants");
    assert!(listed.iter().any(|agent| {
        agent.agent_name == child_path.as_str() && agent.agent_status == AgentStatus::Unloaded
    }));
    assert!(listed.iter().any(|agent| {
        agent.agent_name == verifier_path.as_str()
            && agent.agent_status == AgentStatus::Unloaded
            && agent.agent_nickname.as_deref() == Some("Godel")
    }));

    control
        .ensure_v2_agent_loaded(config.clone(), verifier_id)
        .await
        .expect("addressing the restored verifier should load it");
    let verifier_snapshot = control
        .get_agent_config_snapshot(verifier_id)
        .await
        .expect("loaded verifier config");
    assert_eq!(verifier_snapshot.model_provider_id, "openrouter");
    assert_eq!(verifier_snapshot.model, "x-ai/grok-4.5");

    let duplicate = control
        .spawn_agent(
            config,
            vec![UserInput::Text {
                text: "duplicate work".to_string(),
                text_elements: Vec::new(),
            }],
            Some(child_source),
        )
        .await
        .expect_err("a restored unloaded path must remain reserved");
    assert_matches!(
        duplicate.details(),
        CodexErrorDetails::UnsupportedOperation(message)
            if message.contains("agent path `/root/troll_burzum` already exists")
    );
}

#[tokio::test]
async fn durable_thread_spawn_materializes_lazy_parent_child_and_core_graph_edge() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    config
        .features
        .enable(Feature::Sqlite)
        .expect("sqlite should be available in tests");
    config
        .features
        .enable(Feature::MultiAgentV2)
        .expect("multi-agent v2 should be available in tests");
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    let state_db = init_state_db(&config).await;
    let state_runtime = state_db
        .clone()
        .expect("sqlite state runtime should be available");
    let manager = ThreadManager::with_models_provider_home_and_state_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        state_db,
    );

    let root = manager
        .start_thread(config.clone())
        .await
        .expect("start lazy root");
    assert!(
        state_runtime
            .get_thread(root.thread_id)
            .await
            .expect("query lazy root")
            .is_none(),
        "a root with no turn should begin unmaterialized"
    );

    let child_path = AgentPath::try_from("/root/troll_burzum").expect("child path");
    let child = manager
        .start_thread_with_options(StartThreadOptions {
            config: config.clone(),
            allow_provider_model_fallback: false,
            history_mode: None,
            initial_history: InitialHistory::New,
            session_source: Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: root.thread_id,
                depth: 1,
                agent_path: Some(child_path),
                agent_nickname: Some("Burzum".to_string()),
                agent_role: Some("troll".to_string()),
                agent_class: Some(codex_protocol::crew::AgentClass::CrewMember {
                    crew_id: "cold-root-crew".to_string(),
                    logical_member_id: "troll-1".to_string(),
                    human_addressable: true,
                }),
            })),
            thread_source: Some(ThreadSource::Subagent),
            dynamic_tools: Vec::new(),
            metrics_service_name: None,
            parent_trace: None,
            environments: Some(Vec::new()),
            thread_extension_init: Default::default(),
            supports_openai_form_elicitation: false,
        })
        .await
        .expect("spawn durable child beneath lazy root");

    let stored_root = state_runtime
        .get_thread(root.thread_id)
        .await
        .expect("query materialized root")
        .expect("durable spawn must materialize its parent");
    let stored_child = state_runtime
        .get_thread(child.thread_id)
        .await
        .expect("query materialized child")
        .expect("durable spawn must materialize its child");
    assert!(stored_root.rollout_path.exists());
    assert!(stored_child.rollout_path.exists());
    assert_eq!(
        state_runtime
            .list_thread_spawn_children(root.thread_id)
            .await
            .expect("list Core graph children"),
        vec![child.thread_id]
    );
}

#[tokio::test]
async fn resumed_root_quarantines_provider_running_mail_without_replay() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    config
        .features
        .enable(Feature::Sqlite)
        .expect("sqlite should be available in tests");
    config
        .features
        .enable(Feature::MultiAgentV2)
        .expect("multi-agent v2 should be available in tests");
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    let state_db = init_state_db(&config).await;
    let state_runtime = state_db
        .clone()
        .expect("sqlite state runtime should be available");

    let manager = ThreadManager::with_models_provider_home_and_state_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        state_db.clone(),
    );
    let root = manager
        .start_thread(config.clone())
        .await
        .expect("start root thread");
    root.thread
        .inject_user_message_without_turn("persist root".to_string())
        .await;
    root.thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    root.thread
        .codex
        .session
        .flush_rollout()
        .await
        .expect("flush root rollout");
    let root_rollout = root.thread.rollout_path().expect("root rollout path");
    let root_id = root.thread_id;

    let ambiguous = InterAgentCommunication::new(
        AgentPath::try_from("/root/worker").expect("worker path"),
        AgentPath::root(),
        Vec::new(),
        "provider outcome is ambiguous".to_string(),
        /*trigger_turn*/ true,
    );
    let message_id = ambiguous
        .message_id
        .as_deref()
        .expect("stable message id")
        .to_string();
    let control = root.thread.codex.session.services.agent_control.clone();
    control
        .admit_inter_agent_communication(root_id, &ambiguous)
        .await
        .expect("admit root mailbox message");
    assert!(
        state_runtime
            .begin_agent_message_submission(
                &message_id,
                codex_state::AgentMailboxPhase::Ready,
                "root-provider-attempt",
                /*now_ms*/ 1_000,
            )
            .await
            .expect("begin root submission")
    );
    assert!(
        state_runtime
            .transition_agent_message(
                &message_id,
                codex_state::AgentMailboxPhase::Submitting,
                codex_state::AgentMailboxPhase::Submitted,
                /*now_ms*/ 1_001,
            )
            .await
            .expect("mark root message submitted")
    );
    assert!(
        state_runtime
            .transition_agent_message(
                &message_id,
                codex_state::AgentMailboxPhase::Submitted,
                codex_state::AgentMailboxPhase::ProviderRunning,
                /*now_ms*/ 1_002,
            )
            .await
            .expect("mark root provider running")
    );

    let shutdown = manager
        .shutdown_all_threads_bounded(Duration::from_secs(10))
        .await;
    assert!(shutdown.submit_failed.is_empty());
    assert!(shutdown.timed_out.is_empty());

    let resumed_manager = ThreadManager::with_models_provider_home_and_state_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        state_db.clone(),
    );
    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let resumed_root = resumed_manager
        .resume_thread_from_rollout(
            config,
            root_rollout,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume root thread");
    assert_eq!(resumed_root.thread_id, root_id);
    assert_eq!(
        state_runtime
            .get_agent_message(&message_id)
            .await
            .expect("mailbox lookup")
            .expect("mailbox row")
            .phase,
        codex_state::AgentMailboxPhase::UnknownOutcome
    );
    assert!(
        !resumed_root
            .thread
            .codex
            .session
            .has_applied_agent_message_id(&message_id)
            .await,
        "ambiguous root mail must not be replayed into local history"
    );
}

#[tokio::test]
async fn start_thread_seeds_extension_data_for_mcp_and_lifecycle_contributors() {
    struct InitialDataRecorder {
        lifecycle_observed: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        mcp_observed: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl codex_extension_api::ThreadLifecycleContributor<Config> for InitialDataRecorder {
        fn on_thread_start<'a>(
            &'a self,
            input: codex_extension_api::ThreadStartInput<'a, Config>,
        ) -> codex_extension_api::ExtensionFuture<'a, ()> {
            Box::pin(async move {
                let selected_root = input
                    .thread_store
                    .get::<Vec<SelectedCapabilityRoot>>()
                    .and_then(|roots| roots.first().cloned())
                    .expect("selected root should be available");
                self.lifecycle_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((input.thread_store.level_id().to_string(), selected_root.id));
                input
                    .thread_store
                    .insert(Vec::<SelectedCapabilityRoot>::new());
            })
        }
    }

    impl codex_extension_api::McpServerContributor<Config> for InitialDataRecorder {
        fn id(&self) -> &'static str {
            "selected_root_test"
        }

        fn contribute<'a>(
            &'a self,
            context: codex_extension_api::McpServerContributionContext<'a, Config>,
        ) -> codex_extension_api::ExtensionFuture<'a, Vec<codex_extension_api::McpServerContribution>>
        {
            Box::pin(async move {
                let thread_init = context
                    .thread_init()
                    .expect("initial MCP resolution should be thread-scoped");
                let selected_root = thread_init
                    .get::<Vec<SelectedCapabilityRoot>>()
                    .and_then(|roots| roots.first().cloned())
                    .expect("selected root should be available");
                self.mcp_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(selected_root.id.clone());
                let mut server = codex_mcp::codex_apps_mcp_server_config(
                    "https://selected.invalid",
                    /*apps_mcp_product_sku*/ None,
                    /*originator*/ None,
                );
                let CapabilityRootLocation::Environment { environment_id, .. } =
                    &selected_root.location;
                server.environment_id = environment_id.clone();
                server.enabled = false;
                let plugin_id = selected_root.id;
                vec![codex_extension_api::McpServerContribution::SelectedPlugin {
                    name: plugin_id.clone(),
                    plugin_display_name: plugin_id.clone(),
                    plugin_id,
                    selection_order: 0,
                    config: Box::new(server),
                }]
            })
        }
    }

    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    config
        .features
        .enable(Feature::Apps)
        .expect("test config should allow apps");
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let lifecycle_observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mcp_observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = Arc::new(InitialDataRecorder {
        lifecycle_observed: Arc::clone(&lifecycle_observed),
        mcp_observed: Arc::clone(&mcp_observed),
    });
    let mut extensions = codex_extension_api::ExtensionRegistryBuilder::new();
    extensions.thread_lifecycle_contributor(recorder.clone());
    extensions.mcp_server_contributor(recorder);
    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        Arc::new(extensions.build()),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );
    let selected_root_init = |id: &str, environment_id: &str| {
        let mut init = codex_extension_api::ExtensionDataInit::new();
        init.insert(vec![SelectedCapabilityRoot {
            id: id.to_string(),
            location: CapabilityRootLocation::Environment {
                environment_id: environment_id.to_string(),
                path: PathUri::parse(&format!("file:///plugins/{id}")).expect("plugin root URI"),
            },
        }]);
        init
    };

    let first_thread = manager
        .start_thread(StartThreadOptions {
            metrics_service_name: Some("codex_work_desktop".to_string()),
            environments: Some(Vec::new()),
            thread_extension_init: selected_root_init("selected-a", "env-a"),
            ..StartThreadOptions::new(config.clone())
        })
        .await
        .expect("start first thread");
    let second_thread = manager
        .start_thread(StartThreadOptions {
            environments: Some(Vec::new()),
            thread_extension_init: selected_root_init("selected-b", "env-b"),
            ..StartThreadOptions::new(config.clone())
        })
        .await
        .expect("start second thread");
    let first_session = &first_thread.thread.session;
    let first_originator = first_session.originator().await;
    let first_resolved = first_session
        .services
        .mcp_manager
        .runtime_config_for_step(
            &config,
            &first_session.services.mcp_thread_init,
            &first_session.services.thread_extension_data,
            &first_originator,
            /*ready_selected_capability_roots*/ &[],
            /*executor_capability_discovery*/ None,
        )
        .await;
    let second_session = &second_thread.thread.session;
    let second_originator = second_session.originator().await;
    let second_resolved = second_session
        .services
        .mcp_manager
        .runtime_config_for_step(
            &config,
            &second_session.services.mcp_thread_init,
            &second_session.services.thread_extension_data,
            &second_originator,
            /*ready_selected_capability_roots*/ &[],
            /*executor_capability_discovery*/ None,
        )
        .await;

    assert_eq!(
        *lifecycle_observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![
            (first_thread.thread_id.to_string(), "selected-a".to_string()),
            (
                second_thread.thread_id.to_string(),
                "selected-b".to_string()
            ),
        ]
    );
    assert_eq!(
        *mcp_observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![
            "selected-a".to_string(),
            "selected-b".to_string(),
            "selected-a".to_string(),
            "selected-b".to_string(),
        ]
    );
    let selected_servers = |config: &codex_mcp::McpConfig| {
        codex_mcp::configured_mcp_servers(config)
            .into_iter()
            .filter(|(name, _)| name.starts_with("selected-"))
            .map(|(name, server)| (name, server.environment_id))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    assert_eq!(
        selected_servers(&first_resolved.config),
        std::collections::BTreeMap::from([("selected-a".to_string(), "env-a".to_string())])
    );
    assert_eq!(
        selected_servers(&second_resolved.config),
        std::collections::BTreeMap::from([("selected-b".to_string(), "env-b".to_string())])
    );
    let codex_apps_server = codex_mcp::configured_mcp_servers(&first_resolved.config)
        .remove(codex_mcp::CODEX_APPS_MCP_SERVER_NAME)
        .expect("Codex Apps server should be configured");
    let codex_apps_headers = match codex_apps_server.transport {
        codex_config::McpServerTransportConfig::StreamableHttp { http_headers, .. } => http_headers,
        codex_config::McpServerTransportConfig::Stdio { .. } => {
            panic!("Codex Apps server should use streamable HTTP")
        }
    };
    assert_eq!(
        codex_apps_headers
            .expect("Codex Apps headers should be configured")
            .get("originator"),
        Some(&"codex_work_desktop".to_string())
    );
}

#[tokio::test]
async fn selected_capability_roots_round_trip_through_fork() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.to_path_buf(),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
    );
    let selected_roots = vec![SelectedCapabilityRoot {
        id: "demo@1".to_string(),
        location: CapabilityRootLocation::Environment {
            environment_id: "build".to_string(),
            path: PathUri::parse("file:///plugins/demo").expect("plugin root URI"),
        },
    }];
    let inherited = manager
        .start_thread(StartThreadOptions {
            initial_history: InitialHistory::Forked(vec![RolloutItem::SessionMeta(
                SessionMetaLine {
                    meta: SessionMeta {
                        selected_capability_roots: selected_roots.clone(),
                        ..SessionMeta::default()
                    },
                    git: None,
                },
            )]),
            environments: Some(Vec::new()),
            ..StartThreadOptions::new(config)
        })
        .await
        .expect("start inherited fork");
    inherited.thread.ensure_rollout_materialized().await;
    inherited
        .thread
        .flush_rollout()
        .await
        .expect("flush inherited fork");
    let inherited_history = RolloutRecorder::get_rollout_history(
        &inherited
            .thread
            .rollout_path()
            .expect("inherited fork rollout path"),
    )
    .await
    .expect("read inherited fork rollout");

    assert_eq!(
        inherited_history.get_selected_capability_roots(),
        selected_roots
    );
}

#[tokio::test]
async fn resume_and_fork_do_not_restore_thread_environments_from_rollout() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );
    let selected_cwd =
        AbsolutePathBuf::try_from(config.cwd.as_path().join("selected")).expect("absolute path");
    std::fs::create_dir_all(&selected_cwd).expect("create selected cwd");
    let environments = vec![TurnEnvironmentSelection {
        environment_id: "local".to_string(),
        cwd: PathUri::from_abs_path(&selected_cwd),
        workspace_roots: Vec::new(),
    }];
    let default_cwd = config.cwd.clone();
    let mut source_config = config.clone();
    source_config.cwd = selected_cwd.clone();
    let source = manager
        .start_thread(StartThreadOptions {
            environments: Some(environments.clone()),
            ..StartThreadOptions::new(source_config)
        })
        .await
        .expect("start source thread");
    source.thread.ensure_rollout_materialized().await;
    source
        .thread
        .flush_rollout()
        .await
        .expect("flush source rollout");
    let rollout_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread before resume");
    let _ = manager.remove_thread(&source.thread_id).await;

    let resumed = manager
        .resume_thread_from_rollout(
            config.clone(),
            rollout_path.clone(),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume source thread");
    let resumed_turn = resumed
        .thread
        .session
        .new_turn_with_sub_id("resume-turn".to_string(), SessionSettingsUpdate::default())
        .await
        .expect("build resumed turn context");
    assert_eq!(resumed_turn.environments.turn_environments().count(), 1);
    assert_eq!(
        resumed_turn
            .environments
            .primary()
            .expect("primary environment")
            .cwd(),
        &PathUri::from_abs_path(&default_cwd)
    );
    assert_ne!(
        resumed_turn
            .environments
            .primary()
            .expect("primary environment")
            .cwd(),
        &PathUri::from_abs_path(&selected_cwd)
    );

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config,
            rollout_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork source thread");
    let forked_turn = forked
        .thread
        .session
        .new_turn_with_sub_id("fork-turn".to_string(), SessionSettingsUpdate::default())
        .await
        .expect("build forked turn context");
    assert_eq!(forked_turn.environments.turn_environments().count(), 1);
    assert_eq!(
        forked_turn
            .environments
            .primary()
            .expect("primary environment")
            .cwd(),
        &PathUri::from_abs_path(&default_cwd)
    );
    assert_ne!(
        forked_turn
            .environments
            .primary()
            .expect("primary environment")
            .cwd(),
        &PathUri::from_abs_path(&selected_cwd)
    );
}

#[tokio::test]
async fn explicit_installation_id_skips_codex_home_file() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let installation_id = uuid::Uuid::new_v4().to_string();
    let state_db = init_state_db(&config).await;
    let thread_store = thread_store_from_config(&config, state_db.clone());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store,
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        installation_id.clone(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let thread = manager
        .start_thread(StartThreadOptions::new(config.clone()))
        .await
        .expect("start thread with explicit installation id");

    assert!(!config.codex_home.join(INSTALLATION_ID_FILENAME).exists());
    assert_eq!(thread.thread.session.installation_id, installation_id);

    thread
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown thread");
    let _ = manager.remove_thread(&thread.thread_id).await;
}

#[tokio::test]
async fn resume_active_thread_from_rollout_returns_running_thread() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread(StartThreadOptions::new(config.clone()))
        .await
        .expect("start source thread");
    source.thread.ensure_rollout_materialized().await;
    source
        .thread
        .flush_rollout()
        .await
        .expect("flush source rollout");
    let rollout_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");

    let resumed = manager
        .resume_thread_from_rollout(
            config,
            rollout_path,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume active source thread");
    assert_eq!(resumed.thread_id, source.thread_id);
    assert!(Arc::ptr_eq(&resumed.thread, &source.thread));

    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread");
}

#[tokio::test]
async fn resume_stopped_thread_from_rollout_spawns_new_thread() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread(StartThreadOptions::new(config.clone()))
        .await
        .expect("start source thread");
    source.thread.ensure_rollout_materialized().await;
    source
        .thread
        .flush_rollout()
        .await
        .expect("flush source rollout");
    let rollout_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread");

    let resumed = manager
        .resume_thread_from_rollout(
            config,
            rollout_path,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume stopped source thread");
    assert_eq!(resumed.thread_id, source.thread_id);
    assert!(!Arc::ptr_eq(&resumed.thread, &source.thread));

    resumed
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown resumed thread");
}

#[tokio::test]
async fn resume_stopped_thread_from_rollout_preserves_thread_source() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let thread_store = thread_store_from_config(&config, state_db.clone());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store,
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread(StartThreadOptions {
            thread_source: Some(ThreadSource::User),
            environments: Some(Vec::new()),
            ..StartThreadOptions::new(config.clone())
        })
        .await
        .expect("start source thread");
    source.thread.ensure_rollout_materialized().await;
    source
        .thread
        .flush_rollout()
        .await
        .expect("flush source rollout");
    let rollout_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread before resume");
    let _ = manager.remove_thread(&source.thread_id).await;

    let resumed = manager
        .resume_thread_from_rollout(
            config,
            rollout_path,
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume source thread");

    assert_eq!(
        resumed
            .thread
            .config_snapshot()
            .await
            .thread_source
            .as_ref(),
        Some(&ThreadSource::User)
    );

    resumed
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown resumed thread");
}

#[tokio::test]
async fn subtree_listing_uses_injected_graph_store_without_state_db() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let root_thread_id = ThreadId::new();
    let descendant_thread_ids = vec![ThreadId::new(), ThreadId::new()];
    let agent_graph_store = Arc::new(FakeAgentGraphStore {
        root_thread_id,
        descendant_thread_ids: descendant_thread_ids.clone(),
    });
    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        Some(agent_graph_store),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let mut expected_thread_ids = vec![root_thread_id];
    expected_thread_ids.extend(descendant_thread_ids);
    assert_eq!(
        manager
            .list_agent_subtree_thread_ids(root_thread_id)
            .await
            .expect("subtree should load from injected graph store"),
        expected_thread_ids
    );
}

#[tokio::test]
async fn rollout_path_resume_and_fork_read_history_through_thread_store() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    config.experimental_thread_store = ThreadStoreConfig::InMemory {
        id: format!("thread-manager-{}", uuid::Uuid::new_v4()),
    };
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let thread_store = thread_store_from_config(&config, state_db.clone());
    let in_memory_store = thread_store
        .as_any()
        .downcast_ref::<InMemoryThreadStore>()
        .expect("configured in-memory store");
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store.clone(),
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .start_thread(StartThreadOptions::new(config.clone()))
        .await
        .expect("start source thread");
    source
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown source thread");
    let _ = manager.remove_thread(&source.thread_id).await;

    let rollout_path = config
        .codex_home
        .join("rollouts/source.jsonl")
        .to_path_buf();
    let resumed = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::Resumed(ResumedHistory {
                conversation_id: source.thread_id,
                history: Arc::new(vec![RolloutItem::ResponseItem(user_msg("hello"))]),
                rollout_path: Some(rollout_path.clone()),
            }),
            auth_manager.clone(),
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("seed rollout path in store");
    resumed
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown seeded resumed thread");
    let _ = manager.remove_thread(&resumed.thread_id).await;

    let resumed_from_path = manager
        .resume_thread_from_rollout(
            config.clone(),
            rollout_path.clone(),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("resume from rollout path");
    assert_eq!(resumed_from_path.thread_id, resumed.thread_id);

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config,
            rollout_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork from rollout path");
    assert_ne!(forked.thread_id, resumed.thread_id);

    let calls = in_memory_store.calls().await;
    assert_eq!(calls.read_thread_by_rollout_path, 2);

    resumed_from_path
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown path-resumed thread");
    forked
        .thread
        .shutdown_and_wait()
        .await
        .expect("shutdown forked thread");
}

#[tokio::test]
async fn new_uses_active_provider_for_model_refresh() {
    let server = MockServer::start().await;
    let models_mock = mount_models_once(&server, ModelsResponse { models: vec![] }).await;

    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    config.model_catalog = None;
    config.model_provider = ModelProviderInfo::create_openai_provider(Some(server.uri()));

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let _ = manager
        .list_models(
            RefreshStrategy::Online,
            crate::test_support::default_http_client_factory(),
        )
        .await;
    assert_eq!(models_mock.requests().len(), 1);
}

#[tokio::test]
async fn injected_models_manager_controls_refresh_policy() {
    let server = MockServer::start().await;
    let _ = mount_models_once(&server, ModelsResponse { models: vec![] }).await;
    let _ = mount_models_once(&server, ModelsResponse { models: vec![] }).await;

    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");
    config.model_catalog = None;
    config.model_provider.base_url = Some(server.uri());

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let provider = create_model_provider(
        config.model_provider.clone(),
        Some(Arc::clone(&auth_manager)),
    );
    let models_manager = provider.models_manager_without_cache(config.model_catalog.clone());
    let manager = ThreadManager::new(
        &config,
        auth_manager,
        models_manager,
        crate::CodexAppsToolsCache::default(),
        SessionSource::Custom("test-embedder".to_string()),
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, /*state_db*/ None),
        /*agent_graph_store*/ None,
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let http_client_factory = crate::test_support::default_http_client_factory();
    let _ = manager
        .list_models(
            RefreshStrategy::OnlineIfUncached,
            http_client_factory.clone(),
        )
        .await;
    let _ = manager
        .list_models(RefreshStrategy::OnlineIfUncached, http_client_factory)
        .await;

    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        2
    );
    assert!(!config.codex_home.join("models_cache.json").exists());
}

#[test]
fn interrupted_fork_snapshot_appends_interrupt_boundary() {
    let committed_history =
        InitialHistory::Forked(vec![RolloutItem::ResponseItem(user_msg("hello"))]);

    assert_eq!(
        serde_json::to_value(
            append_interrupted_boundary(
                committed_history,
                /*turn_id*/ None,
                /*started_at*/ None,
                InterruptedTurnHistoryMarker::ContextualUser,
            )
            .get_rollout_items()
        )
        .expect("serialize interrupted fork history"),
        serde_json::to_value(vec![
            RolloutItem::ResponseItem(user_msg("hello")),
            RolloutItem::ResponseItem(contextual_user_interrupted_marker()),
            RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: None,
                started_at: None,
                reason: TurnAbortReason::Interrupted,
                completed_at: None,
                duration_ms: None,
            })),
        ])
        .expect("serialize expected interrupted fork history"),
    );
    assert_eq!(
        serde_json::to_value(
            append_interrupted_boundary(
                InitialHistory::New,
                /*turn_id*/ None,
                /*started_at*/ None,
                InterruptedTurnHistoryMarker::ContextualUser,
            )
            .get_rollout_items()
        )
        .expect("serialize interrupted empty fork history"),
        serde_json::to_value(vec![
            RolloutItem::ResponseItem(contextual_user_interrupted_marker()),
            RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: None,
                started_at: None,
                reason: TurnAbortReason::Interrupted,
                completed_at: None,
                duration_ms: None,
            })),
        ])
        .expect("serialize expected interrupted empty history"),
    );
}

#[test]
fn disabled_interrupted_fork_snapshot_appends_only_interrupt_event() {
    let committed_history =
        InitialHistory::Forked(vec![RolloutItem::ResponseItem(user_msg("hello"))]);

    assert_eq!(
        serde_json::to_value(
            append_interrupted_boundary(
                committed_history,
                /*turn_id*/ None,
                /*started_at*/ None,
                InterruptedTurnHistoryMarker::Disabled,
            )
            .get_rollout_items()
        )
        .expect("serialize disabled interrupted fork history"),
        serde_json::to_value(vec![
            RolloutItem::ResponseItem(user_msg("hello")),
            RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: None,
                started_at: None,
                reason: TurnAbortReason::Interrupted,
                completed_at: None,
                duration_ms: None,
            })),
        ])
        .expect("serialize expected disabled interrupted fork history"),
    );
    assert_eq!(
        serde_json::to_value(
            append_interrupted_boundary(
                InitialHistory::New,
                /*turn_id*/ None,
                /*started_at*/ None,
                InterruptedTurnHistoryMarker::Disabled,
            )
            .get_rollout_items()
        )
        .expect("serialize disabled interrupted empty fork history"),
        serde_json::to_value(vec![RolloutItem::EventMsg(EventMsg::TurnAborted(
            TurnAbortedEvent {
                turn_id: None,
                started_at: None,
                reason: TurnAbortReason::Interrupted,
                completed_at: None,
                duration_ms: None,
            },
        ))])
        .expect("serialize expected disabled interrupted empty fork history"),
    );
}

#[test]
fn interrupted_snapshot_is_not_mid_turn() {
    let interrupted_history = InitialHistory::Forked(vec![
        RolloutItem::ResponseItem(user_msg("hello")),
        RolloutItem::ResponseItem(assistant_msg("partial")),
        RolloutItem::ResponseItem(contextual_user_interrupted_marker()),
        RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
            turn_id: Some("turn-1".to_string()),
            started_at: None,
            reason: TurnAbortReason::Interrupted,
            completed_at: None,
            duration_ms: None,
        })),
    ]);

    assert_eq!(
        snapshot_turn_state(&interrupted_history),
        SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
}

#[test]
fn multi_agent_v2_interrupted_marker_uses_developer_input_message() {
    let marker = developer_interrupted_marker();

    let ResponseItem::Message { role, content, .. } = marker else {
        panic!("expected interrupted marker to be a message");
    };
    assert_eq!(role, "developer");
    assert!(
        matches!(
            content.as_slice(),
            [ContentItem::InputText { text }]
                if text.contains(crate::context::TurnAborted::INTERRUPTED_DEVELOPER_GUIDANCE)
        ),
        "expected interrupted marker to use developer InputText content"
    );
}

#[test]
fn completed_legacy_event_history_is_not_mid_turn() {
    let completed_history = InitialHistory::Forked(vec![
        RolloutItem::EventMsg(EventMsg::UserMessage(UserMessageEvent {
            client_id: None,
            message: "hello".to_string(),
            images: None,
            text_elements: Vec::new(),
            local_images: Vec::new(),
            ..Default::default()
        })),
        RolloutItem::EventMsg(EventMsg::AgentMessage(AgentMessageEvent {
            message: "done".to_string(),
            phase: None,
            memory_citation: None,
        })),
    ]);

    assert_eq!(
        snapshot_turn_state(&completed_history),
        SnapshotTurnState {
            ends_mid_turn: false,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
}

#[test]
fn mixed_response_and_legacy_user_event_history_is_mid_turn() {
    let mixed_history = InitialHistory::Forked(vec![
        RolloutItem::ResponseItem(user_msg("hello")),
        RolloutItem::EventMsg(EventMsg::UserMessage(UserMessageEvent {
            client_id: None,
            message: "hello".to_string(),
            images: None,
            text_elements: Vec::new(),
            local_images: Vec::new(),
            ..Default::default()
        })),
    ]);

    assert_eq!(
        snapshot_turn_state(&mixed_history),
        SnapshotTurnState {
            ends_mid_turn: true,
            active_turn_id: None,
            active_turn_started_at: None,
            active_turn_start_index: None,
        },
    );
}

#[tokio::test]
async fn interrupted_fork_snapshot_does_not_synthesize_turn_id_for_legacy_history() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, state_db.clone()),
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::Forked(vec![
                RolloutItem::ResponseItem(user_msg("hello")),
                RolloutItem::ResponseItem(assistant_msg("partial")),
            ]),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("create source thread from completed history");
    let source_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    let source_history = RolloutRecorder::get_rollout_history(&source_path)
        .await
        .expect("read source rollout history");
    let source_snapshot_state = snapshot_turn_state(&source_history);
    assert!(source_snapshot_state.ends_mid_turn);
    let expected_turn_id = source_snapshot_state.active_turn_id.clone();
    assert_eq!(expected_turn_id, None);

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config.clone(),
            source_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork interrupted snapshot");
    let forked_path = forked
        .thread
        .rollout_path()
        .expect("forked rollout path should exist");
    let history = RolloutRecorder::get_rollout_history(&forked_path)
        .await
        .expect("read forked rollout history");
    assert!(!snapshot_turn_state(&history).ends_mid_turn);
    let rollout_items: Vec<_> = history
        .get_rollout_items()
        .iter()
        .filter(|item| !matches!(item, RolloutItem::SessionMeta(_)))
        .collect();
    let interrupted_marker_json = serde_json::to_value(RolloutItem::ResponseItem(
        contextual_user_interrupted_marker(),
    ))
    .expect("serialize interrupted marker");
    let interrupted_abort_json = serde_json::to_value(RolloutItem::EventMsg(
        EventMsg::TurnAborted(TurnAbortedEvent {
            turn_id: expected_turn_id,
            started_at: None,
            reason: TurnAbortReason::Interrupted,
            completed_at: None,
            duration_ms: None,
        }),
    ))
    .expect("serialize interrupted abort event");
    assert_eq!(
        rollout_items
            .iter()
            .filter(|item| {
                strip_response_item_ids_from_json(
                    serde_json::to_value(item).expect("serialize rollout item"),
                ) == interrupted_marker_json
            })
            .count(),
        1,
    );
    assert_eq!(
        rollout_items
            .iter()
            .filter(|item| {
                serde_json::to_value(item).expect("serialize rollout item")
                    == interrupted_abort_json
            })
            .count(),
        1,
    );
}

#[tokio::test]
async fn interrupted_fork_snapshot_preserves_explicit_turn_id() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, state_db.clone()),
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::Forked(vec![
                RolloutItem::EventMsg(EventMsg::TurnStarted(TurnStartedEvent {
                    turn_id: "turn-explicit".to_string(),
                    trace_id: None,
                    started_at: None,
                    model_context_window: None,
                    collaboration_mode_kind: Default::default(),
                })),
                RolloutItem::ResponseItem(user_msg("hello")),
                RolloutItem::ResponseItem(assistant_msg("partial")),
            ]),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("create source thread from explicit partial history");
    let source_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    let source_history = RolloutRecorder::get_rollout_history(&source_path)
        .await
        .expect("read source rollout history");
    let source_snapshot_state = snapshot_turn_state(&source_history);
    assert_eq!(
        source_snapshot_state,
        SnapshotTurnState {
            ends_mid_turn: true,
            active_turn_id: Some("turn-explicit".to_string()),
            active_turn_started_at: None,
            active_turn_start_index: Some(1),
        },
    );

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config.clone(),
            source_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork interrupted snapshot");
    let forked_path = forked
        .thread
        .rollout_path()
        .expect("forked rollout path should exist");
    let history = RolloutRecorder::get_rollout_history(&forked_path)
        .await
        .expect("read forked rollout history");
    let rollout_items: Vec<_> = history
        .get_rollout_items()
        .iter()
        .filter(|item| !matches!(item, RolloutItem::SessionMeta(_)))
        .collect();

    assert!(rollout_items.iter().any(|item| {
        matches!(
            item,
            RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: Some(turn_id),
                started_at: None,
                reason: TurnAbortReason::Interrupted,
            completed_at: None,
            duration_ms: None,
            })) if turn_id == "turn-explicit"
        )
    }));
}

#[tokio::test]
async fn interrupted_fork_snapshot_uses_persisted_mid_turn_history_without_live_source() {
    let temp_dir = tempdir().expect("tempdir");
    let mut config = test_config().await;
    config.codex_home = temp_dir.path().join("codex-home").abs();
    config.cwd = config.codex_home.abs();
    std::fs::create_dir_all(&config.codex_home).expect("create codex home");

    let auth_manager =
        AuthManager::from_auth_for_testing(CodexAuth::create_dummy_chatgpt_auth_for_testing());
    let state_db = init_state_db(&config).await;
    let manager = ThreadManager::new(
        &config,
        auth_manager.clone(),
        build_models_manager(&config, auth_manager.clone()),
        crate::CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
        empty_extension_registry(),
        Arc::new(crate::test_support::EmptyUserInstructionsProvider),
        /*analytics_events_client*/ None,
        thread_store_from_config(&config, state_db.clone()),
        local_agent_graph_store_from_state_db(state_db.as_ref()),
        TEST_INSTALLATION_ID.to_string(),
        /*attestation_provider*/ None,
        /*external_time_provider*/ None,
    );

    let source = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::Forked(vec![
                RolloutItem::ResponseItem(user_msg("hello")),
                RolloutItem::ResponseItem(assistant_msg("partial")),
            ]),
            auth_manager,
            /*parent_trace*/ None,
            /*supports_openai_form_elicitation*/ false,
        )
        .await
        .expect("create source thread from partial history");
    let source_path = source
        .thread
        .rollout_path()
        .expect("source rollout path should exist");
    let source_history = RolloutRecorder::get_rollout_history(&source_path)
        .await
        .expect("read source rollout history");
    assert!(snapshot_turn_state(&source_history).ends_mid_turn);
    manager.remove_thread(&source.thread_id).await;

    let forked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config.clone(),
            source_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("fork interrupted snapshot");
    let forked_path = forked
        .thread
        .rollout_path()
        .expect("forked rollout path should exist");
    let history = RolloutRecorder::get_rollout_history(&forked_path)
        .await
        .expect("read forked rollout history");
    assert!(!snapshot_turn_state(&history).ends_mid_turn);

    let forked_rollout_items: Vec<_> = history
        .get_rollout_items()
        .iter()
        .filter(|item| !matches!(item, RolloutItem::SessionMeta(_)))
        .collect();
    let interrupted_marker_json = serde_json::to_value(RolloutItem::ResponseItem(
        contextual_user_interrupted_marker(),
    ))
    .expect("serialize interrupted marker");
    assert_eq!(
        forked_rollout_items
            .iter()
            .filter(|item| {
                strip_response_item_ids_from_json(
                    serde_json::to_value(item).expect("serialize forked rollout item"),
                ) == interrupted_marker_json
            })
            .count(),
        1,
    );

    manager.remove_thread(&forked.thread_id).await;
    let reforked = manager
        .fork_thread(
            ForkSnapshot::Interrupted,
            config.clone(),
            forked_path,
            /*thread_source*/ None,
            /*parent_trace*/ None,
        )
        .await
        .expect("re-fork interrupted snapshot");
    let reforked_path = reforked
        .thread
        .rollout_path()
        .expect("re-forked rollout path should exist");
    let reforked_history = RolloutRecorder::get_rollout_history(&reforked_path)
        .await
        .expect("read re-forked rollout history");
    let reforked_rollout_items: Vec<_> = reforked_history
        .get_rollout_items()
        .iter()
        .filter(|item| !matches!(item, RolloutItem::SessionMeta(_)))
        .collect();

    assert_eq!(
        reforked_rollout_items
            .iter()
            .filter(|item| {
                strip_response_item_ids_from_json(
                    serde_json::to_value(item).expect("serialize re-forked rollout item"),
                ) == interrupted_marker_json
            })
            .count(),
        1,
    );
    assert_eq!(
        reforked_rollout_items
            .iter()
            .filter(|item| {
                matches!(
                    item,
                    RolloutItem::EventMsg(EventMsg::TurnAborted(TurnAbortedEvent {
                        reason: TurnAbortReason::Interrupted,
                        ..
                    }))
                )
            })
            .count(),
        1,
    );
}

/// PF-84-S06 (#571): a session whose configured provider is Z.AI gets the
/// API-key-only onboarding default (`forced_login_method` reads `api`), but
/// a named OpenAI ChatGPT account selected for it (`--account openai:work`)
/// keeps its sign-in: the account's manager, built from the real config,
/// loads it, so a switch to OpenAI sends work's token.
#[tokio::test]
async fn named_chatgpt_account_loads_in_a_session_on_a_third_party_provider() {
    use base64::Engine;
    let home = tempdir().expect("tempdir");
    let b64 = |data: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    let id_token = format!(
        "{}.{}.{}",
        b64(br#"{"alg":"none","typ":"JWT"}"#),
        b64(serde_json::json!({
            "email": "work@example.com",
            "https://api.openai.com/auth": {"chatgpt_account_id": "ws-work"},
        })
        .to_string()
        .as_bytes()),
        b64(b"sig")
    );
    let sign_in: codex_login::AuthDotJson = serde_json::from_value(serde_json::json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": id_token,
            "access_token": "work-access",
            "refresh_token": "work-refresh",
            "account_id": "ws-work",
        },
        "last_refresh": "2026-10-01T00:00:00Z",
    }))
    .expect("sign-in");
    let work = codex_login::NamedChatgptAccount {
        provider_id: "openai".to_string(),
        name: "work".to_string(),
    };
    codex_login::save_named_account_auth(home.path(), &work, &sign_in, /*must_be_new*/ true)
        .expect("named sign-in");
    let config = crate::config::ConfigBuilder::default()
        .codex_home(home.path().to_path_buf())
        .cli_overrides(vec![
            ("model_provider".to_string(), "zai".into()),
            ("model".to_string(), "glm-5.3-flash".into()),
            ("features.named_accounts".to_string(), true.into()),
        ])
        .harness_overrides(crate::config::ConfigOverrides {
            cwd: Some(home.path().to_path_buf()),
            provider_account: Some("openai:work".to_string()),
            ..Default::default()
        })
        .build()
        .await
        .expect("config");
    assert_eq!(config.model_provider_id, "zai");
    assert_eq!(config.forced_login_method, Some(ForcedLoginMethod::Api));
    assert_eq!(config.configured_forced_login_method, None);
    assert_eq!(crate::config::session_account_error(&config), None);

    let base = AuthManager::shared_from_config(&config, /*enable_codex_api_key_env*/ false).await;
    let named = base.for_named_account(work);
    assert!(
        named
            .auth()
            .await
            .is_some_and(|auth| auth.is_chatgpt_auth())
    );
    assert_eq!(named.named_sign_in_unavailable(), None);
}
