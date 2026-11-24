//! Session- and turn-scoped helpers for talking to model provider APIs.
//!
//! `ModelClient` is intended to live for the lifetime of a Codex session and holds the stable
//! configuration and state needed to talk to a provider (auth, provider selection, conversation id,
//! and transport fallback state).
//!
//! Per-turn settings (model selection, reasoning controls, telemetry context, and turn metadata)
//! are passed explicitly to streaming and unary methods so that the turn lifetime is visible at the
//! call site.
//!
//! A [`ModelClientSession`] is created per turn and is used to stream one or more Responses API
//! requests during that turn. It caches a Responses WebSocket connection (opened lazily) and stores
//! per-turn state such as the `x-codex-turn-state` token used for sticky routing.
//! Cached connections, incremental response state, and turn routing are discarded when auth
//! ownership changes.
//!
//! WebSocket prewarm is a v2-only `response.create` with `generate=false`; it waits for completion
//! so the next request can reuse the same connection and `previous_response_id`.
//!
//! Turn execution performs prewarm as a best-effort step before the first stream request so the
//! subsequent request can reuse the same connection.
//!
//! ## Retry-Budget Tradeoff
//!
//! WebSocket prewarm is treated as the first websocket connection attempt for a turn. If it
//! fails, normal stream retry/fallback logic handles recovery on the same turn.

#[path = "client_anthropic_recovery.rs"]
mod anthropic_recovery;

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

#[path = "client_tool_metadata.rs"]
mod tool_metadata;

use crate::CodexResponsesHeaders;
use crate::PromptCacheKey;
use crate::tools::ExecutedToolCalls;
use async_channel::Sender;
use codex_api::AgentIdentityTelemetry;
use codex_api::AnthropicMessagesClient as ApiAnthropicMessagesClient;
use codex_api::AnthropicMessagesOptions as ApiAnthropicMessagesOptions;
use codex_api::AnthropicMessagesRequest;
use codex_api::ApiError;
use codex_api::AuthProvider;
use codex_api::ChatCacheControl;
use codex_api::ChatCompletionsClient as ApiChatCompletionsClient;
use codex_api::ChatCompletionsOptions as ApiChatCompletionsOptions;
use codex_api::ChatCompletionsRequest;
use codex_api::ChatContentPart;
use codex_api::ChatMessage;
use codex_api::ChatMessageContent;
use codex_api::ChatStreamOptions;
use codex_api::ChatToolCall;
use codex_api::ChatToolFunction;
use codex_api::Compression;
use codex_api::MemoriesClient as ApiMemoriesClient;
use codex_api::MemorySummarizeInput as ApiMemorySummarizeInput;
use codex_api::MemorySummarizeOutput as ApiMemorySummarizeOutput;
use codex_api::Provider as ApiProvider;
use codex_api::RESPONSES_PATH;
use codex_api::RawMemory as ApiRawMemory;
use codex_api::RealtimeCallClient as ApiRealtimeCallClient;
use codex_api::RealtimeSessionConfig as ApiRealtimeSessionConfig;
use codex_api::Reasoning;
use codex_api::ReasoningContext;
use codex_api::RequestTelemetry;
use codex_api::ReqwestTransport;
use codex_api::ResponseCreateWsRequest;
use codex_api::ResponsesApiRequest;
use codex_api::ResponsesClient as ApiResponsesClient;
use codex_api::ResponsesOptions as ApiResponsesOptions;
use codex_api::ResponsesWebsocketClient as ApiWebSocketResponsesClient;
use codex_api::ResponsesWebsocketConnection as ApiWebSocketConnection;
use codex_api::ResponsesWsRequest;
use codex_api::SharedAuthProvider;
use codex_api::SseTelemetry;
use codex_api::StreamOptions;
use codex_api::TransportError;
use codex_api::WebsocketTelemetry;
use codex_api::auth_header_telemetry;
use codex_api::build_session_headers;
use codex_api::create_text_param_for_request;
use codex_api::response_create_client_metadata;
use codex_features::Feature;
use codex_features::RuntimeAuthMode;
use codex_http_client::ClientRouteClass;
use codex_http_client::HttpClientFactory;
use codex_login::AuthManager;
use codex_login::CodexAuth;
use codex_login::RefreshTokenError;
use codex_login::UnauthorizedRecovery;
use codex_login::default_client::ClientRedirectPolicy;
use codex_login::default_client::add_originator_header;
use codex_login::default_client::create_client_for_route;
use codex_otel::SessionTelemetry;
use codex_otel::WEBSOCKET_CONTINUATION_COUNT_METRIC;
use codex_otel::current_span_w3c_trace_context;
use codex_protocol::ResponseItemId;
use codex_protocol::auth::AuthMode;
use codex_runtime_agent_instance::RuntimeAuthManager;

use codex_protocol::AgentPath;
use codex_protocol::ThreadId;
use codex_protocol::config_types::ReasoningSummary as ReasoningSummaryConfig;
use codex_protocol::config_types::Verbosity as VerbosityConfig;
use codex_protocol::config_types::WebSearchContextSize;
use codex_protocol::models::AgentMessageInputContent;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ReasoningItemContent;
use codex_protocol::models::ResponseItem;
use codex_protocol::models::plaintext_agent_message_content;
use codex_protocol::openai_models::ChatReasoningEffortProtocol;
use codex_protocol::openai_models::ChatReasoningProtocol;
use codex_protocol::openai_models::ModelInfo;
use codex_protocol::openai_models::ReasoningEffort as ReasoningEffortConfig;
use codex_protocol::protocol::AuthRecoveryEvent;
use codex_protocol::protocol::Event as ProtocolEvent;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::InternalSessionSource;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::protocol::W3cTraceContext;
use codex_rollout_trace::InferenceTraceAttempt;
use codex_rollout_trace::InferenceTraceContext;
use codex_tools::ToolSpec;
use codex_tools::create_tools_json_for_responses_lite;
use codex_tools::create_tools_raw_json_for_responses_api;
use eventsource_stream::Event;
use eventsource_stream::EventStreamError;
use futures::StreamExt;
use http::HeaderMap as ApiHeaderMap;
use http::HeaderValue;
use http::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio_tungstenite::tungstenite::Error;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::instrument;
use tracing::trace;
use tracing::warn;
use uuid::Uuid;

use crate::anthropic_payload::ImageDimensionReport;
use crate::anthropic_payload::enforce_anthropic_payload_budget;
use crate::anthropic_payload::fit_anthropic_image_dimensions;
use crate::anthropic_payload::is_anthropic_payload_too_large;
use crate::attestation::AttestationContext;
use crate::attestation::AttestationProvider;
use crate::attestation::X_OAI_ATTESTATION_HEADER;
use crate::client_common::Prompt;
use crate::client_common::ResponseEvent;
use crate::client_common::ResponseStream;
use crate::client_common::retain_latest_contextual_developer_fragments;
use crate::config::Config;
use crate::context::BaseInstructionsFragment;
use crate::context::ContextualUserFragment;
use crate::cyber_access_program;
use crate::feedback_tags;
use crate::responses_metadata::CodexResponsesMetadata;
use crate::responses_metadata::subagent_header_value;
use crate::util::emit_feedback_auth_recovery_tags;
use codex_feedback::FeedbackRequestTags;
use codex_feedback::emit_feedback_request_tags_with_auth_env;
use codex_login::auth::AgentIdentityAuthPolicy;
use codex_login::auth_env_telemetry::AuthEnvTelemetry;
use codex_login::auth_env_telemetry::collect_auth_env_telemetry;
use codex_model_provider::AgentIdentitySessionFallback;
use codex_model_provider::ProviderAuthScope;
use codex_model_provider::ProviderUnauthorizedRecovery;
use codex_model_provider::ResolvedProviderAuth;
use codex_model_provider::ResponsesConnectionKey;
use codex_model_provider::SharedModelProvider;
use codex_model_provider::WorkspaceRoutingContext;
use codex_model_provider::create_model_provider;
use codex_model_provider_info::AMBIENT_DEFAULT_MODEL;
use codex_model_provider_info::AMBIENT_LEGACY_GLM_5_2_FP8_MODEL;
use codex_model_provider_info::ANTHROPIC_LEGACY_OPUS_4_8_MODEL;
use codex_model_provider_info::CLAUDE_FABLE_5_1_PLAN_MODEL;
use codex_model_provider_info::CLAUDE_FABLE_5_1_PLAN_UPSTREAM_MODEL;
use codex_model_provider_info::CLAUDE_FABLE_5_PLAN_MODEL;
use codex_model_provider_info::CLAUDE_FABLE_5_PLAN_UPSTREAM_MODEL;
use codex_model_provider_info::CLAUDE_OPUS_5_5_PLAN_MODEL;
use codex_model_provider_info::CLAUDE_OPUS_5_5_PLAN_UPSTREAM_MODEL;
use codex_model_provider_info::CLAUDE_PLAN_LEGACY_OPUS_4_8_MODEL;
use codex_model_provider_info::CLAUDE_PLAN_MODEL;
use codex_model_provider_info::CLAUDE_PLAN_UPSTREAM_MODEL;
#[cfg(test)]
use codex_model_provider_info::DEFAULT_WEBSOCKET_CONNECT_TIMEOUT_MS;
use codex_model_provider_info::ModelProviderInfo;
use codex_model_provider_info::VERCEL_DEFAULT_MODEL;
use codex_model_provider_info::VERCEL_GLM_5_2_FAST_MODEL;
use codex_model_provider_info::WireApi;
use codex_model_provider_info::vercel_gateway_upstream_model;
use codex_protocol::error::CodexErr;
use codex_protocol::error::CodexErrorDetails;
use codex_protocol::error::Result;
use codex_response_debug_context::extract_response_debug_context;
use codex_response_debug_context::extract_response_debug_context_from_api_error;
use codex_response_debug_context::telemetry_api_error_message;
use codex_response_debug_context::telemetry_transport_error_message;

pub const OPENAI_BETA_HEADER: &str = "OpenAI-Beta";
pub const X_CODEX_INSTALLATION_ID_HEADER: &str = "x-codex-installation-id";
pub const X_CODEX_ROUTING_HINT_HEADER: &str = "x-codex-routing-hint";
pub const X_CODEX_TURN_STATE_HEADER: &str = "x-codex-turn-state";
pub const X_CODEX_TURN_METADATA_HEADER: &str = "x-codex-turn-metadata";
pub const X_CODEX_PARENT_THREAD_ID_HEADER: &str = "x-codex-parent-thread-id";
pub const X_CODEX_WINDOW_ID_HEADER: &str = "x-codex-window-id";
pub const X_OPENAI_MEMGEN_REQUEST_HEADER: &str = "x-openai-memgen-request";
pub const X_OPENAI_SUBAGENT_HEADER: &str = "x-openai-subagent";
pub const X_RESPONSESAPI_INCLUDE_TIMING_METRICS_HEADER: &str =
    "x-responsesapi-include-timing-metrics";
const X_CODEX_WS_STREAM_REQUEST_START_MS_CLIENT_METADATA_KEY: &str =
    "x-codex-ws-stream-request-start-ms";
const WS_REQUEST_HEADER_RESPONSES_LITE_CLIENT_METADATA_KEY: &str =
    "ws_request_header_x_openai_internal_codex_responses_lite";
const RESPONSES_WEBSOCKETS_V2_BETA_HEADER_VALUE: &str = "responses_websockets=2026-02-06";
const X_OPENAI_INTERNAL_CODEX_RESPONSES_LITE_HEADER: &str =
    "x-openai-internal-codex-responses-lite";
const REALTIME_CALLS_ENDPOINT: &str = "/realtime/calls";
const RESPONSES_ENDPOINT: &str = "/responses";
const CHAT_COMPLETIONS_ENDPOINT: &str = "/chat/completions";
const ANTHROPIC_MESSAGES_ENDPOINT: &str = "/messages";
const ANTHROPIC_MESSAGES_MAX_CACHE_CONTROL_BLOCKS: usize = 4;
const ANTHROPIC_WEB_SEARCH_TOOL_TYPE: &str = "web_search_20260209";
const ANTHROPIC_WEB_SEARCH_TOOL_TYPE_LEGACY: &str = "web_search_20250305";
const CLAUDE_CODE_IDENTITY_PROMPT: &str =
    "You are Claude Code, Anthropic's official CLI for Claude.";
#[cfg_attr(not(test), allow(dead_code))]
const MEMORIES_SUMMARIZE_ENDPOINT: &str = "/memories/trace_summarize";
#[cfg(test)]
pub(crate) const WEBSOCKET_CONNECT_TIMEOUT: Duration =
    Duration::from_millis(DEFAULT_WEBSOCKET_CONNECT_TIMEOUT_MS);

fn session_telemetry_for_request(
    session_telemetry: &SessionTelemetry,
    request: &ResponsesApiRequest,
) -> SessionTelemetry {
    session_telemetry.clone().with_inference_request(
        request.service_tier.as_deref(),
        request
            .reasoning
            .as_ref()
            .and_then(|reasoning| reasoning.effort.as_ref()),
    )
}

/// Session-scoped state shared by all [`ModelClient`] clones.
///
/// This is intentionally kept minimal so `ModelClient` does not need to hold a full `Config`. Most
/// configuration is per turn and is passed explicitly to streaming/unary methods.
#[derive(Debug)]
struct ModelClientState {
    thread_id: ThreadId,
    provider: SharedModelProvider,
    workspace_routing: WorkspaceRoutingContext,
    auth_env_telemetry: AuthEnvTelemetry,
    session_source: SessionSource,
    originator: String,
    model_verbosity: Option<VerbosityConfig>,
    content_item_kinds_enabled: bool,
    reasoning_effort_override_enabled: bool,
    enable_request_compression: bool,
    include_timing_metrics: bool,
    beta_features_header: Option<String>,
    concurrent_reasoning_summaries_enabled: bool,
    output_token_replay_enabled: bool,
    include_attestation: bool,
    attestation_provider: Option<Arc<dyn AttestationProvider>>,
    disable_websockets: AtomicBool,
    agent_identity_session_fallback: AgentIdentitySessionFallback,
    cached_websocket_session: StdMutex<WebsocketSession>,
    server_conversation_state: SharedServerConversationState,
    /// Set once the gateway rejects a `previous_response_id` continuation for
    /// this session. Some upstream models (Kimi K3 on Vercel) reject every
    /// incremental continuation; retrying it each turn doubles the requests.
    http_server_state_rejected: AtomicBool,
    /// Set once the Vercel gateway refuses the pinned Z.AI upstream because an
    /// account policy (for example zero data retention) excludes it. The
    /// session then uses the gateway's own routing.
    vercel_vendor_pin_rejected: AtomicBool,
    /// Set once a provider rejects a tool continuation that ends in tool output after an
    /// assistant message. The session then restores the legacy synthetic `Continue.` turn.
    legacy_synthetic_continuation: AtomicBool,
    /// #578: item IDs a Responses host reported it could not find (`store:
    /// false` keeps nothing to look up). Later requests of this client send
    /// none of them as a reference.
    unresolvable_item_ids: StdMutex<HashSet<String>>,
    /// Last full tool list used for sampling, retained across turns and connection resets.
    last_inference_tools: StdMutex<Option<Arc<[ToolSpec]>>>,
}

enum ClientRouting {
    Workspace,
    ConfiguredProvider,
}

/// Resolved API client setup for a single request attempt.
///
/// Keeping this as a single bundle ensures prewarm and normal request paths
/// share the same auth/provider setup flow.
struct CurrentClientSetup {
    auth: Option<CodexAuth>,
    auth_owner_generation: Option<u64>,
    auth_revision: Option<u64>,
    api_provider: ApiProvider,
    http_client_factory: HttpClientFactory,
    redirect_policy: ClientRedirectPolicy,
    api_auth: SharedAuthProvider,
    agent_identity_telemetry: Option<AgentIdentityTelemetry>,
    runtime_id: Option<String>,
}

impl CurrentClientSetup {
    /// The redirect policy of this setup's requests: an account-routed request never follows
    /// a redirect.
    fn effective_redirect_policy(&self) -> ClientRedirectPolicy {
        if self
            .api_provider
            .headers
            .contains_key(codex_model_provider::ACCOUNT_ROUTING_HEADER)
        {
            ClientRedirectPolicy::Reject
        } else {
            self.redirect_policy
        }
    }

    fn build_api_transport(&self, endpoint: &str) -> Result<ReqwestTransport> {
        let api_provider = &self.api_provider;
        let redirect_policy = self.effective_redirect_policy();
        let client = create_client_for_route(
            &self.http_client_factory,
            &api_provider.url_for_path(endpoint),
            ClientRouteClass::Api,
            redirect_policy,
        )
        .map_err(std::io::Error::from)?;
        Ok(ReqwestTransport::from_http_client(client))
    }

    /// Corbanu accounting: the ordinary, redirect-following transport a recorded request is
    /// resent on when its provider redirects it (see
    /// `AccountingTransport::with_redirect_fallback`). It follows this setup's redirect policy.
    fn redirect_fallback(&self, request_url: &str) -> Result<ReqwestTransport> {
        let client = create_client_for_route(
            &self.http_client_factory,
            request_url,
            ClientRouteClass::Api,
            self.effective_redirect_policy(),
        )
        .map_err(std::io::Error::from)?;
        Ok(ReqwestTransport::from_http_client(client))
    }

    /// Corbanu accounting: a no-redirect client for one recorded model request, so a response
    /// from elsewhere can never be attributed to the approved endpoint.
    fn api_client_without_redirects(
        &self,
        request_url: &str,
    ) -> Result<codex_http_client::HttpClient> {
        Ok(
            codex_login::default_client::create_client_for_route_without_redirects(
                &self.http_client_factory,
                request_url,
                ClientRouteClass::Api,
            )
            .map_err(std::io::Error::from)?,
        )
    }
}

#[derive(Clone, Copy)]
struct RequestRouteTelemetry {
    endpoint: &'static str,
}

impl RequestRouteTelemetry {
    fn for_endpoint(endpoint: &'static str) -> Self {
        Self { endpoint }
    }
}

/// Issue #445: why a model request was not sent while the kill switch is on.
pub const KILL_SWITCH_REFUSAL: &str = "Not sent: the security kill switch is on, so Corbanu sends nothing to the model, and this message was not kept. To turn it off, open /security, press g, choose \"Turn the kill switch off\" and confirm.";

/// A session-scoped client for model-provider API calls.
///
/// This holds configuration and state that should be shared across turns within a Codex session
/// (auth, provider selection, thread id, and transport fallback state).
///
/// WebSocket fallback is session-scoped: once a turn activates the HTTP fallback, subsequent turns
/// will also use HTTP for the remainder of the session.
///
/// Turn-scoped settings (model selection, reasoning controls, telemetry context, and turn
/// metadata) are passed explicitly to the relevant methods to keep turn lifetime visible at the
/// call site.
#[derive(Debug, Clone)]
pub struct ModelClient {
    state: Arc<ModelClientState>,
    agent_identity_policy: AgentIdentityAuthPolicy,
    prompt_cache_key_policy: PromptCacheKey,
    session_id_override: Option<String>,
    codex_responses_headers: Option<Arc<CodexResponsesHeaders>>,
    event_sender: Option<Sender<ProtocolEvent>>,
    http_client_factory: HttpClientFactory,
    // Restrictive configured intent, not an assertion of protected readiness.
    ingress_level: codex_security_policy::SecurityLevel,
    ingress_policy: Option<crate::security::ingress::BoundIngressPolicy>,
    pub(crate) stage_one_memory_binding:
        Arc<OnceLock<Arc<crate::memory_stage_one::StageOneMemoryBinding>>>,
    ingress_items: Arc<StdMutex<crate::security::ingress::NativeIngress>>,
    restored_history: bool,
    request_contributors: Vec<Arc<dyn codex_extension_api::ModelRequestContributor>>,
    executed_tool_calls: Option<ExecutedToolCalls>,
    // Resolved once when the session is created, like other session feature flags.
    api_key_cyber_access_programs: cyber_access_program::ApiKeyCyberAccessPrograms,
    runtime_auth: Option<(Arc<RuntimeAuthManager>, RuntimeAuthMode)>,
}

/// A turn-scoped streaming session created from a [`ModelClient`].
///
/// The session establishes a Responses WebSocket connection lazily and reuses it across multiple
/// requests within the turn. It also caches per-turn state:
///
/// - The last full request, so subsequent calls can reuse incremental websocket request payloads
///   only when the current request is an incremental extension of the previous one.
/// - The `x-codex-turn-state` sticky-routing token, which must be replayed for all requests within
///   the same turn.
///
/// Create a fresh `ModelClientSession` for each Codex turn. Reusing it across turns would replay
/// the previous turn's sticky-routing token into the next turn, which violates the client/server
/// contract and can cause routing bugs.
pub struct ModelClientSession {
    pub(crate) accounting: crate::accounting::Slot,
    pub(crate) responses_accounting: crate::accounting::responses::Slot,
    pub(crate) chat_accounting: crate::accounting::chat::Slot,
    client: ModelClient,
    websocket_session: WebsocketSession,
    /// Turn state for sticky routing.
    ///
    /// This is an `OnceLock` that stores the turn state value received from the server
    /// on turn start via the `x-codex-turn-state` response header. Once set, this value
    /// should be sent back to the server in the `x-codex-turn-state` request header for
    /// all subsequent requests within the same turn to maintain sticky routing.
    ///
    /// This is a contract between the client and server: we receive it at turn start,
    /// keep sending it unchanged between turn requests (e.g., for retries, incremental
    /// appends, or continuation requests), and must not send it between different turns.
    /// An auth ownership change clears it so the new owner gets fresh routing state.
    turn_state: Arc<OnceLock<String>>,
}

/// Executes HTTP Responses requests without owning a turn's WebSocket state.
pub(crate) struct ResponsesHttpExecutor<'a> {
    client: &'a ModelClient,
    /// Corbanu accounting (D16): the session's collection slot; `None` sends unrecorded.
    accounting: Option<&'a crate::accounting::responses::Slot>,
}

#[derive(Debug, Clone)]
struct LastResponse {
    response_id: String,
    items_added: Vec<ResponseItem>,
}

#[derive(Debug, Clone)]
struct ServerConversationState {
    last_request: Option<ResponsesApiRequest>,
    last_response: LastResponse,
}

type SharedServerConversationState = Arc<StdMutex<Option<ServerConversationState>>>;

/// #1311 (D171): who a websocket connection was opened as (the ChatGPT
/// account and user, or the API key), as a digest, never the credential. A
/// session whose sign-in was replaced by another user's or another key never
/// reuses a connection opened with the old one; a refreshed token of the same
/// sign-in keeps it. Sign-ins without an account, user or API key (no
/// `CodexAuth`, or externally supplied auth headers) use a digest of their
/// configured provider headers and resolved API auth headers instead; the
/// others also digest the configured provider headers (#1326, #1343). A
/// brokered credential is invisible to Core, so brokered identities never
/// match (#1343).
#[derive(Clone, PartialEq, Eq)]
struct ConnectionIdentity([u8; 32]);

impl std::fmt::Debug for ConnectionIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConnectionIdentity(..)")
    }
}

impl ConnectionIdentity {
    fn of(
        auth: Option<&CodexAuth>,
        provider_headers: &ApiHeaderMap,
        api_auth: &dyn AuthProvider,
    ) -> Self {
        Self::with_broker_required(
            codex_model_provider::model_key_broker_required(),
            auth,
            provider_headers,
            api_auth,
        )
    }

    /// [`Self::of`] with the process's broker state passed in, so tests can
    /// cover a brokered process without installing a process-wide broker.
    fn with_broker_required(
        broker_required: bool,
        auth: Option<&CodexAuth>,
        provider_headers: &ApiHeaderMap,
        api_auth: &dyn AuthProvider,
    ) -> Self {
        use sha2::Digest;
        let mut digest = sha2::Sha256::new();
        let mut field = |value: Option<&str>| match value {
            Some(value) => {
                digest.update([1]);
                digest.update((value.len() as u64).to_le_bytes());
                digest.update(value.as_bytes());
            }
            None => digest.update([0]),
        };
        let mode = auth.map(|auth| format!("{:?}", auth.auth_mode()));
        let account_id = auth.and_then(CodexAuth::get_account_id);
        let user_id = auth.and_then(CodexAuth::get_chatgpt_user_id);
        let api_key = auth.and_then(CodexAuth::api_key);
        field(mode.as_deref());
        field(account_id.as_deref());
        field(user_id.as_deref());
        field(api_key);
        if broker_required || api_key == Some(codex_model_provider::BROKERED_KEY_PLACEHOLDER) {
            // The broker attaches the credential, so Core cannot tell two
            // brokered sign-ins apart: never reuse a connection across them.
            // In a brokered process this holds for every provider, including
            // unbrokered command/AWS auth, so a socket would reconnect on
            // every turn. That relies on websockets staying off under the
            // credential broker (`responses_websocket_enabled`); revisit this
            // before turning them on there (#1504).
            static BROKERED: AtomicU64 = AtomicU64::new(0);
            digest.update(b"brokered");
            digest.update(BROKERED.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        }
        let mut headers = provider_headers.clone();
        if account_id.is_none() && user_id.is_none() && api_key.is_none() {
            // No semantic sign-in identity: the resolved auth headers are the
            // sign-in. Apply them last, matching websocket handshake
            // precedence. A semantic identity skips them so that a refreshed
            // bearer token keeps the connection.
            if api_auth.add_auth_headers(&mut headers).is_err() {
                // #2259: the sign-in could not be resolved, so fail closed:
                // the identity is unique and never matches another
                // connection (the partly written headers are still hashed
                // but cannot make two identities equal).
                static AUTH_ERROR: AtomicU64 = AtomicU64::new(0);
                digest.update(b"auth-error");
                digest.update(AUTH_ERROR.fetch_add(1, Ordering::Relaxed).to_le_bytes());
            }
        }
        // Configured headers can carry the sign-in too. Hash bytes rather than
        // an object's address or Debug output. Keep duplicate-value order, but
        // ignore insertion order between header names.
        let mut fields = headers.iter().collect::<Vec<_>>();
        fields.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));
        digest.update(b"api-auth-headers");
        for (name, value) in fields {
            digest.update((name.as_str().len() as u64).to_le_bytes());
            digest.update(name.as_str().as_bytes());
            digest.update((value.as_bytes().len() as u64).to_le_bytes());
            digest.update(value.as_bytes());
        }
        Self(digest.finalize().into())
    }
}

struct WebsocketContinuation {
    response_id: String,
    items: Vec<ResponseItem>,
    from_untraced_warmup: bool,
}

#[derive(Debug, Default)]
struct WebsocketSession {
    connection: Option<ApiWebSocketConnection>,
    /// Who `connection` was opened as.
    identity: Option<ConnectionIdentity>,
    provenance: Option<crate::accounting::websocket::Provenance>,
    responses_headers: ApiHeaderMap,
    parent_routing_affinity: Option<codex_http_client::ChatGptRoutingAffinity>,
    runtime_id: Option<String>,
    /// Owner of the cached state, including before a connection is opened.
    auth_owner_generation: Option<u64>,
    connection_key: Option<ResponsesConnectionKey>,
    last_request: Option<ResponsesApiRequest>,
    last_response_rx: Option<oneshot::Receiver<LastResponse>>,
    last_response_from_untraced_warmup: bool,
    connection_reused: StdMutex<bool>,
    continuation_reset_reason: Option<&'static str>,
}

// Continuation diagnostics use bounded labels, never request contents or identifiers.
#[derive(Debug, PartialEq, Eq)]
enum NonIncrementalReason {
    NoPreviousRequest,
    NoPreviousResponse,
    NoPreviousResponseId,
    RequestPropertyChanged {
        reason: &'static str,
    },
    InputShortened {
        previous: &'static str,
    },
    InputMismatch {
        previous: &'static str,
        current: &'static str,
    },
}

impl NonIncrementalReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::NoPreviousRequest => "no_previous_request",
            Self::NoPreviousResponse => "no_previous_response",
            Self::NoPreviousResponseId => "no_previous_response_id",
            Self::RequestPropertyChanged { reason } => reason,
            Self::InputShortened { .. } => "input_shortened",
            Self::InputMismatch { .. } => "input_mismatch",
        }
    }

    fn item_types(&self) -> (&'static str, &'static str) {
        match self {
            Self::InputShortened { previous } => (previous, "none"),
            Self::InputMismatch { previous, current } => (previous, current),
            Self::NoPreviousRequest
            | Self::NoPreviousResponse
            | Self::NoPreviousResponseId
            | Self::RequestPropertyChanged { .. } => ("none", "none"),
        }
    }
}

// This is intentionally not a `PartialEq` implementation: request equality includes `input` and
// `client_metadata`, while websocket reuse compares input and late tool-result metadata separately.
// Access programs are authorized per response, including continuations, without replaying input.
// Keep the destructuring exhaustive so new request fields require an explicit reuse decision.
fn responses_request_properties_mismatch(
    previous: &ResponsesApiRequest,
    current: &ResponsesApiRequest,
) -> Option<&'static str> {
    let ResponsesApiRequest {
        model: previous_model,
        instructions: previous_instructions,
        previous_response_id,
        input: _,
        tools: previous_tools,
        tool_choice: previous_tool_choice,
        parallel_tool_calls: previous_parallel_tool_calls,
        reasoning: previous_reasoning,
        store: previous_store,
        stream: previous_stream,
        stream_options: _,
        include: previous_include,
        service_tier: previous_service_tier,
        prompt_cache_key: previous_prompt_cache_key,
        text: previous_text,
        client_metadata: _,
        thinking_budget: previous_thinking_budget,
        emit_usage: previous_emit_usage,
        enable_thinking: previous_enable_thinking,
        reasoning_effort: previous_reasoning_effort,
        provider_options: previous_provider_options,
        access_programs: _,
    } = previous;
    let ResponsesApiRequest {
        model: current_model,
        instructions: current_instructions,
        previous_response_id: current_previous_response_id,
        input: _,
        tools: current_tools,
        tool_choice: current_tool_choice,
        parallel_tool_calls: current_parallel_tool_calls,
        reasoning: current_reasoning,
        store: current_store,
        stream: current_stream,
        stream_options: _,
        include: current_include,
        service_tier: current_service_tier,
        prompt_cache_key: current_prompt_cache_key,
        text: current_text,
        client_metadata: _,
        thinking_budget: current_thinking_budget,
        emit_usage: current_emit_usage,
        enable_thinking: current_enable_thinking,
        reasoning_effort: current_reasoning_effort,
        provider_options: current_provider_options,
        access_programs: _,
    } = current;

    // Stream options control delivery for this response, not the context
    // referenced by `previous_response_id`.
    let reason = if previous_model != current_model {
        "model_changed"
    } else if previous_instructions != current_instructions {
        "instructions_changed"
    } else if previous_response_id != current_previous_response_id {
        "previous_response_id_changed"
    } else if previous_tools != current_tools {
        "tools_changed"
    } else if previous_tool_choice != current_tool_choice {
        "tool_choice_changed"
    } else if previous_parallel_tool_calls != current_parallel_tool_calls {
        "parallel_tool_calls_changed"
    } else if previous_reasoning != current_reasoning {
        "reasoning_changed"
    } else if previous_store != current_store {
        "store_changed"
    } else if previous_stream != current_stream {
        "stream_changed"
    } else if previous_include != current_include {
        "include_changed"
    } else if previous_service_tier != current_service_tier {
        "service_tier_changed"
    } else if previous_prompt_cache_key != current_prompt_cache_key {
        "prompt_cache_key_changed"
    } else if previous_text != current_text {
        "text_changed"
    } else if previous_thinking_budget != current_thinking_budget
        || previous_emit_usage != current_emit_usage
        || previous_enable_thinking != current_enable_thinking
        || previous_reasoning_effort != current_reasoning_effort
        || previous_provider_options != current_provider_options
    {
        // Corbanu: Ambient/Z.AI and Vercel gateway request fields.
        "provider_options_changed"
    } else {
        return None;
    };
    Some(reason)
}

fn response_items_equal_ignoring_internal_metadata(
    previous: &ResponseItem,
    current: &ResponseItem,
) -> bool {
    if previous == current {
        return true;
    }

    // Late results update an already-sent output. A delta cannot carry that update.
    if !previous.has_same_tool_result_metadata(current) {
        return false;
    }

    let mut previous = previous.clone();
    // Item ids are transport metadata, not conversation content. The durable history may assign
    // a canonical id to a provider item that arrived without one, so requiring id equality would
    // reject an otherwise exact incremental continuation. Tool linkage remains protected by the
    // semantic `call_id` fields compared below as part of the full item value.
    previous.set_id(/*new_id*/ None);
    previous.clear_internal_chat_message_metadata_passthrough();
    let mut current = current.clone();
    current.set_id(/*new_id*/ None);
    current.clear_internal_chat_message_metadata_passthrough();
    previous == current
}

fn incremental_items_for_request(
    request: &ResponsesApiRequest,
    previous_request: &ResponsesApiRequest,
    last_response: Option<&LastResponse>,
    allow_empty_delta: bool,
) -> Option<Vec<ResponseItem>> {
    if responses_request_properties_mismatch(previous_request, request).is_some() {
        trace!("incremental request failed, reuse properties didn't match");
        return None;
    }

    let response_items = last_response.map_or(&[][..], |response| response.items_added.as_slice());
    let previous_items_len = previous_request
        .input
        .len()
        .checked_add(response_items.len())?;
    let Some((request_items_to_compare, incremental_items)) =
        request.input.split_at_checked(previous_items_len)
    else {
        trace!("incremental request failed, incompatible request length");
        return None;
    };
    let previous_items = previous_request.input.iter().chain(response_items);
    if !previous_items
        .zip(request_items_to_compare)
        .all(|(previous, current)| {
            response_items_equal_ignoring_internal_metadata(previous, current)
        })
    {
        trace!("incremental request failed, items didn't match");
        return None;
    }
    if !allow_empty_delta && incremental_items.is_empty() {
        return None;
    }
    Some(incremental_items.to_vec())
}

fn items_after_last_model_output(input: &[ResponseItem]) -> Option<Vec<ResponseItem>> {
    let last_model_output_index = input.iter().rposition(is_model_output_item)?;
    let incremental_items = input.get(last_model_output_index + 1..)?;
    (!incremental_items.is_empty()).then(|| incremental_items.to_vec())
}

/// Prevent a completed assistant message from becoming an accidental prefill on the next model
/// request.
///
/// Only a request whose conversation genuinely ends with assistant output is a prefill; some
/// upstream models reject that shape (Claude via Vercel: "This model does not support assistant
/// message prefill"). Tool results after an assistant message are an ordinary tool continuation
/// and are accepted by Kimi K3, GLM 5.3, Claude and DeepSeek V4 on the Vercel Responses route.
/// Appending `Continue.` there made models read a user interjection after every tool result.
/// The continuation is request-only: it does not rewrite the durable conversation history.
fn responses_input_needs_synthetic_user_turn(input: &[ResponseItem]) -> bool {
    // A compaction trigger is itself the terminal request control. Appending anything after it is
    // invalid, and it does not need the user-message continuation used for ordinary sampling.
    if input
        .iter()
        .any(|item| matches!(item, ResponseItem::CompactionTrigger { .. }))
    {
        return false;
    }

    input
        .iter()
        .rev()
        .find_map(terminal_item_is_assistant_output)
        == Some(true)
}

/// Legacy session fallback: treat the conversation as a prefill whenever the latest *message* is
/// assistant, even when tool activity follows. Used only after a provider rejects the narrower
/// shape in this session.
fn responses_input_latest_message_is_assistant(input: &[ResponseItem]) -> bool {
    if input
        .iter()
        .any(|item| matches!(item, ResponseItem::CompactionTrigger { .. }))
    {
        return false;
    }
    let latest_message_is_assistant = input.iter().rev().find_map(|item| match item {
        ResponseItem::Message { role, .. } => Some(role == "assistant"),
        // Incoming collaboration mail is serialized as an assistant-originated message by the
        // Responses adapters. Treat it as message-shaped here as well.
        ResponseItem::AgentMessage { .. } => Some(true),
        _ => None,
    });
    latest_message_is_assistant == Some(true)
}

/// Classifies the item that ends a request: `Some(true)` for assistant output (a prefill),
/// `Some(false)` for user input or tool activity, `None` for items that do not reach the model as
/// conversation turns and are skipped.
fn terminal_item_is_assistant_output(item: &ResponseItem) -> Option<bool> {
    match item {
        ResponseItem::Message { role, .. } => Some(role == "assistant"),
        // Incoming collaboration mail is serialized as an assistant-originated message by the
        // Responses adapters; child completion mail arriving after a turn is a prefill shape.
        ResponseItem::AgentMessage { .. } => Some(true),
        ResponseItem::LocalShellCall { .. }
        | ResponseItem::FunctionCall { .. }
        | ResponseItem::ToolSearchCall { .. }
        | ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::CustomToolCall { .. }
        | ResponseItem::CustomToolCallOutput { .. }
        | ResponseItem::ToolSearchOutput { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::ImageGenerationCall { .. }
        | ResponseItem::Compaction { .. }
        | ResponseItem::ContextCompaction { .. } => Some(false),
        ResponseItem::AdditionalTools { .. }
        | ResponseItem::Reasoning { .. }
        | ResponseItem::ConfigurationUpdate { .. }
        | ResponseItem::CompactionTrigger { .. }
        | ResponseItem::Other => None,
    }
}

fn append_synthetic_responses_user_turn(input: &mut Vec<ResponseItem>) {
    input.push(ResponseItem::Message {
        encrypted_content: None,
        status: None,
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::InputText {
            text: "Continue.".to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    });
}

fn responses_input_includes_user_message(items: &[ResponseItem]) -> bool {
    items
        .iter()
        .any(|item| matches!(item, ResponseItem::Message { role, .. } if role == "user"))
}

fn apply_http_server_state_continuation(
    request: &mut ResponsesApiRequest,
    response_id: String,
    mut incremental_items: Vec<ResponseItem>,
    append_user_turn: bool,
) {
    if append_user_turn {
        append_synthetic_responses_user_turn(&mut incremental_items);
    }
    if !responses_input_includes_user_message(&incremental_items) {
        debug!(
            "skipping server-state incremental continuation without a user message; sending full-context responses request"
        );
        return;
    }
    request.previous_response_id = Some(response_id);
    request.input = incremental_items;
}

#[cfg(test)]
fn ensure_responses_input_ends_with_user_turn(input: &mut Vec<ResponseItem>) {
    if responses_input_needs_synthetic_user_turn(input) {
        append_synthetic_responses_user_turn(input);
    }
}

fn is_model_output_item(item: &ResponseItem) -> bool {
    match item {
        ResponseItem::Message { role, .. } => role == "assistant",
        ResponseItem::AgentMessage { .. }
        | ResponseItem::Reasoning { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::FunctionCall { .. }
        | ResponseItem::ToolSearchCall { .. }
        | ResponseItem::CustomToolCall { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::ImageGenerationCall { .. }
        | ResponseItem::Compaction { .. }
        | ResponseItem::ContextCompaction { .. } => true,
        ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::ToolSearchOutput { .. }
        | ResponseItem::CustomToolCallOutput { .. }
        | ResponseItem::AdditionalTools { .. }
        | ResponseItem::ConfigurationUpdate { .. }
        | ResponseItem::CompactionTrigger { .. }
        | ResponseItem::Other => false,
    }
}

fn maybe_dump_responses_request(request: &ResponsesApiRequest) {
    let Ok(path) = std::env::var("CORBANU_DUMP_RESPONSES_REQUEST") else {
        return;
    };
    let Ok(payload) = serde_json::to_vec_pretty(request) else {
        return;
    };
    let _ = std::fs::write(path, payload);
}

fn maybe_dump_chat_request(request: &ChatCompletionsRequest) {
    let Ok(path) = std::env::var("CORBANU_DUMP_CHAT_REQUEST") else {
        return;
    };
    let Ok(payload) = serde_json::to_vec_pretty(request) else {
        return;
    };
    let _ = std::fs::write(path, payload);
}

fn maybe_dump_anthropic_messages_request(request: &AnthropicMessagesRequest) {
    let Ok(path) = std::env::var("CORBANU_DUMP_ANTHROPIC_REQUEST") else {
        return;
    };
    let Ok(payload) = serde_json::to_vec_pretty(request) else {
        return;
    };
    let _ = std::fs::write(path, payload);
}

fn trace_stream_timing_enabled() -> bool {
    std::env::var_os("CORBANU_TRACE_STREAM_TIMING").is_some()
}

fn trace_stream_timing(label: &str, start: Instant) {
    if trace_stream_timing_enabled() {
        debug!(
            target: "corbanu_stream",
            label,
            elapsed_ms = start.elapsed().as_millis(),
            "corbanu stream timing"
        );
    }
}

fn response_event_name(event: &ResponseEvent) -> &'static str {
    match event {
        ResponseEvent::Created { .. } => "created",
        ResponseEvent::GuardianAssessment(_) => "guardian_assessment",
        ResponseEvent::OutputItemDone(_) => "output_item_done",
        ResponseEvent::OutputItemAdded(_) => "output_item_added",
        ResponseEvent::ServerModel(_) => "server_model",
        ResponseEvent::ModelVerifications(_) => "model_verifications",
        ResponseEvent::TurnModerationMetadata(_) => "turn_moderation_metadata",
        ResponseEvent::ServerReasoningIncluded(_) => "server_reasoning_included",
        ResponseEvent::Completed { .. } => "completed",
        ResponseEvent::OutputTextDelta { .. } => "output_text_delta",
        ResponseEvent::ToolCallInputDelta { .. } => "tool_call_input_delta",
        ResponseEvent::ReasoningSummaryDelta { .. } => "reasoning_summary_delta",
        ResponseEvent::ReasoningContentDelta { .. } => "reasoning_content_delta",
        ResponseEvent::ReasoningSummaryPartAdded { .. } => "reasoning_summary_part_added",
        ResponseEvent::ReasoningSummaryDone { .. } => "reasoning_summary_done",
        ResponseEvent::SafetyBuffering(_) => "safety_buffering",
        ResponseEvent::RateLimits(_) => "rate_limits",
        ResponseEvent::ModelsEtag(_) => "models_etag",
    }
}

impl WebsocketSession {
    fn reset(&mut self, reason: Option<&'static str>) {
        // Per-socket backend metrics call a resend after reconnect "initial".
        // Retain the loss reason across reconnects/turns until the next send.
        let continuation_reset_reason = self
            .continuation_reset_reason
            .or_else(|| self.last_request.as_ref().and(reason));
        *self = Self {
            auth_owner_generation: self.auth_owner_generation,
            continuation_reset_reason,
            ..Default::default()
        };
    }

    fn set_connection_reused(&self, connection_reused: bool) {
        *self
            .connection_reused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = connection_reused;
    }

    fn connection_reused(&self) -> bool {
        *self
            .connection_reused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

enum WebsocketStreamOutcome {
    Stream(ResponseStream),
    FallbackToHttp,
}

/// Result of opening a WebRTC Realtime call.
///
/// The SDP answer goes back to the client. The call id and auth headers stay on the server so the
/// ordinary Realtime WebSocket machinery can join the same in-progress call as a sideband
/// controller.
pub(crate) struct RealtimeWebrtcCallStart {
    pub(crate) sdp: String,
    pub(crate) call_id: String,
    pub(crate) sideband_headers: ApiHeaderMap,
    pub(crate) record: Option<crate::accounting::realtime::RealtimeSessionRecord>,
}

/// Reuses the API-auth material that created the WebRTC call for the sideband WebSocket join.
///
/// API-key sessions send that API bearer. ChatGPT-auth sessions send their bearer plus account id;
/// transceiver is responsible for accepting that same call-create identity on the direct
/// `api.openai.com` sideband path.
fn sideband_websocket_auth_headers(
    api_auth: &dyn AuthProvider,
) -> std::result::Result<ApiHeaderMap, ApiError> {
    let mut headers = ApiHeaderMap::new();
    api_auth.add_auth_headers(&mut headers)?;
    Ok(headers)
}

impl ModelClient {
    #[allow(clippy::too_many_arguments)]
    /// Creates a new session-scoped `ModelClient`.
    ///
    /// All arguments are expected to be stable for the lifetime of a Codex session. Per-turn values
    /// are passed to [`ModelClientSession::stream`] (and other turn-scoped methods) explicitly. The
    /// HTTP client factory must come from the effective session configuration so every transport
    /// observes the resolved outbound proxy policy.
    pub fn new(
        auth_manager: Option<Arc<AuthManager>>,
        agent_identity_policy: AgentIdentityAuthPolicy,
        thread_id: ThreadId,
        provider_info: ModelProviderInfo,
        session_source: SessionSource,
        originator: String,
        model_verbosity: Option<VerbosityConfig>,
        content_item_kinds_enabled: bool,
        reasoning_effort_override_enabled: bool,
        enable_request_compression: bool,
        include_timing_metrics: bool,
        beta_features_header: Option<String>,
        concurrent_reasoning_summaries_enabled: bool,
        output_token_replay_enabled: bool,
        attestation_provider: Option<Arc<dyn AttestationProvider>>,
        http_client_factory: HttpClientFactory,
        workspace_routing: WorkspaceRoutingContext,
        request_contributors: Vec<Arc<dyn codex_extension_api::ModelRequestContributor>>,
    ) -> Self {
        let model_provider = create_model_provider(provider_info, auth_manager);
        let codex_api_key_env_enabled = model_provider
            .auth_manager()
            .as_ref()
            .is_some_and(|manager| manager.codex_api_key_env_enabled());
        let auth_env_telemetry =
            collect_auth_env_telemetry(model_provider.info(), codex_api_key_env_enabled);
        let include_attestation = model_provider.supports_attestation();
        // Fixed-effort workers use request-level effort even when managed requirements
        // pin the feature on. Share this decision with update injection and pinning.
        let memory_consolidation = matches!(
            &session_source,
            SessionSource::Internal(InternalSessionSource::MemoryConsolidation)
                | SessionSource::SubAgent(SubAgentSource::MemoryConsolidation)
        );
        let reasoning_effort_override_enabled = reasoning_effort_override_enabled
            && !crate::guardian::is_basic_session_source(&session_source)
            && !memory_consolidation;
        Self {
            state: Arc::new(ModelClientState {
                thread_id,
                provider: model_provider,
                workspace_routing,
                auth_env_telemetry,
                session_source,
                originator,
                model_verbosity,
                content_item_kinds_enabled,
                reasoning_effort_override_enabled,
                enable_request_compression,
                include_timing_metrics,
                beta_features_header,
                concurrent_reasoning_summaries_enabled,
                output_token_replay_enabled,
                include_attestation,
                attestation_provider,
                disable_websockets: AtomicBool::new(false),
                agent_identity_session_fallback: AgentIdentitySessionFallback::default(),
                cached_websocket_session: StdMutex::new(WebsocketSession::default()),
                server_conversation_state: Arc::new(StdMutex::new(None)),
                http_server_state_rejected: AtomicBool::new(false),
                vercel_vendor_pin_rejected: AtomicBool::new(false),
                legacy_synthetic_continuation: AtomicBool::new(false),
                unresolvable_item_ids: StdMutex::new(HashSet::new()),
                last_inference_tools: StdMutex::new(None),
            }),
            agent_identity_policy,
            prompt_cache_key_policy: PromptCacheKey::default(),
            session_id_override: None,
            codex_responses_headers: None,
            event_sender: None,
            http_client_factory,
            ingress_level: codex_security_policy::SecurityLevel::Permissive,
            ingress_policy: None,
            stage_one_memory_binding: Arc::new(OnceLock::new()),
            ingress_items: Arc::new(StdMutex::new(
                crate::security::ingress::NativeIngress::default(),
            )),
            runtime_auth: None,
            restored_history: false,
            request_contributors,
            executed_tool_calls: None,
            api_key_cyber_access_programs:
                cyber_access_program::ApiKeyCyberAccessPrograms::UnsupportedProvider,
        }
    }

    /// Install a denial binding once for this client and every existing/future clone.
    pub(crate) fn with_stage_one_memory_binding(
        &self,
        binding: Arc<crate::memory_stage_one::StageOneMemoryBinding>,
    ) -> std::result::Result<(), crate::memory_stage_one::StageOneMemoryDenial> {
        self.stage_one_memory_binding
            .set(binding)
            .map_err(|_| crate::memory_stage_one::StageOneMemoryDenial::PolicyUnavailable)
    }

    #[cfg(test)]
    pub(crate) fn with_ingress_level(
        mut self,
        level: codex_security_policy::SecurityLevel,
    ) -> Self {
        self.ingress_level = level;
        self
    }

    pub(crate) fn with_ingress_policy(
        mut self,
        level: codex_security_policy::SecurityLevel,
        policy: crate::security::EffectivePolicyView,
    ) -> Self {
        self.ingress_level = level;
        self.ingress_policy = Some(crate::security::ingress::BoundIngressPolicy(policy));
        self
    }

    /// Provider transport replacement is not a new conversation. Preserve the
    /// host-held bindings only within the same thread, never across sessions
    /// belonging to a different thread identity.
    pub(crate) fn with_native_ingress_from(mut self, previous: &Self) -> Self {
        if self.state.thread_id == previous.state.thread_id {
            self.ingress_items = Arc::clone(&previous.ingress_items);
        }
        self
    }

    fn source_admission_level(&self) -> Result<codex_security_policy::SecurityLevel> {
        let mut level = self.ingress_level;
        if let Some(policy) = &self.ingress_policy {
            let snapshot = policy
                .0
                .snapshot_for_agent(self.state.thread_id)
                .map_err(|_| {
                    CodexErr::InvalidRequest("source admission policy is unavailable".into())
                })?;
            level = level.max(snapshot.level);
        }
        Ok(level)
    }

    /// Issue #443: whether Aggressive is in force for this session now: in
    /// its config, or in the live policy (also right after a person confirms
    /// Aggressive in `/security`, before a restart). A bound policy that
    /// cannot be read counts as Aggressive, as for source admission.
    pub(crate) fn live_level_is_aggressive(&self) -> bool {
        self.live_level() == codex_security_policy::SecurityLevel::Aggressive
    }

    /// The level in force for this session now: its config, or the live
    /// policy (also right after a person confirms a level in `/security`).
    /// A bound policy that cannot be read counts as Aggressive. Unlike the
    /// post-taint state, this does not depend on `source_envelopes`.
    pub(crate) fn live_level(&self) -> codex_security_policy::SecurityLevel {
        live_level_of(
            self.ingress_level,
            self.ingress_policy.as_ref().map(|policy| &policy.0),
            self.state.thread_id,
        )
    }

    /// Issue #445: whether the security kill switch a person turned on in
    /// `/security` is on for this session. Only that switch: a session
    /// started from unreadable state or a cold-resumed child agent is denied
    /// protected actions too. A detached child also receives a parent-task refusal.
    pub(crate) fn kill_switch_on(&self) -> bool {
        self.ingress_policy.as_ref().is_some_and(|policy| {
            policy
                .0
                .snapshot_for_agent(self.state.thread_id)
                .is_ok_and(|snapshot| snapshot.authority_kill_switch_active)
        })
    }

    /// Issue #445: with the kill switch on, no model request is sent (a
    /// turn, compaction, memory summary or realtime call); a turn is also
    /// refused before its input is recorded (`session::turn`). A policy that
    /// cannot be read is refused by the source admission check instead.
    pub(crate) fn refuse_under_kill_switch(&self) -> Result<()> {
        if self
            .ingress_policy
            .as_ref()
            .is_some_and(|policy| policy.0.parent_unavailable(self.state.thread_id))
        {
            return Err(CodexErr::InvalidRequest(
                "Not sent: this sub-agent is locked down because its parent task is not open. Open the parent task, then reopen this sub-agent before trying again. This message was not kept.".to_string(),
            ));
        }
        if self.kill_switch_on() {
            Err(CodexErr::InvalidRequest(KILL_SWITCH_REFUSAL.to_string()))
        } else {
            Ok(())
        }
    }

    pub(crate) fn check_source_admission(&self, prompt: &Prompt) -> Result<()> {
        self.refuse_under_kill_switch()?;
        crate::security::ingress::check_native_request(
            self.source_admission_level()?,
            &prompt.input,
        )
        .map_err(|error| CodexErr::InvalidRequest(error.to_string()))
    }

    fn source_admitted_input(
        &self,
        prompt: &Prompt,
        model_info: &ModelInfo,
    ) -> Result<Vec<ResponseItem>> {
        self.refuse_under_kill_switch()?;
        if self.source_admission_level()? == codex_security_policy::SecurityLevel::Permissive {
            return Ok(prompt.get_formatted_input_for_request(model_info));
        }
        let mut ingress = self.ingress_items.lock().map_err(|_| {
            CodexErr::InvalidRequest("source admission registry is unavailable".into())
        })?;
        if ingress.labelled_mode() {
            // Look up host registrations on recorded bytes, then format.
            let mut input = ingress.project_labelled(&prompt.input);
            crate::client_common::normalize_image_details(&mut input, model_info);
            return Ok(input);
        }
        // Without `source_envelopes` no producer admits external context, so
        // protected requests fail closed here. Missing admissions (including the
        // registry's size bound) mean the flag is off; keep any other cause.
        use crate::security::ingress::IngressError;
        ingress.project(&prompt.input).map_err(|error| {
            let off = IngressError::SourceEnvelopesOff;
            CodexErr::InvalidRequest(match error {
                IngressError::NativeAdmissionUnavailable
                | IngressError::RegistryUnavailable
                | IngressError::TooLarge => off.to_string(),
                other => format!("{off} ({other})"),
            })
        })
    }

    /// `source_envelopes`: send external context as labelled untrusted data
    /// under Moderate/Aggressive. Permissive requests are unchanged.
    pub(crate) fn with_source_envelopes(self, enabled: bool) -> Self {
        if let Ok(mut ingress) = self.ingress_items.lock() {
            ingress.set_labelled_mode(enabled);
        }
        // PF-41-S01: the inspector reads this thread's taint from here.
        crate::security::inspection::register_ingress(self.state.thread_id, &self.ingress_items);
        self
    }

    /// `source_envelopes`: load the key that authenticates origin records
    /// for `codex_home`. Without it no records are written or restored, so
    /// content resumes labelled. Replacement clients share the loaded key.
    pub(crate) fn with_source_origin_key(self, codex_home: &std::path::Path) -> Self {
        if let Ok(mut ingress) = self.ingress_items.lock()
            && ingress.labelled_mode()
            && !ingress.has_origin_key()
        {
            match crate::security::ingress::OriginKey::load_or_create(codex_home) {
                Ok(key) => ingress.set_origin_key(key),
                Err(error) => tracing::warn!(
                    "source origin key unavailable ({}); content resumes as labelled data",
                    error.kind()
                ),
            }
        }
        self
    }

    /// Restored/forked history keeps the standing its rollout origin records
    /// give it; unrecorded content stays labelled and, when restored messages
    /// lack records, fresh host context is reinjected on the next turn.
    pub(crate) fn note_restored_history<'a>(
        &self,
        items: &[ResponseItem],
        records: impl IntoIterator<Item = &'a codex_protocol::provenance::SourceOriginRecord>,
    ) {
        if let Ok(mut ingress) = self.ingress_items.lock() {
            ingress.note_restored_history(items, records);
        }
    }

    /// Restate the current origins of `items` for a history checkpoint.
    pub(crate) fn journal_current_origins(&self, items: &[ResponseItem]) {
        if let Ok(mut ingress) = self.ingress_items.lock() {
            ingress.journal_current(items);
        }
    }

    /// New origin registrations to persist right after the items they describe.
    pub(crate) fn take_source_origin_record(
        &self,
    ) -> Option<codex_protocol::provenance::SourceOriginRecord> {
        self.ingress_items
            .lock()
            .ok()
            .and_then(|mut ingress| ingress.take_origin_record())
    }

    pub(crate) fn source_envelopes_enabled(&self) -> bool {
        self.ingress_items
            .lock()
            .is_ok_and(|ingress| ingress.labelled_mode())
    }

    /// Host-recorded origin of an exact history message (labelled mode only).
    pub(crate) fn message_origin(
        &self,
        item: &ResponseItem,
    ) -> Option<crate::security::ingress::MessageOrigin> {
        self.ingress_items
            .lock()
            .ok()
            .filter(|ingress| ingress.labelled_mode())
            .and_then(|ingress| ingress.message_origin(item))
    }

    /// See `NativeIngress::all_have_standing`; false when the flag is off.
    pub(crate) fn all_have_standing(&self, items: &[ResponseItem]) -> bool {
        self.ingress_items
            .lock()
            .is_ok_and(|ingress| ingress.labelled_mode() && ingress.all_have_standing(items))
    }

    /// PF-30-S03: note a batch just recorded into history (see
    /// `NativeIngress::note_recorded`).
    pub(crate) fn note_recorded_for_taint(&self, items: &[ResponseItem]) {
        if let Ok(mut ingress) = self.ingress_items.lock() {
            ingress.note_recorded(items);
        }
    }

    /// D624 (a): whether content without standing has reached this session, at any level. A
    /// poisoned ingress lock counts as seen (fail closed).
    pub(crate) fn untrusted_content_seen(&self) -> bool {
        match self.ingress_items.lock() {
            Ok(ingress) => ingress.taint_generation() > 0,
            Err(_) => true,
        }
    }

    /// PF-23-S01: see `NativeIngress::note_unrecorded_input`.
    pub(crate) fn note_unrecorded_input_for_taint(&self) {
        if let Ok(mut ingress) = self.ingress_items.lock() {
            ingress.note_unrecorded_input();
        }
    }

    /// PF-30-S03: the session's taint generation and effective policy when
    /// post-taint checks apply (`source_envelopes` on and a protected level in
    /// force), else `None`. An unavailable policy counts as protected; a
    /// poisoned registry as tainted.
    pub(crate) fn post_taint_state(
        &self,
    ) -> Option<crate::security::tainted_action::PostTaintState> {
        use crate::security::tainted_action::PolicyBinding;
        let protected = self.source_admission_level().map_or(true, |level| {
            level != codex_security_policy::SecurityLevel::Permissive
        });
        let taint_generation = match self.ingress_items.lock() {
            Ok(ingress) => {
                (ingress.labelled_mode() && protected).then(|| ingress.taint_generation())
            }
            // A poisoned registry still says whether the flag is on; with it on,
            // count the session as tainted (fail closed). Flag off stays off.
            Err(poisoned) => {
                (poisoned.into_inner().labelled_mode() && protected).then_some(u64::MAX)
            }
        }?;
        let policy = match &self.ingress_policy {
            None => PolicyBinding::Unbound,
            Some(policy) => match policy.0.snapshot_for_agent(self.state.thread_id) {
                Ok(snapshot) => PolicyBinding::Bound {
                    epoch: snapshot.epoch,
                    revocation_generation: snapshot.revocation_generation,
                    kill_switch_active: snapshot.kill_switch_active,
                    level: snapshot.level,
                    actor_chain: snapshot.actor_chain,
                },
                Err(_) => PolicyBinding::Unavailable,
            },
        };
        let level = self
            .source_admission_level()
            .unwrap_or(codex_security_policy::SecurityLevel::Aggressive);
        Some(crate::security::tainted_action::PostTaintState {
            taint_generation,
            policy,
            level,
        })
    }

    /// Mark `input` as submitted to this session by another agent (see
    /// `NativeIngress::mark_agent_input`). Keyed on the exact input, before
    /// any media preparation, so the prompt seam sees the same key.
    pub(crate) fn mark_agent_input(
        &self,
        input: &[codex_protocol::user_input::UserInput],
        origin: crate::security::ingress::MessageOrigin,
    ) {
        if !self.source_envelopes_enabled() {
            return;
        }
        if let Ok(bytes) = serde_json::to_vec(input)
            && let Ok(mut ingress) = self.ingress_items.lock()
        {
            ingress.mark_agent_input(codex_content_security::ContentDigest::of(&bytes), origin);
        }
    }

    /// A prompt that will never be recorded (blocked by a hook) drops one mark.
    pub(crate) fn discard_agent_input(&self, input: &[codex_protocol::user_input::UserInput]) {
        if !self.source_envelopes_enabled() {
            return;
        }
        if let Ok(bytes) = serde_json::to_vec(input)
            && let Ok(mut ingress) = self.ingress_items.lock()
        {
            ingress.discard_agent_input(&codex_content_security::ContentDigest::of(&bytes));
        }
    }

    /// The origin to record for a prompt: another agent's mark, if any.
    pub(crate) fn take_agent_input_origin(
        &self,
        input: &[codex_protocol::user_input::UserInput],
    ) -> Option<crate::security::ingress::MessageOrigin> {
        if !self.source_envelopes_enabled() {
            return None;
        }
        let bytes = serde_json::to_vec(input).ok()?;
        self.ingress_items
            .lock()
            .ok()?
            .take_agent_input(&codex_content_security::ContentDigest::of(&bytes))
    }

    /// Standing of text this session's model hands to another agent (a
    /// spawn task or `send_input`): host only while every item in `history`
    /// had standing, otherwise agent data. Mirrors the compaction-summary rule,
    /// so one tool output, memory or unattributed input taints the handoff.
    pub(crate) fn agent_handoff_origin(
        &self,
        history: &[ResponseItem],
    ) -> crate::security::ingress::MessageOrigin {
        use crate::security::ingress::MessageOrigin;
        if self.all_have_standing(history) {
            MessageOrigin::Host
        } else {
            MessageOrigin::External(codex_protocol::provenance::SourceKind::ChildAgent)
        }
    }

    /// Consumed only while protected: Permissive history stays unchanged and
    /// a later live strengthening still gets fresh host context.
    pub(crate) fn take_host_context_reinjection(&self) -> bool {
        if self
            .source_admission_level()
            .is_ok_and(|level| level == codex_security_policy::SecurityLevel::Permissive)
        {
            return false;
        }
        self.ingress_items
            .lock()
            .is_ok_and(|mut ingress| ingress.take_host_context_reinjection())
    }

    /// Record the host-chosen origin of exact history messages. Only Core
    /// record seams call this; text and role labels cannot choose an origin.
    pub(crate) fn register_message_origin(
        &self,
        items: &[ResponseItem],
        origin: crate::security::ingress::MessageOrigin,
    ) {
        if let Ok(mut ingress) = self.ingress_items.lock()
            && ingress.labelled_mode()
        {
            ingress.register_messages(items, origin);
        }
    }

    pub(crate) fn observe_native_ingress(&self, items: &[ResponseItem]) {
        if self
            .source_admission_level()
            .is_ok_and(|level| level == codex_security_policy::SecurityLevel::Permissive)
        {
            return;
        }
        if let Ok(mut ingress) = self.ingress_items.lock()
            && !ingress.labelled_mode()
        {
            let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or_default();
            ingress.observe(items, now);
        }
    }

    /// Staged producer handoff: reading a candidate does not release its data.
    #[allow(dead_code)]
    pub(crate) fn pending_native_screening(
        &self,
        item: &ResponseItem,
    ) -> Result<crate::security::ingress::NativeScreeningCandidate> {
        self.ingress_items
            .lock()
            .map_err(|_| {
                CodexErr::InvalidRequest("source admission registry is unavailable".into())
            })?
            .screening_candidate(item)
            .map_err(|error| CodexErr::InvalidRequest(error.to_string()))
    }

    /// A complete screening result must match this exact host-observed item.
    #[allow(dead_code)]
    pub(crate) fn admit_native_screening(
        &self,
        item: &ResponseItem,
        screened: codex_content_security::ScreenedContent,
    ) -> Result<()> {
        self.ingress_items
            .lock()
            .map_err(|_| {
                CodexErr::InvalidRequest("source admission registry is unavailable".into())
            })?
            .admit_screened(item, screened)
            .map_err(|error| CodexErr::InvalidRequest(error.to_string()))
    }

    pub(crate) fn register_native_tool_origin(
        &self,
        call_id: &str,
        kind: codex_protocol::provenance::SourceKind,
    ) {
        let permissive = self
            .source_admission_level()
            .is_ok_and(|level| level == codex_security_policy::SecurityLevel::Permissive);
        // Labelled mode records origins even while Permissive so a later live
        // strengthening still labels earlier tool output with its real route.
        if let Ok(mut ingress) = self.ingress_items.lock()
            && (!permissive || ingress.labelled_mode())
        {
            ingress.register_call(call_id, kind);
        }
    }

    pub(crate) fn with_executed_tool_calls(mut self, recorder: ExecutedToolCalls) -> Self {
        self.executed_tool_calls = Some(recorder);
        self
    }

    pub(crate) fn reasoning_effort_override_enabled(&self, model_info: &ModelInfo) -> bool {
        self.state.reasoning_effort_override_enabled
            && self.state.provider.info().is_openai()
            && model_info.supports_reasoning_effort_updates
    }

    pub(crate) fn with_restored_history(mut self, restored_history: bool) -> Self {
        self.restored_history = restored_history;
        self
    }

    /// Use the harness-owned runtime for this first-party provider. The owner must share this
    /// client's credential manager. Provider-specific overrides need their own runtime owner.
    pub fn with_runtime_auth(
        mut self,
        manager: Arc<RuntimeAuthManager>,
        mode: RuntimeAuthMode,
    ) -> Result<Self> {
        let info = self.state.provider.info();
        codex_model_provider::validate_runtime_destination(info.base_url.as_deref())?;
        codex_model_provider::validate_runtime_provider(
            info,
            self.auth_manager().as_ref(),
            &manager,
        )?;
        self.runtime_auth = Some((manager, mode));
        Ok(self)
    }

    pub(crate) fn with_session_context(
        mut self,
        prompt_cache_key: PromptCacheKey,
        session_id_override: Option<String>,
        event_sender: Sender<ProtocolEvent>,
        codex_responses_headers: Option<Arc<CodexResponsesHeaders>>,
        api_key_cyber_access_programs: cyber_access_program::ApiKeyCyberAccessPrograms,
    ) -> Self {
        self.prompt_cache_key_policy = prompt_cache_key;
        self.session_id_override = session_id_override;
        self.event_sender = Some(event_sender);
        self.codex_responses_headers = codex_responses_headers;
        self.api_key_cyber_access_programs = api_key_cyber_access_programs;
        self
    }

    pub(crate) fn prompt_cache_key_policy(&self) -> PromptCacheKey {
        self.prompt_cache_key_policy.clone()
    }

    /// The caller's policy controls the request body independently of the session-id header.
    fn prompt_cache_key(&self, metadata: &CodexResponsesMetadata) -> Option<String> {
        match &self.prompt_cache_key_policy {
            PromptCacheKey::SessionDerived => Some(self.session_derived_cache_key(metadata)),
            PromptCacheKey::Custom(key) => Some(key.clone()),
            PromptCacheKey::Omit => None,
        }
    }

    fn session_derived_cache_key(&self, metadata: &CodexResponsesMetadata) -> String {
        if let Some(session_id) = &self.session_id_override {
            return session_id.clone();
        }

        if let SessionSource::Internal(source) = &self.state.session_source
            && let Some(parent_thread_id) = metadata.parent_thread_id
        {
            return format!("{source}:{parent_thread_id}");
        }

        metadata.session_id.clone()
    }

    // ChatGPT derives cache affinity from the Responses session-id header. Keep the
    // actual session identity in turn metadata, hooks, and history/notes requests.
    fn responses_session_id(&self, metadata: &CodexResponsesMetadata) -> String {
        if self.state.session_source.is_non_root_agent() {
            metadata.session_id.clone()
        } else {
            self.session_derived_cache_key(metadata)
        }
    }

    pub(crate) fn seed_server_response_id(&self, response_id: String) {
        if response_id.is_empty() {
            return;
        }
        let mut state = self
            .state
            .server_conversation_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = Some(ServerConversationState {
            last_request: None,
            last_response: LastResponse {
                response_id,
                items_added: Vec::new(),
            },
        });
    }

    fn server_conversation_state(&self) -> Option<ServerConversationState> {
        self.state
            .server_conversation_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn server_conversation_state_handle(&self) -> SharedServerConversationState {
        Arc::clone(&self.state.server_conversation_state)
    }

    /// Creates a fresh turn-scoped streaming session.
    ///
    /// This constructor does not perform network I/O itself; the session opens a websocket lazily
    /// when the first stream request is issued.
    pub fn new_session(&self) -> ModelClientSession {
        let auth_owner_generation = self.auth_owner_generation();
        let mut websocket_session = self.take_cached_websocket_session();
        if websocket_session.auth_owner_generation != auth_owner_generation {
            // Drop the old owner's cache before this turn can establish fresh routing state.
            websocket_session.reset(Some("auth_changed"));
            websocket_session.auth_owner_generation = auth_owner_generation;
        }
        ModelClientSession {
            accounting: Default::default(),
            responses_accounting: Default::default(),
            chat_accounting: Default::default(),
            client: self.clone(),
            websocket_session,
            turn_state: Arc::new(OnceLock::new()),
        }
    }

    /// Creates a turn-scoped client for the provider committed in the current
    /// thread settings.
    ///
    /// A thread may switch providers after startup. Reusing the session-scoped
    /// client's original transport would keep sending the newly selected model
    /// to the old base URL. Same-provider turns retain the cached WebSocket;
    /// cross-provider turns receive isolated transport and fallback state.
    pub(crate) fn new_session_for_provider(
        &self,
        provider_info: &ModelProviderInfo,
    ) -> ModelClientSession {
        self.for_provider(provider_info).new_session()
    }

    /// Returns a client whose transport and authentication are bound to the
    /// supplied provider. Same-provider calls retain the session cache.
    pub(crate) fn for_provider(&self, provider_info: &ModelProviderInfo) -> Self {
        if self.state.provider.info() == provider_info {
            return self.clone();
        }
        let provider =
            create_model_provider(provider_info.clone(), self.state.provider.auth_manager());
        self.with_provider(provider, /*config*/ None)
    }

    /// PF-84: the client after a provider switch. Everything session-scoped stays (session
    /// context and prompt cache key, event sender, executed tool calls, request contributors,
    /// attestation, native ingress, and runtime auth where its checks pass for the new
    /// provider); the provider and its request settings come from `config`.
    pub(crate) fn for_provider_switch(
        &self,
        provider: SharedModelProvider,
        config: &Config,
    ) -> Self {
        self.with_provider(provider, Some(config))
    }

    /// A client on `provider` with isolated transport and fallback state. Request settings
    /// come from `config` when given, else from this client.
    fn with_provider(&self, provider: SharedModelProvider, config: Option<&Config>) -> Self {
        // Upstream's runtime authentication is validated for one first-party provider and its
        // credential owner; it carries over only where the same checks pass for `provider`.
        let runtime_auth = self.runtime_auth.clone().filter(|(manager, _)| {
            codex_model_provider::validate_runtime_destination(provider.info().base_url.as_deref())
                .is_ok()
                && codex_model_provider::validate_runtime_provider(
                    provider.info(),
                    provider.auth_manager().as_ref(),
                    manager,
                )
                .is_ok()
        });
        let codex_api_key_env_enabled = provider
            .auth_manager()
            .as_ref()
            .is_some_and(|manager| manager.codex_api_key_env_enabled());
        let auth_env_telemetry =
            collect_auth_env_telemetry(provider.info(), codex_api_key_env_enabled);
        let include_attestation = provider.supports_attestation();
        let state = &self.state;
        let feature = |feature: Feature, current: bool| {
            config.map_or(current, |config| config.features.enabled(feature))
        };
        Self {
            state: Arc::new(ModelClientState {
                thread_id: state.thread_id,
                provider,
                workspace_routing: state.workspace_routing.clone(),
                auth_env_telemetry,
                session_source: state.session_source.clone(),
                originator: state.originator.clone(),
                model_verbosity: config
                    .map_or(state.model_verbosity, |config| config.model_verbosity),
                content_item_kinds_enabled: feature(
                    Feature::ContentItemKinds,
                    state.content_item_kinds_enabled,
                ),
                reasoning_effort_override_enabled: state.reasoning_effort_override_enabled,
                enable_request_compression: feature(
                    Feature::EnableRequestCompression,
                    state.enable_request_compression,
                ),
                include_timing_metrics: feature(
                    Feature::RuntimeMetrics,
                    state.include_timing_metrics,
                ),
                beta_features_header: state.beta_features_header.clone(),
                concurrent_reasoning_summaries_enabled: feature(
                    Feature::ConcurrentReasoningSummaries,
                    state.concurrent_reasoning_summaries_enabled,
                ),
                output_token_replay_enabled: feature(
                    Feature::OutputTokenReplay,
                    state.output_token_replay_enabled,
                ),
                include_attestation,
                attestation_provider: state.attestation_provider.clone(),
                disable_websockets: AtomicBool::new(false),
                agent_identity_session_fallback: state.agent_identity_session_fallback.clone(),
                cached_websocket_session: StdMutex::new(WebsocketSession::default()),
                server_conversation_state: Arc::new(StdMutex::new(None)),
                http_server_state_rejected: AtomicBool::new(false),
                vercel_vendor_pin_rejected: AtomicBool::new(false),
                legacy_synthetic_continuation: AtomicBool::new(false),
                unresolvable_item_ids: StdMutex::new(HashSet::new()),
                last_inference_tools: StdMutex::new(None),
            }),
            agent_identity_policy: self.agent_identity_policy,
            prompt_cache_key_policy: self.prompt_cache_key_policy.clone(),
            session_id_override: self.session_id_override.clone(),
            codex_responses_headers: self.codex_responses_headers.clone(),
            event_sender: self.event_sender.clone(),
            http_client_factory: config.map_or_else(
                || self.http_client_factory.clone(),
                Config::http_client_factory,
            ),
            ingress_level: self.ingress_level,
            ingress_policy: self.ingress_policy.clone(),
            stage_one_memory_binding: self.stage_one_memory_binding.clone(),
            ingress_items: Arc::clone(&self.ingress_items),
            restored_history: self.restored_history,
            request_contributors: self.request_contributors.clone(),
            executed_tool_calls: self.executed_tool_calls.clone(),
            api_key_cyber_access_programs: config.map_or(
                self.api_key_cyber_access_programs,
                cyber_access_program::ApiKeyCyberAccessPrograms::from_config,
            ),
            runtime_auth,
        }
    }

    pub(crate) fn session_matches_provider(
        session: &ModelClientSession,
        provider_info: &ModelProviderInfo,
    ) -> bool {
        session.client.state.provider.info() == provider_info
    }

    pub(crate) fn auth_manager(&self) -> Option<Arc<AuthManager>> {
        self.state.provider.auth_manager()
    }

    pub(crate) fn auth_owner_generation(&self) -> Option<u64> {
        self.auth_manager().map(|manager| {
            manager
                .auth_change_state_receiver()
                .borrow()
                .owner_generation
        })
    }

    pub(crate) fn provider_info(&self) -> &ModelProviderInfo {
        self.state.provider.info()
    }

    fn take_cached_websocket_session(&self) -> WebsocketSession {
        let mut cached_websocket_session = self
            .state
            .cached_websocket_session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *cached_websocket_session)
    }

    fn store_cached_websocket_session(&self, websocket_session: WebsocketSession) {
        *self
            .state
            .cached_websocket_session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = websocket_session;
    }

    pub(crate) fn force_http_fallback(
        &self,
        session_telemetry: &SessionTelemetry,
        _model_info: &ModelInfo,
    ) -> bool {
        let websocket_enabled = self.responses_websocket_enabled();
        let activated =
            websocket_enabled && !self.state.disable_websockets.swap(true, Ordering::Relaxed);
        if activated {
            warn!("falling back to HTTP");
            session_telemetry.counter(
                "codex.transport.fallback_to_http",
                /*inc*/ 1,
                &[("from_wire_api", "responses_websocket")],
            );
        }

        self.store_cached_websocket_session(WebsocketSession::default());
        activated
    }

    pub(crate) async fn create_realtime_call_with_headers(
        &self,
        sdp: String,
        session_config: ApiRealtimeSessionConfig,
        mut extra_headers: ApiHeaderMap,
        api_provider_override: Option<ApiProvider>,
        accounting: &crate::accounting::responses::Slot,
    ) -> Result<RealtimeWebrtcCallStart> {
        self.check_source_admission(&Prompt::default())?;
        // Create the media call over HTTP first, then retain matching auth so realtime can attach
        // the server-side control WebSocket to the call id from that HTTP response.
        let mut client_setup = self.realtime_client_setup().await?;
        if let Some(header_value) = self.generate_attestation_header_for().await {
            extra_headers.insert(X_OAI_ATTESTATION_HEADER, header_value);
        }
        let mut sideband_headers = extra_headers.clone();
        sideband_headers.extend(
            sideband_websocket_auth_headers(client_setup.api_auth.as_ref())
                .map_err(|error| self.state.provider.map_api_error(error))?,
        );
        if let Some(api_provider) = api_provider_override {
            client_setup.api_provider = api_provider;
        }
        // Creating the call is a model request the operator paid for, so it is
        // recorded. Its response carries no usage, and the call's sideband
        // reports are not recorded (#889 D223 covers WebSocket sessions), so
        // the attempt lands with its tokens unknown.
        //
        // The route is read from the API client rather than restated: call
        // creation picks its path from the session's parser and appends the
        // pairs that select its architecture, and a pin missing those would
        // refuse every call it was meant to record.
        let call_url = codex_api::realtime_call_url(&client_setup.api_provider, &session_config);
        let call_route =
            codex_api::realtime_call_route(&client_setup.api_provider, &session_config);
        let sampling = match crate::accounting::responses::read(accounting)? {
            Some(deferred) => {
                deferred
                    .resolve_path(
                        self.state.provider.info(),
                        client_setup.auth.as_ref().map(CodexAuth::auth_mode),
                        &call_url,
                        &call_route,
                    )
                    .await?
            }
            None => None,
        };
        let evidence = sampling.map(crate::accounting::transport::ResponseEvidence::new);
        let follow = if evidence.is_some() {
            Some(client_setup.redirect_fallback(&call_url)?)
        } else {
            None
        };
        let transport = if evidence.is_some() {
            let client = client_setup.api_client_without_redirects(&call_url)?;
            self.guarded_transport(ReqwestTransport::from_http_client(client))
        } else {
            self.guarded_transport(client_setup.build_api_transport(REALTIME_CALLS_ENDPOINT)?)
        };
        let transport = transport.map_inner(|inner| {
            crate::accounting::transport::AccountingTransport::new(
                inner,
                evidence.clone(),
                session_config.model.clone().unwrap_or_default(),
            )
            .with_redirect_fallback(follow)
        });
        let response =
            ApiRealtimeCallClient::new(transport, client_setup.api_provider, client_setup.api_auth)
                .create_with_session_and_headers(sdp, session_config, extra_headers)
                .await
                .map_err(|error| self.state.provider.map_api_error(error))?;
        Ok(RealtimeWebrtcCallStart {
            sdp: response.sdp,
            call_id: response.call_id,
            sideband_headers,
            record: evidence
                .as_deref()
                .and_then(crate::accounting::transport::ResponseEvidence::realtime_session_record),
        })
    }

    pub(crate) async fn realtime_sideband_headers(
        &self,
        mut extra_headers: ApiHeaderMap,
    ) -> Result<ApiHeaderMap> {
        // Issue #445: the sideband carries the session's credential; refused like the call.
        self.check_source_admission(&Prompt::default())?;
        let client_setup = self.realtime_client_setup().await?;
        if let Some(header_value) = self.generate_attestation_header_for().await {
            extra_headers.insert(X_OAI_ATTESTATION_HEADER, header_value);
        }
        extra_headers.extend(
            sideband_websocket_auth_headers(client_setup.api_auth.as_ref())
                .map_err(|error| self.state.provider.map_api_error(error))?,
        );
        Ok(extra_headers)
    }

    /// #824: record a realtime WebSocket session that has just opened under
    /// `base_url` as one request. The record states the route, model,
    /// provider and start time now, the tokens each finished response reports
    /// (#889 D223, `RealtimeSessionRecord::observe_response`), the end time
    /// when the session closes (`RealtimeSessionRecord::end`), and no price.
    /// `credential` is
    /// the API key the session sends. `None` leaves the session unrecorded; it
    /// is never refused.
    pub(crate) async fn begin_realtime_session_record(
        &self,
        base_url: &str,
        session_config: &ApiRealtimeSessionConfig,
        accounting: &crate::accounting::responses::Slot,
        credential: Option<&codex_login::CodexAuth>,
    ) -> Option<crate::accounting::realtime::RealtimeSessionRecord> {
        // Nothing collects this session: say nothing.
        let deferred = crate::accounting::responses::read(accounting)
            .ok()
            .flatten()?;
        let unrecorded = |cause: &dyn std::fmt::Display| {
            deferred.reject();
            crate::accounting::gap("realtime session route", cause);
        };
        let route = match codex_api::realtime_websocket_route(base_url, session_config) {
            Ok(route) => route,
            Err(error) => {
                unrecorded(&error);
                return None;
            }
        };
        let Some(path) = route.route else {
            unrecorded(&"the session URL is not under its base URL");
            return None;
        };
        // The provider's configured query parameters ride on the session URL
        // as on every other request; the pin adds them the same way.
        let provider = self.state.provider.info();
        let url = match crate::accounting::canonical_query(provider) {
            Some(query) if route.url.contains('?') => format!("{}&{query}", route.url),
            Some(query) => format!("{}?{query}", route.url),
            None => route.url,
        };
        let model = session_config.model.as_deref().unwrap_or_default();
        crate::accounting::realtime::RealtimeSessionRecord::begin(
            &deferred,
            provider,
            credential.map(CodexAuth::auth_mode),
            &url,
            &path,
            model,
        )
        .await
    }

    /// Leave a realtime WebSocket session that opened unrecorded, with the
    /// `cause` logged as a gap (#889). Nothing is said when nothing collects.
    pub(crate) fn leave_realtime_session_unrecorded(
        &self,
        accounting: &crate::accounting::responses::Slot,
        cause: &'static str,
    ) {
        if let Some(deferred) = crate::accounting::responses::read(accounting)
            .ok()
            .flatten()
        {
            deferred.reject();
            crate::accounting::gap("realtime session account", cause);
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    /// Builds memory summaries for each provided normalized raw memory.
    ///
    /// This is a unary call (no streaming) to `/v1/memories/trace_summarize`.
    ///
    /// The model selection, reasoning effort, and telemetry context are passed explicitly to keep
    /// `ModelClient` session-scoped.
    pub(crate) async fn summarize_memories(
        &self,
        raw_memories: Vec<ApiRawMemory>,
        model_info: &ModelInfo,
        effort: Option<ReasoningEffortConfig>,
        session_telemetry: &SessionTelemetry,
        accounting: &crate::accounting::responses::Slot,
    ) -> Result<Vec<ApiMemorySummarizeOutput>> {
        if raw_memories.is_empty() {
            return Ok(Vec::new());
        }
        // PF-28-S01: raw memories cannot be rebuilt after gating; refuse.
        if crate::security::disclosure_gate::would_disclose(
            codex_secret_broker::output_gate::OutputSink::ModelRequest,
            &raw_memories,
        ) {
            return Err(CodexErr::UnsupportedOperation(
                "memory summaries would send a managed secret to the model".to_string(),
            ));
        }

        self.check_source_admission(&Prompt::default())?;

        let client_setup = self
            .current_client_setup(ClientRouting::ConfiguredProvider)
            .await?;
        // Summarising memories names a model and a reasoning effort: it is
        // inference the operator paid for, answered with one JSON body rather
        // than a stream, so it is collected the way the legacy compaction
        // endpoint was. The slot is a parameter because this client is
        // session-scoped by design - which is also why this call could be
        // written with no way to record it at all.
        let summarize_url = client_setup
            .api_provider
            .url_for_path(MEMORIES_SUMMARIZE_ENDPOINT);
        let sampling = match crate::accounting::responses::read(accounting)? {
            Some(deferred) => {
                deferred
                    .resolve_path(
                        self.state.provider.info(),
                        client_setup.auth.as_ref().map(CodexAuth::auth_mode),
                        &summarize_url,
                        MEMORIES_SUMMARIZE_ENDPOINT.trim_start_matches('/'),
                    )
                    .await?
            }
            None => None,
        };
        let evidence = sampling.map(crate::accounting::transport::ResponseEvidence::new);
        // A collected request must not be able to follow a redirect, for the
        // same reason every other collected route may not.
        let follow = if evidence.is_some() {
            Some(client_setup.redirect_fallback(&summarize_url)?)
        } else {
            None
        };
        let transport = if evidence.is_some() {
            let client = client_setup.api_client_without_redirects(&summarize_url)?;
            self.guarded_transport(ReqwestTransport::from_http_client(client))
        } else {
            self.guarded_transport(client_setup.build_api_transport(MEMORIES_SUMMARIZE_ENDPOINT)?)
        };
        let transport = transport.map_inner(|inner| {
            crate::accounting::transport::AccountingTransport::new(
                inner,
                evidence.clone(),
                model_info.slug.clone(),
            )
            .with_redirect_fallback(follow)
        });
        let request_telemetry = Self::build_request_telemetry(
            session_telemetry,
            AuthRequestTelemetryContext::new(
                client_setup.auth.as_ref().map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                PendingUnauthorizedRetry::default(),
            )
            .map_err(|error| self.state.provider.map_api_error(error))?,
            RequestRouteTelemetry::for_endpoint(MEMORIES_SUMMARIZE_ENDPOINT),
            self.state.auth_env_telemetry.clone(),
        );
        let client =
            ApiMemoriesClient::new(transport, client_setup.api_provider, client_setup.api_auth)
                .with_telemetry(Some(request_telemetry));

        let payload = ApiMemorySummarizeInput {
            model: model_info.slug.clone(),
            raw_memories,
            reasoning: effort
                .map(|effort| model_info.resolve_reasoning_effort(effort))
                .map(|effort| Reasoning {
                    enabled: None,
                    effort: Some(effort),
                    max_tokens: None,
                    summary: None,
                    exclude: None,
                    context: None,
                }),
        };

        client
            .summarize_input(&payload, self.build_subagent_headers())
            .await
            .map_err(|error| self.state.provider.map_api_error(error))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn build_subagent_headers(&self) -> ApiHeaderMap {
        let mut extra_headers = ApiHeaderMap::new();
        add_originator_header(&mut extra_headers, self.state.originator.as_str());
        if let Some(subagent) = subagent_header_value(&self.state.session_source)
            && let Ok(val) = HeaderValue::from_str(&subagent)
        {
            extra_headers.insert(X_OPENAI_SUBAGENT_HEADER, val);
        }
        if matches!(
            self.state.session_source,
            SessionSource::Internal(InternalSessionSource::MemoryConsolidation)
        ) {
            extra_headers.insert(
                X_OPENAI_MEMGEN_REQUEST_HEADER,
                HeaderValue::from_static("true"),
            );
        }
        extra_headers
    }

    fn build_responses_compatibility_headers(
        &self,
        responses_metadata: &CodexResponsesMetadata,
    ) -> ApiHeaderMap {
        let mut extra_headers = responses_metadata.compatibility_headers();
        if matches!(
            self.state.session_source,
            SessionSource::Internal(InternalSessionSource::MemoryConsolidation)
        ) {
            extra_headers.insert(
                X_OPENAI_MEMGEN_REQUEST_HEADER,
                HeaderValue::from_static("true"),
            );
        }
        extra_headers
    }

    fn build_ws_client_metadata(
        &self,
        responses_metadata: &CodexResponsesMetadata,
        include_internal: bool,
        use_responses_lite: bool,
    ) -> HashMap<String, String> {
        let mut client_metadata = responses_metadata.client_metadata(include_internal);
        if use_responses_lite {
            client_metadata.insert(
                WS_REQUEST_HEADER_RESPONSES_LITE_CLIENT_METADATA_KEY.to_string(),
                "true".to_string(),
            );
        }
        client_metadata
    }

    async fn generate_attestation_header_for(&self) -> Option<HeaderValue> {
        if !self.state.include_attestation {
            return None;
        }

        self.state
            .attestation_provider
            .as_ref()?
            .header_for_request(AttestationContext {
                thread_id: self.state.thread_id,
            })
            .await
    }

    /// Builds request telemetry for unary API calls (e.g., Compact endpoint).
    fn build_request_telemetry(
        session_telemetry: &SessionTelemetry,
        auth_context: AuthRequestTelemetryContext,
        request_route_telemetry: RequestRouteTelemetry,
        auth_env_telemetry: AuthEnvTelemetry,
    ) -> Arc<dyn RequestTelemetry> {
        let telemetry = Arc::new(ApiTelemetry::new(
            session_telemetry.clone(),
            auth_context,
            request_route_telemetry,
            auth_env_telemetry,
        ));
        let request_telemetry: Arc<dyn RequestTelemetry> = telemetry;
        request_telemetry
    }

    fn build_reasoning(
        &self,
        model_info: &ModelInfo,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
    ) -> Reasoning {
        Reasoning {
            enabled: None,
            effort: effort
                .or_else(|| model_info.default_reasoning_level.clone())
                .map(|effort| model_info.resolve_reasoning_effort(effort)),
            summary: (self.state.provider.capabilities().reasoning_summaries
                && model_info.supports_reasoning_summary_parameter
                && summary != ReasoningSummaryConfig::None)
                .then_some(summary),
            max_tokens: None,
            exclude: None,
            // When Responses Lite is disabled, omit context so Responses uses the default,
            // which is currently `current_turn`.
            context: model_info
                .use_responses_lite
                .then_some(ReasoningContext::AllTurns),
        }
    }

    fn ambient_zai_reasoning_effort(
        effort: Option<&ReasoningEffortConfig>,
    ) -> Option<&'static str> {
        match effort {
            None | Some(ReasoningEffortConfig::None) => None,
            Some(effort) if wants_deep_reasoning(Some(effort)) => Some("max"),
            Some(_) => Some("high"),
        }
    }

    fn direct_zai_enable_thinking(protocol: ChatReasoningProtocol, effort: Option<&str>) -> bool {
        match protocol {
            ChatReasoningProtocol::PreservedRequired => effort.is_some(),
            ChatReasoningProtocol::Independent => effort.is_some_and(|effort| effort != "none"),
        }
    }

    fn chat_reasoning_effort(
        protocol: ChatReasoningEffortProtocol,
        effort: Option<&ReasoningEffortConfig>,
    ) -> Result<Option<String>> {
        let deep_effort = || {
            matches!(
                effort,
                Some(
                    ReasoningEffortConfig::XHigh
                        | ReasoningEffortConfig::Max
                        | ReasoningEffortConfig::Ultra
                )
            ) || matches!(
                effort,
                Some(ReasoningEffortConfig::Custom(value))
                    if matches!(value.as_str(), "xhigh" | "max" | "deep" | "extra_high" | "extra-high" | "ultra")
            )
        };

        match protocol {
            ChatReasoningEffortProtocol::ProviderDefault => Ok(None),
            ChatReasoningEffortProtocol::NoneHighMaxDefaultHigh => {
                let value = if matches!(effort, Some(ReasoningEffortConfig::None)) {
                    "none"
                } else if deep_effort() {
                    "max"
                } else {
                    "high"
                };
                Ok(Some(value.to_string()))
            }
            ChatReasoningEffortProtocol::LowHighMaxRequiredDefaultMax => {
                let value = match effort {
                    Some(ReasoningEffortConfig::None) => {
                        return Err(CodexErr::InvalidRequest(
                            "this route requires preserved reasoning; use low, high, or max"
                                .to_string(),
                        ));
                    }
                    Some(ReasoningEffortConfig::Minimal | ReasoningEffortConfig::Low) => "low",
                    Some(ReasoningEffortConfig::Medium | ReasoningEffortConfig::High) => "high",
                    Some(
                        ReasoningEffortConfig::XHigh
                        | ReasoningEffortConfig::Max
                        | ReasoningEffortConfig::Ultra
                        | ReasoningEffortConfig::Persistent,
                    ) => "max",
                    Some(ReasoningEffortConfig::Custom(value)) => match value.as_str() {
                        "low" | "light" | "minimum" | "min" => "low",
                        "medium" | "high" => "high",
                        "xhigh" | "max" | "ultra" => "max",
                        unsupported => {
                            return Err(CodexErr::InvalidRequest(format!(
                                "this route does not support reasoning effort `{unsupported}`; use low, high, or max"
                            )));
                        }
                    },
                    None => "max",
                };
                Ok(Some(value.to_string()))
            }
            ChatReasoningEffortProtocol::HighMaxDefaultHigh => {
                if matches!(effort, Some(ReasoningEffortConfig::None)) {
                    Ok(None)
                } else {
                    Ok(Some(if deep_effort() { "max" } else { "high" }.to_string()))
                }
            }
        }
    }

    /// OpenRouter's unified `reasoning` object is the only thinking control it
    /// honours. `enable_thinking` and `thinking.type` are silently dropped, so
    /// a model with reasoning on by default kept thinking on every turn while
    /// we believed we had disabled it (measured 2026-07-27: GLM 5.2 143 tok
    /// with our old field vs 3 tok with `reasoning.enabled=false`; Kimi K3 73
    /// vs 8). Absent or `none` effort therefore has to serialize as an
    /// explicit `{"enabled": false}` rather than as an omitted field.
    fn openrouter_reasoning(
        model_info: &ModelInfo,
        effort: Option<&ReasoningEffortConfig>,
    ) -> Result<Option<Value>> {
        let supports_reasoning = model_info.default_reasoning_level.is_some()
            || !model_info.supported_reasoning_levels.is_empty();
        if !supports_reasoning {
            // OpenRouter omits the reasoning capability for models that do not
            // reason, and `provider.require_parameters` restricts routing to
            // upstreams that support every parameter supplied. Sending a
            // reasoning object to such a model can make otherwise valid routes
            // ineligible, so stay silent rather than assert a default.
            return Ok(None);
        }
        let effort = effort
            .or(model_info.default_reasoning_level.as_ref())
            .map(ReasoningEffortConfig::as_str);
        if model_info.chat_completions.reasoning_protocol
            == ChatReasoningProtocol::PreservedRequired
        {
            let Some(effort) = effort.filter(|effort| *effort != "none") else {
                return Err(CodexErr::InvalidRequest(format!(
                    "{} requires preserved reasoning; reasoning effort `none` would select a \
                     different effective model",
                    model_info.slug
                )));
            };
            let effort = match effort {
                "xhigh"
                    if model_info
                        .supported_reasoning_levels
                        .iter()
                        .any(|preset| preset.effort.as_str() == "max") =>
                {
                    "max"
                }
                effort => effort,
            };
            if !model_info
                .supported_reasoning_levels
                .iter()
                .any(|preset| preset.effort.as_str() == effort)
            {
                let supported = model_info
                    .supported_reasoning_levels
                    .iter()
                    .map(|preset| preset.effort.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(CodexErr::InvalidRequest(format!(
                    "{} does not support reasoning effort `{effort}`; use {supported}",
                    model_info.slug
                )));
            }
            return Ok(Some(json!({ "effort": effort })));
        }
        match effort {
            // Do not use `{"exclude": true}` here: it suppresses the reasoning
            // text while still billing the tokens.
            None | Some("none") => Ok(Some(json!({ "enabled": false }))),
            Some(effort) => Ok(Some(json!({ "effort": effort }))),
        }
    }

    /// The Chat wire needs the same disable the Responses and Anthropic wires
    /// send. Pinning the upstream only guarantees the instruction reaches a
    /// host that obeys it; it is not itself an instruction.
    fn vercel_reasoning(
        model_info: &ModelInfo,
        effort: Option<&ReasoningEffortConfig>,
    ) -> Result<Value> {
        let effort = Self::vercel_reasoning_effort(model_info, effort)?;
        Ok(json!({ "effort": effort.as_str() }))
    }

    fn vercel_reasoning_effort(
        model_info: &ModelInfo,
        effort: Option<&ReasoningEffortConfig>,
    ) -> Result<ReasoningEffortConfig> {
        let selected = effort.or(model_info.default_reasoning_level.as_ref());
        // The older GLM 5.2 routes were qualified as a binary thinking toggle:
        // Standard means no hidden reasoning and Deep maps to xhigh. New Vercel
        // catalog routes publish the complete gateway reasoning dialect, so
        // preserve the selected effort instead of collapsing Low/High to off.
        if matches!(
            model_info.slug.as_str(),
            VERCEL_DEFAULT_MODEL | VERCEL_GLM_5_2_FAST_MODEL
        ) {
            return Ok(if wants_deep_reasoning(selected) {
                ReasoningEffortConfig::XHigh
            } else {
                ReasoningEffortConfig::None
            });
        }
        let normalized = match selected {
            Some(ReasoningEffortConfig::Max | ReasoningEffortConfig::Ultra) => {
                ReasoningEffortConfig::XHigh
            }
            Some(ReasoningEffortConfig::Custom(value))
                if matches!(value.as_str(), "max" | "ultra" | "deep") =>
            {
                ReasoningEffortConfig::XHigh
            }
            Some(effort) => effort.clone(),
            None => ReasoningEffortConfig::None,
        };
        if model_info
            .supported_reasoning_levels
            .iter()
            .any(|preset| preset.effort.as_str() == normalized.as_str())
        {
            return Ok(normalized);
        }
        let supported = model_info
            .supported_reasoning_levels
            .iter()
            .map(|preset| preset.effort.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Err(CodexErr::InvalidRequest(format!(
            "{} does not support Vercel reasoning effort `{}`; use {supported}",
            model_info.slug,
            normalized.as_str()
        )))
    }

    /// Ambient publishes OpenRouter's `ReasoningConfiguration` shape and does
    /// not implement `enable_thinking` at all — the field appears zero times in
    /// their OpenAPI spec, so every request we sent kept thinking on.
    fn ambient_reasoning(effort: Option<&str>) -> Value {
        match effort {
            Some(effort) => json!({ "enabled": true, "effort": effort }),
            None => json!({ "enabled": false }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_responses_request(
        &self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        include_internal: bool,
    ) -> Result<ResponsesApiRequest> {
        let mut input = self.source_admitted_input(prompt, model_info)?;
        if !self.reasoning_effort_override_enabled(model_info) {
            // Unsupported models and disabled overrides must also accept saved history.
            // Filter only the request copy; persisted history remains unchanged.
            input.retain(|item| !matches!(item, ResponseItem::ConfigurationUpdate { .. }));
        } else {
            input.dedup_by(|next, previous| {
                if matches!(next, ResponseItem::ConfigurationUpdate { .. })
                    && matches!(previous, ResponseItem::ConfigurationUpdate { .. })
                {
                    // Keep the latest update; dedup_by removes `next`.
                    std::mem::swap(previous, next);
                    true
                } else {
                    false
                }
            });
        }
        // #578: after labelling, which looks items up by their recorded bytes.
        if let Some(producer) = prompt.producer.as_deref() {
            crate::context_manager::provider_items::strip_foreign_references(&mut input, producer);
        }
        self.drop_unresolvable_item_references(&mut input);
        let is_openai = self.state.provider.info().is_openai();
        // These prompt-only items are rebuilt on every request. Hash their visible payloads
        // within the thread so retries and resumed sessions preserve their identity.
        let prefix_namespace = Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            self.state.thread_id.to_string().as_bytes(),
        );
        let mut prefix = Vec::new();
        let tools = if model_info.use_responses_lite {
            if !prompt.tools.is_empty() {
                let tools = create_tools_json_for_responses_lite(&prompt.tools)?;
                prefix.push(ResponseItem::AdditionalTools {
                    id: Some(ResponseItemId::with_suffix(
                        "at",
                        Uuid::new_v5(&prefix_namespace, &serde_json::to_vec(&tools)?),
                    )),
                    role: "developer".to_string(),
                    tools: Arc::from(tools),
                });
            }
            None
        } else {
            Some(create_tools_raw_json_for_responses_api(&prompt.tools)?.into())
        };
        // Corbanu keeps main's request shape for Responses (`instructions`, which every
        // Responses-compatible provider accepts); only Responses Lite carries them in input.
        let instructions = if model_info.use_responses_lite {
            String::new()
        } else {
            prompt.base_instructions.text.clone()
        };
        if model_info.use_responses_lite && !prompt.base_instructions.text.is_empty() {
            let mut instructions = ContextualUserFragment::into(BaseInstructionsFragment(
                prompt.base_instructions.text.clone(),
            ));
            instructions.set_id(Some(ResponseItemId::with_suffix(
                "msg",
                Uuid::new_v5(&prefix_namespace, prompt.base_instructions.text.as_bytes()),
            )));
            prefix.push(instructions);
        }
        input.splice(0..0, prefix);
        if !model_info.use_responses_lite {
            // Only RLite accepts per-content attribution until the Responses API schema expands.
            for item in &mut input {
                item.clear_content_item_metadata();
            }
        }
        if !is_openai {
            retain_latest_contextual_developer_fragments(&mut input);
            adapt_plaintext_collaboration_messages_for_responses(&mut input);
            for item in &mut input {
                item.clear_internal_chat_message_metadata_passthrough();
                if !matches!(
                    item,
                    ResponseItem::Reasoning { .. }
                        | ResponseItem::Compaction { .. }
                        | ResponseItem::ContextCompaction { .. }
                ) {
                    item.clear_encrypted_content();
                }
                if let ResponseItem::FunctionCall {
                    encrypted_function_args,
                    ..
                } = item
                {
                    *encrypted_function_args = None;
                }
            }
        }
        let uses_zai_reasoning =
            self.state.provider.info().is_ambient() || self.state.provider.info().is_zai();
        let ambient_reasoning_effort = uses_zai_reasoning
            .then(|| {
                Self::ambient_zai_reasoning_effort(
                    effort
                        .as_ref()
                        .or(model_info.default_reasoning_level.as_ref()),
                )
                .map(str::to_string)
            })
            .flatten();
        let ambient_enable_thinking =
            uses_zai_reasoning.then_some(ambient_reasoning_effort.is_some());
        let is_vercel_gateway = self.state.provider.info().is_vercel_gateway();
        let upstream_model = if is_vercel_gateway {
            vercel_gateway_upstream_model(&model_info.slug)
        } else {
            &model_info.slug
        };
        let vercel_provider_options = is_vercel_gateway
            .then(|| self.vercel_gateway_provider_options(upstream_model))
            .flatten();
        let mut reasoning = self.build_reasoning(model_info, effort, summary);
        if is_vercel_gateway {
            reasoning.effort = Some(Self::vercel_reasoning_effort(
                model_info,
                reasoning.effort.as_ref(),
            )?);
        }
        let stream_options = (self.state.concurrent_reasoning_summaries_enabled
            && is_openai
            && !uses_zai_reasoning
            && reasoning.summary.is_some())
        .then_some(StreamOptions {
            reasoning_summary_delivery: codex_api::ReasoningSummaryDelivery::SequentialCutoff,
        });
        let mut include = if uses_zai_reasoning {
            Vec::new()
        } else {
            vec!["reasoning.encrypted_content".to_string()]
        };
        if self.state.output_token_replay_enabled && is_openai {
            include.push("output.encrypted_content".to_string());
        }
        let verbosity = if model_info.support_verbosity {
            self.state.model_verbosity.or(model_info.default_verbosity)
        } else {
            if self.state.model_verbosity.is_some() {
                warn!(
                    "model_verbosity is set but ignored as the model does not support verbosity: {}",
                    model_info.slug
                );
            }
            None
        };
        let text = create_text_param_for_request(
            verbosity,
            &prompt.output_schema,
            prompt.output_schema_strict,
        );
        let prompt_cache_key = if uses_zai_reasoning {
            None
        } else {
            self.prompt_cache_key(responses_metadata)
        };
        let service_tier = if uses_zai_reasoning {
            None
        } else {
            model_info
                .service_tier_for_request(service_tier)
                .filter(|tier| {
                    // Bedrock requires an advertised tier, including for flex, which the
                    // generic OpenAI resolver permits without catalog support.
                    !self.state.provider.info().is_amazon_bedrock()
                        || model_info
                            .service_tiers
                            .iter()
                            .any(|supported| supported.id == *tier)
                })
        };
        if !include_internal {
            for item in &mut input {
                item.clear_tool_result_metadata();
            }
        }
        let client_metadata = responses_metadata.client_metadata(include_internal);
        let request = ResponsesApiRequest {
            model: upstream_model.to_string(),
            instructions,
            previous_response_id: None,
            input,
            tools,
            tool_choice: "auto".to_string(),
            parallel_tool_calls: prompt.parallel_tool_calls && !model_info.use_responses_lite,
            reasoning: (!uses_zai_reasoning).then_some(reasoning),
            // Upstream sends `store: false` (Azure included); Corbanu's Vercel
            // gateway keeps server-side state.
            store: self.state.provider.info().is_vercel(),
            stream: true,
            stream_options,
            include,
            service_tier,
            prompt_cache_key,
            text,
            client_metadata: (!uses_zai_reasoning).then_some(client_metadata),
            thinking_budget: None,
            emit_usage: uses_zai_reasoning.then_some(true),
            enable_thinking: ambient_enable_thinking,
            reasoning_effort: ambient_reasoning_effort,
            provider_options: vercel_provider_options,
            access_programs: None,
        };
        Ok(request)
    }

    fn build_chat_completions_request(
        &self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        effort: Option<ReasoningEffortConfig>,
        responses_metadata: &CodexResponsesMetadata,
    ) -> Result<ChatCompletionsRequest> {
        let mut messages = Vec::new();
        let instructions = prompt.base_instructions.text.trim();
        if !instructions.is_empty() {
            messages.push(ChatMessage {
                role: "system".to_string(),
                content: Some(ChatMessageContent::text(instructions.to_string())),
                reasoning_content: None,
                tool_call_id: None,
                tool_calls: Vec::new(),
            });
        }

        let mut input = self.source_admitted_input(prompt, model_info)?;
        if !self.state.provider.info().is_openai() {
            retain_latest_contextual_developer_fragments(&mut input);
        }
        flatten_namespaced_history(&mut input, &prompt.tools, &prompt.flat_tool_names);
        let mut skipped_tool_call_ids = HashSet::new();
        append_chat_messages_for_response_items(
            input,
            &mut messages,
            &mut skipped_tool_call_ids,
            model_info.chat_completions.reasoning_protocol,
        );

        // GLM chat streams proper tool calls when OpenAI's `strict` function
        // flag is omitted. Keep the JSON schema, but drop that
        // provider-incompatible wrapper bit for Ambient and Z.AI.
        let uses_zai_reasoning =
            self.state.provider.info().is_ambient() || self.state.provider.info().is_zai();
        let strip_strict_from_tools = uses_zai_reasoning || self.state.provider.info().is_baseten();
        let mut tools = create_tools_json_for_chat_completions(
            &prompt.tools,
            strip_strict_from_tools,
            self.state.provider.info().is_zai(),
        )?;
        // OpenRouter web search must ride the request-level `plugins` field. A
        // non-function entry in `tools` makes every GLM host ineligible and
        // diverts the request to a tool-middleware tier with a fixed ~10s
        // header hold (openrouter-parity IC probes, 2026-07-02).
        let openrouter_web_plugins = self
            .state
            .provider
            .info()
            .is_openrouter()
            .then(|| {
                prompt.tools.iter().find_map(|tool| match tool {
                    ToolSpec::WebSearch {
                        search_context_size,
                        ..
                    } => Some(openrouter_web_plugin(*search_context_size)),
                    _ => None,
                })
            })
            .flatten()
            .map(|plugin| vec![plugin]);
        if self.state.provider.info().is_zai() {
            let has_native_web_search = tools
                .iter()
                .any(|tool| tool.get("type").and_then(Value::as_str) == Some("web_search"));
            let has_function_tools = tools
                .iter()
                .any(|tool| tool.get("type").and_then(Value::as_str) == Some("function"));
            if has_native_web_search && has_function_tools {
                // Z.AI rejects mixed native web_search + function-tool payloads.
                // Preserve client-executed function tools here; without them the
                // coding agent cannot run shell/file actions and turns stop after
                // the model merely says what it would do.
                tools.retain(|tool| tool.get("type").and_then(Value::as_str) != Some("web_search"));
            }
        }
        // The Corbanu Plan gateway routes `z-ai/glm-5.2` to Ambient and forwards the request body
        // unchanged (#1489), so that row needs Ambient's `reasoning` object; other Plan rows keep
        // the OpenAI-style default.
        let sends_ambient_reasoning = self.state.provider.info().is_ambient()
            || (self.state.provider.info().is_pfterminal_plan()
                && model_info.slug == AMBIENT_DEFAULT_MODEL);
        let ambient_reasoning_effort = (uses_zai_reasoning || sends_ambient_reasoning)
            .then(|| {
                Self::ambient_zai_reasoning_effort(
                    effort
                        .as_ref()
                        .or(model_info.default_reasoning_level.as_ref()),
                )
                .map(str::to_string)
            })
            .flatten();
        let catalogue_reasoning_effort = Self::chat_reasoning_effort(
            model_info.chat_completions.reasoning_effort_protocol,
            effort
                .as_ref()
                .or(model_info.default_reasoning_level.as_ref()),
        )?;
        // Prefer the exact catalogue dialect over the coarse Ambient/Z.AI compatibility mapping.
        // Ambient carries this control only in its `reasoning` object, while direct Z.AI uses the
        // top-level scalar plus `enable_thinking`.
        let selected_reasoning_effort = catalogue_reasoning_effort.or(ambient_reasoning_effort);
        let direct_zai_enable_thinking =
            self.state
                .provider
                .info()
                .is_zai()
                .then_some(Self::direct_zai_enable_thinking(
                    model_info.chat_completions.reasoning_protocol,
                    selected_reasoning_effort.as_deref(),
                ));
        let response_format = prompt.output_schema.as_ref().map(|schema| {
            json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "codex_output_schema",
                    "strict": prompt.output_schema_strict,
                    "schema": schema,
                }
            })
        });
        let chat_cache_policy = self.chat_cache_policy(model_info);
        if chat_cache_policy.explicit_cache_control {
            apply_chat_cache_control(&mut messages);
        }

        let upstream_model =
            chat_completions_upstream_model(&model_info.slug, self.state.provider.info());
        let vercel_provider_options = self
            .state
            .provider
            .info()
            .is_vercel_gateway()
            .then(|| self.vercel_gateway_provider_options(upstream_model))
            .flatten();
        let provider_reasoning = if self.state.provider.info().is_openrouter() {
            Self::openrouter_reasoning(model_info, effort.as_ref())?
        } else if sends_ambient_reasoning {
            Some(Self::ambient_reasoning(
                selected_reasoning_effort.as_deref(),
            ))
        } else if self.state.provider.info().is_vercel_gateway() {
            Some(Self::vercel_reasoning(model_info, effort.as_ref())?)
        } else {
            None
        };
        let reasoning_effort = (!sends_ambient_reasoning)
            .then_some(selected_reasoning_effort)
            .flatten();
        Ok(ChatCompletionsRequest {
            model: upstream_model.to_string(),
            messages,
            stream: true,
            stream_options: Some(ChatStreamOptions {
                include_usage: true,
            }),
            tool_choice: (!tools.is_empty()).then(|| "auto".to_string()),
            parallel_tool_calls: (!tools.is_empty() && prompt.parallel_tool_calls).then_some(true),
            prompt_cache_key: chat_cache_policy
                .prompt_cache_key
                .then(|| self.prompt_cache_key(responses_metadata))
                .flatten(),
            tools,
            response_format,
            emit_usage: uses_zai_reasoning.then_some(true),
            enable_thinking: direct_zai_enable_thinking,
            reasoning_effort,
            reasoning: provider_reasoning,
            provider: self.state.provider.info().chat_completions_provider.clone(),
            plugins: openrouter_web_plugins,
            provider_options: vercel_provider_options,
        })
    }

    fn build_anthropic_messages_request(
        &self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        effort: Option<ReasoningEffortConfig>,
    ) -> Result<AnthropicMessagesRequest> {
        self.build_anthropic_messages_request_with_history_repair(
            prompt, model_info, effort, /*repair_incomplete_latest_assistant*/ false,
        )
    }

    fn build_anthropic_messages_request_with_history_repair(
        &self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        effort: Option<ReasoningEffortConfig>,
        repair_incomplete_latest_assistant: bool,
    ) -> Result<AnthropicMessagesRequest> {
        let mut system = Vec::new();
        let instructions = prompt.base_instructions.text.trim();
        let is_claude_plan = is_claude_plan_model_slug(&model_info.slug);
        let cache_control = anthropic_cache_control(is_claude_plan);
        if is_claude_plan {
            system.push(json!({
                "type": "text",
                "text": CLAUDE_CODE_IDENTITY_PROMPT,
            }));
        }
        if !instructions.is_empty() {
            let instruction_block = json!({
                "type": "text",
                "text": instructions,
            });
            system.push(instruction_block);
        }
        apply_anthropic_cache_control_to_last_system_block(&mut system, &cache_control);

        let mut input = self.source_admitted_input(prompt, model_info)?;
        if !self.state.provider.info().is_openai() {
            retain_latest_contextual_developer_fragments(&mut input);
        }
        flatten_namespaced_history(&mut input, &prompt.tools, &prompt.flat_tool_names);
        let mut messages = Vec::new();
        let mut skipped_tool_call_ids = HashSet::new();
        for item in input {
            append_anthropic_message_for_response_item(
                item,
                &mut messages,
                &mut skipped_tool_call_ids,
            );
        }
        let removed_incomplete_signed_response =
            remove_latest_signed_thinking_only_assistant_message(&mut messages);
        if repair_incomplete_latest_assistant && !removed_incomplete_signed_response {
            remove_latest_signed_thinking_assistant_message(&mut messages);
        }
        ensure_anthropic_messages_end_with_user_turn(&mut messages);
        apply_anthropic_cache_control_to_last_user_messages(&mut messages, &cache_control);

        let tools = create_tools_json_for_anthropic_messages(
            &prompt.tools,
            &cache_control,
            self.state
                .provider
                .info()
                .runtime_policy
                .web_search_max_uses,
        )?;
        let tool_choice = (!tools.is_empty()).then(|| json!({ "type": "auto" }));
        let catalog_model = if self.state.provider.info().is_vercel_gateway() {
            vercel_gateway_upstream_model(&model_info.slug)
        } else {
            &model_info.slug
        };
        let upstream_model = anthropic_upstream_model(catalog_model);
        let selected_effort = if self.state.provider.info().is_vercel_gateway() {
            Some(Self::vercel_reasoning_effort(model_info, effort.as_ref())?)
        } else {
            effort.or_else(|| model_info.default_reasoning_level.clone())
        };
        let (mut thinking, output_config) =
            anthropic_reasoning_for_model_and_effort(upstream_model, selected_effort.as_ref());
        let provider_options = self
            .state
            .provider
            .info()
            .is_vercel_gateway()
            .then(|| self.vercel_gateway_provider_options(upstream_model))
            .flatten();
        // Third-party slugs on this wire think by default, so an omitted
        // `thinking` block is not the same as thinking off. Only Anthropic's
        // own models treat the omission that way.
        if provider_options.is_some() && thinking.is_none() {
            thinking = Some(json!({ "type": "disabled" }));
        }

        let mut request = AnthropicMessagesRequest {
            model: upstream_model.to_string(),
            system,
            messages,
            tools,
            tool_choice,
            stream: true,
            max_tokens: model_info.max_output_tokens.ok_or_else(|| {
                // Upstream keeps a model's catalog origin on `CatalogModel`, not on the
                // `ModelInfo` a request sees, so one message covers both cases.
                CodexErr::InvalidRequest(format!(
                    "model `{}` has no catalogued maximum output length (it may not be in this \
                     provider's model catalog); choose another model with /model or change \
                     `model` in config.toml",
                    model_info.slug
                ))
            })?,
            thinking,
            output_config,
            provider_options,
        };
        let image_report = fit_anthropic_image_dimensions(&mut request);
        if image_report != ImageDimensionReport::default() {
            warn!(
                resized_images = image_report.resized_images,
                omitted_images = image_report.omitted_images,
                "fitted Anthropic request images to the provider's dimension limits"
            );
        }
        let payload_report = enforce_anthropic_payload_budget(
            &mut request,
            self.state
                .provider
                .info()
                .runtime_policy
                .request_body_max_bytes,
        )?;
        if payload_report.omitted_images > 0 {
            warn!(
                original_bytes = payload_report.original_bytes,
                final_bytes = payload_report.final_bytes,
                omitted_images = payload_report.omitted_images,
                "omitted older images from Anthropic request to enforce provider payload budget"
            );
        }
        Ok(request)
    }

    fn chat_cache_policy(&self, model_info: &ModelInfo) -> ChatCachePolicy {
        let provider = self.state.provider.info();
        let slug = model_info.slug.as_str();

        if provider.is_openrouter() {
            return ChatCachePolicy {
                explicit_cache_control: chat_model_supports_openai_compatible_cache_control(slug),
                prompt_cache_key: false,
            };
        }

        if provider.is_vercel() {
            return ChatCachePolicy {
                explicit_cache_control: chat_model_supports_vercel_cache_control(slug),
                prompt_cache_key: true,
            };
        }

        ChatCachePolicy::default()
    }

    /// #578: records the item a Responses host reported missing (`Item with
    /// id '…' not found`). Returns the ID when it is new, so the caller can
    /// retry once without it; `None` for any other error or an ID already
    /// dropped (the retry did not help).
    pub(crate) fn note_unresolvable_item_reference(&self, err: &CodexErr) -> Option<String> {
        if self.state.provider.info().wire_api != WireApi::Responses {
            return None;
        }
        let id = unresolvable_item_id(&err.to_string())?;
        let mut ids = self.state.unresolvable_item_ids.lock().ok()?;
        ids.insert(id.clone()).then_some(id)
    }

    /// Leaves the items in [`ModelClientState::unresolvable_item_ids`] out of
    /// a Responses request as references: reasoning is dropped (without the
    /// stored item it carries nothing the host can read), other items are
    /// sent inline without their ID.
    fn drop_unresolvable_item_references(&self, input: &mut Vec<ResponseItem>) {
        let Ok(ids) = self.state.unresolvable_item_ids.lock() else {
            return;
        };
        if ids.is_empty() {
            return;
        }
        input.retain_mut(|item| {
            if !item.id().is_some_and(|id| ids.contains(id.as_str())) {
                return true;
            }
            if matches!(item, ResponseItem::Reasoning { .. }) {
                return false;
            }
            item.set_id(/*new_id*/ None);
            true
        });
    }

    fn prepare_response_items_for_request(&self, input: &mut [ResponseItem]) {
        for item in input {
            if item.id().is_some_and(|id| !id.is_prefixed()) {
                item.set_id(/*new_id*/ None);
            }
            if !self.state.content_item_kinds_enabled {
                item.clear_content_item_kinds();
            }
        }
    }

    fn vercel_gateway_provider_options(&self, upstream_model: &str) -> Option<Value> {
        if self
            .state
            .vercel_vendor_pin_rejected
            .load(Ordering::Relaxed)
        {
            return None;
        }
        vercel_gateway_provider_options(upstream_model)
    }

    /// Records a policy exclusion of the pinned Vercel upstream. Returns true
    /// when this is the first one for the session, so the caller retries the
    /// request once with the gateway's own routing.
    fn drop_vercel_vendor_pin_after_policy_exclusion(&self, err: &ApiError) -> bool {
        if !self.state.provider.info().is_vercel_gateway()
            || !is_vercel_gateway_policy_exclusion(err)
        {
            return false;
        }
        let first = !self
            .state
            .vercel_vendor_pin_rejected
            .swap(true, Ordering::Relaxed);
        if first {
            warn!(
                "Vercel gateway skipped every provider for the pinned upstream under this \
                 account's policy; using gateway routing for the rest of this session"
            );
        }
        first
    }

    fn responses_input_needs_synthetic_user_turn(&self, input: &[ResponseItem]) -> bool {
        // This is conversation-shape normalization, not a provider-specific compatibility hack.
        // Collaboration mail and completed assistant output are model output for every Responses
        // endpoint; when either is terminal, append a request-only user continuation so the next
        // sample cannot be interpreted as an assistant prefill.
        responses_input_needs_synthetic_user_turn(input)
            || (self
                .state
                .legacy_synthetic_continuation
                .load(Ordering::Relaxed)
                && responses_input_latest_message_is_assistant(input))
    }

    /// True when this request omits the synthetic turn only because of the narrower prefill
    /// rule, so a 400 may come from a provider that still needs the legacy shape.
    fn responses_input_omits_legacy_synthetic_turn(&self, input: &[ResponseItem]) -> bool {
        !self
            .state
            .legacy_synthetic_continuation
            .load(Ordering::Relaxed)
            && responses_input_latest_message_is_assistant(input)
            && !responses_input_needs_synthetic_user_turn(input)
    }

    /// Returns whether the Responses-over-WebSocket transport is active for this session.
    ///
    /// WebSocket use is controlled by provider capability and session-scoped fallback state.
    pub fn responses_websocket_enabled(&self) -> bool {
        // PF-27-S05: a websocket handshake cannot carry a signed broker frame.
        // `ConnectionIdentity` also relies on this: brokered identities never
        // match, so a socket under the broker would reconnect every turn
        // (#1504).
        if !self.state.provider.info().supports_websockets
            || self.state.disable_websockets.load(Ordering::Relaxed)
            || codex_model_provider::model_key_broker_required()
        {
            return false;
        }

        true
    }

    /// Returns auth + provider configuration resolved from the current session auth state.
    ///
    /// This centralizes setup used by both prewarm and normal request paths so they stay in
    /// lockstep when auth/provider resolution changes.
    async fn current_client_setup(&self, routing: ClientRouting) -> Result<CurrentClientSetup> {
        if let Some((manager, mode)) = &self.runtime_auth {
            // PF-27-S05: with a credential broker the model credential never reaches this
            // process; upstream's runtime authentication signs here, so it is refused.
            if codex_model_provider::model_key_broker_required() {
                return Err(CodexErr::UnsupportedOperation(
                    "runtime authentication is off under broker_model_auth".to_string(),
                ));
            }
            let selected = codex_model_provider::select_runtime_auth(
                manager,
                &self.state.provider.info().build_header_map()?,
            )
            .await
            .map_err(|error| self.state.provider.map_api_error(error.into()))?;
            let auth = selected.auth().clone();
            let auth_revision = Some(selected.change_state().generation);
            let auth_owner_generation = Some(selected.change_state().owner_generation);
            let api_provider = self.state.provider.api_provider_for_auth(Some(&auth))?;
            let (api_provider, redirect_policy) = match routing {
                ClientRouting::Workspace => {
                    let resolved = self
                        .state
                        .provider
                        .route_responses_api_provider(
                            api_provider,
                            Some(&auth),
                            &self.state.workspace_routing,
                        )
                        .await?;
                    (resolved.provider, resolved.redirect_policy)
                }
                ClientRouting::ConfiguredProvider => (api_provider, ClientRedirectPolicy::Default),
            };
            let runtime = selected.runtime();
            codex_model_provider::validate_runtime_selectors(
                &api_provider.headers,
                runtime.actor().info(),
            )?;
            let runtime_id = Some(runtime.id().to_string());
            let http_client_factory = selected.http_client_factory().clone();
            let resolved_auth = self
                .state
                .provider
                .compose_auth(ResolvedProviderAuth {
                    auth: selected.clone().into_auth_provider(*mode),
                    agent_identity_telemetry: None,
                    runtime: Some(selected),
                })
                .await?;
            tracing::debug!(runtime_auth_mode = ?mode, "selected runtime authentication");
            return Ok(CurrentClientSetup {
                auth: Some(auth),
                auth_owner_generation,
                auth_revision,
                api_provider,
                http_client_factory,
                redirect_policy,
                api_auth: resolved_auth.auth,
                agent_identity_telemetry: None,
                runtime_id,
            });
        }
        self.provider_client_setup(routing, &self.state.provider)
            .await
    }

    // Realtime keeps provider auth until its runtime integration lands later in the stack.
    async fn realtime_client_setup(&self) -> Result<CurrentClientSetup> {
        let provider = if self.state.provider.runtime_auth().is_some() {
            create_model_provider(
                self.state.provider.info().clone(),
                self.state.provider.auth_manager(),
            )
        } else {
            Arc::clone(&self.state.provider)
        };
        self.provider_client_setup(ClientRouting::ConfiguredProvider, &provider)
            .await
    }

    async fn provider_client_setup(
        &self,
        routing: ClientRouting,
        provider: &SharedModelProvider,
    ) -> Result<CurrentClientSetup> {
        let routing = &routing;
        codex_model_provider::prepare_provider_request(
            provider.as_ref(),
            provider.info().auth.is_none(),
            |state| async move {
                let auth = provider.auth().await;
                let (api_provider, redirect_policy) = match routing {
                    ClientRouting::Workspace => {
                        let resolved = provider
                            .responses_api_provider(&self.state.workspace_routing)
                            .await?;
                        (resolved.provider, resolved.redirect_policy)
                    }
                    ClientRouting::ConfiguredProvider => (
                        provider.api_provider().await?,
                        ClientRedirectPolicy::Default,
                    ),
                };
                // #878: a broker refusal of this auth is this session's. PF-27-S05: with a
                // credential broker installed, `api_auth` signs for it and the transport sends
                // the request only to its socket.
                let resolved_auth = crate::model_broker_auth::refusals::owned_by(
                    self.state.thread_id,
                    provider.api_auth_for_scope(ProviderAuthScope {
                        agent_identity_policy: self.agent_identity_policy,
                        session_source: self.state.session_source.clone(),
                        agent_identity_session_fallback: self
                            .state
                            .agent_identity_session_fallback
                            .clone(),
                    }),
                )
                .await?;
                Ok(CurrentClientSetup {
                    auth,
                    auth_owner_generation: state.map(|state| state.owner_generation),
                    auth_revision: state.map(|state| state.generation),
                    api_provider,
                    http_client_factory: self.http_client_factory.clone(),
                    redirect_policy,
                    api_auth: resolved_auth.auth,
                    agent_identity_telemetry: resolved_auth.agent_identity_telemetry,
                    runtime_id: None,
                })
            },
        )
        .await
    }

    fn responses_headers(&self, auth: Option<&CodexAuth>, model: &str) -> ApiHeaderMap {
        self.codex_responses_headers
            .as_ref()
            .filter(|config| config.model == model && self.uses_codex_backend(auth))
            .map(|config| config.headers.clone())
            .unwrap_or_default()
    }

    fn uses_codex_backend(&self, auth: Option<&CodexAuth>) -> bool {
        let provider = self.state.provider.info();
        auth.is_some_and(CodexAuth::uses_codex_backend)
            && provider.is_openai()
            && provider.requires_openai_auth
            && provider.env_key.is_none()
            && provider.experimental_bearer_token.is_none()
            && provider.auth.is_none()
            && provider.aws.is_none()
    }

    fn set_guardian_metadata(
        &self,
        metadata: &mut Option<HashMap<String, String>>,
        parent_response_id: Option<&str>,
        auth: Option<&CodexAuth>,
        responses_headers: &ApiHeaderMap,
    ) {
        if let Some(metadata) = metadata.as_mut() {
            metadata.remove("guardian_credits_requested");
            metadata.remove("parent_response_id");
        }
        let guardian_reviewer = is_guardian_reviewer(responses_headers);
        if guardian_reviewer && let Some(parent_response_id) = parent_response_id {
            metadata.get_or_insert_with(HashMap::new).insert(
                "parent_response_id".to_owned(),
                parent_response_id.to_owned(),
            );
        }
        if !guardian_reviewer
            && !crate::guardian::is_basic_session_source(&self.state.session_source)
            && matches!(
                auth,
                Some(CodexAuth::Chatgpt(_) | CodexAuth::ChatgptAuthTokens(_))
            )
            && self.uses_codex_backend(auth)
        {
            metadata
                .get_or_insert_with(HashMap::new)
                .insert("guardian_credits_requested".to_owned(), "true".to_owned());
        }
    }

    fn build_routing_hint_header(
        &self,
        auth: Option<&CodexAuth>,
        responses_headers: &ApiHeaderMap,
        model: &str,
        service_tier: Option<&str>,
    ) -> Option<HeaderValue> {
        if !self.uses_codex_backend(auth) || is_guardian_reviewer(responses_headers) {
            return None;
        }

        let routing_hint = match service_tier {
            Some(tier) => format!("model={model};tier={tier}"),
            None => format!("model={model}"),
        };
        HeaderValue::from_str(&routing_hint).ok()
    }

    /// Corbanu: every model-request transport carries the session's stage-one memory guard.
    fn guarded_transport(
        &self,
        transport: ReqwestTransport,
    ) -> crate::memory_stage_one::StageOneGuardedTransport {
        crate::memory_stage_one::StageOneGuardedTransport::new(
            transport,
            self.stage_one_memory_binding.get().cloned(),
        )
    }

    pub(crate) async fn prewarm_auth(&self) -> Result<()> {
        self.current_client_setup(ClientRouting::Workspace)
            .await
            .map(|_| ())
    }

    fn unauthorized_recovery(&self) -> Option<UnauthorizedRecovery> {
        if self.state.provider.info().env_key.is_some() {
            return None;
        }
        self.state
            .provider
            .auth_manager()
            .map(|manager| manager.unauthorized_recovery())
    }

    /// Opens a websocket connection using the same header and telemetry wiring as normal turns.
    ///
    /// Both startup prewarm and in-turn `needs_new` reconnects call this path so handshake
    /// behavior remains consistent across both flows.
    #[allow(clippy::too_many_arguments)]
    async fn connect_websocket(
        &self,
        session_telemetry: &SessionTelemetry,
        api_provider: codex_api::Provider,
        api_auth: SharedAuthProvider,
        http_client_factory: &HttpClientFactory,
        responses_metadata: &CodexResponsesMetadata,
        auth_context: AuthRequestTelemetryContext,
        request_route_telemetry: RequestRouteTelemetry,
        responses_headers: &ApiHeaderMap,
        parent_routing_affinity: Option<&codex_http_client::ChatGptRoutingAffinity>,
    ) -> std::result::Result<ApiWebSocketConnection, ApiError> {
        // PF-27-S05: a brokered credential never travels over a websocket handshake.
        if codex_model_provider::model_key_broker_required() {
            return Err(ApiError::InvalidRequest {
                message: "websockets are off under broker_model_auth".to_string(),
            });
        }
        let mut headers = self.build_websocket_headers(responses_metadata).await;
        headers.extend(responses_headers.clone());
        if let Some(affinity) = parent_routing_affinity {
            let uri = api_provider
                .websocket_url_for_path(RESPONSES_PATH)
                .map_err(|err| ApiError::Stream(format!("failed to build websocket URL: {err}")))?
                .as_str()
                .parse::<http::Uri>()
                .map_err(|err| ApiError::Stream(format!("invalid websocket URI: {err}")))?;
            let cookies = headers
                .get(http::header::COOKIE)
                .cloned()
                .or_else(|| api_provider.headers.get(http::header::COOKIE).cloned())
                .or_else(|| http_client_factory.chatgpt_cookie_header(&uri));
            if let Some(cookies) = affinity.merge_cookie_header(&uri, cookies.as_ref()) {
                headers.insert(http::header::COOKIE, cookies);
            }
        }
        let websocket_telemetry = ModelClientSession::build_websocket_telemetry(
            session_telemetry,
            auth_context.clone(),
            request_route_telemetry,
            self.state.auth_env_telemetry.clone(),
        );
        let websocket_connect_timeout = self.state.provider.info().websocket_connect_timeout();
        let start = Instant::now();
        let result = match tokio::time::timeout(
            websocket_connect_timeout,
            ApiWebSocketResponsesClient::new(api_provider, api_auth).connect(
                http_client_factory,
                headers,
                codex_login::default_client::default_headers(),
                /*turn_state*/ None,
                Some(websocket_telemetry),
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(ApiError::Transport(TransportError::Timeout)),
        };
        let error_message = result.as_ref().err().map(telemetry_api_error_message);
        let response_debug = result
            .as_ref()
            .err()
            .map(extract_response_debug_context_from_api_error)
            .unwrap_or_default();
        let status = result.as_ref().err().and_then(api_error_http_status);
        session_telemetry.record_websocket_connect(
            start.elapsed(),
            status,
            error_message.as_deref(),
            auth_context.auth_header_attached,
            auth_context.auth_header_name,
            auth_context.retry_after_unauthorized,
            auth_context.recovery_mode,
            auth_context.recovery_phase,
            request_route_telemetry.endpoint,
            /*connection_reused*/ false,
            response_debug.request_id.as_deref(),
            response_debug.cf_ray.as_deref(),
            response_debug.auth_error.as_deref(),
            response_debug.auth_error_code.as_deref(),
            auth_context.agent_identity_telemetry(),
        );
        emit_feedback_request_tags_with_auth_env(
            &FeedbackRequestTags {
                endpoint: request_route_telemetry.endpoint,
                auth_header_attached: auth_context.auth_header_attached,
                auth_header_name: auth_context.auth_header_name,
                auth_mode: auth_context.auth_mode,
                auth_retry_after_unauthorized: Some(auth_context.retry_after_unauthorized),
                auth_recovery_mode: auth_context.recovery_mode,
                auth_recovery_phase: auth_context.recovery_phase,
                auth_connection_reused: Some(false),
                auth_request_id: response_debug.request_id.as_deref(),
                auth_cf_ray: response_debug.cf_ray.as_deref(),
                auth_error: response_debug.auth_error.as_deref(),
                auth_error_code: response_debug.auth_error_code.as_deref(),
                auth_recovery_followup_success: auth_context
                    .retry_after_unauthorized
                    .then_some(result.is_ok()),
                auth_recovery_followup_status: auth_context
                    .retry_after_unauthorized
                    .then_some(status)
                    .flatten(),
            },
            &self.state.auth_env_telemetry,
        );
        result
    }

    /// Builds websocket handshake headers for both prewarm and turn-time reconnect.
    async fn build_websocket_headers(
        &self,
        responses_metadata: &CodexResponsesMetadata,
    ) -> ApiHeaderMap {
        let mut headers = build_responses_headers(
            self.state.beta_features_header.as_deref(),
            /*turn_state*/ None,
        );
        add_originator_header(&mut headers, self.state.originator.as_str());
        if let Ok(header_value) = HeaderValue::from_str(&responses_metadata.thread_id) {
            headers.insert("x-client-request-id", header_value);
        }
        headers.extend(build_session_headers(
            Some(self.responses_session_id(responses_metadata)),
            Some(responses_metadata.thread_id.to_string()),
        ));
        headers.extend(self.build_responses_compatibility_headers(responses_metadata));
        if let Some(routing_hint) = &responses_metadata.routing_hint {
            headers.insert(X_CODEX_ROUTING_HINT_HEADER, routing_hint.clone());
        }
        if let Some(header_value) = self.generate_attestation_header_for().await {
            headers.insert(X_OAI_ATTESTATION_HEADER, header_value);
        }
        headers.insert(
            OPENAI_BETA_HEADER,
            HeaderValue::from_static(RESPONSES_WEBSOCKETS_V2_BETA_HEADER_VALUE),
        );
        if self.state.include_timing_metrics {
            headers.insert(
                X_RESPONSESAPI_INCLUDE_TIMING_METRICS_HEADER,
                HeaderValue::from_static("true"),
            );
        }
        headers
    }
}

impl Drop for ModelClientSession {
    fn drop(&mut self) {
        let websocket_session = std::mem::take(&mut self.websocket_session);
        self.client
            .store_cached_websocket_session(websocket_session);
    }
}

impl ModelClientSession {
    pub(crate) fn inference_tools_changed(&self, tools: &Arc<[ToolSpec]>) -> bool {
        let previous = self
            .client
            .state
            .last_inference_tools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(Arc::clone(tools));
        previous.is_some_and(|previous| previous != *tools)
    }
}

impl ModelClientSession {
    /// The provider this session's requests go through, with the credential
    /// cache they use (a command-backed credential is cached per provider).
    pub(crate) fn provider(&self) -> &SharedModelProvider {
        &self.client.state.provider
    }

    /// Hammer-reduction preflight: the size of the request body this turn would send.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serialized_request_body_bytes(
        &self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        auth_mode: Option<AuthMode>,
    ) -> Result<usize> {
        let body = match self.client.state.provider.info().wire_api {
            WireApi::Responses => {
                let api_provider = self
                    .client
                    .state
                    .provider
                    .info()
                    .to_api_provider(auth_mode)?;
                let include_internal = self
                    .client
                    .state
                    .provider
                    .include_internal_metadata(&api_provider);
                let mut request = self.client.build_responses_request(
                    prompt,
                    model_info,
                    effort,
                    summary,
                    service_tier,
                    responses_metadata,
                    include_internal,
                )?;
                if self
                    .client
                    .responses_input_needs_synthetic_user_turn(&request.input)
                {
                    append_synthetic_responses_user_turn(&mut request.input);
                }
                serde_json::to_vec(&request)?
            }
            WireApi::Chat => {
                let request = self.client.build_chat_completions_request(
                    prompt,
                    model_info,
                    effort,
                    responses_metadata,
                )?;
                serde_json::to_vec(&request)?
            }
            WireApi::Anthropic => {
                let request = self
                    .client
                    .build_anthropic_messages_request(prompt, model_info, effort)?;
                serde_json::to_vec(&request)?
            }
        };
        Ok(body.len())
    }

    /// #1311 (D171): drops a connection (and the conversation state on it)
    /// opened as another sign-in than the one this request uses.
    fn drop_websocket_of_another_sign_in(&mut self, identity: &ConnectionIdentity) {
        if self.websocket_session.connection.is_some()
            && self.websocket_session.identity.as_ref() != Some(identity)
        {
            self.websocket_session.reset(Some("auth_changed"));
        }
    }
}

impl<'a> ResponsesHttpExecutor<'a> {
    pub(crate) fn new(client: &'a ModelClient) -> Self {
        Self {
            client,
            accounting: None,
        }
    }

    /// Records this executor's requests in `accounting` (D16).
    pub(crate) fn with_accounting(
        mut self,
        accounting: &'a crate::accounting::responses::Slot,
    ) -> Self {
        self.accounting = Some(accounting);
        self
    }

    #[allow(clippy::too_many_arguments)]
    /// Builds shared Responses API transport options and request-body options.
    ///
    /// Keeping option construction in one place ensures request-scoped headers are consistent
    /// regardless of transport choice.
    async fn build_responses_options(
        &self,
        turn_state: &Arc<OnceLock<String>>,
        responses_metadata: &CodexResponsesMetadata,
        compression: Compression,
        use_responses_lite: bool,
    ) -> ApiResponsesOptions {
        ApiResponsesOptions {
            session_id: Some(self.client.responses_session_id(responses_metadata)),
            thread_id: Some(responses_metadata.thread_id.to_string()),
            session_source: Some(self.client.state.session_source.clone()),
            extra_headers: {
                let mut headers = build_responses_headers(
                    self.client.state.beta_features_header.as_deref(),
                    Some(turn_state),
                );
                add_originator_header(&mut headers, self.client.state.originator.as_str());
                headers.extend(
                    self.client
                        .build_responses_compatibility_headers(responses_metadata),
                );
                if let Some(header_value) = self.client.generate_attestation_header_for().await {
                    headers.insert(X_OAI_ATTESTATION_HEADER, header_value);
                }
                add_responses_lite_header(&mut headers, use_responses_lite);
                headers
            },
            compression,
            turn_state: Some(Arc::clone(turn_state)),
        }
    }
}

impl ModelClientSession {
    pub(crate) fn turn_state_with_auth_owner(&self) -> (Option<String>, Option<u64>) {
        let owner = self.client.auth_owner_generation();
        let turn_state = (self.websocket_session.auth_owner_generation == owner)
            .then(|| self.turn_state.get().cloned())
            .flatten();
        (turn_state, owner)
    }

    /// Checks whether the current request is an incremental extension of the previous request.
    /// We only reuse an incremental input delta when non-input request fields are unchanged and
    /// `input` extends or equals the previous known input. Server-returned output items
    /// are treated as part of the baseline so we do not resend them.
    async fn build_chat_completions_options(
        &self,
        responses_metadata: &CodexResponsesMetadata,
    ) -> ApiChatCompletionsOptions {
        ApiChatCompletionsOptions {
            session_id: Some(responses_metadata.session_id.to_string()),
            thread_id: Some(responses_metadata.thread_id.to_string()),
            session_source: Some(self.client.state.session_source.clone()),
            extra_headers: {
                let mut headers = ApiHeaderMap::new();
                if let Ok(header_value) = HeaderValue::from_str(&responses_metadata.installation_id)
                {
                    headers.insert(X_CODEX_INSTALLATION_ID_HEADER, header_value);
                }
                if self.client.state.provider.info().is_openrouter()
                    && let Ok(header_value) =
                        HeaderValue::from_str(&responses_metadata.session_id.to_string())
                {
                    // OpenRouter uses this header as the provider-sticky
                    // conversation key. Its `session-id` header is unrelated,
                    // and `prompt_cache_key` is an OpenAI/Vercel body field.
                    headers.insert("x-session-id", header_value);
                }
                if let Some(header_value) = self.client.generate_attestation_header_for().await {
                    headers.insert(X_OAI_ATTESTATION_HEADER, header_value);
                }
                headers
            },
            same_turn_attempt_index: None,
            actionable_silence_timeout: Some(
                self.client
                    .state
                    .provider
                    .info()
                    .stream_actionable_timeout(),
            ),
        }
    }

    async fn build_anthropic_messages_options(
        &self,
        responses_metadata: &CodexResponsesMetadata,
    ) -> ApiAnthropicMessagesOptions {
        ApiAnthropicMessagesOptions {
            session_id: Some(responses_metadata.session_id.to_string()),
            thread_id: Some(responses_metadata.thread_id.to_string()),
            session_source: Some(self.client.state.session_source.clone()),
            extra_headers: {
                let mut headers = ApiHeaderMap::new();
                if let Ok(header_value) = HeaderValue::from_str(&responses_metadata.installation_id)
                {
                    headers.insert(X_CODEX_INSTALLATION_ID_HEADER, header_value);
                }
                if let Some(header_value) = self.client.generate_attestation_header_for().await {
                    headers.insert(X_OAI_ATTESTATION_HEADER, header_value);
                }
                headers
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(
        name = "model_client.stream_anthropic_messages_api",
        level = "info",
        skip_all,
        fields(
            model = %model_info.slug,
            wire_api = %self.client.state.provider.info().wire_api,
            transport = "anthropic_messages_http",
            http.method = "POST",
            api.path = "messages",
            turn.has_metadata_header = responses_metadata.has_turn_metadata()
        )
    )]
    async fn stream_anthropic_messages_api(
        &self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        responses_metadata: &CodexResponsesMetadata,
        inference_trace: &InferenceTraceContext,
    ) -> Result<ResponseStream> {
        let mut auth_recovery = self.client.unauthorized_recovery();
        let mut provider_auth_recovery_attempted = false;
        let mut pending_retry = PendingUnauthorizedRetry::default();
        let mut transient_rate_limit_retries = 0;
        let mut signed_thinking_history_retry_used = false;
        let mut payload_retry_used = false;
        loop {
            let provider_request_started_at = Instant::now();
            trace_stream_timing(
                "anthropic_http_before_client_setup",
                provider_request_started_at,
            );
            let client_setup = self
                .client
                .current_client_setup(ClientRouting::ConfiguredProvider)
                .await?;
            trace_stream_timing(
                "anthropic_http_after_client_setup",
                provider_request_started_at,
            );
            let evidence = crate::accounting::read_slot(&self.accounting)?
                .map(crate::accounting::transport::ResponseEvidence::new);
            let follow = if evidence.is_some() {
                Some(
                    client_setup.redirect_fallback(
                        &client_setup
                            .api_provider
                            .url_for_path(ANTHROPIC_MESSAGES_ENDPOINT),
                    )?,
                )
            } else {
                None
            };
            let transport = if evidence.is_some() {
                let client = client_setup.api_client_without_redirects(
                    &client_setup
                        .api_provider
                        .url_for_path(ANTHROPIC_MESSAGES_ENDPOINT),
                )?;
                self.client
                    .guarded_transport(ReqwestTransport::from_http_client(client))
            } else {
                self.client.guarded_transport(
                    client_setup.build_api_transport(ANTHROPIC_MESSAGES_ENDPOINT)?,
                )
            };
            let request_auth_context = AuthRequestTelemetryContext::new(
                client_setup.auth.as_ref().map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                pending_retry,
            )
            .map_err(|error| self.client.state.provider.map_api_error(error))?;
            let (request_telemetry, sse_telemetry) = Self::build_streaming_telemetry(
                session_telemetry,
                request_auth_context,
                RequestRouteTelemetry::for_endpoint(ANTHROPIC_MESSAGES_ENDPOINT),
                self.client.state.auth_env_telemetry.clone(),
            );
            let mut options = self
                .build_anthropic_messages_options(responses_metadata)
                .await;
            trace_stream_timing(
                "anthropic_http_before_build_request",
                provider_request_started_at,
            );
            let mut request = self
                .client
                .build_anthropic_messages_request_with_history_repair(
                    prompt,
                    model_info,
                    effort.clone(),
                    signed_thinking_history_retry_used,
                )?;
            if payload_retry_used {
                let payload_report = enforce_anthropic_payload_budget(
                    &mut request,
                    self.client
                        .state
                        .provider
                        .info()
                        .runtime_policy
                        .retry_request_body_max_bytes,
                )?;
                warn!(
                    original_bytes = payload_report.original_bytes,
                    final_bytes = payload_report.final_bytes,
                    omitted_images = payload_report.omitted_images,
                    "retrying Anthropic request with stricter payload budget after HTTP 413"
                );
            }
            trace_stream_timing(
                "anthropic_http_after_build_request",
                provider_request_started_at,
            );
            let inference_trace_attempt = inference_trace.start_attempt();
            inference_trace_attempt.add_request_headers(&mut options.extra_headers);
            inference_trace_attempt.record_started(&request);
            maybe_dump_anthropic_messages_request(&request);
            let transport = transport.map_inner(|inner| {
                crate::accounting::transport::AccountingTransport::new(
                    inner,
                    evidence.clone(),
                    accounting_model_identity(&model_info.slug),
                )
                .with_redirect_fallback(follow)
                .with_configured_routing(
                    self.client
                        .state
                        .provider
                        .info()
                        .chat_completions_provider
                        .clone(),
                )
                .with_configured_routing_options(
                    self.client
                        .state
                        .provider
                        .info()
                        .is_vercel_gateway()
                        .then(|| vercel_gateway_provider_options(&request.model))
                        .flatten(),
                )
            });
            let client = ApiAnthropicMessagesClient::new(
                transport,
                client_setup.api_provider,
                client_setup.api_auth,
            )
            .with_telemetry(Some(request_telemetry), Some(sse_telemetry))
            .with_usage_observer(
                evidence.map(|value| value as Arc<dyn codex_api::AnthropicUsageObserver>),
            );
            trace_stream_timing(
                "anthropic_http_before_stream_request",
                provider_request_started_at,
            );
            let stream_result = client.stream_request(request, options).await;
            trace_stream_timing(
                if stream_result.is_ok() {
                    "anthropic_http_stream_request_ok"
                } else {
                    "anthropic_http_stream_request_err"
                },
                provider_request_started_at,
            );

            match stream_result {
                Ok(mut stream) => {
                    // Main #2115 (Anthropic signed-thinking recovery) on upstream's stream
                    // mapping: take the stream's metadata as `map_response_stream` does, then
                    // map the prefetched prefix plus the rest of the stream.
                    let routing_affinity = stream.routing_affinity.take();
                    let interrupt = stream.interrupt.take();
                    let upstream_request_id = stream.upstream_request_id.take();
                    let prefix = if signed_thinking_history_retry_used {
                        Vec::new()
                    } else {
                        match anthropic_recovery::prefetch(&mut stream, || {
                            inference_trace_attempt.record_cancelled(
                                STREAM_DROPPED_REASON,
                                upstream_request_id.as_deref(),
                                /*output_items*/ &[],
                            );
                        })
                        .await
                        {
                            Ok(prefix) => prefix,
                            Err(error) => {
                                let mapped = self.client.state.provider.map_api_error(error);
                                inference_trace_attempt.record_failed(
                                    &mapped,
                                    upstream_request_id.as_deref(),
                                    /*output_items*/ &[],
                                );
                                signed_thinking_history_retry_used = true;
                                continue;
                            }
                        }
                    };
                    let mut mapped = map_response_events_with_server_state(
                        upstream_request_id,
                        futures::stream::iter(prefix)
                            .chain(stream)
                            .map(anthropic_recovery::terminalize),
                        session_telemetry.clone(),
                        inference_trace_attempt,
                        Arc::clone(&self.client.state.provider),
                        /*server_conversation_update*/ None,
                        /*last_response_tx*/ None,
                    );
                    mapped.interrupt = interrupt;
                    mapped.routing_affinity = routing_affinity;
                    return Ok(mapped);
                }
                Err(ApiError::Transport(
                    unauthorized_transport @ TransportError::Http { status, .. },
                )) if status == StatusCode::UNAUTHORIZED => {
                    let response_debug_context =
                        extract_response_debug_context(&unauthorized_transport);
                    inference_trace_attempt.record_failed(
                        &unauthorized_transport,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    pending_retry = PendingUnauthorizedRetry::from_recovery(
                        handle_unauthorized(
                            unauthorized_transport,
                            &mut auth_recovery,
                            &mut provider_auth_recovery_attempted,
                            session_telemetry,
                            &self.client.state.provider,
                            self.client.event_sender.as_ref(),
                            responses_metadata.turn_id.as_deref(),
                        )
                        .await?,
                    );
                    continue;
                }
                Err(err)
                    if !signed_thinking_history_retry_used
                        && is_anthropic_signed_thinking_history_rejection(&err) =>
                {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let mapped_err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &mapped_err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    warn!(
                        "Anthropic rejected an incomplete signed-thinking assistant response; \
                         removing that response from this request and retrying once"
                    );
                    signed_thinking_history_retry_used = true;
                    continue;
                }
                Err(err) if !payload_retry_used && is_anthropic_payload_too_large(&err) => {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let mapped_err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &mapped_err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    warn!(
                        "Anthropic rejected the request with HTTP 413; pruning additional older \
                         images and retrying once"
                    );
                    payload_retry_used = true;
                    continue;
                }
                Err(err)
                    if transient_rate_limit_retries < MAX_TRANSIENT_RATE_LIMIT_RETRIES
                        && is_transient_upstream_rate_limit(&err) =>
                {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let delay = transient_rate_limit_delay(&err, transient_rate_limit_retries);
                    let mapped_err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &mapped_err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    transient_rate_limit_retries += 1;
                    warn!(
                        attempt = transient_rate_limit_retries,
                        delay_ms = delay.as_millis() as u64,
                        "gateway reported a transient shared upstream rate limit; retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(err)
                    if self
                        .client
                        .drop_vercel_vendor_pin_after_policy_exclusion(&err) =>
                {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let mapped_err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &mapped_err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    continue;
                }
                Err(err) => {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    return Err(err);
                }
            }
        }
    }

    fn get_incremental_items(
        &self,
        request: &ResponsesApiRequest,
        last_response: &LastResponse,
    ) -> std::result::Result<Vec<ResponseItem>, NonIncrementalReason> {
        let previous_request = self
            .websocket_session
            .last_request
            .as_ref()
            .ok_or(NonIncrementalReason::NoPreviousRequest)?;
        if let Some(reason) = responses_request_properties_mismatch(previous_request, request) {
            return Err(NonIncrementalReason::RequestPropertyChanged { reason });
        }

        let response_items = &last_response.items_added;
        let previous_items = previous_request.input.iter().chain(response_items);
        let mut current_items = request.input.iter();
        for previous in previous_items {
            let Some(current) = current_items.next() else {
                return Err(NonIncrementalReason::InputShortened {
                    previous: previous.item_type(),
                });
            };
            if !response_items_equal_ignoring_internal_metadata(previous, current) {
                return Err(NonIncrementalReason::InputMismatch {
                    previous: previous.item_type(),
                    current: current.item_type(),
                });
            }
        }
        Ok(current_items.cloned().collect())
    }

    fn get_last_response(&mut self) -> Option<LastResponse> {
        self.websocket_session
            .last_response_rx
            .take()
            .and_then(|mut receiver| match receiver.try_recv() {
                Ok(last_response) => Some(last_response),
                Err(TryRecvError::Closed) | Err(TryRecvError::Empty) => None,
            })
    }

    fn prepare_websocket_request(
        &mut self,
        request: &ResponsesApiRequest,
    ) -> std::result::Result<WebsocketContinuation, NonIncrementalReason> {
        let last_response = self
            .get_last_response()
            .ok_or(NonIncrementalReason::NoPreviousResponse)?;
        let items = self.get_incremental_items(request, &last_response)?;

        if last_response.response_id.is_empty() {
            return Err(NonIncrementalReason::NoPreviousResponseId);
        }

        Ok(WebsocketContinuation {
            response_id: last_response.response_id,
            items,
            from_untraced_warmup: self.websocket_session.last_response_from_untraced_warmup,
        })
    }

    /// Opportunistically preconnects a websocket for this turn-scoped client session.
    ///
    /// This performs only connection setup; it never sends prompt payloads.
    pub async fn preconnect_websocket(
        &mut self,
        model_info: &ModelInfo,
        service_tier: Option<String>,
        session_telemetry: &SessionTelemetry,
        responses_metadata: &CodexResponsesMetadata,
    ) -> Result<()> {
        if !self.client.responses_websocket_enabled() {
            return Ok(());
        }
        let provider = Arc::clone(&self.client.state.provider);
        let mut auth_recovery = self.client.unauthorized_recovery();
        let mut provider_auth_recovery_attempted = false;
        let mut pending_retry = PendingUnauthorizedRetry::default();
        loop {
            let client_setup = self
                .client
                .current_client_setup(ClientRouting::Workspace)
                .await?;
            let auth_context = AuthRequestTelemetryContext::new(
                client_setup.auth.as_ref().map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                pending_retry,
            )
            .map_err(|error| provider.map_api_error(error))?;
            // #1311 (D171): who the connection is opened as; a connection opened as another
            // sign-in is replaced (`websocket_connection`).
            let identity = ConnectionIdentity::of(
                client_setup.auth.as_ref(),
                &client_setup.api_provider.headers,
                client_setup.api_auth.as_ref(),
            );
            let provenance = crate::accounting::websocket::Provenance::capture(
                self.client.state.provider.info(),
                client_setup.auth.as_ref(),
                &client_setup.api_provider,
            );
            let responses_headers = self
                .client
                .responses_headers(client_setup.auth.as_ref(), &model_info.slug);
            let mut websocket_metadata = responses_metadata.clone();
            websocket_metadata.routing_hint = self.client.build_routing_hint_header(
                client_setup.auth.as_ref(),
                &responses_headers,
                &model_info.slug,
                model_info
                    .service_tier_for_request(service_tier.clone())
                    .as_deref(),
            );
            match self
                .websocket_connection(WebsocketConnectParams {
                    identity,
                    provenance,
                    session_telemetry,
                    api_provider: client_setup.api_provider,
                    auth_revision: client_setup.auth_revision,
                    api_auth: client_setup.api_auth,
                    http_client_factory: client_setup.http_client_factory,
                    auth_owner_generation: client_setup.auth_owner_generation,
                    responses_metadata: &websocket_metadata,
                    auth_context,
                    request_route_telemetry: RequestRouteTelemetry::for_endpoint("/responses"),
                    responses_headers: &responses_headers,
                    runtime_id: client_setup.runtime_id,
                })
                .await
            {
                Ok(_) => return Ok(()),
                Err(ApiError::Transport(TransportError::Http { status, .. }))
                    if status == StatusCode::UPGRADE_REQUIRED =>
                {
                    self.try_switch_fallback_transport(session_telemetry, model_info);
                    return Ok(());
                }
                Err(ApiError::Transport(unauthorized_transport))
                    if provider.is_recoverable_auth_error(&unauthorized_transport) =>
                {
                    pending_retry = PendingUnauthorizedRetry::from_recovery(
                        handle_unauthorized(
                            unauthorized_transport,
                            &mut auth_recovery,
                            &mut provider_auth_recovery_attempted,
                            session_telemetry,
                            &provider,
                            self.client.event_sender.as_ref(),
                            responses_metadata.turn_id.as_deref(),
                        )
                        .await?,
                    );
                }
                Err(err) => return Err(provider.map_api_error(err)),
            }
        }
    }

    /// Returns a websocket connection for this turn.
    #[instrument(
        name = "model_client.websocket_connection",
        level = "info",
        skip_all,
        fields(
            provider = %self.client.state.provider.info().name,
            wire_api = %self.client.state.provider.info().wire_api,
            transport = "responses_websocket",
            api.path = "/responses",
            turn.has_metadata_header = params.responses_metadata.has_turn_metadata()
        )
    )]
    async fn websocket_connection(
        &mut self,
        params: WebsocketConnectParams<'_>,
    ) -> std::result::Result<&ApiWebSocketConnection, ApiError> {
        let WebsocketConnectParams {
            identity,
            provenance,
            session_telemetry,
            api_provider,
            auth_revision,
            api_auth,
            http_client_factory,
            auth_owner_generation,
            responses_metadata,
            auth_context,
            request_route_telemetry,
            responses_headers,
            runtime_id,
        } = params;
        let parent_routing_affinity = if is_guardian_reviewer(responses_headers) {
            responses_metadata.parent_routing_affinity.clone()
        } else {
            None
        };
        let connection_key = ResponsesConnectionKey::new(&api_provider, auth_revision);
        let reset_reason = match self.websocket_session.connection.as_ref() {
            // #1311 (D171): never reuse a connection opened as another sign-in.
            Some(_) if self.websocket_session.identity.as_ref() != Some(&identity) => {
                Some("auth_changed")
            }
            Some(_)
                if self.websocket_session.responses_headers != *responses_headers
                    || self.websocket_session.connection_key.as_ref() != Some(&connection_key)
                    || self.websocket_session.runtime_id != runtime_id
                    || self.websocket_session.parent_routing_affinity
                        != parent_routing_affinity =>
            {
                Some("other")
            }
            Some(conn) if conn.is_closed().await => Some("connection_closed"),
            Some(_) | None => None,
        };
        let needs_new = self.websocket_session.connection.is_none() || reset_reason.is_some();
        // Resolving an external auth provider can change ownership during client setup.
        let owner_changed = self.websocket_session.auth_owner_generation != auth_owner_generation
            || self.client.auth_owner_generation() != auth_owner_generation;
        if owner_changed {
            self.turn_state = Arc::new(OnceLock::new());
        }

        if needs_new || owner_changed {
            self.websocket_session.reset(if owner_changed {
                Some("auth_changed")
            } else {
                reset_reason
            });
            let new_conn = self
                .client
                .connect_websocket(
                    session_telemetry,
                    api_provider,
                    api_auth,
                    &http_client_factory,
                    responses_metadata,
                    auth_context,
                    request_route_telemetry,
                    responses_headers,
                    parent_routing_affinity.as_ref(),
                )
                .await?;
            self.websocket_session.connection = Some(new_conn);
            self.websocket_session.identity = Some(identity);
            self.websocket_session.provenance = Some(provenance);
            self.websocket_session.parent_routing_affinity = parent_routing_affinity;
            self.websocket_session.responses_headers = responses_headers.clone();
            self.websocket_session.runtime_id = runtime_id;
            self.websocket_session.auth_owner_generation = auth_owner_generation;
            self.websocket_session.connection_key = Some(connection_key);
            self.websocket_session
                .set_connection_reused(/*connection_reused*/ false);
        } else {
            self.websocket_session
                .set_connection_reused(/*connection_reused*/ true);
        }

        self.websocket_session
            .connection
            .as_ref()
            .ok_or(ApiError::Stream(
                "websocket connection is unavailable".to_string(),
            ))
    }
}

impl ResponsesHttpExecutor<'_> {
    /// Corbanu (Vercel gateway): continue the server-held conversation with
    /// `previous_response_id` and only the new items, when this request extends the last one.
    fn prepare_http_server_state_request(
        &self,
        request: &mut ResponsesApiRequest,
        logical_request: &ResponsesApiRequest,
        append_user_turn: bool,
    ) {
        let Some(state) = self.client.server_conversation_state() else {
            return;
        };
        if state.last_response.response_id.is_empty() {
            return;
        }
        let incremental_items = match state.last_request.as_ref() {
            Some(previous_request) => incremental_items_for_request(
                logical_request,
                previous_request,
                Some(&state.last_response),
                /*allow_empty_delta*/ false,
            ),
            None => items_after_last_model_output(&logical_request.input),
        };
        if let Some(incremental_items) = incremental_items {
            apply_http_server_state_continuation(
                request,
                state.last_response.response_id,
                incremental_items,
                append_user_turn,
            );
        }
    }

    fn clear_http_server_conversation_state(&self) {
        let handle = self.client.server_conversation_state_handle();
        let mut state = handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = None;
    }

    fn responses_request_compression(&self, auth: Option<&CodexAuth>) -> Compression {
        if self.client.state.enable_request_compression
            && auth.is_some_and(CodexAuth::uses_codex_backend)
            && self.client.state.provider.info().is_openai()
        {
            Compression::Zstd
        } else {
            Compression::None
        }
    }

    /// Streams a turn via the OpenAI Responses API over HTTP.
    ///
    /// Handles reasoning summaries, verbosity, and the `text` controls used for output schemas.
    #[allow(clippy::too_many_arguments)]
    #[instrument(
        name = "model_client.stream_responses_api",
        level = "info",
        skip_all,
        fields(
            model = %model_info.slug,
            wire_api = %self.client.state.provider.info().wire_api,
            transport = "responses_http",
            http.method = "POST",
            api.path = tracing::field::Empty,
            turn.has_metadata_header = responses_metadata.has_turn_metadata()
        )
    )]
    pub(crate) async fn stream_responses_http(
        &self,
        turn_state: &Arc<OnceLock<String>>,
        expected_auth_owner: Option<u64>,
        event_sender: Option<&Sender<ProtocolEvent>>,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        inference_trace: &InferenceTraceContext,
    ) -> Result<ResponseStream> {
        let mut auth_recovery = self.client.unauthorized_recovery();
        let mut provider_auth_recovery_attempted = false;
        let mut pending_retry = PendingUnauthorizedRetry::default();
        let mut transient_rate_limit_retries = 0;
        let mut server_state_retry_used = false;
        let mut legacy_continuation_retry_used = false;
        loop {
            let provider_request_started_at = Instant::now();
            trace_stream_timing(
                "responses_http_before_client_setup",
                provider_request_started_at,
            );
            let client_setup = self
                .client
                .current_client_setup(ClientRouting::Workspace)
                .await?;
            if expected_auth_owner.is_some_and(|owner| {
                Some(owner) != client_setup.auth_owner_generation
                    || Some(owner) != self.client.auth_owner_generation()
            }) {
                return Err(CodexErr::TurnAborted);
            }
            let include_internal = self
                .client
                .state
                .provider
                .include_internal_metadata(&client_setup.api_provider);
            let responses_headers = self
                .client
                .responses_headers(client_setup.auth.as_ref(), &model_info.slug);
            tracing::Span::current().record("api.path", "/responses");
            let responses_url = client_setup.api_provider.url_for_path(RESPONSES_ENDPOINT);
            // Corbanu accounting (D16): a collected request is pinned to the approved endpoint.
            let sampling = match self.accounting.map(crate::accounting::responses::read) {
                Some(slot) => match slot? {
                    Some(deferred) => {
                        deferred
                            .resolve(
                                self.client.state.provider.info(),
                                client_setup.auth.as_ref(),
                                &responses_url,
                            )
                            .await?
                    }
                    None => None,
                },
                None => None,
            };
            let evidence = sampling.map(crate::accounting::transport::ResponseEvidence::new);
            let follow = if evidence.is_some() {
                Some(client_setup.redirect_fallback(&responses_url)?)
            } else {
                None
            };
            let transport = if evidence.is_some() {
                let client = client_setup.api_client_without_redirects(&responses_url)?;
                self.client
                    .guarded_transport(ReqwestTransport::from_http_client(client))
            } else {
                self.client
                    .guarded_transport(client_setup.build_api_transport(RESPONSES_ENDPOINT)?)
            };
            let request_auth_context = AuthRequestTelemetryContext::new(
                client_setup.auth.as_ref().map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                pending_retry,
            )
            .map_err(|error| self.client.state.provider.map_api_error(error))?;
            let (request_telemetry, sse_telemetry) = ModelClientSession::build_streaming_telemetry(
                session_telemetry,
                request_auth_context,
                RequestRouteTelemetry::for_endpoint("/responses"),
                self.client.state.auth_env_telemetry.clone(),
            );
            let compression = self.responses_request_compression(client_setup.auth.as_ref());
            let mut options = self
                .build_responses_options(
                    turn_state,
                    responses_metadata,
                    compression,
                    model_info.use_responses_lite,
                )
                .await;

            let mut request = self.client.build_responses_request(
                prompt,
                model_info,
                effort.clone(),
                summary,
                service_tier.clone(),
                responses_metadata,
                include_internal,
            )?;
            self.client.set_guardian_metadata(
                &mut request.client_metadata,
                responses_metadata.parent_response_id.as_deref(),
                client_setup.auth.as_ref(),
                &responses_headers,
            );
            if is_guardian_reviewer(&responses_headers) {
                request.service_tier = None;
            }
            if let Some(header_value) = self.client.build_routing_hint_header(
                client_setup.auth.as_ref(),
                &responses_headers,
                &request.model,
                request.service_tier.as_deref(),
            ) {
                options
                    .extra_headers
                    .insert(X_CODEX_ROUTING_HINT_HEADER, header_value);
            }
            request.access_programs = cyber_access_program::for_auth(
                client_setup.auth.as_ref(),
                prompt.cyber_access_program,
                self.client.api_key_cyber_access_programs,
            )?;
            let logical_request = request.clone();
            let uses_http_server_state = self.client.state.provider.info().is_vercel()
                && !self
                    .client
                    .state
                    .http_server_state_rejected
                    .load(Ordering::Relaxed);
            let append_user_turn = self
                .client
                .responses_input_needs_synthetic_user_turn(&logical_request.input);
            let omitted_legacy_synthetic_turn = self
                .client
                .responses_input_omits_legacy_synthetic_turn(&logical_request.input);
            if uses_http_server_state {
                self.prepare_http_server_state_request(
                    &mut request,
                    &logical_request,
                    append_user_turn,
                );
            }
            if append_user_turn && request.previous_response_id.is_none() {
                append_synthetic_responses_user_turn(&mut request.input);
            }
            let request_used_server_state = request.previous_response_id.is_some();
            self.client
                .prepare_response_items_for_request(&mut request.input);
            let request_session_telemetry =
                session_telemetry_for_request(session_telemetry, &request);
            options.extra_headers.extend(responses_headers);
            let interceptors = crate::model_request::prepare(
                &self.client.request_contributors,
                &self.client.state.thread_id.to_string(),
                &model_info.slug,
                codex_extension_api::ModelRequestKind::Generation,
                &mut request.client_metadata,
            );
            let inference_trace_attempt = inference_trace.start_attempt();
            inference_trace_attempt.add_request_headers(&mut options.extra_headers);
            if let Some(input) = tool_metadata::bounded_input(&request, &request.input) {
                if let Some(recorder) = &self.client.executed_tool_calls {
                    recorder.invalidate_wire_inventory_loss(&request.input, &input);
                }
                request.input = input;
            }
            inference_trace_attempt.record_started(&request);
            maybe_dump_responses_request(&request);
            let transport = transport.map_inner(|inner| {
                crate::accounting::transport::AccountingTransport::new(
                    inner,
                    evidence.clone(),
                    accounting_model_identity(&model_info.slug),
                )
                .with_redirect_fallback(follow)
                .with_configured_routing(
                    self.client
                        .state
                        .provider
                        .info()
                        .chat_completions_provider
                        .clone(),
                )
                .with_configured_routing_options(
                    self.client
                        .state
                        .provider
                        .info()
                        .is_vercel_gateway()
                        .then(|| vercel_gateway_provider_options(&request.model))
                        .flatten(),
                )
                .with_tier(request.service_tier.clone())
            });
            let client = ApiResponsesClient::new(
                transport,
                client_setup.api_provider,
                client_setup.api_auth,
            )
            .with_telemetry(Some(request_telemetry), Some(sse_telemetry))
            .with_usage_observer(
                evidence.map(|value| value as Arc<dyn codex_api::ResponsesUsageObserver>),
            );
            trace_stream_timing(
                "responses_http_before_stream_request",
                provider_request_started_at,
            );
            let stream_result = client.stream_request(request, options).await;
            trace_stream_timing(
                if stream_result.is_ok() {
                    "responses_http_stream_request_ok"
                } else {
                    "responses_http_stream_request_err"
                },
                provider_request_started_at,
            );

            match stream_result {
                Ok(stream) => {
                    let server_conversation_update = uses_http_server_state.then(|| {
                        (
                            self.client.server_conversation_state_handle(),
                            logical_request.clone(),
                        )
                    });
                    return Ok(map_response_stream(
                        stream,
                        request_session_telemetry,
                        inference_trace_attempt,
                        Arc::clone(&self.client.state.provider),
                        server_conversation_update,
                        interceptors,
                        /*last_response_tx*/ None,
                    ));
                }
                Err(ApiError::Transport(unauthorized_transport))
                    if self
                        .client
                        .state
                        .provider
                        .is_recoverable_auth_error(&unauthorized_transport) =>
                {
                    let response_debug_context =
                        extract_response_debug_context(&unauthorized_transport);
                    inference_trace_attempt.record_failed(
                        &unauthorized_transport,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    pending_retry = PendingUnauthorizedRetry::from_recovery(
                        handle_unauthorized(
                            unauthorized_transport,
                            &mut auth_recovery,
                            &mut provider_auth_recovery_attempted,
                            session_telemetry,
                            &self.client.state.provider,
                            event_sender,
                            responses_metadata.turn_id.as_deref(),
                        )
                        .await?,
                    );
                    continue;
                }
                Err(ApiError::Transport(
                    bad_request_transport @ TransportError::Http { status, .. },
                )) if status == StatusCode::BAD_REQUEST
                    && request_used_server_state
                    && !server_state_retry_used =>
                {
                    let response_debug_context =
                        extract_response_debug_context(&bad_request_transport);
                    inference_trace_attempt.record_failed(
                        &bad_request_transport,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    warn!(
                        "server-state responses continuation rejected with 400; using full-context requests for the rest of this session"
                    );
                    self.client
                        .state
                        .http_server_state_rejected
                        .store(true, Ordering::Relaxed);
                    self.clear_http_server_conversation_state();
                    server_state_retry_used = true;
                    continue;
                }
                Err(ApiError::Transport(
                    bad_request_transport @ TransportError::Http { status, .. },
                )) if status == StatusCode::BAD_REQUEST
                    && !request_used_server_state
                    && omitted_legacy_synthetic_turn
                    && !legacy_continuation_retry_used =>
                {
                    let response_debug_context =
                        extract_response_debug_context(&bad_request_transport);
                    inference_trace_attempt.record_failed(
                        &bad_request_transport,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    warn!(
                        "provider rejected a tool continuation without a synthetic user turn; restoring it for this session"
                    );
                    self.client
                        .state
                        .legacy_synthetic_continuation
                        .store(true, Ordering::Relaxed);
                    legacy_continuation_retry_used = true;
                    continue;
                }
                Err(err)
                    if transient_rate_limit_retries < MAX_TRANSIENT_RATE_LIMIT_RETRIES
                        && is_transient_upstream_rate_limit(&err) =>
                {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let delay = transient_rate_limit_delay(&err, transient_rate_limit_retries);
                    let mapped_err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &mapped_err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    transient_rate_limit_retries += 1;
                    warn!(
                        attempt = transient_rate_limit_retries,
                        delay_ms = delay.as_millis() as u64,
                        "gateway reported a transient shared upstream rate limit; retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(err)
                    if self
                        .client
                        .drop_vercel_vendor_pin_after_policy_exclusion(&err) =>
                {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let mapped_err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &mapped_err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    continue;
                }
                Err(err) => {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    return Err(err);
                }
            }
        }
    }
}

impl ModelClientSession {
    /// Streams a turn via the OpenAI-compatible Chat Completions API.
    #[allow(clippy::too_many_arguments)]
    #[instrument(
        name = "model_client.stream_chat_completions_api",
        level = "info",
        skip_all,
        fields(
            model = %model_info.slug,
            wire_api = %self.client.state.provider.info().wire_api,
            transport = "chat_completions_http",
            http.method = "POST",
            api.path = "chat/completions",
            turn.has_metadata_header = responses_metadata.has_turn_metadata()
        )
    )]
    async fn stream_chat_completions_api(
        &self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        responses_metadata: &CodexResponsesMetadata,
        inference_trace: &InferenceTraceContext,
        same_turn_attempt_index: u64,
    ) -> Result<ResponseStream> {
        let plan_request_id = self
            .client
            .state
            .provider
            .info()
            .is_pfterminal_plan()
            .then(|| uuid::Uuid::new_v4().to_string());
        let mut auth_recovery = self.client.unauthorized_recovery();
        let mut provider_auth_recovery_attempted = false;
        let mut pending_retry = PendingUnauthorizedRetry::default();
        let mut transient_rate_limit_retries = 0;
        loop {
            let provider_request_started_at = Instant::now();
            trace_stream_timing("chat_http_before_client_setup", provider_request_started_at);
            let client_setup = self
                .client
                .current_client_setup(ClientRouting::ConfiguredProvider)
                .await?;
            trace_stream_timing("chat_http_after_client_setup", provider_request_started_at);
            let request_auth_context = AuthRequestTelemetryContext::new(
                client_setup.auth.as_ref().map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                pending_retry,
            )
            .map_err(|error| self.client.state.provider.map_api_error(error))?;
            let (request_telemetry, sse_telemetry) = Self::build_streaming_telemetry(
                session_telemetry,
                request_auth_context,
                RequestRouteTelemetry::for_endpoint(CHAT_COMPLETIONS_ENDPOINT),
                self.client.state.auth_env_telemetry.clone(),
            );
            let mut options = self
                .build_chat_completions_options(responses_metadata)
                .await;
            if let Some(request_id) = plan_request_id.as_deref()
                && let Ok(value) = HeaderValue::from_str(request_id)
            {
                options
                    .extra_headers
                    .insert("x-pfterminal-request-id", value);
            }
            options.same_turn_attempt_index = Some(same_turn_attempt_index);
            trace_stream_timing(
                "chat_http_before_build_request",
                provider_request_started_at,
            );
            let request = self.client.build_chat_completions_request(
                prompt,
                model_info,
                effort.clone(),
                responses_metadata,
            )?;
            trace_stream_timing("chat_http_after_build_request", provider_request_started_at);
            // Agent-identity sessions collect like any other. Excluding them here
            // meant a whole class of sessions recorded nothing at all on every
            // provider, while the policy that decides their economics already
            // treats an agent identity as subscription capacity.
            let sampling = match crate::accounting::chat::read(&self.chat_accounting)? {
                Some(deferred) => {
                    deferred
                        .resolve(
                            self.client.state.provider.info(),
                            client_setup.auth.as_ref(),
                            &client_setup
                                .api_provider
                                .url_for_path(CHAT_COMPLETIONS_ENDPOINT),
                            &request,
                        )
                        .await?
                }
                None => None,
            };
            let evidence = sampling.map(crate::accounting::transport::ResponseEvidence::new);
            let follow = if evidence.is_some() {
                Some(
                    client_setup.redirect_fallback(
                        &client_setup
                            .api_provider
                            .url_for_path(CHAT_COMPLETIONS_ENDPOINT),
                    )?,
                )
            } else {
                None
            };
            let transport = if evidence.is_some() {
                let client = client_setup.api_client_without_redirects(
                    &client_setup
                        .api_provider
                        .url_for_path(CHAT_COMPLETIONS_ENDPOINT),
                )?;
                self.client
                    .guarded_transport(ReqwestTransport::from_http_client(client))
            } else {
                self.client
                    .guarded_transport(client_setup.build_api_transport(CHAT_COMPLETIONS_ENDPOINT)?)
            };
            let transport = transport.map_inner(|inner| {
                crate::accounting::transport::AccountingTransport::new(
                    inner,
                    evidence.clone(),
                    accounting_model_identity(&model_info.slug),
                )
                .with_redirect_fallback(follow)
                .with_configured_routing(
                    self.client
                        .state
                        .provider
                        .info()
                        .chat_completions_provider
                        .clone(),
                )
                .with_configured_routing_options(
                    self.client
                        .state
                        .provider
                        .info()
                        .is_vercel_gateway()
                        .then(|| vercel_gateway_provider_options(&request.model))
                        .flatten(),
                )
                .with_configured_plugins(
                    // Only the Chat request type carries `plugins`; OpenRouter web
                    // search rides it, emitted by this client from the provider and
                    // the session's tool set.
                    serde_json::to_value(request.plugins.clone())
                        .ok()
                        .filter(|value| !value.is_null()),
                )
            });
            let inference_trace_attempt = inference_trace.start_attempt();
            inference_trace_attempt.add_request_headers(&mut options.extra_headers);
            inference_trace_attempt.record_started(&request);
            maybe_dump_chat_request(&request);
            let client = ApiChatCompletionsClient::new(
                transport,
                client_setup.api_provider,
                client_setup.api_auth,
            )
            .with_telemetry(Some(request_telemetry), Some(sse_telemetry))
            .with_usage_observer(
                evidence.map(|value| value as Arc<dyn codex_api::ChatUsageObserver>),
            );
            trace_stream_timing(
                "chat_http_before_stream_request",
                provider_request_started_at,
            );
            let stream_result = client.stream_request(request, options).await;
            trace_stream_timing(
                if stream_result.is_ok() {
                    "chat_http_stream_request_ok"
                } else {
                    "chat_http_stream_request_err"
                },
                provider_request_started_at,
            );

            match stream_result {
                Ok(stream) => {
                    return Ok(map_response_stream(
                        stream,
                        session_telemetry.clone(),
                        inference_trace_attempt,
                        Arc::clone(&self.client.state.provider),
                        /*server_conversation_update*/ None,
                        /*interceptors*/ Vec::new(),
                        /*last_response_tx*/ None,
                    ));
                }
                Err(ApiError::Transport(
                    unauthorized_transport @ TransportError::Http { status, .. },
                )) if status == StatusCode::UNAUTHORIZED => {
                    let response_debug_context =
                        extract_response_debug_context(&unauthorized_transport);
                    inference_trace_attempt.record_failed(
                        &unauthorized_transport,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    pending_retry = PendingUnauthorizedRetry::from_recovery(
                        handle_unauthorized(
                            unauthorized_transport,
                            &mut auth_recovery,
                            &mut provider_auth_recovery_attempted,
                            session_telemetry,
                            &self.client.state.provider,
                            self.client.event_sender.as_ref(),
                            responses_metadata.turn_id.as_deref(),
                        )
                        .await?,
                    );
                    continue;
                }
                Err(err)
                    if transient_rate_limit_retries < MAX_TRANSIENT_RATE_LIMIT_RETRIES
                        && is_transient_upstream_rate_limit(&err) =>
                {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let delay = transient_rate_limit_delay(&err, transient_rate_limit_retries);
                    let mapped_err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &mapped_err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    transient_rate_limit_retries += 1;
                    warn!(
                        attempt = transient_rate_limit_retries,
                        delay_ms = delay.as_millis() as u64,
                        "gateway reported a transient shared upstream rate limit; retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(err)
                    if self
                        .client
                        .drop_vercel_vendor_pin_after_policy_exclusion(&err) =>
                {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let mapped_err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &mapped_err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    continue;
                }
                Err(err) => {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let err = self.client.state.provider.map_api_error(err);
                    inference_trace_attempt.record_failed(
                        &err,
                        response_debug_context.request_id.as_deref(),
                        /*output_items*/ &[],
                    );
                    return Err(err);
                }
            }
        }
    }

    /// Streams a turn via the Responses API over WebSocket transport.
    #[allow(clippy::too_many_arguments)]
    #[instrument(
        name = "model_client.stream_responses_websocket",
        level = "info",
        skip_all,
        fields(
            model = %model_info.slug,
            wire_api = %self.client.state.provider.info().wire_api,
            transport = "responses_websocket",
            api.path = tracing::field::Empty,
            turn.has_metadata_header = responses_metadata.has_turn_metadata(),
            websocket.warmup = warmup
        )
    )]
    async fn stream_responses_websocket(
        &mut self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        warmup: bool,
        request_trace: Option<W3cTraceContext>,
        inference_trace: &InferenceTraceContext,
    ) -> Result<WebsocketStreamOutcome> {
        let after_prewarm = !warmup && self.websocket_session.last_response_from_untraced_warmup;
        let provider = Arc::clone(&self.client.state.provider);
        let mut auth_recovery = self.client.unauthorized_recovery();
        let mut provider_auth_recovery_attempted = false;
        let mut pending_retry = PendingUnauthorizedRetry::default();
        loop {
            let client_setup = self
                .client
                .current_client_setup(ClientRouting::Workspace)
                .await?;
            // #1311 (D171): a connection opened as another sign-in is never reused.
            let identity = ConnectionIdentity::of(
                client_setup.auth.as_ref(),
                &client_setup.api_provider.headers,
                client_setup.api_auth.as_ref(),
            );
            self.drop_websocket_of_another_sign_in(&identity);
            let include_internal = self
                .client
                .state
                .provider
                .include_internal_metadata(&client_setup.api_provider);
            let responses_headers = self
                .client
                .responses_headers(client_setup.auth.as_ref(), &model_info.slug);
            tracing::Span::current().record("api.path", "/responses");
            let request_auth_context = AuthRequestTelemetryContext::new(
                client_setup.auth.as_ref().map(CodexAuth::auth_mode),
                client_setup.api_auth.as_ref(),
                client_setup.agent_identity_telemetry.clone(),
                pending_retry,
            )
            .map_err(|error| self.client.state.provider.map_api_error(error))?;
            let mut request = self.client.build_responses_request(
                prompt,
                model_info,
                effort.clone(),
                summary,
                service_tier.clone(),
                responses_metadata,
                include_internal,
            )?;
            // Warmup is collected too. Skipping it here meant the prompt this
            // client sends to prime the cache - and the cache writes the provider
            // charges for - never reached the ledger on any provider.
            let deferred = crate::accounting::responses::read(&self.responses_accounting)?
                .filter(|value| !matches!(value.websocket_endpoint(), Ok(None)));
            let provenance = crate::accounting::websocket::Provenance::capture(
                self.client.state.provider.info(),
                client_setup.auth.as_ref(),
                &client_setup.api_provider,
            );
            let sampling = if let Some(deferred) = &deferred {
                let open = self.websocket_session.connection.is_some();
                let cached = self.websocket_session.provenance.as_ref().filter(|_| open);
                if open && cached.is_none() {
                    // Not attributable: send it unrecorded.
                    deferred.reject();
                    crate::accounting::gap(
                        "websocket admission",
                        "open connection has no recorded provenance",
                    );
                    None
                } else if provenance.validate(deferred, cached)? {
                    deferred
                        .resolve(
                            self.client.state.provider.info(),
                            client_setup.auth.as_ref(),
                            &client_setup.api_provider.url_for_path(RESPONSES_ENDPOINT),
                        )
                        .await?
                } else {
                    None
                }
            } else {
                None
            };
            if is_guardian_reviewer(&responses_headers) {
                request.service_tier = None;
            }
            request.access_programs = cyber_access_program::for_auth(
                client_setup.auth.as_ref(),
                prompt.cyber_access_program,
                self.client.api_key_cyber_access_programs,
            )?;
            let mut websocket_metadata = responses_metadata.clone();
            websocket_metadata.routing_hint = self.client.build_routing_hint_header(
                client_setup.auth.as_ref(),
                &responses_headers,
                &request.model,
                request.service_tier.as_deref(),
            );
            let request_session_telemetry = if warmup {
                // `generate=false` prewarm is connection setup, not an inference request.
                session_telemetry.clone()
            } else {
                session_telemetry_for_request(session_telemetry, &request)
            };
            match self
                .websocket_connection(WebsocketConnectParams {
                    identity,
                    provenance,
                    session_telemetry,
                    api_provider: client_setup.api_provider,
                    auth_revision: client_setup.auth_revision,
                    api_auth: client_setup.api_auth,
                    http_client_factory: client_setup.http_client_factory,
                    auth_owner_generation: client_setup.auth_owner_generation,
                    runtime_id: client_setup.runtime_id,
                    responses_metadata: &websocket_metadata,
                    auth_context: request_auth_context,
                    request_route_telemetry: RequestRouteTelemetry::for_endpoint("/responses"),
                    responses_headers: &responses_headers,
                })
                .await
            {
                Ok(_) => {}
                // A websocket connection never follows a redirect, recorded
                // or not; accounting only stops recording this turn.
                Err(err @ ApiError::Transport(TransportError::Http { status, .. }))
                    if status.is_redirection() && sampling.is_some() =>
                {
                    if let Some(deferred) = &deferred {
                        deferred.reject();
                    }
                    crate::accounting::gap(
                        "websocket connect",
                        format_args!("provider redirected the connection ({status})"),
                    );
                    return Err(self.client.state.provider.map_api_error(err));
                }
                Err(ApiError::Transport(TransportError::Http { status, .. }))
                    if status == StatusCode::UPGRADE_REQUIRED =>
                {
                    return Ok(WebsocketStreamOutcome::FallbackToHttp);
                }
                Err(ApiError::Transport(unauthorized_transport))
                    if provider.is_recoverable_auth_error(&unauthorized_transport) =>
                {
                    pending_retry = PendingUnauthorizedRetry::from_recovery(
                        handle_unauthorized(
                            unauthorized_transport,
                            &mut auth_recovery,
                            &mut provider_auth_recovery_attempted,
                            session_telemetry,
                            &provider,
                            self.client.event_sender.as_ref(),
                            responses_metadata.turn_id.as_deref(),
                        )
                        .await?,
                    );
                    continue;
                }
                Err(err) => return Err(provider.map_api_error(err)),
            }

            let mut client_metadata = self.client.build_ws_client_metadata(
                responses_metadata,
                include_internal,
                model_info.use_responses_lite,
            );
            if let Some(turn_state) = self.turn_state.get() {
                client_metadata.insert(X_CODEX_TURN_STATE_HEADER.to_string(), turn_state.clone());
            }
            let (continuation, mode, reason, previous_item_type, current_item_type) =
                match self.prepare_websocket_request(&request) {
                    Ok(continuation) => (
                        Some(continuation),
                        "incremental",
                        "incremental",
                        "none",
                        "none",
                    ),
                    Err(failure) => {
                        let reason = self
                            .websocket_session
                            .continuation_reset_reason
                            .take()
                            .unwrap_or(if self.websocket_session.last_request.is_some() {
                                failure.as_str()
                            } else if self.client.restored_history {
                                "restored_history"
                            } else {
                                "no_previous_request"
                            });
                        let (previous_item_type, current_item_type) = failure.item_types();
                        trace!(
                            reason,
                            previous_item_type, current_item_type, "non-incremental request"
                        );
                        (None, "full", reason, previous_item_type, current_item_type)
                    }
                };
            let previous_response_id_from_untraced_warmup = continuation
                .as_ref()
                .is_some_and(|c| c.from_untraced_warmup);
            let inference_trace_attempt = if warmup {
                // Prewarm sends `generate=false`; it is connection setup, not a
                // model inference attempt that should appear in rollout traces.
                InferenceTraceAttempt::disabled()
            } else {
                inference_trace.start_attempt()
            };
            if previous_response_id_from_untraced_warmup {
                // The transport can reuse an untraced warmup response id and omit the
                // already-sent input, but rollout replay needs the logical model-visible
                // request rather than the compressed websocket delta.
                inference_trace_attempt.record_started(&request);
            }

            let (previous_response_id, mut incremental_items) = match continuation {
                Some(continuation) => (Some(continuation.response_id), Some(continuation.items)),
                None => (None, None),
            };
            let original_item_ids = if let Some(incremental_items) = &mut incremental_items {
                self.client
                    .prepare_response_items_for_request(incremental_items);
                None
            } else {
                let original_item_ids = request
                    .input
                    .iter()
                    .map(|item| item.id().cloned())
                    .collect::<Vec<_>>();
                self.client
                    .prepare_response_items_for_request(&mut request.input);
                Some(original_item_ids)
            };
            let mut ws_payload = ResponseCreateWsRequest {
                previous_response_id,
                input: incremental_items.as_deref().unwrap_or(&request.input),
                generate: if warmup { Some(false) } else { None },
                client_metadata: response_create_client_metadata(
                    Some(client_metadata),
                    request_trace.as_ref(),
                ),
                ..ResponseCreateWsRequest::from(&request)
            };
            self.client.set_guardian_metadata(
                &mut ws_payload.client_metadata,
                responses_metadata.parent_response_id.as_deref(),
                client_setup.auth.as_ref(),
                &responses_headers,
            );
            let interceptors = crate::model_request::prepare(
                &self.client.request_contributors,
                &self.client.state.thread_id.to_string(),
                &model_info.slug,
                if warmup {
                    codex_extension_api::ModelRequestKind::Warmup
                } else {
                    codex_extension_api::ModelRequestKind::Generation
                },
                &mut ws_payload.client_metadata,
            );
            let mut ws_request = ResponsesWsRequest::ResponseCreate(ws_payload);
            stamp_ws_stream_request_start_ms(&mut ws_request);
            let ResponsesWsRequest::ResponseCreate(payload) = &ws_request;
            let bounded_input = tool_metadata::bounded_input(&ws_request, payload.input);
            if let Some(input) = bounded_input.as_deref() {
                if let Some(recorder) = &self.client.executed_tool_calls {
                    recorder.invalidate_wire_inventory_loss(payload.input, input);
                }
                let ResponsesWsRequest::ResponseCreate(payload) = &mut ws_request;
                payload.input = input;
            }
            if !previous_response_id_from_untraced_warmup {
                inference_trace_attempt.record_started(&ws_request);
            }

            let websocket_connection =
                self.websocket_session.connection.as_ref().ok_or_else(|| {
                    self.client.state.provider.map_api_error(ApiError::Stream(
                        "websocket connection is unavailable".to_string(),
                    ))
                })?;
            if let Some(binding) = self.client.stage_one_memory_binding.get() {
                binding
                    .check()
                    .await
                    .map_err(|reason| CodexErr::InvalidRequest(reason.to_string()))?;
            }
            let admission = match (sampling, deferred.as_ref()) {
                (Some(sampling), Some(deferred)) => {
                    match (
                        self.websocket_session.provenance.clone(),
                        deferred.websocket_endpoint()?,
                    ) {
                        (Some(established), Some(expected)) => {
                            Some(crate::accounting::websocket::Admission::new(
                                sampling,
                                established,
                                expected,
                                self.client.stage_one_memory_binding.clone(),
                            ))
                        }
                        // Not attributable: send it unrecorded.
                        (established, _) => {
                            deferred.reject();
                            crate::accounting::gap(
                                "websocket admission",
                                if established.is_none() {
                                    "connection has no recorded provenance"
                                } else {
                                    "turn has no approved websocket endpoint"
                                },
                            );
                            None
                        }
                    }
                }
                _ => None,
            };
            request_session_telemetry.counter(
                WEBSOCKET_CONTINUATION_COUNT_METRIC,
                /*inc*/ 1,
                &[
                    ("mode", mode),
                    ("reason", reason),
                    ("previous_item_type", previous_item_type),
                    ("current_item_type", current_item_type),
                    ("phase", if warmup { "warmup" } else { "generation" }),
                    (
                        "after_prewarm",
                        if after_prewarm { "true" } else { "false" },
                    ),
                ],
            );
            let stream_result = websocket_connection
                .stream_request_with_accounting(
                    ws_request,
                    self.websocket_session.connection_reused(),
                    Some(Arc::clone(&self.turn_state)),
                    admission,
                )
                .await;
            if let Some(original_item_ids) = original_item_ids {
                for (item, original_item_id) in request.input.iter_mut().zip(original_item_ids) {
                    item.set_id(original_item_id);
                }
            }
            self.websocket_session.last_request = Some(request);
            self.websocket_session.last_response_from_untraced_warmup = warmup;
            let stream_result = stream_result.map_err(|err| {
                let response_debug_context = extract_response_debug_context_from_api_error(&err);
                let err = self.client.state.provider.map_api_error(err);
                inference_trace_attempt.record_failed(
                    &err,
                    response_debug_context.request_id.as_deref(),
                    /*output_items*/ &[],
                );
                err
            })?;
            let (last_response_tx, last_response_rx) = oneshot::channel();
            let stream = map_response_stream(
                stream_result,
                request_session_telemetry,
                inference_trace_attempt,
                Arc::clone(&self.client.state.provider),
                /*server_conversation_update*/ None,
                interceptors,
                Some(last_response_tx),
            );
            self.websocket_session.last_response_rx = Some(last_response_rx);
            return Ok(WebsocketStreamOutcome::Stream(stream));
        }
    }

    /// Builds request and SSE telemetry for streaming API calls.
    fn build_streaming_telemetry(
        session_telemetry: &SessionTelemetry,
        auth_context: AuthRequestTelemetryContext,
        request_route_telemetry: RequestRouteTelemetry,
        auth_env_telemetry: AuthEnvTelemetry,
    ) -> (Arc<dyn RequestTelemetry>, Arc<dyn SseTelemetry>) {
        let telemetry = Arc::new(ApiTelemetry::new(
            session_telemetry.clone(),
            auth_context,
            request_route_telemetry,
            auth_env_telemetry,
        ));
        let request_telemetry: Arc<dyn RequestTelemetry> = telemetry.clone();
        let sse_telemetry: Arc<dyn SseTelemetry> = telemetry;
        (request_telemetry, sse_telemetry)
    }

    /// Builds telemetry for the Responses API WebSocket transport.
    fn build_websocket_telemetry(
        session_telemetry: &SessionTelemetry,
        auth_context: AuthRequestTelemetryContext,
        request_route_telemetry: RequestRouteTelemetry,
        auth_env_telemetry: AuthEnvTelemetry,
    ) -> Arc<dyn WebsocketTelemetry> {
        let telemetry = Arc::new(ApiTelemetry::new(
            session_telemetry.clone(),
            auth_context,
            request_route_telemetry,
            auth_env_telemetry,
        ));
        let websocket_telemetry: Arc<dyn WebsocketTelemetry> = telemetry;
        websocket_telemetry
    }

    /// Whether this session has sent a request over its WebSocket, such as a
    /// completed warm-up. A warm-up that fell back to HTTP sent nothing.
    pub(crate) fn sent_websocket_request(&self) -> bool {
        self.websocket_session.last_request.is_some()
    }

    /// Whether a previous request prepared a connection that is not known to be closed.
    /// The next request still validates provider, auth, and headers before reuse.
    pub(crate) async fn is_websocket_prewarmed(&self) -> bool {
        if self.websocket_session.last_request.is_some()
            && let Some(connection) = self.websocket_session.connection.as_ref()
        {
            !connection.is_closed().await
        } else {
            false
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prewarm_websocket(
        &mut self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
    ) -> Result<()> {
        if !self.client.responses_websocket_enabled() {
            return Ok(());
        }
        if self.is_websocket_prewarmed().await {
            return Ok(());
        }

        let disabled_trace = InferenceTraceContext::disabled();
        match self
            .stream_responses_websocket(
                prompt,
                model_info,
                session_telemetry,
                effort,
                summary,
                service_tier,
                responses_metadata,
                /*warmup*/ true,
                current_span_w3c_trace_context(),
                &disabled_trace,
            )
            .await
        {
            Ok(WebsocketStreamOutcome::Stream(mut stream)) => {
                // Wait for the v2 warmup request to complete before sending the first turn request.
                while let Some(event) = stream.next().await {
                    match event {
                        Ok(ResponseEvent::Completed { .. }) => break,
                        Err(err) => return Err(err),
                        _ => {}
                    }
                }
                Ok(())
            }
            Ok(WebsocketStreamOutcome::FallbackToHttp) => {
                self.try_switch_fallback_transport(session_telemetry, model_info);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Streams a single model request within the current turn.
    ///
    /// The caller is responsible for passing per-turn settings explicitly (model selection,
    /// reasoning settings, telemetry context, and turn metadata). This method will prefer the
    /// Responses WebSocket transport when the provider supports it and it remains healthy, and will
    /// fall back to the HTTP Responses API transport otherwise. The trace context may be enabled or
    /// disabled, but is always explicit so transport paths do not need separate trace/no-trace
    /// branches.
    pub async fn stream(
        &mut self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        inference_trace: &InferenceTraceContext,
    ) -> Result<ResponseStream> {
        self.stream_with_same_turn_attempt(
            prompt,
            model_info,
            session_telemetry,
            effort,
            summary,
            service_tier,
            responses_metadata,
            inference_trace,
            /*same_turn_attempt_index*/ 1,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn stream_with_same_turn_attempt(
        &mut self,
        prompt: &Prompt,
        model_info: &ModelInfo,
        session_telemetry: &SessionTelemetry,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        service_tier: Option<String>,
        responses_metadata: &CodexResponsesMetadata,
        inference_trace: &InferenceTraceContext,
        same_turn_attempt_index: u64,
    ) -> Result<ResponseStream> {
        // PF-28-S01: the model sink never receives a managed secret, even one
        // recorded before the value was registered.
        let gated_prompt = crate::security::disclosure_gate::gate_prompt(prompt);
        let prompt = gated_prompt.as_ref().unwrap_or(prompt);
        let wire_api = self.client.state.provider.info().wire_api;
        match wire_api {
            WireApi::Responses => {
                if self.client.responses_websocket_enabled() {
                    let request_trace = current_span_w3c_trace_context();
                    match Box::pin(self.stream_responses_websocket(
                        prompt,
                        model_info,
                        session_telemetry,
                        effort.clone(),
                        summary,
                        service_tier.clone(),
                        responses_metadata,
                        /*warmup*/ false,
                        request_trace,
                        inference_trace,
                    ))
                    .await?
                    {
                        WebsocketStreamOutcome::Stream(stream) => return Ok(stream),
                        WebsocketStreamOutcome::FallbackToHttp => {
                            self.try_switch_fallback_transport(session_telemetry, model_info);
                        }
                    }
                }

                Box::pin(
                    ResponsesHttpExecutor::new(&self.client)
                        .with_accounting(&self.responses_accounting)
                        .stream_responses_http(
                            &self.turn_state,
                            /*expected_auth_owner*/ None,
                            self.client.event_sender.as_ref(),
                            prompt,
                            model_info,
                            session_telemetry,
                            effort,
                            summary,
                            service_tier,
                            responses_metadata,
                            inference_trace,
                        ),
                )
                .await
            }
            WireApi::Chat => {
                Box::pin(self.stream_chat_completions_api(
                    prompt,
                    model_info,
                    session_telemetry,
                    effort,
                    responses_metadata,
                    inference_trace,
                    same_turn_attempt_index,
                ))
                .await
            }
            WireApi::Anthropic => {
                Box::pin(self.stream_anthropic_messages_api(
                    prompt,
                    model_info,
                    session_telemetry,
                    effort,
                    responses_metadata,
                    inference_trace,
                ))
                .await
            }
        }
    }

    /// See [`ModelClient::note_unresolvable_item_reference`].
    pub(crate) fn note_unresolvable_item_reference(&self, err: &CodexErr) -> Option<String> {
        self.client.note_unresolvable_item_reference(err)
    }

    /// Permanently disables WebSockets for this Codex session and resets WebSocket state.
    ///
    /// This is used after exhausting the provider retry budget, to force subsequent requests onto
    /// the HTTP transport.
    ///
    /// Returns `true` if this call activated fallback, or `false` if fallback was already active.
    pub(crate) fn try_switch_fallback_transport(
        &mut self,
        session_telemetry: &SessionTelemetry,
        model_info: &ModelInfo,
    ) -> bool {
        let activated = self
            .client
            .force_http_fallback(session_telemetry, model_info);
        self.websocket_session = WebsocketSession::default();
        activated
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ChatCachePolicy {
    explicit_cache_control: bool,
    prompt_cache_key: bool,
}

fn chat_model_supports_openai_compatible_cache_control(model_slug: &str) -> bool {
    model_slug.starts_with("anthropic/")
        || model_slug.starts_with("minimax/")
        || matches!(
            model_slug,
            "deepseek/deepseek-v3.2"
                | "qwen/qwen-plus"
                | "qwen/qwen3-max"
                | "qwen/qwen3.6-plus"
                | "qwen/qwen3.7-max"
                | "qwen/qwen3-coder-plus"
                | "qwen/qwen3-coder-flash"
        )
}

fn chat_model_supports_vercel_cache_control(model_slug: &str) -> bool {
    model_slug.starts_with("anthropic/") || model_slug.starts_with("minimax/")
}

/// Rolling conversation breakpoints for explicit prompt caching.
const CHAT_CACHE_ROLLING_BREAKPOINTS: usize = 2;

fn apply_chat_cache_control(messages: &mut [ChatMessage]) {
    if let Some(system_message) = messages.iter_mut().find(|message| message.role == "system") {
        mark_chat_message_cache_control(system_message);
    }

    // The breakpoints must follow the newest turn. An agent loop grows the
    // transcript with assistant tool calls and `tool` results, not new user
    // messages, so anchoring on user messages froze the cached prefix at the
    // first request and re-billed every later turn at the uncached rate.
    let mut marked = 0usize;
    for message in messages.iter_mut().rev() {
        if marked >= CHAT_CACHE_ROLLING_BREAKPOINTS {
            break;
        }
        if message.role != "system"
            && chat_message_has_cacheable_text(message)
            && mark_chat_message_cache_control(message)
        {
            marked += 1;
        }
    }
}

/// Anthropic rejects cache breakpoints on empty text blocks, and a
/// tool-call-only assistant message has no text to mark.
fn chat_message_has_cacheable_text(message: &ChatMessage) -> bool {
    match &message.content {
        Some(ChatMessageContent::Text(text)) => !text.trim().is_empty(),
        Some(ChatMessageContent::Parts(parts)) => parts.iter().any(|part| {
            part.kind == "text"
                && part
                    .text
                    .as_deref()
                    .is_some_and(|text| !text.trim().is_empty())
        }),
        None => false,
    }
}

fn mark_chat_message_cache_control(message: &mut ChatMessage) -> bool {
    let Some(content) = message.content.take() else {
        return false;
    };

    let marked_content = match content {
        ChatMessageContent::Text(text) => ChatMessageContent::cache_control_text(text),
        ChatMessageContent::Parts(mut parts) => {
            if let Some(part) = parts.iter_mut().rev().find(|part| {
                part.kind == "text"
                    && part
                        .text
                        .as_deref()
                        .is_some_and(|text| !text.trim().is_empty())
            }) {
                part.cache_control = Some(ChatCacheControl::ephemeral());
            } else {
                parts.push(ChatContentPart::cache_control_text("..."));
            }
            ChatMessageContent::Parts(parts)
        }
    };

    message.content = Some(marked_content);
    true
}

/// Largest slice of malformed tool-call arguments replayed to the model.
const MALFORMED_CHAT_ARGUMENTS_REPLAY_CHARS: usize = 4_000;

/// Chat Completions providers reject tool calls whose arguments are not JSON.
/// Rather than dropping such a call and the error it produced, which leaves the
/// model unaware that its call failed, replay the raw text inside a JSON
/// object so the call and its error output stay visible.
fn chat_replay_function_arguments(arguments: String) -> String {
    if serde_json::from_str::<Value>(&arguments).is_ok() {
        return arguments;
    }
    let total_chars = arguments.chars().count();
    let mut raw: String = arguments
        .chars()
        .take(MALFORMED_CHAT_ARGUMENTS_REPLAY_CHARS)
        .collect();
    if total_chars > MALFORMED_CHAT_ARGUMENTS_REPLAY_CHARS {
        raw.push_str(&format!(
            "…[{} more characters omitted]",
            total_chars - MALFORMED_CHAT_ARGUMENTS_REPLAY_CHARS
        ));
    }
    json!({ "malformed_arguments": raw }).to_string()
}

/// Chat Completions and Anthropic Messages have no namespaces. A namespaced
/// call recorded on the Responses wire (before a provider switch or in forked
/// history) replays under the flat name this request offers for that exact
/// tool (`flat_tool_names`, the request's own mapping), such as an MCP tool's
/// `mcp__server__tool`, or the offered `*_v1` alias for a V1 agent tool;
/// otherwise under its bare name, as before, except that a tool outside the
/// built-in namespaces (an MCP tool, with or without the `mcp__` prefix) this
/// request does not offer (server removed, tool dropped by the tool limit)
/// replays under a flat name no offered tool has: MCP tools are never offered
/// under their bare name here, which a built-in may share. A tool whose
/// preferred flat name a plain tool already takes is offered under a hashed
/// name, so its earlier calls never appear as calls of the plain tool (#688).
fn flatten_namespaced_history(
    input: &mut [ResponseItem],
    tools: &[ToolSpec],
    flat_tool_names: &crate::tools::flat_tool_names::FlatToolNames,
) {
    let offered: HashSet<&str> = tools
        .iter()
        .filter(|tool| matches!(tool, ToolSpec::Function(_) | ToolSpec::Freeform(_)))
        .map(ToolSpec::name)
        .collect();
    for item in input {
        let (ResponseItem::FunctionCall {
            name, namespace, ..
        }
        | ResponseItem::CustomToolCall {
            name, namespace, ..
        }) = item
        else {
            continue;
        };
        let Some(namespace) = namespace.take() else {
            continue;
        };
        let tool_name = codex_tools::ToolName::namespaced(namespace, name.clone());
        let flat = flat_tool_names
            .flat_name_for(&tool_name)
            .filter(|flat| offered.contains(flat))
            .or_else(|| {
                // V1 tools use explicit plain aliases on these wires, so they
                // are not present in the namespaced-tools flat-name mapping.
                if tool_name.namespace.as_deref()
                    != Some(crate::tools::handlers::multi_agents_spec::MULTI_AGENT_V1_NAMESPACE)
                {
                    return None;
                }
                let alias = match tool_name.name.as_str() {
                    "spawn_agent" => "spawn_agent_v1",
                    "send_input" => "send_input_v1",
                    "wait_agent" => "wait_agent_v1",
                    "close_agent" => "close_agent_v1",
                    "resume_agent" => "resume_agent_v1",
                    _ => return None,
                };
                offered.contains(alias).then_some(alias)
            })
            .map(str::to_string)
            .or_else(|| {
                tool_name
                    .namespace
                    .as_deref()
                    .is_some_and(|namespace| !flat_tool_names.is_builtin_namespace(namespace))
                    .then(|| {
                        crate::tools::flat_tool_names::unoffered_flat_tool_name(
                            &tool_name, &offered,
                        )
                    })
            });
        if let Some(flat) = flat {
            *name = flat;
        }
    }
}

fn push_chat_tool_call(
    messages: &mut Vec<ChatMessage>,
    call_id: String,
    name: String,
    arguments: String,
) {
    let tool_call = ChatToolCall {
        id: call_id,
        kind: "function".to_string(),
        function: ChatToolFunction { name, arguments },
    };
    if let Some(message) = messages
        .last_mut()
        .filter(|message| message.role == "assistant" && message.tool_call_id.is_none())
    {
        message.tool_calls.push(tool_call);
    } else {
        messages.push(ChatMessage {
            role: "assistant".to_string(),
            content: None,
            reasoning_content: None,
            tool_call_id: None,
            tool_calls: vec![tool_call],
        });
    }
}

fn append_chat_messages_for_response_items(
    items: impl IntoIterator<Item = ResponseItem>,
    messages: &mut Vec<ChatMessage>,
    skipped_tool_call_ids: &mut HashSet<String>,
    reasoning_protocol: ChatReasoningProtocol,
) {
    let mut pending_tool_result_images = Vec::new();

    for item in items {
        if !matches!(
            &item,
            ResponseItem::FunctionCallOutput { .. } | ResponseItem::CustomToolCallOutput { .. }
        ) {
            flush_chat_tool_result_images(messages, &mut pending_tool_result_images);
        }

        append_chat_message_for_response_item(
            item,
            messages,
            skipped_tool_call_ids,
            &mut pending_tool_result_images,
            reasoning_protocol,
        );
    }

    flush_chat_tool_result_images(messages, &mut pending_tool_result_images);
}

fn append_chat_message_for_response_item(
    item: ResponseItem,
    messages: &mut Vec<ChatMessage>,
    skipped_tool_call_ids: &mut HashSet<String>,
    pending_tool_result_images: &mut Vec<ChatContentPart>,
    reasoning_protocol: ChatReasoningProtocol,
) {
    match item {
        ResponseItem::Message { role, content, .. } => {
            if let Some(content) = content_items_to_chat_content(&content) {
                let role = normalize_chat_role(&role);
                if role == "assistant"
                    && let Some(message) = messages.last_mut().filter(|message| {
                        message.role == "assistant"
                            && message.content.is_none()
                            && message.tool_call_id.is_none()
                            && (message.reasoning_content.is_some()
                                || !message.tool_calls.is_empty())
                    })
                {
                    message.content = Some(content);
                } else {
                    messages.push(ChatMessage {
                        role,
                        content: Some(content),
                        reasoning_content: None,
                        tool_call_id: None,
                        tool_calls: Vec::new(),
                    });
                }
            }
        }
        ResponseItem::AgentMessage {
            author,
            recipient,
            content,
            ..
        } => {
            // Native collaboration mail is a first-class Responses item, but Chat Completions
            // has no equivalent role. Preserve its external-input semantics as a user message.
            // The canonical path check distinguishes typed mailbox traffic from legacy
            // display/transcript AgentMessage items, which must not be replayed to providers.
            if let Some(message) = plaintext_collaboration_message(&author, &recipient, &content) {
                messages.push(ChatMessage {
                    role: "user".to_string(),
                    content: Some(ChatMessageContent::text(message)),
                    reasoning_content: None,
                    tool_call_id: None,
                    tool_calls: Vec::new(),
                });
            }
        }
        ResponseItem::Reasoning { content, .. }
            if reasoning_protocol == ChatReasoningProtocol::PreservedRequired =>
        {
            let reasoning_content = content
                .unwrap_or_default()
                .into_iter()
                .map(|content| match content {
                    ReasoningItemContent::ReasoningText { text }
                    | ReasoningItemContent::Text { text } => text,
                })
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join("");
            if reasoning_content.is_empty() {
                return;
            }
            if let Some(message) = messages.last_mut().filter(|message| {
                message.role == "assistant"
                    && message.tool_call_id.is_none()
                    && message.reasoning_content.is_none()
            }) {
                message.reasoning_content = Some(reasoning_content);
            } else {
                messages.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: None,
                    reasoning_content: Some(reasoning_content),
                    tool_call_id: None,
                    tool_calls: Vec::new(),
                });
            }
        }
        ResponseItem::FunctionCall {
            name,
            arguments,
            call_id,
            ..
        } => {
            let arguments = chat_replay_function_arguments(arguments);
            push_chat_tool_call(messages, call_id, name, arguments);
        }
        ResponseItem::CustomToolCall {
            name,
            input,
            call_id,
            ..
        } => {
            // Chat Completions exposes freeform tools as `{"input": string}`
            // functions, so replay custom calls in that same shape.
            let arguments = json!({ "input": input }).to_string();
            push_chat_tool_call(messages, call_id, name, arguments);
        }
        ResponseItem::FunctionCallOutput { .. } | ResponseItem::CustomToolCallOutput { .. } => {
            let (call_id, output) = match item {
                ResponseItem::FunctionCallOutput {
                    call_id: Some(call_id),
                    output,
                    ..
                }
                | ResponseItem::CustomToolCallOutput {
                    call_id, output, ..
                } => (call_id, output),
                // An output without a call id answers no replayable call.
                _ => return,
            };
            if skipped_tool_call_ids.contains(&call_id) {
                debug!(
                    call_id = %call_id,
                    "skipping historical chat tool output for malformed replayed call"
                );
                return;
            }
            let image_parts = chat_tool_result_image_parts(&output);
            let output_text = output.body.to_text().filter(|text| !text.trim().is_empty());
            let output_text = output_text.unwrap_or_else(|| {
                if image_parts.is_empty() {
                    "(tool output omitted)".to_string()
                } else {
                    "(image attached)".to_string()
                }
            });
            messages.push(ChatMessage {
                role: "tool".to_string(),
                content: Some(ChatMessageContent::text(output_text)),
                reasoning_content: None,
                tool_call_id: Some(call_id),
                tool_calls: Vec::new(),
            });
            pending_tool_result_images.extend(image_parts);
        }
        ResponseItem::Reasoning { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::ToolSearchCall { .. }
        | ResponseItem::ToolSearchOutput { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::ImageGenerationCall { .. }
        | ResponseItem::AdditionalTools { .. }
        | ResponseItem::Compaction { .. }
        | ResponseItem::CompactionTrigger { .. }
        | ResponseItem::ConfigurationUpdate { .. }
        | ResponseItem::ContextCompaction { .. }
        | ResponseItem::Other => {}
    }
}

fn flush_chat_tool_result_images(
    messages: &mut Vec<ChatMessage>,
    pending_tool_result_images: &mut Vec<ChatContentPart>,
) {
    if pending_tool_result_images.is_empty() {
        return;
    }

    messages.push(ChatMessage {
        role: "user".to_string(),
        content: Some(ChatMessageContent::Parts(std::mem::take(
            pending_tool_result_images,
        ))),
        reasoning_content: None,
        tool_call_id: None,
        tool_calls: Vec::new(),
    });
}

fn chat_image_detail(detail: Option<codex_protocol::models::ImageDetail>) -> Option<String> {
    detail.map(|detail| match detail {
        codex_protocol::models::ImageDetail::Auto => "auto".to_string(),
        codex_protocol::models::ImageDetail::Low => "low".to_string(),
        codex_protocol::models::ImageDetail::High
        | codex_protocol::models::ImageDetail::Original => "high".to_string(),
    })
}

fn chat_image_part(
    image_url: String,
    detail: Option<codex_protocol::models::ImageDetail>,
) -> ChatContentPart {
    ChatContentPart::image_url(image_url, chat_image_detail(detail))
}

fn content_items_to_chat_content(content: &[ContentItem]) -> Option<ChatMessageContent> {
    if !content
        .iter()
        .any(|item| matches!(item, ContentItem::InputImage { .. }))
    {
        return content_items_to_chat_text(content).map(ChatMessageContent::text);
    }

    let parts = content
        .iter()
        .filter_map(|item| match item {
            ContentItem::InputText { text } | ContentItem::OutputText { text, .. }
                if !text.trim().is_empty() =>
            {
                Some(ChatContentPart::text(text.clone()))
            }
            ContentItem::InputImage { image, detail } => Some(match inline_image_url(image) {
                Some(url) => chat_image_part(url.to_string(), *detail),
                None => ChatContentPart::text(UNAVAILABLE_IMAGE_TEXT.to_string()),
            }),
            ContentItem::InputText { .. }
            | ContentItem::OutputText { .. }
            | ContentItem::InputAudio { .. } => None,
        })
        .collect::<Vec<_>>();

    (!parts.is_empty()).then_some(ChatMessageContent::Parts(parts))
}

/// Sent in place of an image this provider cannot receive (an uploaded Responses file).
const UNAVAILABLE_IMAGE_TEXT: &str = "[image not available to this provider]";

/// The URL of an inline image; uploaded files (a Responses file id) have none.
fn inline_image_url(image: &codex_protocol::models::ImageReference) -> Option<&str> {
    match image {
        codex_protocol::models::ImageReference::Inline { image_url } => Some(image_url),
        codex_protocol::models::ImageReference::File { .. } => None,
    }
}

fn chat_tool_result_image_parts(
    output: &codex_protocol::models::FunctionCallOutputPayload,
) -> Vec<ChatContentPart> {
    let codex_protocol::models::FunctionCallOutputBody::ContentItems(items) = &output.body else {
        return Vec::new();
    };

    items
        .iter()
        .filter_map(|item| match item {
            codex_protocol::models::FunctionCallOutputContentItem::InputImage { image, detail } => {
                Some(match inline_image_url(image) {
                    Some(url) => chat_image_part(url.to_string(), *detail),
                    None => ChatContentPart::text(UNAVAILABLE_IMAGE_TEXT.to_string()),
                })
            }
            codex_protocol::models::FunctionCallOutputContentItem::InputText { .. }
            | codex_protocol::models::FunctionCallOutputContentItem::EncryptedContent { .. }
            | codex_protocol::models::FunctionCallOutputContentItem::InputAudio { .. } => None,
        })
        .collect()
}

fn content_items_to_chat_text(content: &[ContentItem]) -> Option<String> {
    let parts = content
        .iter()
        .filter_map(|item| match item {
            ContentItem::InputText { text } | ContentItem::OutputText { text, .. } => {
                (!text.trim().is_empty()).then_some(text.as_str())
            }
            ContentItem::InputImage { .. } | ContentItem::InputAudio { .. } => None,
        })
        .collect::<Vec<_>>();

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

fn anthropic_image_block(image_url: &str) -> Value {
    let source = if let Some((metadata, data)) = image_url
        .strip_prefix("data:")
        .and_then(|value| value.split_once(','))
        && let Some(media_type) = metadata.strip_suffix(";base64")
    {
        json!({
            "type": "base64",
            "media_type": media_type,
            "data": data,
        })
    } else {
        json!({
            "type": "url",
            "url": image_url,
        })
    };

    json!({
        "type": "image",
        "source": source,
    })
}

fn anthropic_tool_result_content(
    output: &codex_protocol::models::FunctionCallOutputPayload,
) -> Value {
    match &output.body {
        codex_protocol::models::FunctionCallOutputBody::Text(text) => Value::String(text.clone()),
        codex_protocol::models::FunctionCallOutputBody::ContentItems(items) => Value::Array(
            items
                .iter()
                .filter_map(|item| match item {
                    codex_protocol::models::FunctionCallOutputContentItem::InputText { text } => {
                        Some(json!({
                            "type": "text",
                            "text": text,
                        }))
                    }
                    codex_protocol::models::FunctionCallOutputContentItem::InputImage {
                        image,
                        ..
                    } => Some(inline_image_url(image).map_or_else(
                        || {
                            json!({
                                "type": "text",
                                "text": UNAVAILABLE_IMAGE_TEXT,
                            })
                        },
                        anthropic_image_block,
                    )),
                    codex_protocol::models::FunctionCallOutputContentItem::EncryptedContent {
                        ..
                    }
                    | codex_protocol::models::FunctionCallOutputContentItem::InputAudio {
                        ..
                    } => None,
                })
                .collect(),
        ),
    }
}

fn normalize_chat_role(role: &str) -> String {
    match role {
        "assistant" | "system" | "tool" | "user" => role.to_string(),
        "developer" => "system".to_string(),
        _ => "user".to_string(),
    }
}

fn plaintext_collaboration_message(
    author: &str,
    recipient: &str,
    content: &[AgentMessageInputContent],
) -> Option<String> {
    AgentPath::try_from(author).ok()?;
    AgentPath::try_from(recipient).ok()?;
    let payload = plaintext_agent_message_content(content)?;
    Some(format!(
        "<inter_agent_message sender={author:?} recipient={recipient:?}>\n\
         {payload}\n\
         </inter_agent_message>"
    ))
}

/// Keep native `AgentMessage` items in durable Core history while adapting them at the provider
/// boundary for Responses-compatible endpoints that do not implement OpenAI's collaboration item.
/// Ordinary user text is the portable external-input role and avoids the synthetic `Continue.`
/// turn that would otherwise hide the task from the recipient model.
fn adapt_plaintext_collaboration_messages_for_responses(input: &mut [ResponseItem]) {
    for item in input {
        let replacement = match item {
            ResponseItem::AgentMessage {
                author,
                recipient,
                content,
                ..
            } => plaintext_collaboration_message(author, recipient, content).map(|text| {
                ResponseItem::Message {
                    encrypted_content: None,
                    status: None,
                    id: None,
                    role: "user".to_string(),
                    content: vec![ContentItem::InputText { text }],
                    phase: None,
                    internal_chat_message_metadata_passthrough: None,
                }
            }),
            _ => None,
        };
        if let Some(replacement) = replacement {
            *item = replacement;
        }
    }
}

fn append_anthropic_message_for_response_item(
    item: ResponseItem,
    messages: &mut Vec<Value>,
    skipped_tool_call_ids: &mut HashSet<String>,
) {
    match item {
        ResponseItem::Message { role, content, .. } => {
            let role = if role == "assistant" {
                "assistant"
            } else {
                "user"
            };
            for item in content {
                let block = match item {
                    ContentItem::InputText { text } | ContentItem::OutputText { text, .. }
                        if !text.trim().is_empty() =>
                    {
                        json!({
                            "type": "text",
                            "text": text,
                        })
                    }
                    // Only inline images reach these providers; an uploaded file id does not.
                    ContentItem::InputImage { image, .. } => match inline_image_url(&image) {
                        Some(url) => anthropic_image_block(url),
                        None => json!({
                            "type": "text",
                            "text": UNAVAILABLE_IMAGE_TEXT,
                        }),
                    },
                    ContentItem::InputText { .. }
                    | ContentItem::OutputText { .. }
                    | ContentItem::InputAudio { .. } => continue,
                };
                push_anthropic_message(messages, role, block);
            }
        }
        ResponseItem::AgentMessage {
            author,
            recipient,
            content,
            ..
        } => {
            if let Some(message) = plaintext_collaboration_message(&author, &recipient, &content) {
                push_anthropic_message(
                    messages,
                    "user",
                    json!({
                        "type": "text",
                        "text": message,
                    }),
                );
            }
        }
        ResponseItem::FunctionCall {
            name,
            arguments,
            call_id,
            ..
        }
        | ResponseItem::CustomToolCall {
            name,
            input: arguments,
            call_id,
            ..
        } => {
            let input = match serde_json::from_str::<Value>(&arguments) {
                Ok(input) => input,
                Err(_) => {
                    debug!(
                        call_id = %call_id,
                        name = %name,
                        "skipping malformed historical Anthropic tool call arguments during replay"
                    );
                    if remove_latest_signed_thinking_assistant_message(messages) {
                        debug!(
                            call_id = %call_id,
                            name = %name,
                            "omitting incomplete signed Anthropic assistant response that contained \
                             a malformed tool call"
                        );
                    }
                    skipped_tool_call_ids.insert(call_id);
                    return;
                }
            };
            push_anthropic_message(
                messages,
                "assistant",
                json!({
                    "type": "tool_use",
                    "id": anthropic_tool_use_id(&call_id),
                    "name": name,
                    "input": input,
                }),
            );
        }
        ResponseItem::FunctionCallOutput { .. } | ResponseItem::CustomToolCallOutput { .. } => {
            let (call_id, output) = match item {
                ResponseItem::FunctionCallOutput {
                    call_id: Some(call_id),
                    output,
                    ..
                }
                | ResponseItem::CustomToolCallOutput {
                    call_id, output, ..
                } => (call_id, output),
                // An output without a call id answers no replayable call.
                _ => return,
            };
            if skipped_tool_call_ids.contains(&call_id) {
                debug!(
                    call_id = %call_id,
                    "skipping historical Anthropic tool output for malformed replayed call"
                );
                return;
            }
            push_anthropic_message(
                messages,
                "user",
                json!({
                    "type": "tool_result",
                    "tool_use_id": anthropic_tool_use_id(&call_id),
                    "content": anthropic_tool_result_content(&output),
                }),
            );
        }
        ResponseItem::WebSearchCall {
            anthropic_content_block: Some(block),
            ..
        } => {
            push_anthropic_message(messages, "assistant", block);
        }
        ResponseItem::Reasoning {
            anthropic_content_block: Some(block),
            ..
        } => {
            push_anthropic_message(messages, "assistant", block);
        }
        ResponseItem::Reasoning { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::ToolSearchCall { .. }
        | ResponseItem::ToolSearchOutput { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::ImageGenerationCall { .. }
        | ResponseItem::AdditionalTools { .. }
        | ResponseItem::Compaction { .. }
        | ResponseItem::CompactionTrigger { .. }
        | ResponseItem::ConfigurationUpdate { .. }
        | ResponseItem::ContextCompaction { .. }
        | ResponseItem::Other => {}
    }
}

/// Anthropic accepts only `tool_use` IDs matching `^[a-zA-Z0-9_-]+$`. Another
/// provider's call IDs (a Chat host's `functions.shell:0`) are mapped onto
/// that alphabet, the same way for a call and its result (#578), with a hash
/// of the original so two IDs that differ only in other characters stay
/// distinct. Valid IDs, Anthropic's own included, are unchanged.
fn anthropic_tool_use_id(call_id: &str) -> Cow<'_, str> {
    let valid = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    if call_id.chars().all(valid) {
        return Cow::Borrowed(call_id);
    }
    let mapped: String = call_id
        .chars()
        .map(|c| if valid(c) { c } else { '_' })
        .collect();
    // FNV-1a: stable across builds, so a replayed history maps the same way.
    let hash = call_id
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    Cow::Owned(format!("{mapped}_{hash:016x}"))
}

/// The item ID in a Responses `Item with id '<id>' not found` error (#578).
fn unresolvable_item_id(message: &str) -> Option<String> {
    const PREFIX: &str = "Item with id '";
    let start = message.find(PREFIX)? + PREFIX.len();
    let (id, rest) = message[start..].split_once('\'')?;
    (rest.starts_with(" not found") && !id.is_empty() && !id.contains(char::is_whitespace))
        .then(|| id.to_string())
}

fn push_anthropic_message(messages: &mut Vec<Value>, role: &str, block: Value) {
    if let Some(last) = messages.last_mut()
        && last.get("role").and_then(Value::as_str) == Some(role)
        && let Some(content) = last.get_mut("content").and_then(Value::as_array_mut)
    {
        content.push(block);
        return;
    }

    messages.push(json!({
        "role": role,
        "content": [block],
    }));
}

/// Removes the request-local residue of a length-truncated Anthropic response.
///
/// The stream adapter intentionally withholds client tool calls and final text when Anthropic
/// reports an output/context limit. A signed reasoning block may already have completed before the
/// provider reports that terminal reason. Such a reasoning-only assistant message is not a complete
/// response and cannot safely be replayed as one.
fn remove_latest_signed_thinking_only_assistant_message(messages: &mut Vec<Value>) -> bool {
    let Some(assistant_index) = messages
        .iter()
        .rposition(|message| message.get("role").and_then(Value::as_str) == Some("assistant"))
    else {
        return false;
    };
    let Some(content) = messages[assistant_index]
        .get("content")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let has_signed_thinking = content.iter().any(|block| {
        matches!(
            block.get("type").and_then(Value::as_str),
            Some("thinking" | "redacted_thinking")
        )
    });
    let has_replayable_completion = content.iter().any(|block| {
        !matches!(
            block.get("type").and_then(Value::as_str),
            Some("thinking" | "redacted_thinking")
        )
    });
    if !has_signed_thinking || has_replayable_completion {
        return false;
    }

    messages.remove(assistant_index);
    merge_adjacent_anthropic_messages(messages);
    true
}

/// Removes a partial Anthropic assistant response that cannot be replayed safely.
///
/// Anthropic signs extended-thinking blocks and requires the latest assistant response that
/// contains one to be replayed exactly. If a stream is interrupted after that block is persisted
/// but before the response reaches its terminal event, the durable history contains only a prefix
/// of the signed response. Anthropic rejects every subsequent turn until that incomplete response
/// is omitted. Keep the repair narrow: only the latest assistant message is eligible, it must
/// contain a signed-thinking protocol block, and tool results tied to tool calls in that same
/// message are the only user content removed with it.
fn remove_latest_signed_thinking_assistant_message(messages: &mut Vec<Value>) -> bool {
    let Some(assistant_index) = messages
        .iter()
        .rposition(|message| message.get("role").and_then(Value::as_str) == Some("assistant"))
    else {
        return false;
    };

    let Some(content) = messages[assistant_index]
        .get("content")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let contains_signed_thinking = content.iter().any(|block| {
        matches!(
            block.get("type").and_then(Value::as_str),
            Some("thinking" | "redacted_thinking")
        )
    });
    if !contains_signed_thinking {
        return false;
    }

    let removed_tool_use_ids = content
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
        .filter_map(|block| block.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<HashSet<_>>();
    messages.remove(assistant_index);

    if !removed_tool_use_ids.is_empty() {
        for message in messages.iter_mut().skip(assistant_index) {
            if message.get("role").and_then(Value::as_str) != Some("user") {
                continue;
            }
            if let Some(content) = message.get_mut("content").and_then(Value::as_array_mut) {
                content.retain(|block| {
                    block.get("type").and_then(Value::as_str) != Some("tool_result")
                        || block
                            .get("tool_use_id")
                            .and_then(Value::as_str)
                            .is_none_or(|id| !removed_tool_use_ids.contains(id))
                });
            }
        }
    }

    messages.retain(|message| {
        message
            .get("content")
            .and_then(Value::as_array)
            .is_none_or(|content| !content.is_empty())
    });
    merge_adjacent_anthropic_messages(messages);
    true
}

fn merge_adjacent_anthropic_messages(messages: &mut Vec<Value>) {
    let unmerged = std::mem::take(messages);
    for mut message in unmerged {
        let role = message.get("role").and_then(Value::as_str);
        if let Some(last) = messages.last_mut()
            && last.get("role").and_then(Value::as_str) == role
            && let Some(last_content) = last.get_mut("content").and_then(Value::as_array_mut)
            && let Some(content) = message.get_mut("content").and_then(Value::as_array_mut)
        {
            last_content.append(content);
        } else {
            messages.push(message);
        }
    }
}

fn is_anthropic_signed_thinking_history_rejection(error: &ApiError) -> bool {
    let message = match error {
        ApiError::Transport(TransportError::Http {
            status,
            body: Some(body),
            ..
        }) if *status == StatusCode::BAD_REQUEST => serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| body.clone()),
        ApiError::InvalidRequest { message } => message.clone(),
        ApiError::Stream(message) => match message.strip_prefix("invalid_request_error: ") {
            Some(message) => message.to_owned(),
            None => return false,
        },
        _ => return false,
    };
    let message = message.to_ascii_lowercase();
    message.contains("latest assistant message")
        && message.contains("cannot be modified")
        && (message.contains("thinking") || message.contains("redacted_thinking"))
}

/// Anthropic rejects assistant-prefill requests.
///
/// Some durable items, including incoming collaboration mail, are intentionally omitted by the
/// Anthropic adapter. When such an item arrives immediately after a completed model turn, the
/// omission can expose that completed assistant message as the terminal request message. Keep the
/// repair request-local so durable history and the operator-visible transcript remain unchanged.
///
/// Anthropic transports also reject a tool-result-only user turn when the preceding assistant
/// message has text after its final tool call. This is not specific to Claude Plan: Anthropic
/// API-key models enforce the same message-shape constraint. Although the request ends in a user
/// message, the service treats that shape as an attempt to continue the assistant prefill. Add an
/// explicit user continuation only for that exact protocol shape. A normal assistant message whose
/// final block is `tool_use` remains untouched.
fn ensure_anthropic_messages_end_with_user_turn(messages: &mut Vec<Value>) {
    let ends_with_assistant = messages
        .last()
        .and_then(|message| message.get("role"))
        .and_then(Value::as_str)
        == Some("assistant");
    let needs_tool_result_repair =
        terminal_anthropic_tool_result_follows_trailing_assistant_text(messages);
    if !(ends_with_assistant || needs_tool_result_repair) {
        return;
    }

    push_anthropic_message(
        messages,
        "user",
        json!({
            "type": "text",
            "text": "Continue.",
        }),
    );
}

fn terminal_anthropic_tool_result_follows_trailing_assistant_text(messages: &[Value]) -> bool {
    let [.., assistant, user] = messages else {
        return false;
    };
    if assistant.get("role").and_then(Value::as_str) != Some("assistant")
        || user.get("role").and_then(Value::as_str) != Some("user")
    {
        return false;
    }

    let Some(user_content) = user.get("content").and_then(Value::as_array) else {
        return false;
    };
    if user_content.is_empty()
        || !user_content
            .iter()
            .all(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
    {
        return false;
    }

    let Some(assistant_content) = assistant.get("content").and_then(Value::as_array) else {
        return false;
    };
    let Some(last_tool_use_index) = assistant_content
        .iter()
        .rposition(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
    else {
        return false;
    };

    assistant_content[last_tool_use_index + 1..]
        .iter()
        .any(|block| {
            block.get("type").and_then(Value::as_str) == Some("text")
                && block
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty())
        })
}

fn anthropic_cache_control(use_one_hour_ttl: bool) -> Value {
    if use_one_hour_ttl {
        json!({ "type": "ephemeral", "ttl": "1h" })
    } else {
        json!({ "type": "ephemeral" })
    }
}

fn apply_anthropic_cache_control_to_last_user_messages(
    messages: &mut [Value],
    cache_control: &Value,
) {
    let max_user_messages = ANTHROPIC_MESSAGES_MAX_CACHE_CONTROL_BLOCKS.saturating_sub(2);
    let mut marked_user_messages = 0usize;
    for index in (0..messages.len()).rev() {
        let is_user = messages[index].get("role").and_then(Value::as_str) == Some("user");
        if is_user && let Some(message) = messages.get_mut(index) {
            mark_anthropic_message_cache_control(message, cache_control);
            marked_user_messages += 1;
            if marked_user_messages >= max_user_messages {
                break;
            }
        }
    }
}

fn apply_anthropic_cache_control_to_last_system_block(system: &mut [Value], cache_control: &Value) {
    if let Some(block) = system.last_mut()
        && let Some(object) = block.as_object_mut()
    {
        object.insert("cache_control".to_string(), cache_control.clone());
    }
}

fn mark_anthropic_message_cache_control(message: &mut Value, cache_control: &Value) {
    let Some(content) = message.get_mut("content").and_then(Value::as_array_mut) else {
        return;
    };
    if let Some(block) = content.iter_mut().rev().find(|block| {
        matches!(
            block.get("type").and_then(Value::as_str),
            Some("text") | Some("tool_result")
        )
    }) && let Some(object) = block.as_object_mut()
    {
        object.insert("cache_control".to_string(), cache_control.clone());
    }
}

fn anthropic_reasoning_for_model_and_effort(
    model: &str,
    effort: Option<&ReasoningEffortConfig>,
) -> (Option<Value>, Option<Value>) {
    // Fable 5.2 always uses adaptive thinking, including when an older
    // session carries an unset or unsupported reasoning preference.
    if model.trim() == codex_model_provider_info::CLAUDE_FABLE_5_2_MODEL {
        let effort = effort
            .and_then(anthropic_adaptive_effort_value)
            .unwrap_or_else(|| "high".to_string());
        return (
            Some(json!({ "type": "adaptive", "display": "summarized" })),
            Some(json!({ "effort": effort })),
        );
    }
    if anthropic_model_uses_adaptive_effort(model)
        && let Some(effort) = effort.and_then(anthropic_adaptive_effort_value)
    {
        return (
            Some(json!({ "type": "adaptive", "display": "summarized" })),
            Some(json!({ "effort": effort })),
        );
    }

    (anthropic_thinking_for_effort(effort), None)
}

/// The identity an accounting attempt records.
///
/// Pricing is a catalogue lookup keyed by (slug, provider), so the ledger must
/// record the identity the catalogue keys rather than the name this client puts
/// on the wire. Those two differ wherever the client maps one to the other, and
/// for every Claude Plan model and every gateway-prefixed model the catalogue
/// keys the selected slug - which is why recording the wire name left those
/// turns unpriceable.
///
/// Ambient's retired `zai-org/GLM-5.2-FP8` alias is the one mapping that runs
/// the other way: it has no catalogue row of its own, and the priced Ambient row
/// is the name it maps to. Following the mapping there is not a return to the
/// wire name, it is the same rule - use whatever string the catalogue keys.
fn accounting_model_identity(slug: &str) -> String {
    match slug.trim() {
        AMBIENT_LEGACY_GLM_5_2_FP8_MODEL => AMBIENT_DEFAULT_MODEL.to_string(),
        _ => slug.to_string(),
    }
}

fn chat_completions_upstream_model<'a>(model: &'a str, provider: &ModelProviderInfo) -> &'a str {
    if provider.is_ambient() && model.trim() == AMBIENT_LEGACY_GLM_5_2_FP8_MODEL {
        AMBIENT_DEFAULT_MODEL
    } else if provider.is_vercel_gateway() {
        vercel_gateway_upstream_model(model)
    } else {
        model
    }
}

fn anthropic_upstream_model(model: &str) -> &str {
    match model.trim() {
        CLAUDE_FABLE_5_1_PLAN_MODEL => CLAUDE_FABLE_5_1_PLAN_UPSTREAM_MODEL,
        CLAUDE_PLAN_MODEL => CLAUDE_PLAN_UPSTREAM_MODEL,
        CLAUDE_OPUS_5_5_PLAN_MODEL => CLAUDE_OPUS_5_5_PLAN_UPSTREAM_MODEL,
        CLAUDE_PLAN_LEGACY_OPUS_4_8_MODEL => ANTHROPIC_LEGACY_OPUS_4_8_MODEL,
        CLAUDE_FABLE_5_PLAN_MODEL => CLAUDE_FABLE_5_PLAN_UPSTREAM_MODEL,
        _ => model,
    }
}

fn is_claude_plan_model_slug(model: &str) -> bool {
    matches!(
        model.trim(),
        CLAUDE_PLAN_MODEL
            | CLAUDE_OPUS_5_5_PLAN_MODEL
            | CLAUDE_PLAN_LEGACY_OPUS_4_8_MODEL
            | CLAUDE_FABLE_5_1_PLAN_MODEL
            | CLAUDE_FABLE_5_PLAN_MODEL
    )
}

fn anthropic_model_uses_adaptive_effort(model: &str) -> bool {
    let model = model.trim();
    model.starts_with("claude-opus-4-7")
        || model.starts_with("claude-opus-4-8")
        || model.starts_with("claude-opus-5")
        || model.starts_with("claude-fable-5")
}

fn anthropic_adaptive_effort_value(effort: &ReasoningEffortConfig) -> Option<String> {
    match effort {
        ReasoningEffortConfig::Low => Some("low".to_string()),
        ReasoningEffortConfig::Medium => Some("medium".to_string()),
        ReasoningEffortConfig::High => Some("high".to_string()),
        ReasoningEffortConfig::XHigh => Some("xhigh".to_string()),
        ReasoningEffortConfig::Custom(value)
            if matches!(value.as_str(), "max" | "xhigh" | "high" | "medium" | "low") =>
        {
            Some(value.clone())
        }
        _ => None,
    }
}

/// The Vercel AI Gateway serves third-party model slugs from whichever upstream
/// host it prefers — `zai/*` defaults to Fireworks — and those hosts silently
/// drop every thinking toggle the gateway forwards. Z.AI's own API is itself a
/// pinnable upstream, and pinning to it restores the toggle.
///
/// Measured 2026-07-27 on `zai/glm-5.2` and `zai/glm-5.2-fast`, all three wire
/// formats, n=3 each: unpinned 88-194 completion tokens with 54-130 of
/// reasoning regardless of parameter shape; pinned to `zai` with thinking off,
/// 3 completion tokens and 0 reasoning.
///
/// Pins are validated server-side, so an incompatible direct upstream fails
/// instead of using the gateway's working fallback routes. Keep the workaround
/// limited to the Z.AI models that need it; other Vercel models retain native
/// multi-provider routing and failover.
fn vercel_gateway_vendor_pin(model: &str) -> Option<&'static str> {
    match model.split('/').next()?.trim() {
        "zai" => Some("zai"),
        _ => None,
    }
}

/// Retries allowed for one request when the gateway reports a transient limit
/// of a shared upstream pool, with exponential backoff from
/// `TRANSIENT_RATE_LIMIT_BASE_DELAY` (about 30 seconds in total).
const MAX_TRANSIENT_RATE_LIMIT_RETRIES: u32 = 4;
const TRANSIENT_RATE_LIMIT_BASE_DELAY: Duration = Duration::from_secs(2);
const TRANSIENT_RATE_LIMIT_MAX_DELAY: Duration = Duration::from_secs(60);

/// True for a 429 that the gateway marks, in its structured error metadata, as
/// a temporary limit of a shared upstream provider pool rather than the
/// caller's own quota. OpenRouter reports these as
/// `error.metadata.limit_source = "upstream_provider_shared_pool"` and asks the
/// caller to retry shortly. Other 429s keep the no-retry behavior.
fn is_transient_upstream_rate_limit(err: &ApiError) -> bool {
    let ApiError::Transport(TransportError::Http {
        status,
        body: Some(body),
        ..
    }) = err
    else {
        return false;
    };
    if *status != StatusCode::TOO_MANY_REQUESTS {
        return false;
    }
    serde_json::from_str::<Value>(body).is_ok_and(|body| {
        body.pointer("/error/metadata/limit_source")
            .and_then(Value::as_str)
            == Some("upstream_provider_shared_pool")
    })
}

/// Backoff before retry `attempt` (0-based), honoring a `Retry-After` header in
/// seconds when the gateway sends one.
fn transient_rate_limit_delay(err: &ApiError, attempt: u32) -> Duration {
    let retry_after = match err {
        ApiError::Transport(TransportError::Http {
            headers: Some(headers),
            ..
        }) => headers
            .get(http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(Duration::from_secs),
        _ => None,
    };
    retry_after
        .unwrap_or_else(|| TRANSIENT_RATE_LIMIT_BASE_DELAY.saturating_mul(1 << attempt.min(8)))
        .min(TRANSIENT_RATE_LIMIT_MAX_DELAY)
}

/// True when the Vercel gateway rejected a request without attempting any
/// upstream because an account policy skipped every candidate, as reported in
/// its structured routing metadata. With a vendor pin in place the pinned
/// upstream is the only candidate, so zero-data-retention accounts get this
/// for every Z.AI-pinned request while unpinned routing succeeds.
fn is_vercel_gateway_policy_exclusion(err: &ApiError) -> bool {
    let ApiError::Transport(TransportError::Http {
        status,
        body: Some(body),
        ..
    }) = err
    else {
        return false;
    };
    if *status != StatusCode::BAD_REQUEST {
        return false;
    }
    let Ok(body) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let routing = &body["providerMetadata"]["gateway"]["routing"];
    routing["totalProviderAttemptCount"].as_u64() == Some(0)
        && routing["skippedProviderAttempts"]
            .as_array()
            .is_some_and(|skipped| !skipped.is_empty())
}

fn vercel_gateway_provider_options(model: &str) -> Option<Value> {
    vercel_gateway_vendor_pin(model).map(|upstream| {
        json!({
            "gateway": { "only": [upstream] },
        })
    })
}

/// True when the caller explicitly asked for deep reasoning.
///
/// The catalog exposes this level as `"xhigh"`, which deserializes to the
/// first-class `XHigh` variant rather than `Custom("xhigh")`. Matching only on
/// `Custom` therefore ignored every user who picked Deep in the model picker,
/// on every provider that routes through here.
fn wants_deep_reasoning(effort: Option<&ReasoningEffortConfig>) -> bool {
    match effort {
        Some(ReasoningEffortConfig::XHigh) => true,
        Some(ReasoningEffortConfig::Custom(value)) => matches!(
            value.as_str(),
            "deep" | "max" | "xhigh" | "extra_high" | "extra-high"
        ),
        _ => false,
    }
}

fn anthropic_thinking_for_effort(effort: Option<&ReasoningEffortConfig>) -> Option<Value> {
    wants_deep_reasoning(effort).then(|| {
        json!({
            "type": "enabled",
            "budget_tokens": 16_000,
        })
    })
}

fn create_tools_json_for_anthropic_messages(
    tools: &[ToolSpec],
    cache_control: &Value,
    web_search_max_uses: Option<u32>,
) -> Result<Vec<Value>> {
    let mut tools = tools
        .iter()
        .filter_map(|tool| tool_spec_to_anthropic_tool(tool, web_search_max_uses))
        .collect::<Result<Vec<_>>>()?;
    tools.sort_by_key(|tool| {
        usize::from(
            tool.get("type").and_then(Value::as_str) != Some(ANTHROPIC_WEB_SEARCH_TOOL_TYPE),
        )
    });
    mark_last_anthropic_tool_cache_control(&mut tools, cache_control);
    Ok(tools)
}

fn mark_last_anthropic_tool_cache_control(tools: &mut [Value], cache_control: &Value) {
    if let Some(object) = tools
        .iter_mut()
        .rev()
        .filter_map(Value::as_object_mut)
        .find(|object| {
            !matches!(
                object.get("type").and_then(Value::as_str),
                Some(ANTHROPIC_WEB_SEARCH_TOOL_TYPE) | Some(ANTHROPIC_WEB_SEARCH_TOOL_TYPE_LEGACY)
            )
        })
    {
        object.insert("cache_control".to_string(), cache_control.clone());
    }
}

fn tool_spec_to_anthropic_tool(
    tool: &ToolSpec,
    web_search_max_uses: Option<u32>,
) -> Option<Result<Value>> {
    match tool {
        ToolSpec::Function(_) => Some(serde_json::to_value(tool).map_err(Into::into).and_then(
            |value| {
                responses_tool_to_anthropic_tool(value).ok_or_else(|| {
                    CodexErr::Fatal("failed to convert function tool for Anthropic".to_string())
                })
            },
        )),
        ToolSpec::Freeform(tool) => Some(Ok(freeform_tool_to_anthropic_tool(tool))),
        ToolSpec::WebSearch { .. } => Some(Ok(anthropic_web_search_tool_with_type(
            tool,
            ANTHROPIC_WEB_SEARCH_TOOL_TYPE,
            web_search_max_uses,
        ))),
        ToolSpec::Namespace(_) | ToolSpec::ToolSearch { .. } => None,
    }
}

fn anthropic_web_search_tool_with_type(
    tool: &ToolSpec,
    tool_type: &str,
    web_search_max_uses: Option<u32>,
) -> Value {
    let ToolSpec::WebSearch {
        filters,
        user_location,
        ..
    } = tool
    else {
        return Value::Null;
    };

    let mut object = serde_json::Map::new();
    object.insert("type".to_string(), json!(tool_type));
    object.insert("name".to_string(), json!("web_search"));
    if let Some(max_uses) = web_search_max_uses {
        object.insert("max_uses".to_string(), json!(max_uses));
    }
    object.insert("allowed_callers".to_string(), json!(["direct"]));
    if let Some(filters) = filters
        && let Some(allowed_domains) = filters.allowed_domains.as_ref()
        && !allowed_domains.is_empty()
    {
        object.insert("allowed_domains".to_string(), json!(allowed_domains));
    }
    if let Some(user_location) = user_location {
        object.insert("user_location".to_string(), json!(user_location));
    }
    Value::Object(object)
}

fn responses_tool_to_anthropic_tool(mut tool: Value) -> Option<Value> {
    let object = tool.as_object_mut()?;
    if object.get("type").and_then(Value::as_str)? != "function" {
        return None;
    }

    let name = object.remove("name")?;
    let description = object.remove("description");
    let input_schema = object.remove("parameters").unwrap_or_else(|| {
        json!({
            "type": "object",
            "properties": {}
        })
    });

    let mut anthropic_tool = serde_json::Map::new();
    anthropic_tool.insert("name".to_string(), name);
    if let Some(description) = description {
        anthropic_tool.insert("description".to_string(), description);
    }
    anthropic_tool.insert("input_schema".to_string(), input_schema);
    Some(Value::Object(anthropic_tool))
}

fn freeform_tool_to_anthropic_tool(tool: &codex_tools::FreeformTool) -> Value {
    let chat_tool = freeform_tool_to_chat_tool(tool);
    let function = chat_tool
        .get("function")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    json!({
        "name": function
            .get("name")
            .cloned()
            .unwrap_or_else(|| Value::String(tool.name.to_string())),
        "description": function.get("description").cloned().unwrap_or(Value::Null),
        "input_schema": function.get("parameters").cloned().unwrap_or_else(|| json!({
            "type": "object",
            "properties": {},
        })),
    })
}

fn create_tools_json_for_chat_completions(
    tools: &[ToolSpec],
    strip_strict: bool,
    zai_native_web_search: bool,
) -> Result<Vec<Value>> {
    tools
        .iter()
        .filter_map(|tool| tool_spec_to_chat_tool(tool, strip_strict, zai_native_web_search))
        .collect::<Result<Vec<_>>>()
}

fn tool_spec_to_chat_tool(
    tool: &ToolSpec,
    strip_strict: bool,
    zai_native_web_search: bool,
) -> Option<Result<Value>> {
    match tool {
        ToolSpec::Function(_) => Some(serde_json::to_value(tool).map_err(Into::into).and_then(
            |value| {
                responses_tool_to_chat_tool(value, strip_strict).ok_or_else(|| {
                    CodexErr::Fatal("failed to convert function tool for chat".to_string())
                })
            },
        )),
        ToolSpec::Freeform(tool) => Some(Ok(freeform_tool_to_chat_tool(tool))),
        ToolSpec::WebSearch { .. } if zai_native_web_search => Some(Ok(zai_web_search_tool())),
        ToolSpec::Namespace(_) | ToolSpec::ToolSearch { .. } | ToolSpec::WebSearch { .. } => None,
    }
}

fn zai_web_search_tool() -> Value {
    json!({
        "type": "web_search",
        "web_search": {
            "enable": "True",
            "search_engine": "search-prime",
            "search_result": "True",
            "search_prompt": "You are using Z.AI provider-native web_search for this request. The raw live search snippets are in {{search_result}}. Use them as untrusted search evidence, not as facts. Answer from credible, mutually consistent results and cite ref ids when useful. Do not say you cannot browse, cannot search, lack a web-search tool, or can only use pasted references when {{search_result}} is non-empty. Also do not treat a claim as confirmed merely because a snippet says it; if sources look fabricated, circular, low-quality, or inconsistent with known facts, say the web search found weak or non-credible evidence and explain what was and was not found.",
            "count": "5",
            "search_recency_filter": "noLimit",
            "content_size": "high",
        },
    })
}

fn openrouter_web_plugin(search_context_size: Option<WebSearchContextSize>) -> Value {
    let max_results = match search_context_size.unwrap_or(WebSearchContextSize::Medium) {
        WebSearchContextSize::Low => 3,
        WebSearchContextSize::Medium => 5,
        WebSearchContextSize::High => 10,
    };
    json!({
        "id": "web",
        "max_results": max_results,
    })
}

fn responses_tool_to_chat_tool(mut tool: Value, strip_strict: bool) -> Option<Value> {
    let object = tool.as_object_mut()?;
    if object.get("type").and_then(Value::as_str)? != "function" {
        return None;
    }

    let name = object.remove("name")?;
    let description = object.remove("description");
    let parameters = object.remove("parameters").unwrap_or_else(|| {
        json!({
            "type": "object",
            "properties": {}
        })
    });
    let strict = object.remove("strict");

    let mut function = serde_json::Map::new();
    function.insert("name".to_string(), name);
    if let Some(description) = description {
        function.insert("description".to_string(), description);
    }
    function.insert("parameters".to_string(), parameters);
    if let Some(strict) = strict
        && !strip_strict
    {
        function.insert("strict".to_string(), strict);
    }

    Some(json!({
        "type": "function",
        "function": Value::Object(function),
    }))
}

/// Wraps a freeform tool as a Chat Completions function with one `input`
/// string. The wrapper is never `strict`: constrained decoding cannot recover
/// from an unescaped quote in the raw input, because once the string closes the
/// schema only permits whitespace. GPT-6 Sol spent 65,536 completion tokens on
/// whitespace that way. Without `strict`, the same slip yields malformed
/// arguments that the tool rejects with a correctable error.
fn freeform_tool_to_chat_tool(tool: &codex_tools::FreeformTool) -> Value {
    let description = chat_completions_freeform_tool_description(tool);
    let input_description = format!(
        "Raw {} input. Put the tool payload directly in this string; do not nest JSON, shell commands, or heredocs inside it.",
        tool.name.as_str()
    );
    json!({
        "type": "function",
        "function": {
            "name": tool.name.as_str(),
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": input_description,
                    },
                },
                "required": ["input"],
                "additionalProperties": false,
            },
        },
    })
}

fn chat_completions_freeform_tool_description(tool: &codex_tools::FreeformTool) -> String {
    if tool.name.as_str() == "apply_patch" {
        return "Use this tool to edit files by applying a patch. Pass the raw patch text in the `input` field. The `input` value must begin with `*** Begin Patch` and end with `*** End Patch`; do not put JSON, shell commands, or heredocs inside `input`.".to_string();
    }

    format!(
        "{} Pass the raw tool input in the `input` field. Do not put nested JSON, shell commands, or heredocs inside `input`.",
        tool.description.trim()
    )
}

/// Stamp a ResponsesWsRequest with the current time.
///
/// Meant to be called just before sending the request over the socket, to capture realistic
/// transport timing.
fn stamp_ws_stream_request_start_ms(request: &mut ResponsesWsRequest<'_>) {
    let ResponsesWsRequest::ResponseCreate(payload) = request;
    payload
        .client_metadata
        .get_or_insert_with(HashMap::new)
        .insert(
            X_CODEX_WS_STREAM_REQUEST_START_MS_CLIENT_METADATA_KEY.to_string(),
            crate::turn_timing::now_unix_timestamp_ms().to_string(),
        );
}

fn is_guardian_reviewer(responses_headers: &ApiHeaderMap) -> bool {
    responses_headers
        .get("x-codex-guardian")
        .is_some_and(|value| value == "reviewer")
}

/// Builds the extra headers attached to Responses API requests.
///
/// These headers implement Codex-specific conventions:
///
/// - `x-codex-beta-features`: comma-separated beta feature keys enabled for the session.
/// - `x-codex-turn-state`: sticky routing token captured earlier in the turn.
fn build_responses_headers(
    beta_features_header: Option<&str>,
    turn_state: Option<&Arc<OnceLock<String>>>,
) -> ApiHeaderMap {
    let mut headers = ApiHeaderMap::new();
    if let Some(value) = beta_features_header
        && !value.is_empty()
        && let Ok(header_value) = HeaderValue::from_str(value)
    {
        headers.insert("x-codex-beta-features", header_value);
    }
    if let Some(turn_state) = turn_state
        && let Some(state) = turn_state.get()
        && let Ok(header_value) = HeaderValue::from_str(state)
    {
        headers.insert(X_CODEX_TURN_STATE_HEADER, header_value);
    }
    headers
}

fn add_responses_lite_header(headers: &mut ApiHeaderMap, use_responses_lite: bool) {
    if use_responses_lite {
        headers.insert(
            X_OPENAI_INTERNAL_CODEX_RESPONSES_LITE_HEADER,
            HeaderValue::from_static("true"),
        );
    }
}

const RESPONSE_STREAM_CHANNEL_CAPACITY: usize = 1600;
const STREAM_DROPPED_REASON: &str = "response stream dropped before provider terminal event";

fn map_response_stream(
    mut api_stream: codex_api::ResponseStream,
    session_telemetry: SessionTelemetry,
    inference_trace_attempt: InferenceTraceAttempt,
    provider: SharedModelProvider,
    server_conversation_update: Option<(SharedServerConversationState, ResponsesApiRequest)>,
    interceptors: Vec<Box<dyn codex_extension_api::ModelResponseInterceptor>>,
    last_response_tx: Option<oneshot::Sender<LastResponse>>,
) -> ResponseStream {
    let routing_affinity = api_stream.routing_affinity.take();
    let upstream_request_id = api_stream.upstream_request_id.take();
    let interrupt = api_stream.interrupt.take();
    let mut stream = map_response_events_with_server_state(
        upstream_request_id,
        crate::model_request::intercept_stream(Box::pin(api_stream), interceptors),
        session_telemetry,
        inference_trace_attempt,
        provider,
        server_conversation_update,
        last_response_tx,
    );
    stream.interrupt = interrupt;
    stream.routing_affinity = routing_affinity;
    stream
}

fn map_response_events_with_server_state<S>(
    upstream_request_id: Option<String>,
    api_stream: S,
    session_telemetry: SessionTelemetry,
    inference_trace_attempt: InferenceTraceAttempt,
    provider: SharedModelProvider,
    server_conversation_update: Option<(SharedServerConversationState, ResponsesApiRequest)>,
    mut last_response_tx: Option<oneshot::Sender<LastResponse>>,
) -> ResponseStream
where
    S: futures::Stream<Item = std::result::Result<ResponseEvent, ApiError>>
        + Unpin
        + Send
        + 'static,
{
    let (tx_event, rx_event) =
        mpsc::channel::<Result<ResponseEvent>>(RESPONSE_STREAM_CHANNEL_CAPACITY);
    let consumer_dropped = CancellationToken::new();
    let consumer_dropped_for_stream = consumer_dropped.clone();

    tokio::spawn(async move {
        let mut logged_error = false;
        // Corbanu (Vercel): the server-side state records the response's output items too.
        let collect_output_items = last_response_tx.is_some()
            || server_conversation_update.is_some()
            || inference_trace_attempt.needs_output_items();
        let mut items_added: Vec<ResponseItem> = Vec::new();
        let mut active_item_id: Option<ResponseItemId> = None;
        let (request_start, mut ttft_ms) = (Instant::now(), None);
        let mut api_stream = api_stream;
        let stream_started_at = Instant::now();
        let mut first_event_seen = false;
        let upstream_request_id = upstream_request_id.as_deref();
        if let Some(upstream_request_id) = upstream_request_id {
            feedback_tags!(last_model_request_id = upstream_request_id);
        }
        loop {
            let event = tokio::select! {
                _ = consumer_dropped.cancelled() => {
                    inference_trace_attempt.record_cancelled(
                        STREAM_DROPPED_REASON,
                        upstream_request_id,
                        &items_added,
                    );
                    return;
                }
                event = api_stream.next() => event,
            };
            let Some(event) = event else {
                break;
            };
            if !first_event_seen {
                first_event_seen = true;
                let label = match &event {
                    Ok(event) => response_event_name(event),
                    Err(_) => "error",
                };
                trace_stream_timing(
                    &format!("response_stream_first_event:{label}"),
                    stream_started_at,
                );
            }
            match event {
                Ok(ResponseEvent::OutputItemDone(mut item)) => {
                    // Assign IDs after interceptors, which may replace provider items.
                    // Reuse the added event's ID so tracing and the harness agree.
                    if item.id().is_none_or(|id| id.is_empty()) {
                        item.set_id(
                            active_item_id
                                .take()
                                .or_else(|| item.id_prefix().map(ResponseItemId::new)),
                        );
                    }
                    active_item_id = None;
                    if collect_output_items {
                        items_added.push(item.clone());
                    }
                    if tx_event
                        .send(Ok(ResponseEvent::OutputItemDone(item)))
                        .await
                        .is_err()
                    {
                        inference_trace_attempt.record_cancelled(
                            STREAM_DROPPED_REASON,
                            upstream_request_id,
                            &items_added,
                        );
                        return;
                    }
                }
                Ok(ResponseEvent::Completed {
                    response_id,
                    token_usage,
                    usage_metadata,
                    end_turn,
                    finish_reason,
                }) => {
                    trace_stream_timing("response_stream_completed", stream_started_at);
                    feedback_tags!(last_model_response_id = &response_id);
                    if let Some(usage) = &token_usage {
                        session_telemetry.sse_event_completed(usage, ttft_ms);
                    }
                    inference_trace_attempt.record_completed(
                        &response_id,
                        upstream_request_id,
                        &token_usage,
                        &items_added,
                    );
                    let last_response = LastResponse {
                        response_id: response_id.clone(),
                        items_added: std::mem::take(&mut items_added),
                    };
                    if !last_response.response_id.is_empty()
                        && let Some((shared_state, logical_request)) = &server_conversation_update
                    {
                        let mut state = shared_state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        *state = Some(ServerConversationState {
                            last_request: Some(logical_request.clone()),
                            last_response: last_response.clone(),
                        });
                    }
                    if let Some(sender) = last_response_tx.take() {
                        let _ = sender.send(last_response);
                    }
                    if tx_event
                        .send(Ok(ResponseEvent::Completed {
                            response_id,
                            token_usage,
                            usage_metadata,
                            end_turn,
                            finish_reason,
                        }))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(mut event) => {
                    if let ResponseEvent::OutputItemAdded(item) = &mut event {
                        if item.id().is_none_or(|id| id.is_empty()) {
                            item.set_id(item.id_prefix().map(ResponseItemId::new));
                        }
                        active_item_id = item.id().cloned();
                    }
                    if matches!(&event, ResponseEvent::OutputItemAdded(_)) && ttft_ms.is_none() {
                        ttft_ms = Some(
                            i64::try_from(request_start.elapsed().as_millis()).unwrap_or(i64::MAX),
                        );
                    }
                    if tx_event.send(Ok(event)).await.is_err() {
                        inference_trace_attempt.record_cancelled(
                            STREAM_DROPPED_REASON,
                            upstream_request_id,
                            &items_added,
                        );
                        return;
                    }
                }
                Err(err) => {
                    let response_debug_context =
                        extract_response_debug_context_from_api_error(&err);
                    let upstream_request_id =
                        upstream_request_id.or(response_debug_context.request_id.as_deref());
                    if let Some(upstream_request_id) = upstream_request_id {
                        feedback_tags!(last_model_request_id = upstream_request_id);
                    }
                    let mapped = provider.map_api_error(err);
                    // Terminal response output is trace evidence. Only streamed done items
                    // belong to the continuation cache or reach tool dispatch.
                    let completed_item_count = items_added.len();
                    if inference_trace_attempt.needs_output_items()
                        && let CodexErrorDetails::ResponseIncomplete(incomplete) = mapped.details()
                    {
                        for raw in &incomplete.partial_output {
                            // Other discards unknown payloads and cannot be replayed as a trace item.
                            if let Ok(item) = ResponseItem::deserialize(raw)
                                && !matches!(item, ResponseItem::Other)
                                && !item.id().is_some_and(|id| {
                                    items_added.iter().any(|seen| seen.id() == Some(id))
                                })
                            {
                                items_added.push(item);
                            }
                        }
                    }
                    inference_trace_attempt.record_failed(
                        &mapped,
                        upstream_request_id,
                        &items_added,
                    );
                    items_added.truncate(completed_item_count);
                    if !logged_error {
                        session_telemetry.see_event_completed_failed(&mapped);
                        logged_error = true;
                    }
                    if tx_event.send(Err(mapped)).await.is_err() {
                        return;
                    }
                }
            }
        }
        inference_trace_attempt.record_failed(
            "stream closed before response.completed",
            upstream_request_id,
            &items_added,
        );
    });

    ResponseStream {
        routing_affinity: None,
        rx_event,
        interrupt: None,
        consumer_dropped: consumer_dropped_for_stream,
    }
}

#[cfg(test)]
fn map_response_events<S>(
    upstream_request_id: Option<String>,
    api_stream: S,
    session_telemetry: SessionTelemetry,
    inference_trace_attempt: InferenceTraceAttempt,
    provider: SharedModelProvider,
    last_response_tx: Option<oneshot::Sender<LastResponse>>,
) -> ResponseStream
where
    S: futures::Stream<Item = std::result::Result<ResponseEvent, ApiError>>
        + Unpin
        + Send
        + 'static,
{
    map_response_events_with_server_state(
        upstream_request_id,
        api_stream,
        session_telemetry,
        inference_trace_attempt,
        provider,
        /*server_conversation_update*/ None,
        last_response_tx,
    )
}

/// Handles a 401 response by optionally refreshing ChatGPT tokens once.
///
/// When refresh succeeds, the caller should retry the API call; otherwise
/// the mapped `CodexErr` is returned to the caller.
#[derive(Clone, Copy, Debug)]
struct UnauthorizedRecoveryExecution {
    mode: &'static str,
    phase: &'static str,
}

#[derive(Clone, Copy, Debug, Default)]
struct PendingUnauthorizedRetry {
    retry_after_unauthorized: bool,
    recovery_mode: Option<&'static str>,
    recovery_phase: Option<&'static str>,
}

impl PendingUnauthorizedRetry {
    fn from_recovery(recovery: UnauthorizedRecoveryExecution) -> Self {
        Self {
            retry_after_unauthorized: true,
            recovery_mode: Some(recovery.mode),
            recovery_phase: Some(recovery.phase),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct AuthRequestTelemetryContext {
    auth_mode: Option<&'static str>,
    auth_header_attached: bool,
    auth_header_name: Option<&'static str>,
    agent_identity_telemetry: Option<AgentIdentityTelemetry>,
    retry_after_unauthorized: bool,
    recovery_mode: Option<&'static str>,
    recovery_phase: Option<&'static str>,
}

impl AuthRequestTelemetryContext {
    fn new(
        auth_mode: Option<AuthMode>,
        api_auth: &dyn AuthProvider,
        agent_identity_telemetry: Option<AgentIdentityTelemetry>,
        retry: PendingUnauthorizedRetry,
    ) -> std::result::Result<Self, ApiError> {
        let auth_telemetry = auth_header_telemetry(api_auth)?;
        Ok(Self {
            auth_mode: auth_mode.map(|mode| match mode {
                AuthMode::ApiKey | AuthMode::BedrockApiKey | AuthMode::BedrockAccessKeys => {
                    "ApiKey"
                }
                AuthMode::Chatgpt
                | AuthMode::ChatgptAuthTokens
                | AuthMode::Headers
                | AuthMode::AgentIdentity
                | AuthMode::PersonalAccessToken => "Chatgpt",
            }),
            auth_header_attached: auth_telemetry.attached,
            auth_header_name: auth_telemetry.name,
            agent_identity_telemetry,
            retry_after_unauthorized: retry.retry_after_unauthorized,
            recovery_mode: retry.recovery_mode,
            recovery_phase: retry.recovery_phase,
        })
    }

    fn agent_identity_telemetry(&self) -> Option<&AgentIdentityTelemetry> {
        self.agent_identity_telemetry.as_ref()
    }
}

struct WebsocketConnectParams<'a> {
    identity: ConnectionIdentity,
    provenance: crate::accounting::websocket::Provenance,
    runtime_id: Option<String>,
    session_telemetry: &'a SessionTelemetry,
    api_provider: codex_api::Provider,
    auth_revision: Option<u64>,
    api_auth: SharedAuthProvider,
    http_client_factory: HttpClientFactory,
    auth_owner_generation: Option<u64>,
    responses_metadata: &'a CodexResponsesMetadata,
    auth_context: AuthRequestTelemetryContext,
    request_route_telemetry: RequestRouteTelemetry,
    responses_headers: &'a ApiHeaderMap,
}

fn emit_auth_recovery_event(
    event_sender: Option<&Sender<ProtocolEvent>>,
    turn_id: Option<&str>,
    provider: &SharedModelProvider,
    message: &str,
    event: fn(AuthRecoveryEvent) -> EventMsg,
) {
    if let (Some(sender), Some(turn_id)) = (event_sender, turn_id) {
        let _ = sender.try_send(ProtocolEvent {
            id: turn_id.to_string(),
            msg: event(AuthRecoveryEvent {
                provider: provider.info().name.clone(),
                message: message.to_string(),
            }),
        });
    }
}

async fn handle_unauthorized(
    transport: TransportError,
    auth_recovery: &mut Option<UnauthorizedRecovery>,
    provider_auth_recovery_attempted: &mut bool,
    session_telemetry: &SessionTelemetry,
    provider: &SharedModelProvider,
    event_sender: Option<&Sender<ProtocolEvent>>,
    turn_id: Option<&str>,
) -> Result<UnauthorizedRecoveryExecution> {
    match try_unauthorized_recovery(
        transport,
        auth_recovery,
        provider_auth_recovery_attempted,
        session_telemetry,
        provider,
        event_sender,
        turn_id,
    )
    .await
    {
        Err(error) => Err(named_sign_in_revoked(provider).await.unwrap_or(error)),
        recovered => recovered,
    }
}

/// D171 (#1311): a named ChatGPT account removed or signed out while a
/// request on it was in flight (its tokens were revoked, so the request got a
/// 401) is reported with the account's recovery, as the next request would
/// be, instead of a generic unauthorized error. The vault is read off the
/// async workers.
async fn named_sign_in_revoked(provider: &SharedModelProvider) -> Option<CodexErr> {
    codex_model_provider::named_sign_in_account(provider.info())?;
    let manager = provider.auth_manager()?;
    let reason = tokio::task::spawn_blocking(move || manager.named_sign_in_unavailable())
        .await
        .ok()
        .flatten()?;
    Some(CodexErr::Fatal(format!(
        "{}: {reason}",
        provider.info().name
    )))
}

async fn try_unauthorized_recovery(
    transport: TransportError,
    auth_recovery: &mut Option<UnauthorizedRecovery>,
    provider_auth_recovery_attempted: &mut bool,
    session_telemetry: &SessionTelemetry,
    provider: &SharedModelProvider,
    event_sender: Option<&Sender<ProtocolEvent>>,
    turn_id: Option<&str>,
) -> Result<UnauthorizedRecoveryExecution> {
    if codex_api::is_plan_entitlement_error(&transport) {
        return Err(provider.map_api_error(ApiError::Transport(transport)));
    }
    let debug = extract_response_debug_context(&transport);
    if !*provider_auth_recovery_attempted {
        *provider_auth_recovery_attempted = true;
        let messages = provider.auth_recovery_messages();
        if let Some(messages) = messages {
            emit_auth_recovery_event(
                event_sender,
                turn_id,
                provider,
                messages.started,
                EventMsg::AuthRecoveryStarted,
            );
        }
        match provider.recover_from_unauthorized().await {
            Ok(ProviderUnauthorizedRecovery::Recovered) => {
                if let Some(messages) = messages {
                    emit_auth_recovery_event(
                        event_sender,
                        turn_id,
                        provider,
                        messages.succeeded,
                        EventMsg::AuthRecoveryCompleted,
                    );
                }
                return Ok(UnauthorizedRecoveryExecution {
                    mode: "provider",
                    phase: "provider_refresh",
                });
            }
            Ok(ProviderUnauthorizedRecovery::NotConfigured) => {}
            Err(error) => {
                let original = provider.map_api_error(ApiError::Transport(transport));
                warn!(
                    error = %error,
                    original_error = %original,
                    "provider authentication recovery failed"
                );
                return Err(if error.retry_delay(/*retry_count*/ 1).is_some() {
                    original
                } else {
                    error
                });
            }
        }
    }

    if let Some(recovery) = auth_recovery
        && recovery.has_next()
    {
        let mode = recovery.mode_name();
        let phase = recovery.step_name();
        return match recovery.next().await {
            Ok(step_result) => {
                session_telemetry.record_auth_recovery(
                    mode,
                    phase,
                    "recovery_succeeded",
                    debug.request_id.as_deref(),
                    debug.cf_ray.as_deref(),
                    debug.auth_error.as_deref(),
                    debug.auth_error_code.as_deref(),
                    /*recovery_reason*/ None,
                    step_result.auth_state_changed(),
                );
                emit_feedback_auth_recovery_tags(
                    mode,
                    phase,
                    "recovery_succeeded",
                    debug.request_id.as_deref(),
                    debug.cf_ray.as_deref(),
                    debug.auth_error.as_deref(),
                    debug.auth_error_code.as_deref(),
                );
                Ok(UnauthorizedRecoveryExecution { mode, phase })
            }
            Err(RefreshTokenError::Policy(error)) => Err(CodexErr::Fatal(error.to_string())),
            Err(RefreshTokenError::Permanent(failed)) => {
                session_telemetry.record_auth_recovery(
                    mode,
                    phase,
                    "recovery_failed_permanent",
                    debug.request_id.as_deref(),
                    debug.cf_ray.as_deref(),
                    debug.auth_error.as_deref(),
                    debug.auth_error_code.as_deref(),
                    /*recovery_reason*/ None,
                    /*auth_state_changed*/ None,
                );
                emit_feedback_auth_recovery_tags(
                    mode,
                    phase,
                    "recovery_failed_permanent",
                    debug.request_id.as_deref(),
                    debug.cf_ray.as_deref(),
                    debug.auth_error.as_deref(),
                    debug.auth_error_code.as_deref(),
                );
                Err(CodexErr::RefreshTokenFailed(failed))
            }
            Err(RefreshTokenError::Transient(other)) => {
                session_telemetry.record_auth_recovery(
                    mode,
                    phase,
                    "recovery_failed_transient",
                    debug.request_id.as_deref(),
                    debug.cf_ray.as_deref(),
                    debug.auth_error.as_deref(),
                    debug.auth_error_code.as_deref(),
                    /*recovery_reason*/ None,
                    /*auth_state_changed*/ None,
                );
                emit_feedback_auth_recovery_tags(
                    mode,
                    phase,
                    "recovery_failed_transient",
                    debug.request_id.as_deref(),
                    debug.cf_ray.as_deref(),
                    debug.auth_error.as_deref(),
                    debug.auth_error_code.as_deref(),
                );
                Err(CodexErr::Io(other))
            }
        };
    }

    let (mode, phase, recovery_reason) = match auth_recovery.as_ref() {
        Some(recovery) => (
            recovery.mode_name(),
            recovery.step_name(),
            Some(recovery.unavailable_reason()),
        ),
        None => ("none", "none", Some("auth_manager_missing")),
    };
    session_telemetry.record_auth_recovery(
        mode,
        phase,
        "recovery_not_run",
        debug.request_id.as_deref(),
        debug.cf_ray.as_deref(),
        debug.auth_error.as_deref(),
        debug.auth_error_code.as_deref(),
        recovery_reason,
        /*auth_state_changed*/ None,
    );
    emit_feedback_auth_recovery_tags(
        mode,
        phase,
        "recovery_not_run",
        debug.request_id.as_deref(),
        debug.cf_ray.as_deref(),
        debug.auth_error.as_deref(),
        debug.auth_error_code.as_deref(),
    );

    Err(with_missing_openai_credentials_hint(
        provider.map_api_error(ApiError::Transport(transport)),
        provider,
    ))
}

/// Names what to set when OpenAI rejects a request that carried no credential (#365).
const MISSING_OPENAI_CREDENTIALS_MESSAGE: &str = "OpenAI rejected the request because no OpenAI \
    credential was found. Set OPENAI_API_KEY (`corbanu exec` also reads CODEX_API_KEY, which \
    takes precedence), or sign in with `corbanu login`";
/// The same, when `forced_login_method = "chatgpt"` turns the key variables off.
const MISSING_OPENAI_SIGN_IN_MESSAGE: &str = "OpenAI rejected the request because no ChatGPT \
    sign-in was found. This configuration requires one: run `corbanu login`";

fn with_missing_openai_credentials_hint(err: CodexErr, provider: &SharedModelProvider) -> CodexErr {
    let info = provider.info();
    let uses_openai_login_only = info.requires_openai_auth
        && info.env_key.is_none()
        && info.experimental_bearer_token.is_none()
        && info.auth.is_none()
        && info.aws.is_none();
    let manager = provider.auth_manager();
    let has_auth = manager
        .as_ref()
        .is_some_and(|manager| manager.auth_cached().is_some());
    let message = if manager
        .as_ref()
        .is_some_and(|manager| !manager.openai_api_key_env_enabled())
    {
        MISSING_OPENAI_SIGN_IN_MESSAGE
    } else {
        MISSING_OPENAI_CREDENTIALS_MESSAGE
    };
    match err.details() {
        codex_protocol::error::CodexErrorDetails::UnexpectedStatus(unexpected)
            if uses_openai_login_only
                && !has_auth
                && unexpected.status == StatusCode::UNAUTHORIZED
                && unexpected.user_message.is_none() =>
        {
            let mut unexpected = unexpected.clone();
            unexpected.user_message = Some(message.to_string());
            CodexErr::UnexpectedStatus(unexpected)
        }
        _ => err,
    }
}

fn api_error_http_status(error: &ApiError) -> Option<u16> {
    match error {
        ApiError::Transport(TransportError::Http { status, .. }) => Some(status.as_u16()),
        _ => None,
    }
}

struct ApiTelemetry {
    session_telemetry: SessionTelemetry,
    auth_context: AuthRequestTelemetryContext,
    request_route_telemetry: RequestRouteTelemetry,
    auth_env_telemetry: AuthEnvTelemetry,
}

impl ApiTelemetry {
    fn new(
        session_telemetry: SessionTelemetry,
        auth_context: AuthRequestTelemetryContext,
        request_route_telemetry: RequestRouteTelemetry,
        auth_env_telemetry: AuthEnvTelemetry,
    ) -> Self {
        Self {
            session_telemetry,
            auth_context,
            request_route_telemetry,
            auth_env_telemetry,
        }
    }
}

impl RequestTelemetry for ApiTelemetry {
    fn on_request(
        &self,
        attempt: u64,
        status: Option<StatusCode>,
        error: Option<&TransportError>,
        duration: Duration,
    ) {
        let error_message = error.map(telemetry_transport_error_message);
        let status = status.map(|s| s.as_u16());
        let debug = error
            .map(extract_response_debug_context)
            .unwrap_or_default();
        self.session_telemetry.record_api_request(
            attempt,
            status,
            error_message.as_deref(),
            duration,
            self.auth_context.auth_header_attached,
            self.auth_context.auth_header_name,
            self.auth_context.retry_after_unauthorized,
            self.auth_context.recovery_mode,
            self.auth_context.recovery_phase,
            self.request_route_telemetry.endpoint,
            debug.request_id.as_deref(),
            debug.cf_ray.as_deref(),
            debug.auth_error.as_deref(),
            debug.auth_error_code.as_deref(),
            self.auth_context.agent_identity_telemetry(),
        );
        emit_feedback_request_tags_with_auth_env(
            &FeedbackRequestTags {
                endpoint: self.request_route_telemetry.endpoint,
                auth_header_attached: self.auth_context.auth_header_attached,
                auth_header_name: self.auth_context.auth_header_name,
                auth_mode: self.auth_context.auth_mode,
                auth_retry_after_unauthorized: Some(self.auth_context.retry_after_unauthorized),
                auth_recovery_mode: self.auth_context.recovery_mode,
                auth_recovery_phase: self.auth_context.recovery_phase,
                auth_connection_reused: None,
                auth_request_id: debug.request_id.as_deref(),
                auth_cf_ray: debug.cf_ray.as_deref(),
                auth_error: debug.auth_error.as_deref(),
                auth_error_code: debug.auth_error_code.as_deref(),
                auth_recovery_followup_success: self
                    .auth_context
                    .retry_after_unauthorized
                    .then_some(error.is_none()),
                auth_recovery_followup_status: self
                    .auth_context
                    .retry_after_unauthorized
                    .then_some(status)
                    .flatten(),
            },
            &self.auth_env_telemetry,
        );
    }
}

impl SseTelemetry for ApiTelemetry {
    fn on_sse_poll(
        &self,
        result: &std::result::Result<
            Option<std::result::Result<Event, EventStreamError<TransportError>>>,
            tokio::time::error::Elapsed,
        >,
        duration: Duration,
    ) {
        self.session_telemetry.log_sse_event(result, duration);
    }
}

impl WebsocketTelemetry for ApiTelemetry {
    fn on_ws_request(&self, duration: Duration, error: Option<&ApiError>, connection_reused: bool) {
        let error_message = error.map(telemetry_api_error_message);
        let status = error.and_then(api_error_http_status);
        let debug = error
            .map(extract_response_debug_context_from_api_error)
            .unwrap_or_default();
        self.session_telemetry.record_websocket_request(
            duration,
            error_message.as_deref(),
            connection_reused,
            self.auth_context.agent_identity_telemetry(),
        );
        emit_feedback_request_tags_with_auth_env(
            &FeedbackRequestTags {
                endpoint: self.request_route_telemetry.endpoint,
                auth_header_attached: self.auth_context.auth_header_attached,
                auth_header_name: self.auth_context.auth_header_name,
                auth_mode: self.auth_context.auth_mode,
                auth_retry_after_unauthorized: Some(self.auth_context.retry_after_unauthorized),
                auth_recovery_mode: self.auth_context.recovery_mode,
                auth_recovery_phase: self.auth_context.recovery_phase,
                auth_connection_reused: Some(connection_reused),
                auth_request_id: debug.request_id.as_deref(),
                auth_cf_ray: debug.cf_ray.as_deref(),
                auth_error: debug.auth_error.as_deref(),
                auth_error_code: debug.auth_error_code.as_deref(),
                auth_recovery_followup_success: self
                    .auth_context
                    .retry_after_unauthorized
                    .then_some(error.is_none()),
                auth_recovery_followup_status: self
                    .auth_context
                    .retry_after_unauthorized
                    .then_some(status)
                    .flatten(),
            },
            &self.auth_env_telemetry,
        );
    }

    fn on_ws_event(
        &self,
        result: &std::result::Result<Option<std::result::Result<Message, Error>>, ApiError>,
        duration: Duration,
    ) {
        self.session_telemetry
            .record_websocket_event(result, duration);
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "client_fable_5_2_tests.rs"]
mod fable_5_2_tests;

/// The level in force for `thread_id`: the session's own level or the
/// stricter one its policy tree holds (Aggressive when that is unreadable).
/// See [`ModelClient::live_level`].
pub(crate) fn live_level_of(
    ingress_level: codex_security_policy::SecurityLevel,
    policy: Option<&crate::security::EffectivePolicyView>,
    thread_id: ThreadId,
) -> codex_security_policy::SecurityLevel {
    use codex_security_policy::SecurityLevel;
    let live = match policy {
        None => SecurityLevel::Permissive,
        Some(policy) => policy
            .snapshot_for_agent(thread_id)
            .map_or(SecurityLevel::Aggressive, |snapshot| snapshot.level),
    };
    ingress_level.max(live)
}
