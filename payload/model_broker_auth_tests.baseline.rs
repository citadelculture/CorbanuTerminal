use super::*;
use pretty_assertions::assert_eq;

use ProviderApiKeyHeader as ModelAuthHeader;

fn binding(host: &str, port: u16, path_prefix: &str, header: ModelAuthHeader) -> Binding {
    Binding {
        host: host.to_string(),
        port,
        path_prefix: path_prefix.to_string(),
        header,
    }
}

#[test]
fn pf_27_s05_base_url_binds_origin_and_path_prefix() {
    assert_eq!(
        binding_for_base_url("https://api.openai.com/v1", ProviderApiKeyHeader::Bearer),
        Some(binding(
            "api.openai.com",
            /*port*/ 443,
            "/v1",
            ModelAuthHeader::Bearer
        ))
    );
    assert_eq!(
        binding_for_base_url(
            "https://API.Z.AI:8443/api/coding/paas/v4/",
            ProviderApiKeyHeader::Bearer
        ),
        Some(binding(
            "api.z.ai",
            /*port*/ 8443,
            "/api/coding/paas/v4",
            ModelAuthHeader::Bearer
        ))
    );
    assert_eq!(
        binding_for_base_url("https://api.anthropic.com", ProviderApiKeyHeader::XApiKey),
        Some(binding(
            "api.anthropic.com",
            /*port*/ 443,
            "/",
            ModelAuthHeader::XApiKey
        ))
    );
    // Plain HTTP, IPv6 literals, queries and garbage are not brokered.
    for url in [
        "http://localhost:11434/v1",
        "https://[::1]/v1",
        "https://api.example.com/v1?key=1",
        "not a url",
    ] {
        assert_eq!(
            binding_for_base_url(url, ProviderApiKeyHeader::Bearer),
            None,
            "{url}"
        );
    }
}

#[test]
fn pf_27_s05_requests_are_rewritten_to_plain_http_for_the_broker() {
    assert_eq!(
        BrokerRewrite::for_url("https://api.openai.com/v1/responses?stream=true"),
        Some(BrokerRewrite {
            host: "api.openai.com".to_string(),
            port: 443,
            path_and_query: "/v1/responses?stream=true".to_string(),
            broker_url: "http://api.openai.com:443/v1/responses?stream=true".to_string(),
        })
    );
    assert_eq!(
        BrokerRewrite::for_url("https://api.z.ai:8443/v4/chat/completions"),
        Some(BrokerRewrite {
            host: "api.z.ai".to_string(),
            port: 8443,
            path_and_query: "/v4/chat/completions".to_string(),
            broker_url: "http://api.z.ai:8443/v4/chat/completions".to_string(),
        })
    );
    for url in [
        "http://api.openai.com/v1/responses",
        "https://[::1]/v1",
        "https://a.example/v1#x",
    ] {
        assert_eq!(BrokerRewrite::for_url(url), None, "{url}");
    }
}

#[test]
fn issue_654_brokered_target_url_inverts_the_broker_rewrite() {
    let request = |url: &str| codex_http_client::Request::new(http::Method::POST, url.to_string());
    for url in [
        "https://api.z.ai/api/paas/v4/chat/completions",
        "https://api.openai.com/v1/responses?stream=true",
        "https://api.z.ai:8443/v4/chat/completions",
        "https://203.0.113.7/v1/messages",
        "https://api.example:80/v1/messages",
    ] {
        let brokered = rewritten_for_broker_in_tests(request(url));
        assert_ne!(brokered.url, url);
        assert_eq!(
            brokered_target_url(&brokered).as_deref(),
            Some(url),
            "{url}"
        );
    }
    // Only a frame-bearing plain-HTTP URL is the broker's.
    let unframed = request("http://api.z.ai:443/api/paas/v4/chat/completions");
    assert_eq!(brokered_target_url(&unframed), None);
    let mut framed_https = rewritten_for_broker_in_tests(request("https://api.z.ai/v4"));
    framed_https.url = "https://api.z.ai/v4".to_string();
    assert_eq!(brokered_target_url(&framed_https), None);
    let mut framed_user = rewritten_for_broker_in_tests(request("https://api.z.ai/v4"));
    framed_user.url = "http://user@api.z.ai:443/v4".to_string();
    assert_eq!(brokered_target_url(&framed_user), None);
}

fn brokered_request(base_url: &str, source: BrokeredKeySource) -> BrokeredAuthRequest {
    BrokeredAuthRequest {
        base_url: base_url.to_string(),
        header: ProviderApiKeyHeader::Bearer,
        source,
        extra_headers: HeaderMap::new(),
    }
}

fn provider_key() -> BrokeredKeySource {
    BrokeredKeySource::ProviderKey {
        account: None,
        provider_key_id: "ZAI_API_KEY".to_string(),
        env_vars: vec!["ZAI_API_KEY".to_string()],
    }
}

fn held_value() -> BrokeredKeySource {
    BrokeredKeySource::Value {
        key: codex_model_provider::ProviderApiKey {
            value: "sk-pf27s05-held".to_string(),
            header: ProviderApiKeyHeader::Bearer,
        },
        slot: None,
    }
}

/// The error a brokered credential use fails with; it ends the turn.
fn refusal(broker: &CoreModelKeyBroker, base_url: &str, source: BrokeredKeySource) -> String {
    match broker.auth(brokered_request(base_url, source)) {
        Ok(_) => panic!("no auth may be produced"),
        Err(error) => {
            assert!(!error.is_retryable(), "{error:?}");
            let message = error.to_string();
            assert!(message.starts_with("Fatal error: "), "{message}");
            message
        }
    }
}

/// PF-27-S05 / PF-27-S06: the branch platforms without the broker take
/// (`start` returns this broker off Unix). Every credential use fails; none
/// is attached directly.
#[test]
fn pf_27_s05_platform_without_broker_refuses_every_credential() {
    let broker = CoreModelKeyBroker::unsupported();
    for source in [provider_key(), held_value()] {
        let error = refusal(&broker, "https://api.z.ai/api/paas/v4", source);
        assert!(error.contains("not available on this platform"), "{error}");
    }
}

#[cfg(not(any(unix, windows)))]
#[test]
fn pf_27_s05_non_unix_start_is_the_refusing_broker() {
    let broker = CoreModelKeyBroker::start(BrokerSettings {
        runtime_dir: std::env::temp_dir(),
        scrub_responses: false,
        program: None,
        store_home: std::env::temp_dir(),
        env_names: Vec::new(),
        origin: BrokerModelAuthOrigin::Config,
    });
    let error = refusal(&broker, "https://api.z.ai/api/paas/v4", held_value());
    assert!(error.contains("not available on this platform"), "{error}");
}

/// PF-27-S09 / #391: a broker that cannot start fails every credential use
/// (nothing is sent directly) with a message naming the setting and how to
/// change level, and the provider keys it would have been handed are still
/// removed from Core's environment.
#[cfg(any(unix, windows))]
#[test]
fn sec_391_broker_that_cannot_start_fails_closed_and_scrubs_keys() {
    let name = format!("SEC391_CORE_KEY_{}", std::process::id());
    // SAFETY: a variable unique to this test; nothing else reads it.
    unsafe { std::env::set_var(&name, "synthetic-sec391-core-key") };
    let home = tempfile::tempdir().expect("home");
    let broker = CoreModelKeyBroker::start(BrokerSettings {
        runtime_dir: home.path().join("run"),
        scrub_responses: false,
        program: Some(home.path().join("missing-corbanu.exe")),
        store_home: home.path().to_path_buf(),
        env_names: vec![name.clone()],
        origin: BrokerModelAuthOrigin::AggressiveLevel,
    });
    assert_eq!(std::env::var_os(&name), None);
    // #436: "restart now" learns the key is gone (names only).
    assert!(removed_environment_keys().contains(&name));
    // #625: a broker that did not start holds nothing.
    assert!(!holds_environment_key(&name));
    assert!(broker.unavailable_reason().is_some());
    for source in [provider_key(), held_value()] {
        let error = refusal(&broker, "https://api.z.ai/api/paas/v4", source);
        for expected in [
            "model requests are refused: the isolated credential broker did not start",
            "Security level Aggressive turns broker_model_auth on",
            "choose Permissive in /security",
            "`broker_model_auth = false`",
        ] {
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }
}

/// #391: the fail-closed message names the setting, and says how to change
/// level only when the level turned it on.
#[test]
fn sec_391_not_started_message_names_the_setting_and_the_level() {
    for (cause, origin, present, absent) in [
        (
            StartFailure::Unavailable,
            BrokerModelAuthOrigin::AggressiveLevel,
            vec!["did not start", "Security level Aggressive", "/security"],
            vec![],
        ),
        (
            StartFailure::Unavailable,
            BrokerModelAuthOrigin::Config,
            vec![
                "did not start",
                "broker_model_auth is on in your configuration",
            ],
            vec!["/security", "Aggressive"],
        ),
        (
            StartFailure::Unavailable,
            BrokerModelAuthOrigin::Policy,
            vec!["did not start", "required by a managed policy"],
            vec!["/security", "Aggressive", "`broker_model_auth = false`"],
        ),
        (
            StartFailure::PipeSquatted,
            BrokerModelAuthOrigin::AggressiveLevel,
            vec![
                "held or served by another process",
                "sent nothing",
                "Security level Aggressive",
            ],
            vec![],
        ),
    ] {
        let broker = CoreModelKeyBroker::not_started(cause, origin);
        assert!(broker.unavailable_reason().is_some());
        let error = refusal(&broker, "https://api.z.ai/api/paas/v4", held_value());
        assert!(error.contains("nothing is sent without it"), "{error}");
        assert!(error.contains("broker_model_auth"), "{error}");
        for text in present {
            assert!(error.contains(text), "{cause:?} {origin:?} {text}: {error}");
        }
        for text in absent {
            assert!(
                !error.contains(text),
                "{cause:?} {origin:?} {text}: {error}"
            );
        }
    }
    assert_eq!(
        CoreModelKeyBroker::unsupported().unavailable_reason(),
        Some("the broker does not run on this system; model requests are refused")
    );
}

/// #391: the default matrix (level x OS x the person's own setting x a
/// project's setting). Aggressive, and Moderate (D2, 2026-10-14), on an OS
/// where the broker runs turn `broker_model_auth` on; the person's own
/// setting always wins, and a project layer cannot turn the level's default
/// off.
#[test]
fn sec_391_default_matrix_level_os_and_explicit_setting() {
    use SecurityLevel::Aggressive;
    use SecurityLevel::Moderate;
    use SecurityLevel::Permissive;
    // The feature's value as config loading resolves it: the level's
    // setting, else the merged config (project layers outrank the user's).
    let resolve = |level, supported, own: Option<bool>, project: Option<bool>| {
        level_broker_setting(level, supported, own)
            .unwrap_or_else(|| project.or(own).unwrap_or(false))
    };
    for level in [Permissive, Moderate, Aggressive] {
        for supported in [true, false] {
            for own in [None, Some(true), Some(false)] {
                for project in [None, Some(true), Some(false)] {
                    let expected = if level != Permissive && supported {
                        own.unwrap_or(true)
                    } else {
                        project.or(own).unwrap_or(false)
                    };
                    assert_eq!(
                        resolve(level, supported, own, project),
                        expected,
                        "{level:?} supported={supported} own={own:?} project={project:?}"
                    );
                }
            }
        }
    }
    // Spot checks of the rows that matter most.
    assert_eq!(
        level_broker_setting(Aggressive, /*supported*/ true, /*explicit*/ None),
        Some(true)
    );
    assert_eq!(
        level_broker_setting(Aggressive, /*supported*/ true, Some(false)),
        Some(false)
    );
    assert_eq!(
        level_broker_setting(Aggressive, /*supported*/ false, /*explicit*/ None),
        None
    );
    assert_eq!(
        level_broker_setting(Moderate, /*supported*/ true, /*explicit*/ None),
        Some(true)
    );
    assert_eq!(
        level_broker_setting(Moderate, /*supported*/ true, Some(false)),
        Some(false)
    );
    assert_eq!(
        level_broker_setting(Moderate, /*supported*/ false, /*explicit*/ None),
        None
    );
    assert!(!resolve(Moderate, true, Some(false), Some(true)));
    assert_eq!(level_origin(Moderate), BrokerModelAuthOrigin::ModerateLevel);
    assert_eq!(
        level_origin(Aggressive),
        BrokerModelAuthOrigin::AggressiveLevel
    );
    assert_eq!(
        level_broker_setting(Permissive, /*supported*/ true, /*explicit*/ None),
        None
    );
    assert!(resolve(Aggressive, true, Some(true), Some(false)));
    assert!(!resolve(Aggressive, true, Some(false), Some(true)));
    // macOS and Linux (PF-27-S05) and Windows (PF-27-S09) run the broker.
    assert_eq!(
        LEVEL_DEFAULT_SUPPORTED,
        cfg!(any(target_os = "macos", target_os = "linux", windows))
    );
}

/// #391: a provider URL the broker cannot bind names the level when the
/// level turned the broker on.
#[test]
fn sec_391_unbindable_url_names_the_level() {
    let broker =
        CoreModelKeyBroker::unsupported().with_origin(BrokerModelAuthOrigin::AggressiveLevel);
    let error = refusal(&broker, "http://localhost:11434/v1", held_value());
    for expected in [
        "cannot be brokered",
        "Security level Aggressive turns broker_model_auth on",
        "choose Permissive in /security",
    ] {
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

/// #839, #878: the inspector learns which session's request the broker
/// refused, for every kind of refusal: a provider URL it cannot bind (MOD-24)
/// and a credential it cannot register (here: no broker on this platform).
/// Another session's inspector does not show it; a refusal outside any
/// session (the model list, the wallet) shows in every inspector, after the
/// session's own.
#[test]
fn issue_878_refusals_belong_to_the_session_that_resolved_them() {
    let broker =
        CoreModelKeyBroker::unsupported().with_origin(BrokerModelAuthOrigin::ModerateLevel);
    let (session, other) = (
        codex_protocol::ThreadId::new(),
        codex_protocol::ThreadId::new(),
    );
    assert_eq!(broker.refused_reason(&[session]), None);

    refusals::owned_by_sync(session, || {
        refusal(&broker, "http://localhost:11434/v1", provider_key())
    });
    let unbindable = broker.refused_reason(&[session]).expect("refused");
    assert!(
        unbindable.starts_with("the last model request of this session")
            && unbindable.contains("provider URL cannot be brokered"),
        "{unbindable}"
    );
    assert_eq!(broker.refused_reason(&[other]), None);
    // The session's tree: a child agent's refusal is the session's.
    assert_eq!(broker.refused_reason(&[other, session]), Some(unbindable));

    refusals::owned_by_sync(other, || {
        refusal(&broker, "https://api.z.ai/api/paas/v4", held_value())
    });
    let unavailable = broker.refused_reason(&[other]).expect("refused");
    assert!(
        unavailable.contains("credential broker is not available"),
        "{unavailable}"
    );
    assert_eq!(broker.refused_reason(&[session]), Some(unbindable));

    let third = codex_protocol::ThreadId::new();
    assert_eq!(broker.refused_reason(&[third]), None);
    refusal(&broker, "https://api.z.ai/api/paas/v4", provider_key());
    let outside = broker.refused_reason(&[third]).expect("refused");
    assert!(
        outside.starts_with("the last brokered request outside a session"),
        "{outside}"
    );
    assert_eq!(broker.refused_reason(&[]), Some(outside));
    assert_eq!(broker.refused_reason(&[session]), Some(unbindable));
}

/// #878: every kind of registration failure is a refusal the inspector
/// shows, with a fixed text that names its kind.
#[test]
fn issue_878_every_broker_error_is_a_refusal() {
    use refusals::Refusal;
    let cases = [
        (
            BrokerModelAuthError::Unbindable {
                url: "http://x".to_string(),
                origin: BrokerModelAuthOrigin::Config,
            },
            Refusal::Unbindable,
        ),
        (
            BrokerModelAuthError::MissingKey {
                env: "ZAI_API_KEY".to_string(),
            },
            Refusal::NoKey,
        ),
        (
            BrokerModelAuthError::MissingAccountKey {
                provider_id: "zai".to_string(),
                name: "work".to_string(),
            },
            Refusal::NoKey,
        ),
        (BrokerModelAuthError::Store("unavailable"), Refusal::NoKey),
        (
            BrokerModelAuthError::Unavailable,
            Refusal::BrokerUnavailable,
        ),
        (
            BrokerModelAuthError::NotStarted {
                cause: StartFailure::Unavailable,
                origin: BrokerModelAuthOrigin::Config,
            },
            Refusal::BrokerUnavailable,
        ),
        (
            BrokerModelAuthError::Unsupported,
            Refusal::BrokerUnavailable,
        ),
        (
            BrokerModelAuthError::PipeSquatted,
            Refusal::BrokerUnavailable,
        ),
        (BrokerModelAuthError::Rejected, Refusal::Rejected),
    ];
    for (error, expected) in cases {
        assert_eq!(Refusal::from(&error), expected, "{error:?}");
    }
}

/// #878: a request URL the broker cannot serve, refused when the request is
/// signed ("model request URL cannot be brokered"), is the session's
/// refusal; a signed request waits for the broker's answer, and only that
/// answer clears the session's refusal.
#[test]
fn issue_878_signing_refusals_and_answers_are_the_sessions() {
    use codex_http_client::ModelBrokerOutcome;
    let refusals = Refusals::default();
    let session = Some(codex_protocol::ThreadId::new());
    let mut extra = HeaderMap::new();
    extra.insert("chatgpt-account-id", http::HeaderValue::from_static("acct"));

    let unbindable = BrokerRewrite::for_request_url("http://localhost:11434/v1/responses")
        .expect_err("plain HTTP is not brokered");
    let error = signed_for(&refusals, session, &extra, Err(unbindable)).expect_err("refused");
    assert!(error.to_string().contains("cannot be brokered"), "{error}");
    let threads: Vec<_> = session.into_iter().collect();
    let refused = refusals.reason(&threads).expect("refused");
    assert!(
        refused.contains("provider URL cannot be brokered"),
        "{refused}"
    );

    let request = rewritten_for_broker_in_tests(codex_http_client::Request::new(
        http::Method::POST,
        "https://api.z.ai/v4/chat/completions".to_string(),
    ));
    let signed = signed_for(&refusals, session, &extra, Ok(request)).expect("signed");
    assert_eq!(
        signed.headers.get("chatgpt-account-id"),
        extra.get("chatgpt-account-id")
    );
    // Signed is not served: the broker may still deny it.
    assert_eq!(refusals.reason(&threads), Some(refused));
    let frame = signed
        .headers
        .get(codex_http_client::MODEL_BROKER_FRAME_HEADER)
        .expect("frame")
        .clone();
    refusals.answered(&frame, ModelBrokerOutcome::Served);
    assert_eq!(refusals.reason(&threads), None);
}

/// #391 through config loading: Core's level, the stored `/security` level,
/// a config setting and a launch flag (`-c`) on this OS.
#[tokio::test]
async fn sec_391_config_load_applies_the_aggressive_default() {
    use crate::config::ConfigBuilder;
    use codex_config::LoaderOverrides;
    let expected_on = LEVEL_DEFAULT_SUPPORTED;
    let level_origin = if expected_on {
        BrokerModelAuthOrigin::AggressiveLevel
    } else {
        BrokerModelAuthOrigin::Config
    };
    let load = |config_toml: String, stored_aggressive: bool, cli: Vec<(String, toml::Value)>| async move {
        let home = tempfile::tempdir().expect("home");
        std::fs::write(home.path().join("config.toml"), config_toml).expect("config");
        if stored_aggressive {
            std::fs::write(
                home.path().join("security_level.toml"),
                "version = 1\nlevel = \"aggressive\"\n",
            )
            .expect("stored level");
        }
        let config = ConfigBuilder::default()
            .codex_home(home.path().to_path_buf())
            .cli_overrides(cli)
            .loader_overrides(LoaderOverrides::without_managed_config_for_tests())
            .build()
            .await
            .expect("config");
        (
            config.security_level,
            config
                .features
                .enabled(codex_features::Feature::BrokerModelAuth),
            config.broker_model_auth_origin,
        )
    };
    let level =
        |level: SecurityLevel| format!("[security]\nversion = 1\nlevel = \"{}\"\n", level.as_str());
    let off = "\n[features]\nbroker_model_auth = false\n";
    let flag_off = || {
        vec![(
            "features.broker_model_auth".to_string(),
            toml::Value::Boolean(false),
        )]
    };
    for (name, config_toml, stored, cli, expected) in [
        (
            "permissive",
            level(SecurityLevel::Permissive),
            false,
            Vec::new(),
            (
                SecurityLevel::Permissive,
                false,
                BrokerModelAuthOrigin::Config,
            ),
        ),
        // D2 (Travis, 2026-10-14): Moderate turns it on too.
        (
            "moderate",
            level(SecurityLevel::Moderate),
            false,
            Vec::new(),
            (
                SecurityLevel::Moderate,
                expected_on,
                if expected_on {
                    BrokerModelAuthOrigin::ModerateLevel
                } else {
                    BrokerModelAuthOrigin::Config
                },
            ),
        ),
        (
            "moderate, config off",
            level(SecurityLevel::Moderate) + off,
            false,
            Vec::new(),
            (
                SecurityLevel::Moderate,
                false,
                BrokerModelAuthOrigin::Config,
            ),
        ),
        (
            "aggressive",
            level(SecurityLevel::Aggressive),
            false,
            Vec::new(),
            (SecurityLevel::Aggressive, expected_on, level_origin),
        ),
        (
            "aggressive, config off",
            level(SecurityLevel::Aggressive) + off,
            false,
            Vec::new(),
            (
                SecurityLevel::Aggressive,
                false,
                BrokerModelAuthOrigin::Config,
            ),
        ),
        (
            "aggressive, -c off",
            level(SecurityLevel::Aggressive),
            false,
            flag_off(),
            (
                SecurityLevel::Aggressive,
                false,
                BrokerModelAuthOrigin::Config,
            ),
        ),
        (
            "stored /security aggressive",
            String::new(),
            true,
            Vec::new(),
            (SecurityLevel::Permissive, expected_on, level_origin),
        ),
        (
            "moderate, stored /security aggressive",
            level(SecurityLevel::Moderate),
            true,
            Vec::new(),
            (SecurityLevel::Moderate, expected_on, level_origin),
        ),
        (
            "stored /security aggressive, config off",
            off.to_string(),
            true,
            Vec::new(),
            (
                SecurityLevel::Permissive,
                false,
                BrokerModelAuthOrigin::Config,
            ),
        ),
    ] {
        assert_eq!(load(config_toml, stored, cli).await, expected, "{name}");
    }
}

#[test]
fn pf_27_s05_failed_broker_and_unbindable_urls_fail_closed() {
    let failed = CoreModelKeyBroker::new(BrokerHandle::Failed(BrokerModelAuthError::Unavailable));
    let error = refusal(&failed, "https://api.z.ai/api/paas/v4", provider_key());
    assert!(error.contains("unavailable"), "{error}");

    // A URL the broker cannot bind is refused before any broker call.
    for base_url in ["http://localhost:11434/v1", "https://[::1]/v1"] {
        let error = refusal(&CoreModelKeyBroker::unsupported(), base_url, held_value());
        assert!(error.contains("cannot be brokered"), "{base_url}: {error}");
    }
}

/// PF-27-S09: what the Windows sender puts on the pipe for a rewritten URL.
#[test]
fn pf_27_s09_pipe_request_target_keeps_the_signed_path_and_query() {
    assert_eq!(
        pipe_request_target("http://api.z.ai:443/api/paas/v4/chat/completions?x=1&y=2"),
        Some((
            "api.z.ai:443".to_string(),
            "/api/paas/v4/chat/completions?x=1&y=2".to_string()
        ))
    );
    // The broker URL is what `broker_request` produced for this request.
    let rewrite =
        BrokerRewrite::for_url("https://api.z.ai/api/paas/v4/models?page=2").expect("rewrite");
    assert_eq!(
        pipe_request_target(&rewrite.broker_url),
        Some(("api.z.ai:443".to_string(), rewrite.path_and_query))
    );
    for url in [
        "https://api.z.ai:443/v1",
        "http://user:secret@api.z.ai:443/v1",
        "http://user@api.z.ai:443/v1",
        "http://api.z.ai:443/v1#fragment",
        "not a url",
    ] {
        assert_eq!(pipe_request_target(url), None, "{url}");
    }
}

/// #390: a broker refused because another process holds or serves its named
/// pipe fails every credential use with a message that says so; nothing is
/// sent directly.
#[test]
fn sec_390_squatted_broker_pipe_fails_closed_with_a_clear_error() {
    let squatted =
        CoreModelKeyBroker::new(BrokerHandle::Failed(BrokerModelAuthError::PipeSquatted));
    for source in [provider_key(), held_value()] {
        let error = refusal(&squatted, "https://api.z.ai/api/paas/v4", source);
        assert!(
            error.contains("held or served by another process"),
            "{error}"
        );
        assert!(error.contains("sent nothing"), "{error}");
    }
}

/// #391: a project's `.codex/config.toml` cannot turn the broker off under
/// Aggressive (a repository may raise protection, never lower it), while the
/// person's own config can.
#[tokio::test]
async fn sec_391_project_config_cannot_turn_the_aggressive_default_off() {
    use crate::config::ConfigBuilder;
    use crate::config::ConfigOverrides;
    use codex_config::LoaderOverrides;
    let root = tempfile::tempdir().expect("root");
    // No `\\?\` prefix on Windows, so the trust key matches the folder.
    let root_path = dunce::canonicalize(root.path()).expect("canonical root");
    let project = root_path.join("project");
    std::fs::create_dir_all(project.join(".git")).expect("project");
    std::fs::create_dir_all(project.join(".codex")).expect("project config dir");
    std::fs::write(
        project.join(".codex/config.toml"),
        "[features]\nbroker_model_auth = false\n",
    )
    .expect("project config");
    let load = |user_features: &'static str| {
        let home = root_path.join(format!("home-{}", user_features.len()));
        let project = project.clone();
        async move {
            std::fs::create_dir_all(&home).expect("home");
            std::fs::write(
                home.join("config.toml"),
                format!(
                    "[security]\nversion = 1\nlevel = \"aggressive\"\n\n[projects.{:?}]\ntrust_level = \"trusted\"\n{user_features}",
                    codex_config::loader::project_trust_key(&project)
                ),
            )
            .expect("user config");
            let config = ConfigBuilder::default()
                .codex_home(home)
                .harness_overrides(ConfigOverrides {
                    cwd: Some(project),
                    ..Default::default()
                })
                .loader_overrides(LoaderOverrides::without_managed_config_for_tests())
                .build()
                .await
                .expect("config");
            assert!(
                config
                    .config_layer_stack
                    .layers_high_to_low()
                    .iter()
                    .any(|layer| matches!(
                        layer.name,
                        codex_config::ConfigLayerSource::Project { .. }
                    )),
                "the project layer loads"
            );
            config
                .features
                .enabled(codex_features::Feature::BrokerModelAuth)
        }
    };
    assert_eq!(load("").await, LEVEL_DEFAULT_SUPPORTED);
    assert!(!load("\n[features]\nbroker_model_auth = false\n").await);
    // The person's explicit `true` also beats the project's `false`. Only on
    // an OS with the broker: elsewhere it would mark this process brokered.
    if LEVEL_DEFAULT_SUPPORTED {
        assert!(load("\n[features]\nbroker_model_auth = true\n").await);
    }
}

/// #391: a managed requirement wins over the level, both ways, and a pin
/// that keeps the broker on is named in the refusal message.
#[tokio::test]
async fn sec_391_managed_requirement_wins_and_is_named() {
    use crate::config::ConfigBuilder;
    use codex_config::test_support::CloudConfigBundleFixture;
    let load = |pin: bool, user: &'static str| async move {
        let home = tempfile::tempdir().expect("home");
        std::fs::write(
            home.path().join("config.toml"),
            format!("[security]\nversion = 1\nlevel = \"aggressive\"\n{user}"),
        )
        .expect("config");
        let config = ConfigBuilder::without_managed_config_for_tests()
            .codex_home(home.path().to_path_buf())
            .fallback_cwd(Some(home.path().to_path_buf()))
            .cloud_config_bundle(
                CloudConfigBundleFixture::loader_with_enterprise_requirement(format!(
                    "[features]\nbroker_model_auth = {pin}\n"
                )),
            )
            .build()
            .await
            .expect("config");
        (
            config
                .features
                .enabled(codex_features::Feature::BrokerModelAuth),
            config.broker_model_auth_origin,
        )
    };
    assert_eq!(
        load(false, "").await,
        (false, BrokerModelAuthOrigin::Config)
    );
    // A pin that keeps the broker on would mark this shared test process
    // brokered where the level sets nothing (no broker on this OS).
    if LEVEL_DEFAULT_SUPPORTED {
        assert_eq!(load(true, "").await, (true, BrokerModelAuthOrigin::Policy));
        assert_eq!(
            load(true, "\n[features]\nbroker_model_auth = false\n").await,
            (true, BrokerModelAuthOrigin::Policy)
        );
    }
}

/// #625: a key the broker holds is reported as held, by name only.
#[test]
fn sec_625_held_environment_keys_are_reported_by_name() {
    let name = format!("SEC625_HELD_KEY_{}", std::process::id());
    assert!(!holds_environment_key(&name));
    note_held_env_keys(std::slice::from_ref(&name));
    assert!(holds_environment_key(&name));
    assert!(!holds_environment_key(&format!("{name}_OTHER")));
}

/// #750 (D2): a Moderate level chosen in `/security` decides the default at
/// the next start, as Aggressive does.
#[test]
fn issue_750_saved_moderate_decides_the_broker_default() {
    let home = tempfile::tempdir().expect("home");
    std::fs::write(
        home.path().join("security_level.toml"),
        "version = 1\nlevel = \"moderate\"\n",
    )
    .expect("stored level");
    assert_eq!(
        level_for_defaults(home.path(), SecurityLevel::Permissive),
        SecurityLevel::Moderate
    );
    assert_eq!(
        level_broker_setting(
            level_for_defaults(home.path(), SecurityLevel::Permissive),
            /*supported*/ true,
            /*explicit*/ None
        ),
        Some(true)
    );
}
