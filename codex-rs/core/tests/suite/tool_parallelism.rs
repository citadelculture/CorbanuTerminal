#![cfg(not(target_os = "windows"))]
#![allow(clippy::unwrap_used)]

use core_test_support::test_codex::local_selections;
use std::fs;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use codex_core::config::Config;
use codex_extension_api::ExtensionRegistry;
use codex_extension_api::ExtensionRegistryBuilder;
use codex_extension_api::ToolCallOutcome;
use codex_extension_api::ToolFinishInput;
use codex_extension_api::ToolLifecycleContributor;
use codex_extension_api::ToolLifecycleFuture;
use codex_extension_api::ToolStartInput;
use codex_protocol::models::PermissionProfile;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_function_call;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_sse_once;
use core_test_support::responses::mount_sse_sequence;
use core_test_support::responses::sse;
use core_test_support::responses::start_mock_server;
use core_test_support::skip_if_no_network;
use core_test_support::skip_if_wine_exec;
use core_test_support::streaming_sse::StreamingSseChunk;
use core_test_support::streaming_sse::start_streaming_sse_server;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use core_test_support::test_codex::turn_permission_fields;
use core_test_support::wait_for_event;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use tokio::sync::Barrier;
use tokio::sync::oneshot;

struct ParallelToolRendezvous {
    barrier: Barrier,
    arrivals: Mutex<Vec<(String, bool)>>,
    outcomes: Mutex<Vec<(String, ToolCallOutcome)>>,
}

impl ParallelToolRendezvous {
    fn assert_completed(&self) {
        let mut arrivals = self.arrivals.lock().unwrap();
        arrivals.sort();
        assert_eq!(
            *arrivals,
            vec![("call-1".to_string(), true), ("call-2".to_string(), true)],
            "both tool calls must reach the rendezvous while the other is still active"
        );

        let mut outcomes = self.outcomes.lock().unwrap();
        outcomes.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            *outcomes,
            vec![
                (
                    "call-1".to_string(),
                    ToolCallOutcome::Completed { success: true }
                ),
                (
                    "call-2".to_string(),
                    ToolCallOutcome::Completed { success: true }
                ),
            ]
        );
    }
}

impl ToolLifecycleContributor for ParallelToolRendezvous {
    fn on_tool_start<'a>(&'a self, input: ToolStartInput<'a>) -> ToolLifecycleFuture<'a> {
        Box::pin(async move {
            // The lifecycle callback runs inside the tool's parallel-execution gate.
            // Neither invocation can proceed until both have been admitted. The
            // timeout only bounds a failed rendezvous; elapsed time is not the proof.
            let overlapped = tokio::time::timeout(Duration::from_secs(10), self.barrier.wait())
                .await
                .is_ok();
            self.arrivals
                .lock()
                .unwrap()
                .push((input.call_id.to_string(), overlapped));
        })
    }

    fn on_tool_finish<'a>(&'a self, input: ToolFinishInput<'a>) -> ToolLifecycleFuture<'a> {
        Box::pin(async move {
            self.outcomes
                .lock()
                .unwrap()
                .push((input.call_id.to_string(), input.outcome));
        })
    }
}

fn parallel_tool_rendezvous() -> (Arc<ParallelToolRendezvous>, Arc<ExtensionRegistry<Config>>) {
    let rendezvous = Arc::new(ParallelToolRendezvous {
        barrier: Barrier::new(2),
        arrivals: Mutex::new(Vec::new()),
        outcomes: Mutex::new(Vec::new()),
    });
    let mut extensions = ExtensionRegistryBuilder::new();
    extensions.tool_lifecycle_contributor(rendezvous.clone());
    (rendezvous, Arc::new(extensions.build()))
}

async fn run_turn(test: &TestCodex, prompt: &str) -> anyhow::Result<()> {
    let session_model = test.session_configured.model.clone();
    let (sandbox_policy, permission_profile) =
        turn_permission_fields(PermissionProfile::Disabled, test.cwd.path());

    test.codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: prompt.into(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
            responsesapi_client_metadata: None,
            additional_context: Default::default(),
            thread_settings: codex_protocol::protocol::ThreadSettingsOverrides {
                environments: Some(local_selections(test.config.cwd.clone())),
                approval_policy: Some(AskForApproval::Never),
                sandbox_policy: Some(sandbox_policy),
                permission_profile,
                collaboration_mode: Some(codex_protocol::config_types::CollaborationMode {
                    mode: codex_protocol::config_types::ModeKind::Default,
                    settings: codex_protocol::config_types::Settings {
                        model: session_model,
                        reasoning_effort: None,
                        developer_instructions: None,
                    },
                }),
                ..Default::default()
            },
        })
        .await?;

    wait_for_event(&test.codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    Ok(())
}

async fn run_turn_and_measure(test: &TestCodex, prompt: &str) -> anyhow::Result<Duration> {
    let start = Instant::now();
    run_turn(test, prompt).await?;
    Ok(start.elapsed())
}

async fn build_codex_with_test_tool(server: &wiremock::MockServer) -> anyhow::Result<TestCodex> {
    let mut builder = test_codex().with_model("test-gpt-5.1-codex");
    builder.build(server).await
}

fn assert_parallel_duration(actual: Duration) {
    // Allow headroom for slow CI scheduling; barrier synchronization already enforces overlap.
    assert!(
        actual < Duration::from_millis(1_600),
        "expected parallel execution to finish quickly, got {actual:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_file_tools_run_in_parallel() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let test = build_codex_with_test_tool(&server).await?;

    let warmup_args = json!({
        "sleep_after_ms": 10,
        "barrier": {
            "id": "parallel-test-sync-warmup",
            "participants": 2,
            "timeout_ms": 1_000,
        }
    })
    .to_string();

    let parallel_args = json!({
        "sleep_after_ms": 300,
        "barrier": {
            "id": "parallel-test-sync",
            "participants": 2,
            "timeout_ms": 1_000,
        }
    })
    .to_string();

    let warmup_first = sse(vec![
        json!({"type": "response.created", "response": {"id": "resp-warm-1"}}),
        ev_function_call("warm-call-1", "test_sync_tool", &warmup_args),
        ev_function_call("warm-call-2", "test_sync_tool", &warmup_args),
        ev_completed("resp-warm-1"),
    ]);
    let warmup_second = sse(vec![
        ev_assistant_message("warm-msg-1", "warmup complete"),
        ev_completed("resp-warm-2"),
    ]);

    let first_response = sse(vec![
        json!({"type": "response.created", "response": {"id": "resp-1"}}),
        ev_function_call("call-1", "test_sync_tool", &parallel_args),
        ev_function_call("call-2", "test_sync_tool", &parallel_args),
        ev_completed("resp-1"),
    ]);
    let second_response = sse(vec![
        ev_assistant_message("msg-1", "done"),
        ev_completed("resp-2"),
    ]);
    mount_sse_sequence(
        &server,
        vec![warmup_first, warmup_second, first_response, second_response],
    )
    .await;

    run_turn(&test, "warm up parallel tool").await?;

    let duration = run_turn_and_measure(&test, "exercise sync tool").await?;
    assert_parallel_duration(duration);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shell_tools_run_in_parallel() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));
    // A timing check: under Wine-exec every shell command starts through
    // Wine, which alone takes most of the bound (1.7 s against 1.6 s on
    // nightly-ci, #636), so it could not tell parallel from serial there.
    skip_if_wine_exec!(
        Ok(()),
        "shell start-up under Wine exceeds the parallel-timing bound"
    );

    let server = start_mock_server().await;
    let (rendezvous, extensions) = parallel_tool_rendezvous();
    let mut builder = test_codex()
        .with_model("gpt-5.4")
        .with_extensions(extensions);
    let test = builder.build(&server).await?;

    let shell_args = json!({
        "command": "echo shell output",
        // Avoid user-specific shell startup scripts.
        "login": false,
        "timeout_ms": 10_000,
    });
    let args_one = serde_json::to_string(&shell_args)?;
    let args_two = serde_json::to_string(&shell_args)?;

    let first_response = sse(vec![
        json!({"type": "response.created", "response": {"id": "resp-1"}}),
        ev_function_call("call-1", "shell_command", &args_one),
        ev_function_call("call-2", "shell_command", &args_two),
        ev_completed("resp-1"),
    ]);
    let second_response = sse(vec![
        ev_assistant_message("msg-1", "done"),
        ev_completed("resp-2"),
    ]);
    let _responses = mount_sse_sequence(&server, vec![first_response, second_response]).await;

    run_turn(&test, "run shell_command twice").await?;
    rendezvous.assert_completed();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_parallel_tools_run_in_parallel() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));
    // A timing check: under Wine-exec every shell command starts through
    // Wine, which alone takes most of the bound (1.7 s against 1.6 s on
    // nightly-ci, #636), so it could not tell parallel from serial there.
    skip_if_wine_exec!(
        Ok(()),
        "shell start-up under Wine exceeds the parallel-timing bound"
    );

    let server = start_mock_server().await;
    let (rendezvous, extensions) = parallel_tool_rendezvous();
    let mut builder = test_codex()
        .with_model("test-gpt-5.1-codex")
        .with_extensions(extensions);
    let test = builder.build(&server).await?;

    let sync_args = json!({}).to_string();
    let shell_args = serde_json::to_string(&json!({
        "command": "echo shell output",
        // Avoid user-specific shell startup scripts.
        "login": false,
        "timeout_ms": 10_000,
    }))?;

    let first_response = sse(vec![
        json!({"type": "response.created", "response": {"id": "resp-1"}}),
        ev_function_call("call-1", "test_sync_tool", &sync_args),
        ev_function_call("call-2", "shell_command", &shell_args),
        ev_completed("resp-1"),
    ]);
    let second_response = sse(vec![
        ev_assistant_message("msg-1", "done"),
        ev_completed("resp-2"),
    ]);
    let _responses = mount_sse_sequence(&server, vec![first_response, second_response]).await;

    run_turn(&test, "mix tools").await?;
    rendezvous.assert_completed();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_results_grouped() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let test = build_codex_with_test_tool(&server).await?;

    let shell_args = serde_json::to_string(&json!({
        "command": "echo 'shell output'",
        "timeout_ms": 1_000,
    }))?;

    mount_sse_once(
        &server,
        sse(vec![
            json!({"type": "response.created", "response": {"id": "resp-1"}}),
            ev_function_call("call-1", "shell_command", &shell_args),
            ev_function_call("call-2", "shell_command", &shell_args),
            ev_function_call("call-3", "shell_command", &shell_args),
            ev_completed("resp-1"),
        ]),
    )
    .await;
    let tool_output_request = mount_sse_once(
        &server,
        sse(vec![
            ev_assistant_message("msg-1", "done"),
            ev_completed("resp-2"),
        ]),
    )
    .await;

    run_turn(&test, "run shell three times").await?;

    let input = tool_output_request.single_request().input();

    // find all function_call inputs with indexes
    let function_calls = input
        .iter()
        .enumerate()
        .filter(|(_, item)| item.get("type").and_then(Value::as_str) == Some("function_call"))
        .collect::<Vec<_>>();

    let function_call_outputs = input
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            item.get("type").and_then(Value::as_str) == Some("function_call_output")
        })
        .collect::<Vec<_>>();

    assert_eq!(function_calls.len(), 3);
    assert_eq!(function_call_outputs.len(), 3);

    for (index, _) in &function_calls {
        for (output_index, _) in &function_call_outputs {
            assert!(
                *index < *output_index,
                "all function calls must come before outputs"
            );
        }
    }

    // output should come in the order of the function calls
    let zipped = function_calls
        .iter()
        .zip(function_call_outputs.iter())
        .collect::<Vec<_>>();
    for (call, output) in zipped {
        assert_eq!(
            call.1.get("call_id").and_then(Value::as_str),
            output.1.get("call_id").and_then(Value::as_str)
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shell_tools_start_before_response_completed_when_stream_delayed() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));

    let output_file = tempfile::NamedTempFile::new()?;
    let output_path = output_file.path();
    let first_response_id = "resp-1";
    let second_response_id = "resp-2";

    let command = |marker: u8| {
        format!(
            "perl -MTime::HiRes -e 'print int(Time::HiRes::time()*1000), \"\\n\"' >> \"{}\" # call-{marker}",
            output_path.display()
        )
    };
    // Use a non-login shell to avoid slow, user-specific shell init (e.g. zsh profiles)
    // from making this timing-based test flaky.
    let first_chunk = sse(vec![
        ev_response_created(first_response_id),
        ev_function_call(
            "call-1",
            "exec_command",
            &serde_json::to_string(&json!({"cmd": command(1), "login": false}))?,
        ),
        ev_function_call(
            "call-2",
            "exec_command",
            &serde_json::to_string(&json!({"cmd": command(2), "login": false}))?,
        ),
        ev_function_call(
            "call-3",
            "exec_command",
            &serde_json::to_string(&json!({"cmd": command(3), "login": false}))?,
        ),
        ev_function_call(
            "call-4",
            "exec_command",
            &serde_json::to_string(&json!({"cmd": command(4), "login": false}))?,
        ),
    ]);
    let second_chunk = sse(vec![ev_completed(first_response_id)]);
    let follow_up = sse(vec![
        ev_assistant_message("msg-1", "done"),
        ev_completed(second_response_id),
    ]);

    let (first_gate_tx, first_gate_rx) = oneshot::channel();
    let (completion_gate_tx, completion_gate_rx) = oneshot::channel();
    let (follow_up_gate_tx, follow_up_gate_rx) = oneshot::channel();
    let (streaming_server, completion_receivers) = start_streaming_sse_server(vec![
        vec![
            StreamingSseChunk {
                gate: Some(first_gate_rx),
                body: first_chunk,
            },
            StreamingSseChunk {
                gate: Some(completion_gate_rx),
                body: second_chunk,
            },
        ],
        vec![StreamingSseChunk {
            gate: Some(follow_up_gate_rx),
            body: follow_up,
        }],
    ])
    .await;

    let mut builder = test_codex().with_model("gpt-5.4");
    let test = builder
        .build_with_streaming_server(&streaming_server)
        .await?;

    let session_model = test.session_configured.model.clone();
    let (sandbox_policy, permission_profile) =
        turn_permission_fields(PermissionProfile::Disabled, test.cwd.path());
    test.codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "stream delayed completion".into(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
            responsesapi_client_metadata: None,
            additional_context: Default::default(),
            thread_settings: codex_protocol::protocol::ThreadSettingsOverrides {
                environments: Some(local_selections(test.config.cwd.clone())),
                approval_policy: Some(AskForApproval::Never),
                sandbox_policy: Some(sandbox_policy),
                permission_profile,
                collaboration_mode: Some(codex_protocol::config_types::CollaborationMode {
                    mode: codex_protocol::config_types::ModeKind::Default,
                    settings: codex_protocol::config_types::Settings {
                        model: session_model,
                        reasoning_effort: None,
                        developer_instructions: None,
                    },
                }),
                ..Default::default()
            },
        })
        .await?;

    let _ = first_gate_tx.send(());
    let _ = follow_up_gate_tx.send(());

    let timestamps = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let contents = fs::read_to_string(output_path)?;
            let timestamps = contents
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    line.trim()
                        .parse::<i64>()
                        .map_err(|err| anyhow::anyhow!("invalid timestamp {line:?}: {err}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if timestamps.len() == 4 {
                return Ok::<_, anyhow::Error>(timestamps);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;

    let _ = completion_gate_tx.send(());
    wait_for_event(&test.codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    let mut completion_iter = completion_receivers.into_iter();
    let completed_at = completion_iter
        .next()
        .expect("completion receiver missing")
        .await
        .expect("completion timestamp missing");
    let count = i64::try_from(timestamps.len()).expect("timestamp count fits in i64");
    assert_eq!(count, 4);

    for timestamp in timestamps {
        assert!(
            timestamp <= completed_at,
            "timestamp {timestamp} should be before or equal to completed {completed_at}"
        );
    }

    streaming_server.shutdown().await;

    Ok(())
}
