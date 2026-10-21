use super::*;
use pretty_assertions::assert_eq;

/// A config as Corbanu Terminal's Aggressive launch leaves it (`marker`), or
/// one without the level.
async fn config(marker: bool) -> (tempfile::TempDir, Config) {
    let home = tempfile::tempdir().expect("home");
    let mut overrides = Vec::new();
    if marker {
        overrides.push((
            format!(
                "shell_environment_policy.set.{}",
                codex_security_level::nested::ORIGIN_ENV
            ),
            toml::Value::String(home.path().to_string_lossy().into_owned()),
        ));
    }
    let config = crate::config::ConfigBuilder::without_managed_config_for_tests()
        .codex_home(home.path().to_path_buf())
        .cli_overrides(overrides)
        .build()
        .await
        .expect("config");
    (home, config)
}

/// #439 (AGG-05/09/10/12): the milestone's refusals under Aggressive named
/// only the operating system's error.
#[tokio::test]
async fn sec_439_aggressive_refusals_name_the_level_and_the_way_forward() {
    let (_home, aggressive) = config(/*marker*/ true).await;
    let cases = [
        // AGG-05: writes outside the project.
        (
            true,
            1,
            "touch: /tmp/agg-probe: Operation not permitted",
            Some(Blocked::Files),
        ),
        (
            true,
            1,
            "/bin/bash: ../outside-notes.txt: Operation not permitted",
            Some(Blocked::Files),
        ),
        // AGG-09: a protected read.
        (
            true,
            1,
            "cat: .env: Operation not permitted",
            Some(Blocked::Files),
        ),
        // AGG-12: no network (no sandbox keyword in the output).
        (
            false,
            6,
            "curl: (6) Could not resolve host: example.com",
            Some(Blocked::Network),
        ),
        (
            false,
            1,
            "socket.gaierror: [Errno 8] nodename nor servname provided, or not known",
            Some(Blocked::Network),
        ),
        // Ordinary failures and successes are not attributed, also when the
        // macOS shims add their cache noise (AGG-36), which the sandbox-denial
        // guess counts as a denial.
        (false, 1, "error: pathspec 'x' did not match", None),
        (
            true,
            1,
            "python3: warning: confstr() failed with code 5: couldn't get path of DARWIN_USER_TEMP_DIR; using /tmp instead\npython3: error: couldn't create cache file '/tmp/xcrun_db-1wa2m1Bl' (errno=Operation not permitted)\nerror: pathspec 'x' did not match",
            None,
        ),
        (
            true,
            1,
            "python3: error: couldn't create cache file '/tmp/xcrun_db-x' (errno=Operation not permitted)\nAssertionError: tests failed",
            None,
        ),
        // AGG-12 as observed (the harness proxy stood in for the network).
        (
            false,
            7,
            "curl: (7) Failed to connect to 127.0.0.1 port 18443 after 0 ms: Couldn't connect to server",
            Some(Blocked::Network),
        ),
        (true, 0, "Operation not permitted", None),
    ];
    for (denied, exit_code, output, expected) in cases {
        assert_eq!(
            blocked(&aggressive, denied, Some(exit_code), output),
            expected,
            "{output}"
        );
    }
    assert_eq!(
        blocked(
            &aggressive,
            /*sandbox_denied*/ true,
            /*exit_code*/ None,
            "Operation not permitted"
        ),
        None
    );

    for blocked in [Blocked::Files, Blocked::Network] {
        let notice = blocked.notice();
        for expected in [
            "security level Aggressive",
            "even when you approve",
            "/security",
        ] {
            assert!(
                notice.to_lowercase().contains(&expected.to_lowercase()),
                "{expected}: {notice}"
            );
        }
        assert!(blocked.model_note().contains(notice));
    }
    // #442: protected reads are never granted, not even once.
    assert!(Blocked::Files.notice().contains("not even once"));
    assert!(!Blocked::Files.notice().contains("Grant once"));
    assert!(
        Blocked::Files
            .model_note()
            .contains("If this is why the command failed")
    );
    assert!(Blocked::Network.notice().contains("web search is off"));
}

/// A sandbox the person configured is theirs, not the level's.
#[tokio::test]
async fn sec_439_other_levels_are_not_attributed() {
    let (_home, permissive) = config(/*marker*/ false).await;
    assert_eq!(
        blocked(
            &permissive,
            /*sandbox_denied*/ true,
            Some(1),
            "touch: /tmp/x: Operation not permitted"
        ),
        None
    );
    assert_eq!(
        blocked(
            &permissive,
            /*sandbox_denied*/ false,
            Some(6),
            "curl: (6) Could not resolve host: x"
        ),
        None
    );
}

/// AGG-13: asked for a web search under Aggressive, the model needs to know
/// the level turned it off.
#[test]
fn sec_439_aggressive_instructions_name_web_search_and_the_way_forward() {
    for expected in [
        "security level Aggressive",
        "web search is off",
        "do not fetch web pages with curl",
        "/security",
    ] {
        assert!(AGGRESSIVE_INSTRUCTIONS.contains(expected), "{expected}");
    }
}

/// The returned guard owns the cwd for every consumer after helper return (#1157).
#[tokio::test]
async fn issue_1157_refusal_config_keeps_the_owned_working_folder() {
    let (home, config) = config(/*marker*/ false).await;
    assert_eq!(
        config.cwd.as_path(),
        home.path(),
        "returned config must use the owned working folder"
    );
    let cwd = config.cwd.to_path_buf();
    std::fs::write(cwd.join("after-return"), "owned").expect("cwd survives helper return");
    assert_eq!(
        std::fs::read_to_string(cwd.join("after-return")).unwrap(),
        "owned"
    );
    drop(config);
    assert!(
        cwd.exists(),
        "the returned owner still holds the working folder"
    );
    drop(home);
    assert!(
        !cwd.exists(),
        "the returned owner cleans up the working folder"
    );
}
