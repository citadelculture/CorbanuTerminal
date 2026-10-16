use super::*;
use crate::runtime::test_support::unique_temp_dir;
use pretty_assertions::assert_eq;
use std::path::Path;

fn key() -> ProviderRequestKey {
    ProviderRequestKey {
        provider_id: "zai".to_string(),
        model: "glm-5.2".to_string(),
        key_fingerprint: "fixture".to_string(),
    }
}

fn preflight() -> ProviderRequestPreflight {
    ProviderRequestPreflight {
        input_tokens: 37_492,
        cached_input_tokens: 0,
        request_bytes: 160_000,
        thread_id: None,
        turn_id: None,
    }
}

fn rate_limited() -> ProviderRequestResult {
    ProviderRequestResult::Failed {
        status: Some(429),
        request_id: Some("req-1".to_string()),
        retry_after_ms: Some(60_000),
    }
}

/// Another process holding the state DB's write lock until it is dropped.
async fn hold_write_lock(path: &Path) -> anyhow::Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
    let pool = crate::sqlite::open_pool_for_testing(
        sqlx::sqlite::SqlitePoolOptions::new().max_connections(1),
        sqlx::sqlite::SqliteConnectOptions::new().filename(path),
    )
    .await?;
    Ok(pool.begin_with("BEGIN IMMEDIATE").await?)
}

async fn acquire(
    runtime: &StateRuntime,
    owner: &str,
    now_ms: i64,
) -> ProviderRequestThrottled<ProviderRequestLeaseDecision> {
    runtime
        .acquire_provider_request_throttle_lease(
            &key(),
            &preflight(),
            owner,
            /*lease_ttl_ms*/ 600_000,
            now_ms,
        )
        .await
}

fn acquired(
    throttled: ProviderRequestThrottled<ProviderRequestLeaseDecision>,
) -> ProviderRequestLease {
    match throttled.decision {
        ProviderRequestLeaseDecision::Acquired(lease) => lease,
        ProviderRequestLeaseDecision::Blocked(block) => panic!("expected a lease, got {block:?}"),
    }
}

fn blocked_reason(
    throttled: &ProviderRequestThrottled<ProviderRequestLeaseDecision>,
) -> Option<ProviderRequestBlockReason> {
    match &throttled.decision {
        ProviderRequestLeaseDecision::Acquired(_) => None,
        ProviderRequestLeaseDecision::Blocked(block) => Some(block.reason.clone()),
    }
}

/// Another process holds the write lock for longer than the throttle waits.
/// Each step goes on from this process's memory, waits only once while the DB
/// is paused, and the limits this process knows still hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_held_past_the_wait_falls_back_to_this_process() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    eprintln!(
        "issue865 lock fixture: quick_pool={}",
        runtime.quick.is_some()
    );
    // A cooldown recorded while the DB answers still applies once it doesn't.
    let first = acquired(acquire(&runtime, "worker-a", /*now_ms*/ 1_000).await);
    assert_eq!(first.in_state_db, true);
    let recorded = runtime
        .record_provider_request_throttle_result(&first, rate_limited(), /*now_ms*/ 2_000)
        .await;
    assert_eq!(
        recorded,
        ProviderRequestThrottled::new(/*decision*/ true, /*state_db_fallback*/ None)
    );

    let held = hold_write_lock(&runtime.sqlite().state_db_path()).await?;
    let started = Instant::now();
    let check = runtime
        .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 3_000)
        .await;
    let first_wait = started.elapsed();
    eprintln!(
        "issue865 first check: elapsed={first_wait:?}, fallback={:?}, quick_pool={}",
        check.state_db_fallback,
        runtime.quick.is_some()
    );
    assert_eq!(check.state_db_fallback, Some(StateDbFallback::Busy));
    let block = check.decision.expect("the cooldown still holds");
    assert_eq!(
        (block.reason, block.last_status, block.last_request_id),
        (
            ProviderRequestBlockReason::Cooldown,
            Some(429),
            Some("req-1".to_string())
        )
    );
    // A step on the turn's path waits about a second (two short-wait
    // attempts), not SQLite's 5 s busy timeout.
    assert!(
        first_wait >= crate::QUICK_BUSY_TIMEOUT / 2 && first_wait < Duration::from_secs(2),
        "{first_wait:?}"
    );

    // While paused, later steps don't wait the lock out again.
    let started = Instant::now();
    let after_cooldown = 70_000;
    let worker_b = acquire(&runtime, "worker-b", after_cooldown).await;
    assert_eq!(worker_b.state_db_fallback, Some(StateDbFallback::Busy));
    let worker_b = acquired(worker_b);
    assert_eq!(worker_b.in_state_db, false);
    let worker_c = acquire(&runtime, "worker-c", after_cooldown + 1).await;
    assert_eq!(
        blocked_reason(&worker_c),
        Some(ProviderRequestBlockReason::Lease)
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );

    // The lease lives only here, so ending it needs no DB.
    let recorded = runtime
        .record_provider_request_throttle_result(&worker_b, rate_limited(), after_cooldown + 2)
        .await;
    assert_eq!(
        recorded,
        ProviderRequestThrottled::new(/*decision*/ true, /*state_db_fallback*/ None)
    );
    let check = runtime
        .check_provider_request_throttle(&key(), &preflight(), after_cooldown + 3)
        .await;
    assert_eq!(
        check.decision.map(|block| block.reason),
        Some(ProviderRequestBlockReason::Cooldown)
    );

    held.rollback().await?;
    // Once the DB answers again, the cooldown it never saw still applies here.
    runtime
        .provider_request_memory
        .paused
        .lock()
        .expect("pause lock")
        .take();
    let worker_d = acquire(&runtime, "worker-d", after_cooldown + 4).await;
    assert_eq!(worker_d.state_db_fallback, None);
    assert_eq!(
        blocked_reason(&worker_d),
        Some(ProviderRequestBlockReason::Cooldown)
    );
    // ...without taking a DB lease it would have to give back.
    let other_process = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let elsewhere = acquire(&other_process, "worker-e", after_cooldown + 5).await;
    assert_eq!(blocked_reason(&elsewhere), None);

    other_process.close().await;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// An interrupt while the result waits for a busy DB keeps the 429 cooldown in
/// this process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_record_keeps_the_cooldown() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let lease = acquired(acquire(&runtime, "worker-a", /*now_ms*/ 1_000).await);
    let held = hold_write_lock(&runtime.sqlite().state_db_path()).await?;
    let interrupted = tokio::time::timeout(
        Duration::from_millis(100),
        runtime.record_provider_request_throttle_result(
            &lease,
            rate_limited(),
            /*now_ms*/ 2_000,
        ),
    )
    .await;
    assert!(interrupted.is_err());
    let block = runtime.provider_request_memory.with_row(&key(), |row| {
        row.cooldown_block(/*now_ms*/ 3_000, /*state_db_answered*/ true)
    });
    assert_eq!(
        block.map(|block| (block.reason, block.until_ms)),
        Some((ProviderRequestBlockReason::Cooldown, 62_000))
    );

    held.rollback().await?;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// A state DB lease whose release failed (the DB stayed busy) is released by
/// the next step that reaches the DB, so it doesn't hold every process's
/// requests back until it expires.
#[tokio::test]
async fn a_lease_left_in_the_state_db_is_released_once_it_answers() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let other_process = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let lease = acquired(acquire(&runtime, "worker-a", /*now_ms*/ 1_000).await);
    // What `release_provider_request_throttle_lease` leaves when the DB fails.
    let memory = &runtime.provider_request_memory;
    memory.with_row(&lease.key, |row| row.release(&lease.owner));
    memory.defer_releases([lease]);
    let elsewhere = acquire(&other_process, "worker-b", /*now_ms*/ 2_000).await;
    assert_eq!(
        blocked_reason(&elsewhere),
        Some(ProviderRequestBlockReason::Lease)
    );

    let check = runtime
        .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 3_000)
        .await;
    assert_eq!(
        check,
        ProviderRequestThrottled::new(/*decision*/ None, /*state_db_fallback*/ None)
    );
    let elsewhere = acquire(&other_process, "worker-c", /*now_ms*/ 4_000).await;
    assert_eq!(blocked_reason(&elsewhere), None);

    other_process.close().await;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// A read-only state DB fails at once; the throttle goes on from memory and
/// still limits this process.
#[cfg(unix)]
#[tokio::test]
async fn a_read_only_state_db_falls_back_to_this_process() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let home = unique_temp_dir();
    let writable = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let db_path = writable.sqlite().state_db_path();
    std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o444))?;
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;

    let check = runtime
        .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 1_000)
        .await;
    assert_eq!(
        check,
        ProviderRequestThrottled::new(/*decision*/ None, Some(StateDbFallback::ReadOnly))
    );
    let lease = acquired(acquire(&runtime, "worker-a", /*now_ms*/ 1_001).await);
    let second = acquire(&runtime, "worker-b", /*now_ms*/ 1_002).await;
    assert_eq!(second.state_db_fallback, Some(StateDbFallback::ReadOnly));
    assert_eq!(
        blocked_reason(&second),
        Some(ProviderRequestBlockReason::Lease)
    );
    assert_eq!(
        runtime
            .release_provider_request_throttle_lease(&lease, /*now_ms*/ 1_003)
            .await?,
        1
    );
    acquired(acquire(&runtime, "worker-b", /*now_ms*/ 1_004).await);

    std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o644))?;
    runtime.close().await;
    writable.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// PF-84-S05: throttle state is kept per account. Account `fake`'s 429
/// cooldown never blocks account `work` of the same provider and model.
#[tokio::test]
async fn one_accounts_cooldown_never_blocks_another() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let account = |name: &str| ProviderRequestKey {
        key_fingerprint: format!("account:{name}"),
        ..key()
    };
    let lease = |key: ProviderRequestKey, owner: &'static str, now_ms: i64| {
        let runtime = &runtime;
        async move {
            runtime
                .acquire_provider_request_throttle_lease(
                    &key,
                    &preflight(),
                    owner,
                    /*lease_ttl_ms*/ 600_000,
                    now_ms,
                )
                .await
        }
    };
    let fake = acquired(lease(account("fake"), "fake-worker", 1_000).await);
    runtime
        .record_provider_request_throttle_result(&fake, rate_limited(), /*now_ms*/ 2_000)
        .await;
    let blocked = runtime
        .check_provider_request_throttle(&account("fake"), &preflight(), /*now_ms*/ 3_000)
        .await;
    assert_eq!(
        blocked.decision.map(|block| block.reason),
        Some(ProviderRequestBlockReason::Cooldown)
    );
    let work = runtime
        .check_provider_request_throttle(&account("work"), &preflight(), /*now_ms*/ 3_000)
        .await;
    assert_eq!(work.decision, None);
    acquired(lease(account("work"), "work-worker", 3_001).await);
    runtime.close().await;
    Ok(())
}

fn check_reason(
    throttled: &ProviderRequestThrottled<Option<ProviderRequestBlock>>,
) -> Option<(ProviderRequestBlockReason, i64, Option<i64>)> {
    throttled
        .decision
        .as_ref()
        .map(|block| (block.reason.clone(), block.until_ms, block.last_status))
}

/// #476: a request sent without a lease (every human-driven session) records
/// its 429, so every process on the home holds the key back for the cooldown
/// the provider asked for; another key is never held back.
#[tokio::test]
async fn an_unleased_429_starts_a_cooldown_every_process_sees() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let other_process = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let account = |name: &str| ProviderRequestKey {
        key_fingerprint: format!("account:{name}"),
        ..key()
    };
    let check = |runtime: &StateRuntime, key: ProviderRequestKey, now_ms: i64| {
        let runtime = runtime.clone();
        async move {
            runtime
                .check_provider_request_throttle(&key, &preflight(), now_ms)
                .await
        }
    };
    assert_eq!(check(&runtime, account("b"), 1_000).await.decision, None);
    let recorded = runtime
        .record_provider_request_throttle_outcome(
            &account("b"),
            rate_limited(),
            /*now_ms*/ 2_000,
        )
        .await;
    assert_eq!(recorded.state_db_fallback, None);

    for process in [&runtime, &other_process] {
        assert_eq!(
            check_reason(&check(process, account("b"), 3_000).await),
            Some((ProviderRequestBlockReason::Cooldown, 62_000, Some(429)))
        );
        assert_eq!(check(process, account("a"), 3_000).await.decision, None);
    }
    // Without Retry-After the cooldown escalates 30 s, 60 s, ... per 429.
    let no_retry_after = ProviderRequestResult::Failed {
        status: Some(429),
        request_id: None,
        retry_after_ms: None,
    };
    for (now_ms, until_ms) in [(100_000, 130_000), (200_000, 260_000)] {
        other_process
            .record_provider_request_throttle_outcome(&account("a"), no_retry_after.clone(), now_ms)
            .await;
        assert_eq!(
            check_reason(&check(&runtime, account("a"), now_ms + 1).await),
            Some((ProviderRequestBlockReason::Cooldown, until_ms, Some(429)))
        );
    }
    // A cooldown expires; a later success resets the escalation.
    other_process
        .record_provider_request_throttle_outcome(
            &account("a"),
            ProviderRequestResult::Success {
                input_tokens: Some(10),
                cached_input_tokens: Some(0),
            },
            /*now_ms*/ 400_000,
        )
        .await;
    assert_eq!(check(&runtime, account("a"), 400_001).await.decision, None);
    other_process
        .record_provider_request_throttle_outcome(
            &account("a"),
            no_retry_after,
            /*now_ms*/ 500_000,
        )
        .await;
    assert_eq!(
        check_reason(&check(&runtime, account("a"), 500_001).await),
        Some((ProviderRequestBlockReason::Cooldown, 530_000, Some(429)))
    );

    other_process.close().await;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// #476: an unleased result never shortens a cooldown another request
/// recorded, and never touches another request's lease.
#[tokio::test]
async fn an_unleased_result_never_ends_a_cooldown_or_lease() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let other_process = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    runtime
        .record_provider_request_throttle_outcome(&key(), rate_limited(), /*now_ms*/ 1_000)
        .await;
    for result in [
        ProviderRequestResult::Success {
            input_tokens: Some(1),
            cached_input_tokens: None,
        },
        ProviderRequestResult::Failed {
            status: Some(401),
            request_id: None,
            retry_after_ms: None,
        },
        ProviderRequestResult::Failed {
            status: Some(429),
            request_id: Some("req-2".to_string()),
            retry_after_ms: Some(1_000),
        },
    ] {
        other_process
            .record_provider_request_throttle_outcome(&key(), result, /*now_ms*/ 2_000)
            .await;
        assert_eq!(
            check_reason(
                &runtime
                    .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 3_000)
                    .await
            ),
            Some((ProviderRequestBlockReason::Cooldown, 61_000, Some(429)))
        );
    }

    let lease = acquired(acquire(&runtime, "worker-a", /*now_ms*/ 70_000).await);
    other_process
        .record_provider_request_throttle_outcome(
            &key(),
            ProviderRequestResult::Success {
                input_tokens: None,
                cached_input_tokens: None,
            },
            /*now_ms*/ 71_000,
        )
        .await;
    assert_eq!(
        blocked_reason(&acquire(&other_process, "worker-b", /*now_ms*/ 72_000).await),
        Some(ProviderRequestBlockReason::Lease)
    );
    runtime
        .release_provider_request_throttle_lease(&lease, /*now_ms*/ 73_000)
        .await?;

    other_process.close().await;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// #476: with the state DB busy, an unleased 429 still holds this process's
/// requests back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unleased_429_holds_this_process_back_while_the_db_is_busy() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let held = hold_write_lock(&runtime.sqlite().state_db_path()).await?;
    let recorded = runtime
        .record_provider_request_throttle_outcome(&key(), rate_limited(), /*now_ms*/ 1_000)
        .await;
    assert_eq!(recorded.state_db_fallback, Some(StateDbFallback::Busy));
    let check = runtime
        .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 2_000)
        .await;
    assert_eq!(
        check_reason(&check),
        Some((ProviderRequestBlockReason::Cooldown, 61_000, Some(429)))
    );
    held.rollback().await?;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// #482: every home has its own key fingerprint salt, read the same by every
/// process on it.
#[tokio::test]
async fn the_key_salt_is_per_home() -> anyhow::Result<()> {
    let (home_a, home_b) = (unique_temp_dir(), unique_temp_dir());
    let a = StateRuntime::init_for_testing(home_a.clone(), "zai".into()).await?;
    let a2 = StateRuntime::init_for_testing(home_a.clone(), "zai".into()).await?;
    let b = StateRuntime::init_for_testing(home_b.clone(), "zai".into()).await?;
    let salt_a = a.provider_request_key_salt().await?;
    assert_eq!(salt_a.len(), 32);
    assert_eq!(salt_a, a2.provider_request_key_salt().await?);
    assert_ne!(salt_a, b.provider_request_key_salt().await?);
    for runtime in [a, a2, b] {
        runtime.close().await;
    }
    let _ = std::fs::remove_dir_all(home_a);
    let _ = std::fs::remove_dir_all(home_b);
    Ok(())
}

/// #482: a row an older build kept under the unsalted key moves to the salted
/// key with its cooldown, and the unsalted value is gone from the DB.
#[tokio::test]
async fn a_legacy_row_moves_to_its_salted_key() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let legacy = ProviderRequestKey {
        key_fingerprint: "env:ZAI_API_KEY:0123456789abcdef".to_string(),
        ..key()
    };
    let salted = ProviderRequestKey {
        key_fingerprint: "env-salted:ZAI_API_KEY:fedcba9876543210".to_string(),
        ..key()
    };
    let lease = acquired(
        runtime
            .acquire_provider_request_throttle_lease(
                &legacy,
                &preflight(),
                "old",
                /*lease_ttl_ms*/ 600_000,
                /*now_ms*/ 1_000,
            )
            .await,
    );
    let recorded = runtime
        .record_provider_request_throttle_result(&lease, rate_limited(), /*now_ms*/ 2_000)
        .await;
    let seeded: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT key_fingerprint, cooldown_until_ms, lease_until_ms FROM provider_request_state",
    )
    .fetch_all(runtime.pool.as_ref())
    .await?;
    eprintln!(
        "issue865 legacy seed: quick_pool={}, lease_in_db={}, recorded={recorded:?}, rows={seeded:?}",
        runtime.quick.is_some(),
        lease.in_state_db
    );

    // A fresh process (no memory of the legacy cooldown) adopts the row.
    let process = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    process
        .adopt_legacy_provider_request_key(
            &legacy.key_fingerprint,
            &salted.key_fingerprint,
            /*now_ms*/ 2_500,
        )
        .await;
    let migrated: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT key_fingerprint, cooldown_until_ms, lease_until_ms FROM provider_request_state",
    )
    .fetch_all(process.pool.as_ref())
    .await?;
    eprintln!(
        "issue865 legacy adoption: quick_pool={}, paused={:?}, rows={migrated:?}",
        process.quick.is_some(),
        process.provider_request_memory.paused()
    );
    assert_eq!(
        check_reason(
            &process
                .check_provider_request_throttle(&salted, &preflight(), /*now_ms*/ 3_000)
                .await
        ),
        Some((ProviderRequestBlockReason::Cooldown, 62_000, Some(429)))
    );
    let keys: Vec<String> =
        sqlx::query_scalar("SELECT key_fingerprint FROM provider_request_state")
            .fetch_all(process.pool.as_ref())
            .await?;
    assert_eq!(keys, vec![salted.key_fingerprint.clone()]);

    process.close().await;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// Review S1: 429s from requests already in flight when a cooldown began are
/// one burst: they extend the cooldown without escalating it.
#[tokio::test]
async fn a_burst_of_429s_does_not_escalate_the_cooldown() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let no_retry_after = ProviderRequestResult::Failed {
        status: Some(429),
        request_id: None,
        retry_after_ms: None,
    };
    for now_ms in [1_000, 1_100, 1_200] {
        runtime
            .record_provider_request_throttle_outcome(&key(), no_retry_after.clone(), now_ms)
            .await;
    }
    assert_eq!(
        check_reason(
            &runtime
                .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 2_000)
                .await
        ),
        Some((ProviderRequestBlockReason::Cooldown, 31_200, Some(429)))
    );
    // The next 429 after the cooldown escalates once.
    runtime
        .record_provider_request_throttle_outcome(&key(), no_retry_after, /*now_ms*/ 40_000)
        .await;
    assert_eq!(
        check_reason(
            &runtime
                .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 40_001)
                .await
        ),
        Some((ProviderRequestBlockReason::Cooldown, 100_000, Some(429)))
    );
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// Review S2: a leased request that succeeds never ends a cooldown an
/// unleased 429 started while it held the lease.
#[tokio::test]
async fn a_leased_success_never_ends_an_unleased_cooldown() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let other_process = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let lease = acquired(acquire(&runtime, "worker-a", /*now_ms*/ 1_000).await);
    other_process
        .record_provider_request_throttle_outcome(&key(), rate_limited(), /*now_ms*/ 2_000)
        .await;
    let recorded = runtime
        .record_provider_request_throttle_result(
            &lease,
            ProviderRequestResult::Success {
                input_tokens: Some(1),
                cached_input_tokens: None,
            },
            /*now_ms*/ 3_000,
        )
        .await;
    assert_eq!(recorded.decision, true);
    for process in [&runtime, &other_process] {
        assert_eq!(
            check_reason(
                &process
                    .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 4_000)
                    .await
            ),
            Some((ProviderRequestBlockReason::Cooldown, 62_000, Some(429)))
        );
    }
    // The lease itself ended.
    assert_eq!(
        blocked_reason(&acquire(&other_process, "worker-b", /*now_ms*/ 70_000).await),
        None
    );
    other_process.close().await;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// Review S4: adoption keeps an existing salted row, and deletes every idle
/// unsalted row (another key's, or one an older build wrote since).
#[tokio::test]
async fn adoption_keeps_the_salted_row_and_deletes_idle_unsalted_rows() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let row = |fingerprint: &str, cooldown_until_ms: i64| {
        let pool = runtime.pool.clone();
        let fingerprint = fingerprint.to_string();
        async move {
            sqlx::query(
                "INSERT INTO provider_request_state (provider_id, model, key_fingerprint, cooldown_until_ms, last_status, updated_at_ms) VALUES ('zai', 'glm-5.2', ?, ?, 429, 0)",
            )
            .bind(fingerprint)
            .bind(cooldown_until_ms)
            .execute(pool.as_ref())
            .await
        }
    };
    row("env:ZAI_API_KEY:aaaaaaaaaaaaaaaa", 50_000).await?;
    row("env-salted:ZAI_API_KEY:1111111111111111", 9_000).await?;
    row("env:OTHER_KEY:bbbbbbbbbbbbbbbb", 0).await?;
    row("env:OTHER_KEY:cccccccccccccccc", 80_000).await?;
    runtime
        .adopt_legacy_provider_request_key(
            "env:ZAI_API_KEY:aaaaaaaaaaaaaaaa",
            "env-salted:ZAI_API_KEY:1111111111111111",
            /*now_ms*/ 10_000,
        )
        .await;
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT key_fingerprint, cooldown_until_ms FROM provider_request_state ORDER BY key_fingerprint",
    )
    .fetch_all(runtime.pool.as_ref())
    .await?;
    assert_eq!(
        rows,
        vec![
            ("env-salted:ZAI_API_KEY:1111111111111111".to_string(), 9_000),
            ("env:OTHER_KEY:cccccccccccccccc".to_string(), 80_000),
        ]
    );
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}

/// Review B1: a busy state DB costs adoption one wait, then pauses the DB as
/// the other throttle steps do; it is not tried again in this process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adoption_waits_out_a_busy_db_once() -> anyhow::Result<()> {
    let home = unique_temp_dir();
    let runtime = StateRuntime::init_for_testing(home.clone(), "zai".into()).await?;
    let held = hold_write_lock(&runtime.sqlite().state_db_path()).await?;
    let adopt = || {
        runtime.adopt_legacy_provider_request_key(
            "env:ZAI_API_KEY:aaaaaaaaaaaaaaaa",
            "env-salted:ZAI_API_KEY:1111111111111111",
            /*now_ms*/ 1_000,
        )
    };
    let started = Instant::now();
    adopt().await;
    assert!(
        started.elapsed() >= crate::QUICK_BUSY_TIMEOUT / 2
            && started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        runtime.provider_request_memory.paused(),
        Some(StateDbFallback::Busy)
    );
    let started = Instant::now();
    adopt().await;
    let check = runtime
        .check_provider_request_throttle(&key(), &preflight(), /*now_ms*/ 2_000)
        .await;
    assert_eq!(check.state_db_fallback, Some(StateDbFallback::Busy));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    held.rollback().await?;
    runtime.close().await;
    let _ = std::fs::remove_dir_all(home);
    Ok(())
}
