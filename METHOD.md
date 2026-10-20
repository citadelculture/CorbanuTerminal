# Issue1056 mount-view dedup qualification

This is a bounded Linux source qualification, not a claim of kernel sandbox isolation or release readiness. Admission remains false until independent review and the publication owner's approval. No local product tests, hosted dispatch or public publication are performed by preparation.

The control machinery derives from the successful [sweep-budget run 39422320488](https://github.com/citadelculture/CorbanuTerminal/actions/runs/39422320488), whose reviewed controller SHA256 is `acb0398110c36d349e3855fa92e92e7ab7ae1e190831705ed5ab3587d36c1294`. Its owned command runner, finite capture/cleanup, process reaping, tool acquisition and binary retention are preserved. This campaign qualifies a distinct patch against public base `bac579e541b8fd8f0d67bc09ef45ab950fd247e3`.

## Source and behavioral contract

The fix retains distinct process mount views when processes share a mount namespace but have different root device/inode identities. Unknown identities are scanned without deduplication. The existing read-failure, owner filtering and cleanup eligibility rules remain unchanged.

The baseline is **not an unmodified-base build**. It adds only the mechanical iterator seam to original production logic and the same frozen tests used by the candidate. `payload/baseline-fixture.patch`, the complete baseline production file and their hashes identify this adaptation. The baseline keeps namespace-only deduplication. `payload/production-only.patch` switches the dedup key to namespace plus root device/inode; it does not change the tests. The controller verifies both patch bindings and each source variant.

Five exact equality-selected tests run through the unchanged ordinary `just test -p codex-linux-sandbox --lib --locked --offline` wrapper:

| Case | Adapted baseline | Candidate |
| --- | --- | --- |
| Different roots in one namespace | Exact assertion failure | Pass |
| Identical view deduplication and another namespace | Pass | Pass |
| Unidentified roots | Exact assertion failure | Pass |
| Unreadable distinct view | Exact assertion failure | Pass |
| Existing real `/proc` mount-point control | Pass | Pass |

The exact Rust names, assertion sites and full 25-case journal suite inventory are in `source-manifest.json`. The three baseline failures are source-derived expectations until actual execution. A compiler/setup failure, wrong assertion site, unexpected failure, missing case, selected skip, runtime body-skip marker, timeout, retry or cleanup defect cannot count as expected red.

The frozen source includes the author's full formatter pass: `just fmt` exited zero; its controller deliberately held because two layout edits were observed. Those exact edits were reconciled before this freeze. No product compiler or tests were run during that formatting pass. Both hosted variants still require their own full formatter pass with unchanged frozen bytes.

The four new fixtures use owned temporary directories, symlinks and synthetic `mountinfo`. The existing fifth control reads real `/proc`. These five tests do not spawn processes, mount, chroot, call Bubblewrap, start a broker or execute a product CLI. The broader journal suite retains existing short-lived `true` child fixtures and a permission test; the controller requires nonroot execution and owned-child cleanup. This suite does not depend on the unavailable Issue943 keyring/Bubblewrap setup or Network broker gates.

## Campaign sequence

1. Require an approved exact controller/source/tools/workflow binding, first-attempt push on the fixed owned repository branch, nonroot GitHub-hosted Linux x86_64 and Python 3.12 or newer.
2. Enforce the original disk floor and owned orphan-reaping preflight. Verify the clean public base checkout and all 19 source-input Git bindings.
3. Verify and apply the exact candidate patch, then restore only the explicitly pinned adapted baseline production file. Verify the baseline patch and candidate transition; the test file remains identical.
4. Fetch the same 12 bounded hash-pinned tool archives used by the successful reference campaign. The source lockfile, toolchain, wrapper, formatter and tool-input versions are unchanged. Preserve homes and all three inherited sandbox markers.
5. Run full `just fmt` on the adapted baseline, capture the resulting diff and require it to leave frozen source bytes unchanged. Fetch locked dependencies once. Run the five baseline cases and require exactly 3 expected assertion failures plus 2 passes.
6. Restore exact candidate production, run full `just fmt` again with the same unchanged-source gate, then scoped `cargo fmt --check` and ordinary `just clippy -p codex-linux-sandbox --lib --locked --offline -- -D warnings`. The repository Clippy recipe additionally selects tests; it does not execute them. Verify source again before the five candidate tests.
7. Require all five candidate cases, then all 25 journal cases, to pass. Verify source and binary identity before/after phases, final owned-child cleanup and inherited home/marker preservation.

A formatter change is retained as evidence and stops the campaign before tests for that variant. It is not silently accepted or mislabeled formatted. Any remaining formatter/source-review prerequisite is identified in the local handoff before admission.

## Controls and evidence

The original 120-minute job and 6,900-second controller deadlines remain. Each test has a 60-second limit, zero retries and one test thread. Compilation uses two jobs. Disk floors remain 30 GiB initially and before first compilation, 8 GiB for target reuse and 4 GiB during commands. Each command stream and JUnit file is capped at 16 MiB; each retained executable at 512 MiB, with at most two distinct binaries totaling 1 GiB.

All available command receipts, normalized stdout/stderr/combined/scripted-session records, JUnit, source diffs and binary digests are preserved, including failure evidence. Public normalization uses literal `[TASK_ROOT]`, `[CHECKOUT]`, `[WORKSPACE]`, `[RUNNER_HOME]` and `[INHERITED_CODEX_HOME]` tokens, so it does not inject invalid XML tags. Original raw byte counts and hashes remain separate from public hashes; normalization is never represented as raw-byte equality.

The controller does not clear inherited `HOME`, `CODEX_HOME`, `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED` or `CODEX_SANDBOX_USER_NAMESPACES_DENIED`. The ordinary repository wrapper creates its documented disposable test profile and debug native-keyring denial. This is not a host policy override. Operator profiles, private runtime receipts, credentials and local native incident data are excluded from the public package.

## Policy and limits

The exact pinned policy inputs are repository `AGENTS.md`, `codex-rs/AGENTS.md`, `.codex/skills/corbanu-terminal-development/SKILL.md`, `docs/development/test-isolation.md` and `docs/corbanu-product-spec.md`. The bounded-fix citation is **“Live MVP versus the P0 security controls”**: “The shipping MVP already has a wallet, vault, scoped signing, approvals, and general workspace sandboxing. These are live product capabilities.”

The applicable requirements are ordinary `just test`, full formatting before final tests, repository-pinned tooling, unchanged security environment handling, exact evidence and no false claim of skipped or unperformed qualification. The internal scanner repair changes no interactive workflow or product boundary; TUI/code-blind/live-repository release gates are not claimed by this focused method. Integrator acceptance and any required security-owner review remain root-owned.

This method does not prove chroot/mount kernel behavior, arbitrary concurrent mutation, root-identity race freedom, mount-path translation, the full sandbox suite or whole-product security. The previous local native incident and host-control override denial remain unresolved and binding.
