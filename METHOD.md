# Issue943 item3: current-source paired qualification

This is an inert, first-attempt hosted package. Root must approve the exact payload and admission before a push. No local product execution is authorized. The base is pinned public commit `c9dbae23b3d3f9753fc27a993479040b6b2735cd`; local DCO candidate is `c50d6fa0291fc01f4827f2ab1549b200314453ab`, currently unpublished. The two exact source payload hashes, not control-branch HEAD, identify the candidate.

The contributor asks for one held-back note per command. The patch preserves approval, protected-file, retry and stale-authority behavior and keeps the existing20-case selection. This is focused automated qualification only: no true-TUI, code-blind, human-test or release-readiness proof is claimed. Coordinator merge sequencing and a fresh public main/PR overlap check remain external prerequisites.

## Changed prerequisite

The previous hosted attempt failed safely before acquisition/tests because its public system keyring was mode0777. That file remains unread and untouched. This route uses a separately reviewed Canonical documented full-fingerprint bootstrap. A fixed public3607-byte keyring is SHA256/fingerprint-bound and created exclusively at `/usr/share/keyrings/issue943-authenticated-ubuntu-archive-v1.gpg`, with verified root-owned nonwritable parent descriptors and mode0444. Existing destination, unsafe identity, missing tools or any partial failure holds. No chmod, replacement, package scripts or trust-gate relaxation. The unchanged gpgv signature/current-release/index/package/ELF gates then apply; only the verified Bubblewrap ELF may be exclusively installed. Actual user/network namespace capability remains required before product work.

## Exact finite campaign

Use a fresh nonroot GitHub-hosted ubuntu-24.04 worker, exact branch push, attempt1, read-only contents and pinned checkout/upload actions; persist-credentials:false. Initial capacity30GiB before acquisition and first compilation; reused target8GiB; running floor4GiB. Job120minutes; campaign6900seconds; each selected test60seconds, no retry, one test thread, Cargo jobs2. Each group has15-minute execution timeout. First test/build invocation4200seconds; later invocations1800seconds. These are stop bounds, not estimates that every phase can fit. No cleanup of SDKs or security configuration is allowed to make it fit.

The unchanged repository `just test` wrapper creates its disposable test profile. Inherited HOME/CODEX_HOME presence and sandbox flags are preserved. Synthetic auth and loopback mocks only. Known inherited skip conditions hold; runtime skip markers, selected JUnit skips, wrong binary IDs, missing tests, retries, capture truncation and remaining owned children cannot qualify.

1. Verify source/payload/tools/bootstrap admission, then setup and real Bubblewrap capability.
2. Fetch exact pinned Rust1.99.1/tool/V8 assets into owned paths; full ordinary `just fmt` must pass without changing the frozen source, then locked dependency fetch.
3. Retain the final test fixture while restoring exact original production. Run14lib controls and6integration cases. Require19passes and exactly the held-note count assertion failure at `issue_874.rs:406`; control failures or setup/compile failures are not red.
4. Restore exact candidate production, scoped format check, then focused `just clippy -p codex-core --locked --offline -- -D warnings`.
5. Run the same20cases, requiring20passes, no selected skips/retries. Preserve complete bounded command captures/JUnit, source before/after and four actual stage binary identities. Baseline/candidate binary identities must differ per target.

One fresh target is reused throughout. Public artifacts contain only normalized output generated on this disposable hosted worker, never raw local receipts or operator environment. Qualification binaries are bounded and uploaded separately, not the target tree. Every failure remains unqualified and is retained. No automatic rerun or unchanged retry is authorized.
