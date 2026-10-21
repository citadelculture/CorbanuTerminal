# PR951 follow-up: full formatting preparation

This packet is inactive. It binds the exact two-file launch re-audit normalization follow-up to public CorbanuCore/CorbanuTerminal commit `a88b55ded5dea23e272db5133b1e93e001e11438`. Its sole intended workload is the unchanged ordinary `just fmt` command. It performs no Rust product build, native test, performance benchmark, permission probe or UI qualification.

## Hold and next step

The original Issue1240 attempt1 reached formatter exit 0 and then failed to remove owned temporary tool state with `PermissionError`. The original PR951 v1 checkpoint preserves that controller unchanged and explicitly holds it. This v2 derivative carries the separately frozen cleanup correction; it makes no claim about the unidentified historical offending path or an actual recovery run.

Cleanup is confined to the known root name, original device/inode and current UID. It opens directories with no-follow file descriptors, repairs only owner directory permissions where necessary, deletes relative to those directory descriptors, never chmods files or follows links, and enforces 60 seconds, 100,000 entries and depth 64. It preserves primary failures, cleanup progress and cleanup failure independently; unsuccessful cleanup still prevents completion. Resource, process-group, source snapshot and evidence-export gates are unchanged.

`admission.json` remains false with no manifest or review SHA. The shared-framework review, once its final receipt is frozen, supplies only scoped cleanup-code evidence. It does not admit PR951's distinct source, Rust 1.95.0 formatter closure or publication route. Root must bind that exact receipt, verify this derivative and its source/tool differences, preserve the existing PR951 review ledger without a reset, and provide normal exact-payload admission. This mechanical preparation conducts no opinion review and invents no extra review allowance.

Root also freshly verifies PR951 demand, exact source head, overlap and destination branch absence. Any later activation is a separate publication copy changing only the admission record under root's exact instructions. No external mutation, formatter or product execution occurred in this preparation.

## Source and tools

The source commit resolves to tree `a901cdd629ad24fbe68dac18d85d9d506c17b4d6`. The worker checks the complete recursive Git tree, 23 selected source/policy/formatter inputs, and typed full-tree snapshots before and after patching and formatting. The tree contains 28,572 regular files and one tracked symlink. Only `codex-rs/tui/src/security/preflight.rs` and `codex-rs/tui/src/security/preflight_tests.rs` may change content. The exact patch is 8,804 bytes with SHA256 `6b7f4136ce32e491644c87eb20743a0801532a4a5702cd7b5d311f1b01996420`.

The license symlink is checked with lstat/readlink against its pinned Git mode, blob, byte count and target SHA256. It is never followed or exported as target content. This older source does not contain the later external QA fixture; no permission for that fixture is imported. Source inventory, modes, file types and link identity must remain unchanged.

The subject pins Rust 1.95.0, not the later 1.99.1 toolchain. Exact official archive metadata supplies rustc, rust-std, cargo and rustfmt (expected version 1.9.0). Just 1.58.0, uv 0.11.3 and DotSlash 0.5.9 use the same retained official public asset pins. Seven archives total 150,361,582 bytes. Each URL, size and SHA256 is verified before bounded safe extraction, then installer component identity and executable versions/hashes are checked. Archive layouts remain expected until actual acquisition. This preparation downloaded no archives and invoked no installed tool binaries.

The source also lists Clippy/rust-src for development. The narrow formatter installs the four Rust components required by cargo fmt directly; it does not invoke rustup or claim a complete product toolchain. The ordinary wrapper keeps all five formatting groups: Just, Rust, Buildifier, SDK Python and scripts Python. Buildifier and Python dependencies remain governed by the exact source DotSlash descriptor and frozen uv locks. Cargo networking is disabled, and only bounded rustc metadata is allowed in the separate target directory.

## Proposed route and unchanged boundaries

The inert workflow is an orphan-method first-push route on `citadelculture/CorbanuTerminal`, branch `codex/pr951-fullfmt-v2-20261021`, workflow `.github/workflows/pr951-fullfmt-v2.yml`. Both checkout actions and artifact upload are commit pinned; checkouts use `persist-credentials: false`, depth 1, no LFS or submodules. The public subject is checked out separately at the exact commit. The controller rejects other repositories, branches, workflow identities, repeated runs/attempts, root UID, unexpected images and altered method/source hashes. No existing product branch or default workflow is modified by this preparation.

The proposed disposable Ubuntu 24.04 x86_64 stage retains the inherited 8 GiB admission and 2 GiB continuous free-space floor, 1,500-second worker deadline, 600-second formatter deadline, 64 MiB logs, 128 MiB evidence, and bounded archive expansion. Job/step deadlines reserve process cleanup and artifact upload. Those disposable-host bounds do not weaken owner-host reserves.

The worker receives fresh owned HOME, temporary/tool/cache state and a strict system-path/locale environment. Every inherited `CODEX_SANDBOX*` value is preserved byte-for-byte. No account credentials, SSH agent, owner profile or general environment dump is forwarded. Public dependency access remains ordinary runner networking; no network isolation is claimed. Descendants use one owned process group; no broad process kill is allowed. Failure or unknown cleanup state cannot become success. The corrected owned-state cleanup is carried from the shared frozen implementation; its integration and admission requirements remain explicit above.

## Evidence and limits

The allowlisted artifact retains original command logs plus separately hashed normalized copies, tool/download identities, command exits, complete typed source-tree hashes, base/candidate/formatted/final copies of both selected sources, and canonical source/formatter-delta patches. The controller takes its own final source snapshot after child-process cleanup. Any unexpected source delta, missing evidence, privacy audit failure or cleanup failure keeps completion false. No raw environment, owner-host paths, general runner files, symlink targets or product binaries are exported. Disposable checkout and ignored formatter virtual environments remain until runner disposal; separate removal is not claimed.

Even a later successful result supplies formatting evidence only. The intended product change preserves isolation verdicts, diagnostic text/order, duplicates, layer identity and the existing macOS Seatbelt path while preparing the non-macOS read view once for the launch isolation batch. These are intended properties, not execution claims. The exact source candidate includes two new regression methods plus four inherited methods. Ordinary final-source Linux debug qualification is still pending; macOS/Windows have explicit platform guards and cannot inherit Linux results. Whole interactive launch, native credential access and wall-clock performance are unqualified. This follow-up does not resubmit PR951's prior paid outcome or establish new task/reward eligibility.

Offline Python controls include the 30 original PR951 packet/toy controls and nine synthetic owned-cleanup regression controls. They exercise packet identities and path, archive, evidence and process-boundary logic. They are not product tests, formatter execution, a source opinion review or admission.
