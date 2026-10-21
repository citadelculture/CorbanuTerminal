This is inert lock-generation preparation for the optional cached-root statx
follow-up after PR1116 merged, as unpaid adoption maintenance. PR1116 merged at
7a20f703f8eb96e4b9bc902ad55b881f6253ebbe on 2026-10-21T15:33:05Z. The old 75954940
candidate and method remain unchanged; this is a new packet bound to the merge.

The subject is that exact public merge commit in CorbanuCore/CorbanuTerminal
plus subject.patch (four files). source-pins.json binds the ported patch,
32 baseline source/policy/config/workflow files, candidate hashes and both exact
tracked symlinks. The direct rustix 1.1.4 fs edge is hand-prepared; generated
Bazel output remains unqualified. This stage is separate from Issue1056 item2
and active PR1238. Fresh 16:03–16:04 public reads found no matching statx/DONT_SYNC
open PR among 61; main's advance to d7684fae changes only unrelated core/TUI
Windows-test files. Root must refresh overlap and base relevance before dispatch.

The stage runs only:

1. `just bazel-lock-update`
2. `just fmt`
3. `just bazel-lock-check`

It requests no product compilation or tests. The update recipe is ordinary
`bazel mod deps --lockfile_mode=update`. The check uses the repository's
BuildBuddy wrapper, which selects local Bazel when no key is provided. The
inspected rules_rs 0.0.102 extension invokes prebuilt Cargo metadata and
toml2json. Its module/dependency evaluation still downloads public tools and
metadata; successful generation is not Linux GNU or musl qualification.

The narrow bazel.py launcher accepts only those two module-lock modes. It adds
batch mode, owned output/cache paths, no home/system rc, and the repository CI
wrapper's existing `--noexperimental_remote_repo_contents_cache` startup choice.
The subject workspace rc and ordinary recipes remain intact. No BuildBuddy
credentials, remote execution configuration, source patches to wrappers or
sandbox marker removal are used. The worker receives an explicit environment
allowlist, retaining the host's HOME unchanged and both sandbox markers exactly
as inherited; it receives no GitHub/Actions/BuildBuddy tokens. Cargo/uv/XDG and
Bazel caches are fresh, owned disposable directories.

The proposed runner is public GitHub ubuntu-24.04, x86_64, nonroot. The label is
not an immutable image: actual ImageOS/ImageVersion and system Python/Git/Bash
versions and binary hashes are retained. The 10 public download pins cover
Rust 1.99.1's six explicit components, Bazel 9.0.0, Just 1.58.0, uv 0.11.3 and
DotSlash 0.5.9. Exact SHA256 and byte counts are checked before extraction or
execution. The ordinary formatter resolves Buildifier and each project's Ruff
from the unchanged repository descriptors/locks. No rustup, apt installation,
cache deletion or owner-host execution is used. No product builds or tests are requested.

GitHub checkout materializes the exact subject with submodules/LFS disabled and
credentials not persisted. HEAD, clean tree and pinned files are checked before
patch application. Symlinks are verified using lstat/readlink and target-byte
hashes. Preparation checked the complete untruncated Git tree metadata at the
merge: exactly the same two authorized symlink modes/blob IDs/lengths, with no
submodules. No link-target blob or target file was fetched in this preparation. The one external credential-looking public fixture link is preserved
as an inert exact Git symlink; its target is never resolved, statted, opened,
copied or printed. Only its public repository path and hashes enter evidence.
No source tar extraction or full source archive is involved.

Proposed disposable-host bounds are 12 GiB admission, 4 GiB continuous free-space
floor, 30 minutes work, 64 MiB aggregate raw logs and 128 MiB evidence. The 45-minute
job leaves time for checkout, owned-process cleanup and upload. These are
workload-specific proposed bounds, not owner-host policy changes or an
execution admission. The outer controller owns one process group. Bazel runs
in batch mode; no persistent server is requested. On timeout/resource error it
signals only that owned group, waits, escalates to KILL if needed, and requires
confirmed group absence and direct-child reaping. Unknown cleanup, missing
worker results or failed steps cannot be reported complete. No process-name,
UID-wide or machine-wide kills occur.

Actual before/after MODULE.bazel.lock and Cargo.lock copies, all command logs,
download/tool identities, source/link hashes, exit codes, final patch and a
SHA256 evidence manifest are retained, including failed attempts. After a
worker stop the outer controller attempts final generated-file capture only
after confirmed owned-group cleanup. Snapshots reject symlinks and oversized
files. Upload contains selected logs/JSON/generated text/patches only, never
the source fixture, tool archives, caches or executable binaries. Raw logs are
preserved because they originate only from public tools/source on the
disposable host with no credentials supplied. Artifact retention is 14 days;
root must download and preserve evidence before expiry.

Only MODULE.bazel.lock may change beyond the four already frozen input files.
The four candidate hashes must remain exact through generation/format/check;
unexpected changes are retained as failure evidence and require human/root
inspection. The final check must leave generated files unchanged. An unchanged
generated lockfile is recorded honestly; no artificial lock delta is created.

This packet is not admitted. admission.json deliberately has approved:false.
Root must obtain independent method review and normal publication approval,
then bind the exact packet-manifest SHA256 and real review-receipt SHA256 in
admission.json. Publish only to a new orphan method branch matching the exact
workflow filter; inherited broad workflows must not be present. No dispatch or
publication has occurred in preparation. The runtime rejects other routes and
rerun attempts; any retry needs a fresh reviewed method/route.

On completion root must inspect actual generated dependency drift, preserve
the full evidence, and adopt it into a separately source-pinned follow-up only
after fresh merge/base/overlap checks. Full GNU/musl build and focused test
qualification are later, separately admitted stages. No product pass, PR
closure, Tasknode eligibility, allocation or reward is claimed here.

This new packet binds Rust 1.99.1 (clippy/rustfmt/rust-src included) and Bazel 9.0.0.
The upstream setup action selects Just 1.51.0; this bounded method retains the
previously pinned Just 1.58.0 formatter tool. That explicit method choice and all
asset digests require the next independent method review. The official rustfmt
print source allows a bare 1.10.0 or 1.10.0 followed by a hyphen and build details;
the version gate accepts only those boundaries and records complete output. No source wrapper,
containment rule, timeout, resource floor or cleanup rule was weakened.

The candidate contains 27 statically registered journal tests (the merge's 26
plus one root-symlink identity fixture); six mount/identity cases are listed in
the source-port handoff. No test is selected or executed by this stage. GNU and
musl compilation, ordinary test bodies, kernel-error behavior and actual timing
remain separate later qualification. The source requests DONT_SYNC, falls back
to scanning unknown roots and makes no universal wall-clock nonblocking claim.

Before publication or execution, independent method review must cover this
exact merged-base patch, updated tool/version pins and source/link bindings;
root must bind the real review receipt and packet manifest in admission.json.
The prepared exact orphan route is codex/pr1116-statx-bazel-lock-v2-20261021.
Keep only this packet on that route, preserving the push filter and avoiding
inherited broad CI workflows. No permission to publish or execute is inferred
from successful offline controls. admission.json remains approved:false.
