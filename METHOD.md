This is a separate, inert setup diagnostic for accepted Issue943 item 3, task
`task_22d1501f1887e33287b4f2d9907d51f6`. It does not qualify the held-note fix.

The original hosted run 39423100324 completed four setup commands, then reported
`controller_FileNotFoundError` without its filename. No formatter, compiler or
product test ran. The source-input hash loop and `/usr/bin/bwrap` identity check
were both in that failure window. Missing Bubblewrap is a leading explanation,
not an established historical fact. No path has been substituted or package
installed on that basis.

The fixed diagnostic checks the same 26 pinned source inputs, the two original
product files, the source checkout / `.git` / Rust working directories, and six
fixed system executable paths. `/bin/bwrap` is an observational alias only; it
does not substitute for the original `/usr/bin/bwrap` requirement. Bubblewrap
retains the original root-owned, non-writable, non-setid, executable ELF and
resolved-path identity checks. Other system executables receive identity checks
only; none is launched.

Missing paths are reported as exact allowlisted system paths or `<SOURCE>/...`
aliases with the exception class and numeric errno. Unknown exception filenames
are replaced with `<UNRECOGNIZED_PATH>`. Exception messages, stacks, environment
values and file contents are never exported. Hash mismatches, missing working
directories and missing executables remain distinct observations. Independent
safe metadata observations continue after a missing item, so one failure does
not hide the rest of the bounded prerequisite set.

The metadata loop has a cooperative 30-second deadline, an 8 MiB per-file limit
and a 64 MiB aggregate source-read limit. Version 2 had a reproduced accounting
bug: it checked the aggregate after reading and continued later source reads.
Version 3 reserves each source file's size before reading, never requests an
extra sentinel byte, and stops subsequent source-content reads after an
aggregate hold. Partial or failed reads retain their reservation; the receipt
reports charged bytes as an upper bound, not an invented exact consumption.
Independent safe directory/executable metadata can still be collected.
Version 2 and its original sixteen passing tests are preserved. Version 3 adds
explicit overshoot, exhaustion, rejected-read and growing-file checks.
It does not claim to interrupt a
blocked filesystem syscall; the hosted job has a separate five-minute limit.
There are no subprocesses, sockets, namespace probes, package acquisitions,
source patches or build/test commands. HOME, CODEX_HOME and inherited sandbox
markers are neither removed nor rebound. The original operator-host override
denial and native incident stay open.

The fixed workflow checks out the original base
`bfa6f7da57b55803be09ccd3613cdcdedd1c7e25` on a disposable Ubuntu 24.04 runner
using pinned checkout/upload actions and no persisted checkout credentials.
The diagnostic verifies selected source-file bytes; it does not independently
execute Git to verify HEAD. Admission is false and binds the controller, inputs
and workflow hashes. Root owns independent method review, any later admission,
publication and actual execution.

Even an all-present result is named
`SETUP_METADATA_PRESENT_NOT_CAPABILITY_OR_TEST_QUALIFICATION`. It proves neither
Bubblewrap namespace capability nor any of the twenty selected Rust test bodies.
A new hosted missing-path observation establishes a fact about that new host,
not the unrecorded filename from run 39423100324. Any subsequent acquisition,
path change or real namespace test requires a concrete separate method change.

Publication subset, if later approved: `setup-diagnostic-v3.py`,
`setup-inputs-v2.json`, `admission-v3.json`, this method text as `METHOD.md`, and the workflow
mapped to `.github/workflows/issue943-setup-diagnostic.yml`. Local tests, raw
local test logs and historical provenance receipts are not runtime payload.
