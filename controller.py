#!/usr/bin/env python3
"""Owned hosted Linux Issue943 paired qualification through unchanged just test."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

BASE = "c9dbae23b3d3f9753fc27a993479040b6b2735cd"
REPO = "citadelculture/CorbanuTerminal"
REF = "refs/heads/codex/issue943-owned-trust-v1-20261020"
PRODUCTION = "codex-rs/core/src/tools/orchestrator.rs"
TESTS = "codex-rs/core/tests/suite/issue_874.rs"
CASE_GROUPS = {'orchestrator': ('tools::orchestrator::tests::issue_540_retry_leaves_the_sandbox_only_where_a_person_approves_it', 'tools::orchestrator::tests::issue_826_user_namespace_rule_joins_sandboxed_profiles_only', 'tools::orchestrator::tests::linux_sandbox_startup_failure_is_classified_narrowly', 'tools::orchestrator::tests::on_request_sandbox_startup_retry_requires_prior_approval', 'tools::orchestrator::stale_tests::issue_1001_approval_before_a_transition_is_asked_again', 'tools::orchestrator::stale_tests::issue_1001_approval_without_a_transition_runs_as_before', 'tools::orchestrator::stale_tests::issue_1001_approval_stale_every_time_is_refused', 'tools::orchestrator::stale_tests::issue_1001_approval_before_aggressive_is_switched_on_is_refused', 'tools::orchestrator::stale_tests::issue_1001_retry_approved_before_a_transition_is_not_run', 'tools::orchestrator::stale_tests::issue_1001_unprompted_retry_after_a_transition_is_not_run', 'tools::orchestrator::stale_tests::issue_1001_stale_approval_with_permissions_is_refused', 'tools::orchestrator::stale_tests::issue_1057_grants_read_before_a_transition_are_not_used', 'tools::orchestrator::stale_tests::issue_1057_aggressive_switched_on_after_the_handler_is_refused', 'tools::orchestrator::stale_tests::issue_1057_handler_window_controls'), 'integration': ('suite::issue_874::issue_874_planted_git_links_and_rebase_steps_are_reported', 'suite::issue_874::issue_874_approval_does_not_lift_the_rules_while_a_finding_stands', 'suite::issue_874::issue_943_held_note_is_sent_once_when_approval_and_retry_are_held', 'suite::issue_874::issue_874_a_standing_finding_keeps_user_namespaces_denied', 'suite::issue_874::issue_874_a_standing_finding_keeps_d48_known_tools_denied', 'suite::issue_874::issue_943_a_command_in_another_repository_is_checked')}
STAGES = ("baseline-orchestrator", "baseline-integration", "candidate-orchestrator", "candidate-integration")
MARKERS = ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_SANDBOX_USER_NAMESPACES_DENIED")
RUNTIME_SKIPS = ("Sandbox-dependent test skipped:",
                 "Skipping test because it cannot execute when network is disabled in a Codex sandbox.",
                 "codex-linux-sandbox binary not available, skipping test")
BWRAP_ARGS = ("--unshare-user", "--unshare-net", "--ro-bind", "/", "/", "--", "/bin/true")
MAX_STREAM = 16 * 1024 * 1024
MAX_XML = 16 * 1024 * 1024
MAX_BINARY = 512 * 1024 * 1024
GIB = 1024 ** 3
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class Hold(RuntimeError):
    pass


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1048576), b""):
            h.update(b)
    return h.hexdigest()


def save(path, value):
    with Path(path).open("x") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def bounded_chunk(observed, retained, data, maximum=MAX_STREAM):
    kept = data[:max(0, maximum - retained)]
    return observed + len(data), retained + len(kept), kept, len(kept) != len(data)


def normalized(data, replacements):
    text = data.decode("utf-8", "strict")
    for old, new in sorted(replacements.items(), key=lambda x: -len(x[0])):
        if old:
            text = text.replace(old, new)
    if re.search(r"(?:github_pat_[A-Za-z0-9_]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})", text):
        raise Hold("public_output_secret_shape")
    return text.encode()


def classify_test(xml_bytes, output, expected, red_rules=None, binary="codex_core"):
    """Pure evidence parser. Filter exclusions never excuse a selected skip."""
    if len(xml_bytes) > MAX_XML or b"<!DOCTYPE" in xml_bytes or b"<!ENTITY" in xml_bytes:
        raise Hold("xml_bound_or_dtd")
    root = ET.fromstring(xml_bytes)
    names, excluded, selected = set(), 0, {}
    for case in root.iter("testcase"):
        name = case.get("name")
        if name in names:
            raise Hold("duplicate_junit_case")
        names.add(name)
        if name not in expected:
            if case.find("skipped") is None:
                raise Hold("unexpected_executed_case")
            excluded += 1
            continue
        if case.find("skipped") is not None:
            raise Hold("selected_test_skipped")
        if case.find("error") is not None:
            raise Hold("test_error_not_assertion")
        if any("rerun" in c.tag.lower() or "flaky" in c.tag.lower() for c in case.iter()):
            raise Hold("retry_or_flaky")
        duration = float(case.get("time", "-1"))
        if not 0 <= duration <= 60:
            raise Hold("test_time_bound")
        classname = case.get("classname", "")
        expected_class = "codex-core" if binary == "codex_core" else "codex-core::all"
        if classname != expected_class:
            raise Hold("wrong_test_binary")
        failures = case.findall("failure")
        body = ANSI.sub("", "\n".join(case.itertext()))
        if any(marker in body for marker in RUNTIME_SKIPS):
            raise Hold("runtime_body_skipped")
        if not red_rules or name not in red_rules:
            if failures:
                raise Hold("unexpected_failure")
            state = "PASS"
        else:
            if len(failures) != 1 or failures[0].get("type") != "test failure with exit code 101":
                raise Hold("expected_assertion_not_observed")
            rule = red_rules[name]
            site = r"issue_874\.rs:" + str(rule["panicLine"]) + r":\d+"
            if not re.search(site, body):
                raise Hold("wrong_assertion_site")
            if not all(re.search(pattern, body, re.S) for pattern in rule["requiredPatterns"]):
                raise Hold("wrong_assertion_signature")
            if any(re.search(pattern, body, re.S) for pattern in rule.get("forbiddenPatterns", [])):
                raise Hold("baseline_control_failed")
            state = "EXPECTED_ASSERTION_FAILURE"
        selected[name] = {"status": state, "seconds": duration}
    if set(selected) != set(expected):
        raise Hold("selected_cases_missing")
    text = ANSI.sub("", output)
    summaries = re.findall(r"(?m)^\s*Summary\s+\[[^\]]+\]\s+(\d+)\s+tests?\s+run:\s*(.+)$", text)
    if len(summaries) != 1:
        raise Hold("summary_missing_or_duplicate")
    count, rest = summaries[0]
    passed = re.search(r"(\d+)\s+passed", rest)
    failed = re.search(r"(\d+)\s+failed", rest)
    numbers = (int(count), int(passed.group(1)) if passed else 0, int(failed.group(1)) if failed else 0)
    red_count = len(red_rules or {})
    if red_rules and not set(red_rules) <= set(expected):
        raise Hold("red_case_outside_selection")
    wanted = (len(expected), len(expected) - red_count, red_count)
    if numbers != wanted or re.search(r"(?im)^\s*(?:TRY\s+\d|RETRY|FLAKY|TIMEOUT|TMPASS|LEAK|CANCEL)", text):
        raise Hold("summary_or_runtime_status_mismatch")
    if any(marker in text for marker in RUNTIME_SKIPS):
        raise Hold("runtime_body_skipped")
    if "Test isolation: disposable profile; native keyring disabled (debug lane)" not in text:
        raise Hold("wrapper_marker_missing")
    return {"cases": selected, "counts": list(numbers), "selectedSkips": 0,
            "observedFilterExclusions": excluded, "retries": 0}


def nextest_config(original, store):
    text = original.decode()
    if "[profile.held-note-" in text or re.search(r"(?m)^\s*\[store\]", text):
        raise Hold("profile_name_collision")
    if not Path(store).is_absolute():
        raise Hold("nextest_store_not_absolute")
    # Nextest resolves store.dir against workspace_root, independently of Cargo
    # target-dir. An explicit absolute directory keeps all reports in our tree.
    text += "\n[store]\ndir = " + json.dumps(str(store)) + "\n"
    for stage in STAGES:
        text += f'''
[profile.held-note-{stage}]
inherits = "local"
retries = 0
test-threads = 1
global-timeout = "15m"
slow-timeout = {{ period = "60s", terminate-after = 1, grace-period = "0s", on-timeout = "fail" }}
fail-fast = false
[profile.held-note-{stage}.junit]
path = "junit.xml"
store-success-output = true
store-failure-output = true
report-skipped = "all"
[[profile.held-note-{stage}.overrides]]
filter = 'package(codex-core)'
retries = 0
slow-timeout = {{ period = "60s", terminate-after = 1, grace-period = "0s", on-timeout = "fail" }}
'''
    return text.encode()


def test_argv(just, config, stage):
    if stage not in STAGES:
        raise Hold("unknown_stage")
    group = stage.split("-", 1)[1]
    expression = " | ".join("test(=" + name + ")" for name in CASE_GROUPS[group])
    target = ["--lib"] if group == "orchestrator" else ["--test", "all"]
    return [str(just), "test", "-p", "codex-core", *target, "--locked", "--offline",
            "--config-file", str(config), "--profile", "held-note-" + stage,
            "--no-tests", "fail", "--retries", "0", "--test-threads", "1",
            "--success-output", "final", "--failure-output", "final",
            "--status-level", "all", "--final-status-level", "none", "-E", expression]


def known_skip_guard(env):
    # Preserve flags; never force a body to run against an inherited restriction.
    if "CODEX_SANDBOX_NETWORK_DISABLED" in env or env.get("CODEX_SANDBOX") == "seatbelt":
        raise Hold("inherited_controls_require_test_skip")


def bwrap_identity(path):
    p = Path(path).resolve(strict=True)
    st = p.stat()
    if (p not in (Path("/usr/bin/bwrap"), Path("/bin/bwrap")) or st.st_uid != 0
            or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or not stat.S_ISREG(st.st_mode) or not st.st_mode & stat.S_IXUSR):
        raise Hold("system_bwrap_identity")
    with p.open("rb") as f:
        if f.read(4) != b"\x7fELF":
            raise Hold("system_bwrap_not_elf")
    return {"path": str(p), "sha256": sha(p), "bytes": st.st_size}


def proc_table():
    table = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            # comm may contain spaces and parentheses: split after its final ')'.
            tail = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            table[int(entry.name)] = (int(tail[1]), int(tail[19]))
        except (OSError, ValueError, IndexError):
            pass
    return table


def children():
    table, owned = proc_table(), set()
    changed = True
    while changed:
        changed = False
        for pid, (ppid, birth) in table.items():
            if pid not in owned and (ppid == os.getpid() or ppid in owned):
                owned.add(pid)
                changed = True
    return {pid: table[pid][1] for pid in owned}


def descendant_states(owned):
    """Only process identity/state, never argv, environment or command names."""
    rows = []
    for pid, birth in sorted(owned.items()):
        try:
            tail = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
            if int(tail[19]) == birth:
                rows.append({"pid": pid, "parentPid": int(tail[1]),
                             "birthTick": birth, "state": tail[0]})
        except (OSError, ValueError, IndexError):
            pass
    return rows


def reap_exited_descendants():
    """Called only after the Popen leader is reaped. Live children still hold."""
    before = descendant_states(children())
    reaped = []
    for _ in range(8):
        progress = False
        for row in descendant_states(children()):
            # waitpid is restricted to actual adopted, already exited children.
            # Recheck the birth identity so a reused numeric PID is never reaped.
            if row["parentPid"] != os.getpid() or row["state"] not in ("Z", "X"):
                continue
            if proc_table().get(row["pid"], (None, None)) != (os.getpid(), row["birthTick"]):
                continue
            try:
                pid, _status = os.waitpid(row["pid"], os.WNOHANG)
            except (ChildProcessError, ProcessLookupError):
                continue
            if pid == row["pid"]:
                reaped.append(row)
                progress = True
        if not progress:
            break
    remaining = children()
    return {"before": before, "reapedExited": reaped,
            "remaining": descendant_states(remaining), "remainingCount": len(remaining)}


def orphan_reaping_fixture_argv():
    # Synthetic process-only preflight; no repository/product code or networking.
    return ["/usr/bin/python3", "-I", "-B", "-c",
            "import os,time; child=os.fork(); "
            "time.sleep(0.05) if child == 0 else None; os._exit(0)"]


def cleanup(process):
    # Linux subreaper adopts orphaned command/test children, including new groups.
    process.poll()
    initial = children()
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, birth in children().items():
            if proc_table().get(pid, (None, None))[1] == birth:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        end = time.monotonic() + 3
        while time.monotonic() < end:
            process.poll()
            for pid in list(children()):
                if pid != process.pid:
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except (ChildProcessError, ProcessLookupError):
                        pass
            if not children():
                break
            time.sleep(0.05)
        if not children():
            break
    process.wait(timeout=3)
    return {"ownedChildrenAtCleanup": len(initial), "ownedDescendantsGone": not children(),
            "leaderReaped": process.returncode is not None}


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Campaign:
    def __init__(self, root, source, env, output, binaries):
        self.root, self.source, self.env, self.output = root, source, env, output
        self.binaries = binaries
        self.deadline = time.monotonic() + 6900
        self.rows = []
        self.replacements = {str(source): "<CHECKOUT>", str(root): "<TASK_ROOT>",
                             os.environ.get("GITHUB_WORKSPACE", ""): "<WORKSPACE>",
                             os.environ.get("HOME", ""): "<RUNNER_HOME>",
                             os.environ.get("CODEX_HOME", ""): "<INHERITED_CODEX_HOME>"}

    def run(self, label, argv, seconds=600, allow_failure=False):
        raw = self.root / "raw" / label
        raw.mkdir()
        started, p, reason = time.monotonic(), None, None
        states = {n: {"observedBytes": 0, "retainedBytes": 0, "truncated": False}
                  for n in ("stdout", "stderr")}
        complete = False
        completion_descendants = None
        clean = {"ownedDescendantsGone": False, "leaderReaped": False}
        if children():
            raise Hold("unexpected_existing_child")
        with (raw / "stdout").open("xb") as out, (raw / "stderr").open("xb") as err, (raw / "combined").open("xb") as combined, selectors.DefaultSelector() as select:
            files = {"stdout": out, "stderr": err}
            try:
                if time.monotonic() >= self.deadline:
                    raise Hold("whole_deadline")
                p = subprocess.Popen(argv, cwd=self.source, env=self.env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True, preexec_fn=limits)
                for name, pipe in (("stdout", p.stdout), ("stderr", p.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    select.register(pipe, selectors.EVENT_READ, name)
                while p.poll() is None or select.get_map():
                    if time.monotonic() - started >= seconds or time.monotonic() >= self.deadline:
                        raise Hold("owned_deadline")
                    if shutil.disk_usage(self.root).free < 4 * GIB:
                        raise Hold("disk_stop_floor")
                    for key, _ in select.select(0.2):
                        b = os.read(key.fd, 65536)
                        if not b:
                            select.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        name = key.data
                        s = states[name]
                        s["observedBytes"], s["retainedBytes"], kept, s["truncated"] = bounded_chunk(
                            s["observedBytes"], s["retainedBytes"], b)
                        files[name].write(kept)
                        combined.write(kept)
                        if s["truncated"]:
                            raise Hold("output_bound")
                p.wait()
                complete = True
                completion_descendants = reap_exited_descendants()
                if completion_descendants["remainingCount"]:
                    raise Hold("child_survived_command")
            except BaseException as e:
                reason = str(e) if isinstance(e, Hold) else "controller_" + type(e).__name__
            finally:
                for key in list(select.get_map().values()):
                    select.unregister(key.fileobj)
                    key.fileobj.close()
                if p:
                    try:
                        clean = cleanup(p)
                    except Exception:
                        reason = "cleanup_incomplete"
        row = {"stage": label, "exitCode": p.returncode if p else None,
               "seconds": round(time.monotonic() - started, 3), "captureComplete": complete,
               "stopReason": reason, "capture": states, "cleanup": clean,
               "completionDescendants": completion_descendants,
               "argv": [normalized(a.encode(), self.replacements).decode() for a in argv]}
        pub = self.output / label
        pub.mkdir()
        for name in ("stdout", "stderr", "combined"):
            f = raw / name
            safe = normalized(f.read_bytes(), self.replacements)
            (pub / (name + ".log")).write_bytes(safe)
            row.setdefault("streams", {})[name] = {"rawSha256": sha(f), "rawBytes": f.stat().st_size,
                                                  "publicSha256": hashlib.sha256(safe).hexdigest(),
                                                  "publicBytes": len(safe), "omittedLines": 0}
        transcript = "$ " + shlex.join(row["argv"]) + "\n"
        transcript += (pub / "combined.log").read_text() + "\n[exitCode=" + str(row["exitCode"]) + "]\n"
        (pub / "scripted-session.log").write_text(transcript)
        row["sessionSha256"] = sha(pub / "scripted-session.log")
        self.rows.append(row)
        save(pub / "result.json", row)
        if reason or not complete or not clean["ownedDescendantsGone"] or not clean["leaderReaped"]:
            raise Hold(label + "_incomplete")
        if row["exitCode"] != 0 and not allow_failure:
            raise Hold(label + "_nonzero")
        return raw, row

    def git(self, label, *args):
        raw, _ = self.run(label, ["/usr/bin/git", *args], seconds=60)
        return (raw / "stdout").read_bytes()

    def verify_source(self, manifest, variant):
        if self.git("head-" + variant, "rev-parse", "HEAD").decode().strip() != BASE:
            raise Hold("head_changed")
        for f in manifest["files"]:
            key = "originalSha256" if variant.startswith("baseline") and f["path"] == PRODUCTION else "candidateSha256"
            if sha(self.source / f["path"]) != f[key]:
                raise Hold("source_variant_mismatch")
        for path, expected in self.source_inputs.items():
            if sha(self.source / path) != expected:
                raise Hold("immutable_source_input_changed")
        if self.git("untracked-" + variant, "ls-files", "--others", "--exclude-standard").strip():
            raise Hold("unexpected_untracked_source")
        paths = self.git("changed-paths-" + variant, "diff", "--name-only", "HEAD").decode().splitlines()
        if not set(paths) <= {PRODUCTION, TESTS}:
            raise Hold("unexpected_source_changes")
        return hashlib.sha256(self.git("source-diff-" + variant, "diff", "--binary", "HEAD")).hexdigest()


def safe_extract(archive, destination):
    destination.mkdir()
    with tarfile.open(archive) as t:
        members = t.getmembers()
        if len(members) > 50000 or sum(x.size for x in members) > 2 * GIB:
            raise Hold("archive_expansion_bound")
        t.extractall(destination, filter="data")


def environment(root):
    e = {"PATH": str(root / "toolchain/bin") + ":" + str(root / "bin") + ":/usr/bin:/bin",
         "CARGO_HOME": str(root / "cargo-home"), "RUSTUP_HOME": str(root / "unused-rustup"),
         "CARGO_TARGET_DIR": str(root / "target"), "TMPDIR": str(root / "tmp"),
         "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
         "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
         "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS": "true", "CARGO_PROFILE_TEST_DEBUG_ASSERTIONS": "true",
         "CORBANU_TEST_NO_NATIVE_KEYRING": "1", "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
         "CARGO_NET_RETRY": "0", "CARGO_TERM_COLOR": "never", "CARGO_HTTP_TIMEOUT": "60",
         "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
         "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "gc.auto", "GIT_CONFIG_VALUE_0": "0",
         "GIT_CONFIG_KEY_1": "maintenance.auto", "GIT_CONFIG_VALUE_1": "false",
         "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false", "SSH_ASKPASS": "/usr/bin/false",
         "GIT_SSH_COMMAND": "/usr/bin/false", "NETRC": str(root / "empty-netrc"),
         "XDG_CONFIG_HOME": str(root / "empty-config"), "CURL_HOME": str(root / "empty-config"),
         "UV_CACHE_DIR": str(root / "uv-cache"), "UV_NO_CONFIG": "1",
         "UV_PYTHON_DOWNLOADS": "never", "DOTSLASH_CACHE": str(root / "dotslash-cache"),
         "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONUNBUFFERED": "1",
         "INSTA_UPDATE": "no", "INSTA_FORCE_PASS": "0"}
    # Preserve inherited home identity. The unchanged repository just-test
    # wrapper creates the disposable CODEX_HOME used by product test processes.
    e.update({k: os.environ[k] for k in ("HOME", "CODEX_HOME", *MARKERS) if k in os.environ})
    return e


def retain_binary(campaign, stage):
    prefix = "codex_core" if stage.endswith("orchestrator") else "all"
    paths = [p for p in (campaign.root / "target/debug/deps").glob(prefix + "-*")
             if p.is_file() and not p.is_symlink() and p.stat().st_mode & stat.S_IXUSR]
    if len(paths) != 1:
        raise Hold("test_binary_identity_ambiguous")
    p = paths[0]
    if p.stat().st_size > MAX_BINARY:
        raise Hold("qualification_binary_size_bound")
    retained = campaign.root / "retained" / (stage + "-" + p.name)
    shutil.copyfile(p, retained)
    identity = sha(p)
    artifact = campaign.binaries / (identity + ".bin")
    if not artifact.exists():
        if sum(f.stat().st_size for f in campaign.binaries.iterdir()) + p.stat().st_size > 4 * MAX_BINARY:
            raise Hold("qualification_binary_total_bound")
        shutil.copyfile(retained, artifact)
    if sha(artifact) != identity:
        raise Hold("qualification_binary_copy_mismatch")
    return {"name": p.name, "sha256": identity, "retainedSha256": sha(retained),
            "artifactFile": artifact.name, "artifactSha256": sha(artifact), "bytes": p.stat().st_size}


def capture_junit(campaign, stage, result):
    """Capture reports before parsing; rejected and incomplete runs retain evidence."""
    reports = result.setdefault("junitReports", {})
    if stage in reports:
        return reports[stage]
    report = campaign.root / "target/nextest" / ("held-note-" + stage) / "junit.xml"
    if not report.is_file():
        return None
    size = report.stat().st_size
    with report.open("rb") as f:
        data = f.read(MAX_XML)
    complete = size <= MAX_XML
    safe = normalized(data, campaign.replacements)
    name = "junit-" + stage + (".xml" if complete else ".xml.partial")
    (campaign.output / name).write_bytes(safe)
    row = {"rawSha256": sha(report), "rawBytes": size, "publicFile": name,
           "publicSha256": hashlib.sha256(safe).hexdigest(), "captureComplete": complete,
           "truncated": not complete}
    reports[stage] = row
    return row


def validate_manifest(m):
    if (m.get("schema") != "issue943-hosted-source-v1" or m.get("baseCommit") != BASE
            or {f["path"] for f in m.get("files", [])} != {PRODUCTION, TESTS}
            or len(m["files"]) != 2 or not digest(m.get("fixtureFreezeSha256"))
            or not digest(m.get("sourceMethodSha256"))
            or m.get("caseGroups") != {k: list(v) for k, v in CASE_GROUPS.items()}
            or [r["name"] for r in m.get("redCases", [])] != [CASE_GROUPS["integration"][2]]
            or m.get("nativeAndHostOverrideHoldsPreserved") is not True
            or m.get("patch", {}).get("path") != "payload/change.patch"
            or not digest(m.get("patch", {}).get("sha256"))):
        raise Hold("source_manifest_contract")
    for f in m["files"]:
        if not digest(f["originalSha256"]) or not digest(f["candidateSha256"]):
            raise Hold("source_hash_unbound")
        if f["payload"] != "payload/" + Path(f["path"]).name:
            raise Hold("payload_path")
    for rule in m["redCases"]:
        if (rule.get("panicLine") != 406 or len(rule.get("requiredPatterns", [])) != 2
                or len(rule.get("forbiddenPatterns", [])) != 2):
            raise Hold("assertion_oracle_unbound")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--dispatch", action="store_true", required=True)
    a.add_argument("--source", type=Path, required=True)
    a.add_argument("--control", type=Path, required=True)
    a.add_argument("--output", type=Path, required=True)
    a.add_argument("--binaries", type=Path, required=True)
    args = a.parse_args()
    if (platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0
            or sys.version_info < (3, 12) or os.environ.get("RUNNER_OS") != "Linux"
            or os.environ.get("GITHUB_REPOSITORY") != REPO or os.environ.get("GITHUB_REF") != REF
            or os.environ.get("GITHUB_EVENT_NAME") != "push"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"):
        raise Hold("fixed_nonroot_hosted_linux_required")
    control, source = args.control.resolve(), args.source.resolve()
    manifest_path, tools_path = control / "source-manifest.json", control / "tools-pins.json"
    manifest, tools = json.loads(manifest_path.read_text()), json.loads(tools_path.read_text())
    validate_manifest(manifest)
    admission = json.loads((control / "admission.json").read_text())
    if (admission.get("approved") is not True or admission.get("controllerSha256") != sha(__file__)
            or admission.get("sourceManifestSha256") != sha(manifest_path)
            or admission.get("toolsPinsSha256") != sha(tools_path)
            or admission.get("bubblewrapSetupSha256") != sha(control / "bubblewrap_setup.py")
            or admission.get("bubblewrapPinsSha256") != sha(control / "bubblewrap-pins.json")
            or admission.get("exclusiveInstallerSha256") != sha(control / "install_elf_exclusive.py")
            or admission.get("keyringProvisionerSha256") != sha(control / "provision_authenticated_keyring.py")
            or admission.get("authenticatedKeyringSha256") != sha(control / "ubuntu-archive-keyring.gpg")
            or admission.get("workflowSha256") != sha(control / ".github/workflows/issue943-owned-trust-v1.yml")):
        raise Hold("admission_not_bound")
    identity = os.environ.get("GITHUB_RUN_ID", "")
    if not identity.isdecimal():
        raise Hold("run_id")
    root = Path("/tmp") / ("issue943-owned-trust-v1-" + identity)
    root.mkdir(mode=0o700)
    for n in ("cargo-home", "unused-rustup", "target", "tmp", "empty-config",
              "uv-cache", "dotslash-cache", "bin", "toolchain", "downloads", "unpacked", "raw", "retained"):
        (root / n).mkdir(mode=0o700)
    (root / "empty-netrc").write_text("")
    args.output.mkdir(mode=0o700)
    args.binaries.mkdir(mode=0o700)
    markers = {k: (k in os.environ, os.environ.get(k)) for k in MARKERS}
    homes = {k: (k in os.environ, os.environ.get(k)) for k in ("HOME", "CODEX_HOME")}
    c = Campaign(root, source, environment(root), args.output, args.binaries)
    result = {"schema": "issue943-hosted-result-v1", "status": "INCOMPLETE", "sourceCommit": BASE,
              "sourceManifestSha256": sha(manifest_path), "toolsPinsSha256": sha(tools_path),
              "controllerSha256": sha(__file__), "runId": identity, "phases": {}, "commands": c.rows,
              "rawLocalReceiptsUploaded": False, "qualified": False}
    c.source_inputs = tools["sourceInputs"]
    code = 1
    try:
        # Unprivileged process-local adoption, not a host setting or sandbox change.
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise Hold("owned_child_subreaper_unavailable")
        result["capacity"] = {"initialFreeBytes": shutil.disk_usage(root).free,
                              "initialFloorBytes": 30 * GIB, "firstCompileFloorBytes": 30 * GIB,
                              "targetReuseFloorBytes": 8 * GIB,
                              "runningStopFloorBytes": 4 * GIB, "beforeStage": {}}
        if result["capacity"]["initialFreeBytes"] < 30 * GIB:
            raise Hold("initial_disk_floor")
        _, fixture = c.run("owned-orphan-reaping-preflight", orphan_reaping_fixture_argv(), 10)
        evidence = fixture["completionDescendants"]
        if (fixture["exitCode"] != 0 or evidence["remainingCount"]
                or len(evidence["reapedExited"]) != 1):
            raise Hold("owned_orphan_reaping_preflight_failed")
        result["ownedProcessPreflight"] = {"passed": True, "reapedExitedCount": 1,
                                           "productTestBodiesExecuted": 0}
        if not (source / ".git").is_dir() or (source / ".git").is_symlink():
            raise Hold("fresh_real_checkout_required")
        if c.git("initial-head", "rev-parse", "HEAD").decode().strip() != BASE:
            raise Hold("wrong_base")
        if c.git("initial-status", "status", "--porcelain").strip():
            raise Hold("checkout_dirty")
        # Inspect names only: an accidental credential value must never enter logs.
        cfg = c.git("git-config", "config", "--local", "--name-only", "--list").decode()
        if re.search(r"extraheader|credential|insteadof|sshcommand|include\.|hookspath|fsmonitor", cfg, re.I):
            raise Hold("checkout_auth_config")
        for p, expected in tools["sourceInputs"].items():
            if sha(source / p) != expected:
                raise Hold("wrapper_or_source_input_changed")
        known_skip_guard(c.env)
        setup_spec = importlib.util.spec_from_file_location("admitted_bubblewrap_setup", control / "bubblewrap_setup.py")
        setup = importlib.util.module_from_spec(setup_spec)
        setup_spec.loader.exec_module(setup)
        try:
            setup.prepare(c, json.loads((control / "bubblewrap-pins.json").read_text()), result)
        except setup.SetupHold as exc:
            raise Hold("bubblewrap_setup_" + str(exc)) from exc
        bwrap = bwrap_identity("/usr/bin/bwrap")
        result["systemBwrap"] = bwrap
        c.run("system-bwrap-version", [bwrap["path"], "--version"], 10)
        c.run("system-bwrap-capability", [bwrap["path"], *BWRAP_ARGS], 10)
        result["systemBwrap"]["directUserAndNetworkNamespaceProbePassed"] = True
        c.run("system-unshare-version", ["/usr/bin/unshare", "--version"], 10)
        c.run("system-libcap-prerequisite", ["/usr/bin/pkg-config", "--exists", "libcap"], 10)
        originals = {}
        for f in manifest["files"]:
            if sha(source / f["path"]) != f["originalSha256"]:
                raise Hold("original_source_hash")
            originals[f["path"]] = (source / f["path"]).read_bytes()
            payload = control / f["payload"]
            if not payload.is_file() or payload.is_symlink() or sha(payload) != f["candidateSha256"]:
                raise Hold("candidate_payload_hash")
        patch = control / manifest["patch"]["path"]
        if sha(patch) != manifest["patch"]["sha256"]:
            raise Hold("patch_hash")
        c.git("patch-check", "apply", "--check", str(patch))
        c.git("patch-apply", "apply", str(patch))
        c.verify_source(manifest, "prepared-candidate")
        for item in tools["archives"]:
            dest = root / "downloads" / item["filename"]
            c.run("fetch-" + item["id"], ["/usr/bin/curl", "-q", "--fail", "--silent", "--show-error",
                  "--location", "--proto", "=https", "--proto-redir", "=https", "--retry", "0",
                  "--connect-timeout", "20", "--max-time", "300", "--max-filesize", str(item["maxBytes"]),
                  "--output", str(dest), item["url"]], 310)
            if dest.stat().st_size > item["maxBytes"] or sha(dest) != item["sha256"]:
                raise Hold("tool_archive_hash")
            if item["kind"] == "v8-asset":
                c.env[item["variable"]] = str(dest)
                result.setdefault("toolHashes", {})[item["variable"]] = sha(dest)
                continue
            unpack = root / "unpacked" / item["id"]
            safe_extract(dest, unpack)
            if item["kind"] == "rust-component":
                installers = list(unpack.glob("*/install.sh"))
                if len(installers) != 1:
                    raise Hold("rust_installer_identity")
                c.run("install-" + item["id"], ["/bin/sh", str(installers[0]),
                      "--prefix=" + str(root / "toolchain"), "--disable-ldconfig"], 180)
            else:
                matches = [p for p in unpack.rglob(item["binary"]) if p.is_file() and not p.is_symlink()]
                if len(matches) != 1:
                    raise Hold("tool_binary_identity")
                dest = root / "bin" / item["binary"]
                shutil.copyfile(matches[0], dest)
                dest.chmod(0o700)
        for binary, version in tools["versions"].items():
            executable = root / ("toolchain/bin" if binary in ("cargo", "rustc", "rustfmt") else "bin") / binary
            raw, _ = c.run("version-" + binary, [str(executable), "--version"], 30)
            text = (raw / "stdout").read_text()
            if version not in text:
                raise Hold("tool_version_mismatch")
            result.setdefault("toolHashes", {})[binary] = sha(executable)
        c.env["RUSTC"] = str(root / "toolchain/bin/rustc")
        c.env["RUSTDOC"] = str(root / "toolchain/bin/rustdoc")
        just = root / "bin/just"
        config = root / "nextest.toml"
        config.write_bytes(nextest_config((source / "codex-rs/.config/nextest.toml").read_bytes(),
                                         root / "target/nextest"))
        result["ownedNextestConfigSha256"] = sha(config)
        before_format = c.verify_source(manifest, "candidate-before-format")
        _, fmt = c.run("full-format-candidate", [str(just), "fmt"], 900, allow_failure=True)
        actual_diff = c.git("format-diff", "diff", "--binary", "HEAD")
        actual_paths = c.git("format-paths", "diff", "--name-only", "HEAD").decode().splitlines()
        after_format = hashlib.sha256(actual_diff).hexdigest()
        result["phases"]["full-format"] = {"exitCode": fmt["exitCode"],
            "sourceUnchanged": before_format == after_format, "diffSha256": after_format,
            "changedFromBasePaths": actual_paths}
        if before_format != after_format or fmt["exitCode"] != 0:
            (args.output / "format-actual.patch").write_bytes(normalized(actual_diff, c.replacements))
            raise Hold("full_format_failed_or_changed_source")
        c.verify_source(manifest, "candidate-after-format")
        c.run("fetch-locked", [str(root / "toolchain/bin/cargo"), "fetch", "--locked",
              "--manifest-path", str(source / "codex-rs/Cargo.toml"),
              "--target", "x86_64-unknown-linux-gnu"], 900)
        c.env["CARGO_NET_OFFLINE"] = "true"
        c.verify_source(manifest, "candidate-after-fetch")
        # Same frozen integration fixture in both phases; only production differs.
        (source / PRODUCTION).write_bytes(originals[PRODUCTION])
        red_rules = {r["name"]: r for r in manifest["redCases"]}
        for stage in STAGES:
            if stage == "candidate-orchestrator":
                production = next(f for f in manifest["files"] if f["path"] == PRODUCTION)
                (source / PRODUCTION).write_bytes((control / production["payload"]).read_bytes())
                c.verify_source(manifest, "candidate-restored")
                free = shutil.disk_usage(root).free
                result["capacity"]["beforeStage"]["scoped-checks"] = free
                if free < 8 * GIB:
                    raise Hold("reuse_compile_disk_floor")
                c.run("scoped-format", [str(root / "toolchain/bin/cargo"), "fmt",
                      "--manifest-path", str(source / "codex-rs/Cargo.toml"),
                      "-p", "codex-core", "--", "--check"], 180)
                c.verify_source(manifest, "candidate-after-scoped-format")
                c.run("clippy", [str(just), "clippy", "-p", "codex-core", "--locked", "--offline",
                      "--", "-D", "warnings"], 1800)
                c.verify_source(manifest, "candidate-after-clippy")
            before = c.verify_source(manifest, stage + "-before")
            result["capacity"]["beforeStage"][stage] = shutil.disk_usage(root).free
            if result["capacity"]["beforeStage"][stage] < (30 if stage == STAGES[0] else 8) * GIB:
                raise Hold("compile_disk_floor")
            report = root / "target/nextest" / ("held-note-" + stage) / "junit.xml"
            if report.exists():
                raise Hold("stale_junit_report")
            raw, row = c.run("tests-" + stage, test_argv(just, config, stage),
                             4200 if stage == STAGES[0] else 1800, allow_failure=True)
            captured = capture_junit(c, stage, result)
            if row["exitCode"] != (100 if stage == "baseline-integration" else 0):
                raise Hold("unexpected_wrapper_exit")
            if not captured or not captured["captureComplete"]:
                raise Hold("junit_missing_or_oversize")
            xml = report.read_bytes()
            binary = retain_binary(c, stage)
            result.setdefault("observedStageBinaries", {})[stage] = binary
            group = stage.split("-", 1)[1]
            outcome = classify_test(xml, (raw / "combined").read_text(), CASE_GROUPS[group],
                                    red_rules if stage == "baseline-integration" else None,
                                    "codex_core" if group == "orchestrator" else "all")
            current = c.verify_source(manifest, stage + "-after-tests")
            if current != before:
                raise Hold("source_changed_during_tests")
            if (stage.startswith("candidate") and binary["sha256"] ==
                    result["phases"]["baseline-" + group]["binary"]["sha256"]):
                raise Hold("candidate_binary_did_not_change")
            result["phases"][stage] = {"qualification": outcome, "binary": binary,
                                       "junitRawSha256": captured["rawSha256"],
                                       "junitPublicSha256": captured["publicSha256"],
                                       "sourceDiffSha256": current}
        result["aggregate"] = {"baseline": {"executed": 20, "passed": 19, "expectedAssertionFailures": 1},
                               "candidate": {"executed": 20, "passed": 20, "failed": 0},
                               "selectedSkips": 0, "retries": 0}
        result["limits"] = {"sourceAwareOnly": True, "nativeIncidentResolved": False,
                           "interactiveQualification": False, "newDirectStaleHeldNoteFixture": False}
        result["status"], result["qualified"], code = "PAIRED_TWENTY_CASE_HELD_NOTE_QUALIFIED", True, 0
    except BaseException as e:
        result["failureCode"] = str(e) if isinstance(e, Hold) else "controller_" + type(e).__name__
    finally:
        for stage in STAGES:
            try:
                capture_junit(c, stage, result)
            except Exception:
                result["status"], result["qualified"], code = "INCOMPLETE", False, 1
                result.setdefault("captureErrors", []).append("junit-" + stage)
        result["inheritedMarkersPreserved"] = markers == {k: (k in c.env, c.env.get(k)) for k in MARKERS}
        result["inheritedHomeIdentityPreserved"] = homes == {
            k: (k in c.env, c.env.get(k)) for k in ("HOME", "CODEX_HOME")}
        result["ownedDescendantsGone"] = not children()
        result["freeBytesAfter"] = shutil.disk_usage(root).free
        if (not result["inheritedMarkersPreserved"] or not result["ownedDescendantsGone"]
                or not result["inheritedHomeIdentityPreserved"]):
            result["status"], result["qualified"], code = "INCOMPLETE", False, 1
        save(args.output / "qualification-result.json", result)
        print(result["status"])
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("HOSTED_VALIDATION_NOT_STARTED:" + (str(e) if isinstance(e, Hold) else type(e).__name__))
        sys.exit(1)
