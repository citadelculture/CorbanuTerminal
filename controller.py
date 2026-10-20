#!/usr/bin/env python3
"""Issue1120 candidate-only continuation; external negative evidence has explicit limitations."""
import argparse
import ctypes
import hashlib
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

BASE = 'c9dbae23b3d3f9753fc27a993479040b6b2735cd'
CANDIDATE_COMMIT = "fa13515160378d45e5c705c99d22c3cd805e88ce"
REPO = "citadelculture/CorbanuTerminal"
REF = "refs/heads/codex/issue1120-candidate-only-v2-20261020"
SOURCE_FILES = ('codex-rs/core/tests/suite/resume_warning.rs', 'codex-rs/core/tests/suite/client.rs', 'codex-rs/core/tests/suite/client_websockets.rs', 'codex-rs/core/tests/suite/personality.rs', 'codex-rs/core/tests/suite/remote_models.rs', 'codex-rs/core/tests/suite/agents_md.rs', 'codex-rs/core/tests/suite/unstable_features_warning.rs', 'codex-rs/core/tests/responses_headers.rs')
NEGATIVE_SOURCE = "codex-rs/core/tests/suite/personality.rs"
CASES = ('suite::resume_warning::emits_warning_when_resumed_model_differs', 'suite::personality::personality_does_not_mutate_base_instructions_without_template', 'suite::personality::base_instructions_override_disables_personality_template', 'suite::personality::instructions_uses_base_if_feature_disabled', 'suite::remote_models::remote_models_get_model_info_uses_longest_matching_prefix', 'suite::agents_md::fork_injects_changed_agents_md_once', 'suite::unstable_features_warning::emits_warning_when_unstable_features_enabled_via_config', 'suite::unstable_features_warning::suppresses_warning_when_configured', 'suite::client::prefers_apikey_when_config_prefers_apikey_even_with_chatgpt_tokens', 'suite::client::azure_responses_request_includes_store_and_prefixed_item_ids', 'suite::client::provider_auth_command_supplies_bearer_token', 'suite::client_websockets::responses_websocket_streams_request', 'suite::client_websockets::responses_websocket_omits_unprefixed_item_ids_without_mutating_prompt', 'responses_stream_includes_subagent_header_on_review', 'responses_stream_includes_subagent_header_on_other', 'responses_respects_model_info_overrides_from_config')
CASE_TARGETS = {'suite::resume_warning::emits_warning_when_resumed_model_differs': 'codex-core::all', 'suite::personality::personality_does_not_mutate_base_instructions_without_template': 'codex-core::all', 'suite::personality::base_instructions_override_disables_personality_template': 'codex-core::all', 'suite::personality::instructions_uses_base_if_feature_disabled': 'codex-core::all', 'suite::remote_models::remote_models_get_model_info_uses_longest_matching_prefix': 'codex-core::all', 'suite::agents_md::fork_injects_changed_agents_md_once': 'codex-core::all', 'suite::unstable_features_warning::emits_warning_when_unstable_features_enabled_via_config': 'codex-core::all', 'suite::unstable_features_warning::suppresses_warning_when_configured': 'codex-core::all', 'suite::client::prefers_apikey_when_config_prefers_apikey_even_with_chatgpt_tokens': 'codex-core::all', 'suite::client::azure_responses_request_includes_store_and_prefixed_item_ids': 'codex-core::all', 'suite::client::provider_auth_command_supplies_bearer_token': 'codex-core::all', 'suite::client_websockets::responses_websocket_streams_request': 'codex-core::all', 'suite::client_websockets::responses_websocket_omits_unprefixed_item_ids_without_mutating_prompt': 'codex-core::all', 'responses_stream_includes_subagent_header_on_review': 'codex-core::responses_headers', 'responses_stream_includes_subagent_header_on_other': 'codex-core::responses_headers', 'responses_respects_model_info_overrides_from_config': 'codex-core::responses_headers'}
NEGATIVE_CASE = 'suite::personality::personality_does_not_mutate_base_instructions_without_template'
MARKERS = ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_SANDBOX_USER_NAMESPACES_DENIED")
PRIOR_NEGATIVE_SHA = "1bd33cab2440f8eab19fb805baff8b783ea7b55398319f5e7fb47e3e51fc9f33"
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


def classify_test(xml_bytes, output, expected, red_rules=None):
    """Full JUnit plus unique pre-Summary execution records; no skip-as-pass."""
    if len(xml_bytes) > MAX_XML or b"<!DOCTYPE" in xml_bytes or b"<!ENTITY" in xml_bytes:
        raise Hold("xml_bound_or_dtd")
    root = ET.fromstring(xml_bytes)
    identities, excluded, selected = set(), 0, {}
    for case in root.iter("testcase"):
        name, classname = case.get("name"), case.get("classname", "")
        identity = (classname, name)
        if identity in identities:
            raise Hold("duplicate_junit_case")
        identities.add(identity)
        if name not in expected:
            if case.find("skipped") is None:
                raise Hold("unexpected_executed_case")
            excluded += 1
            continue
        if name in selected or classname != CASE_TARGETS[name]:
            raise Hold("duplicate_or_wrong_test_binary")
        if case.find("skipped") is not None:
            raise Hold("selected_test_skipped")
        if case.find("error") is not None:
            raise Hold("test_error_not_assertion")
        if any("rerun" in c.tag.lower() or "flaky" in c.tag.lower() for c in case.iter()):
            raise Hold("retry_or_flaky")
        duration = float(case.get("time", "-1"))
        if not 0 <= duration <= 60:
            raise Hold("test_time_bound")
        failures = case.findall("failure")
        body = ANSI.sub("", "\n".join(case.itertext()))
        if red_rules is None or name not in red_rules:
            if failures:
                raise Hold("unexpected_failure")
            state = "PASS"
        else:
            if len(failures) != 1 or failures[0].get("type") != "test failure with exit code 101":
                raise Hold("expected_assertion_not_observed")
            rule = red_rules[name]
            site = re.escape(rule["panicFile"]) + ":" + str(rule["panicLine"]) + r":\d+"
            if not re.search(site, body):
                raise Hold("wrong_assertion_site")
            if not all(re.search(pattern, body, re.S) for pattern in rule["requiredPatterns"]):
                raise Hold("wrong_assertion_signature")
            state = "EXPECTED_ASSERTION_FAILURE"
        selected[name] = {"status": state, "seconds": duration, "binaryId": classname}
    if set(selected) != set(expected):
        raise Hold("selected_cases_missing")
    text = ANSI.sub("", output)
    summaries = list(re.finditer(r"(?m)^\s*Summary\s+\[[^\]]+\]\s+(\d+)\s+tests?\s+run:\s*(.+)$", text))
    if len(summaries) != 1:
        raise Hold("summary_missing_or_duplicate")
    count, rest = summaries[0].groups()
    passed = re.search(r"(\d+)\s+passed", rest)
    failed = re.search(r"(\d+)\s+failed", rest)
    numbers = (int(count), int(passed.group(1)) if passed else 0, int(failed.group(1)) if failed else 0)
    red_count = len(red_rules or {})
    if red_rules and not set(red_rules) <= set(expected):
        raise Hold("red_case_outside_selection")
    if numbers != (len(expected), len(expected)-red_count, red_count):
        raise Hold("summary_or_runtime_status_mismatch")
    if re.search(r"(?im)^\s*(?:TRY\s+\d|RETRY|FLAKY|TIMEOUT|TMPASS|LEAK|CANCEL)", text):
        raise Hold("summary_or_runtime_status_mismatch")
    executed = {}
    for status, binary, name in re.findall(r"(?m)^\s*(PASS|FAIL|SKIP)\s+\[[^\]]+\]\s+(?:\((?:[0-9]+/[0-9]+|─{3})\)\s+)?(\S+)\s+(\S+)\s*$", text[:summaries[0].start()]):
        if name not in expected:
            if status != "SKIP":
                raise Hold("unexpected_execution_record")
            continue
        if name in executed or binary != CASE_TARGETS[name] or status == "SKIP":
            raise Hold("duplicate_wrong_or_skipped_execution_record")
        executed[name] = status
    wanted = {name: "FAIL" if red_rules and name in red_rules else "PASS" for name in expected}
    if executed != wanted:
        raise Hold("execution_record_mismatch")
    skip_markers = ("Sandbox-dependent test skipped:", "Skipping test because",
                    "codex-linux-sandbox binary not available, skipping test")
    all_body = "\n".join("\n".join(case.itertext()) for case in root.iter("testcase"))
    if any(marker in text or marker in all_body for marker in skip_markers):
        raise Hold("runtime_body_skipped")
    if "Test isolation: disposable profile; native keyring disabled (debug lane)" not in text:
        raise Hold("wrapper_marker_missing")
    return {"cases": selected, "counts": list(numbers), "selectedSkips": 0,
            "observedFilterExclusions": excluded, "retries": 0,
            "uniquePreSummaryRecords": executed,
            "binaryCounts": {target: sum(CASE_TARGETS[n] == target for n in expected)
                             for target in sorted({CASE_TARGETS[n] for n in expected})}}



def nextest_config(original, store):
    text = original.decode()
    if "[profile.test-roots-" in text or re.search(r"(?m)^\s*\[store\]", text):
        raise Hold("profile_name_collision")
    if not Path(store).is_absolute():
        raise Hold("nextest_store_not_absolute")
    text += "\n[store]\ndir = " + json.dumps(str(store)) + "\n"
    for stage in ("candidate",):
        text += f'''
[profile.test-roots-{stage}]
inherits = "local"
retries = 0
test-threads = 1
global-timeout = "20m"
slow-timeout = {{ period = "60s", terminate-after = 1, grace-period = "0s", on-timeout = "fail" }}
fail-fast = false
[profile.test-roots-{stage}.junit]
path = "junit.xml"
store-success-output = true
store-failure-output = true
report-skipped = "all"
[[profile.test-roots-{stage}.overrides]]
filter = 'package(codex-core)'
retries = 0
slow-timeout = {{ period = "60s", terminate-after = 1, grace-period = "0s", on-timeout = "fail" }}
'''
    return text.encode()



def test_argv(just, config, stage):
    if stage != "candidate":
        raise Hold("candidate_only_no_negative_dispatch")
    cases = CASES
    targets = ["--test", "all", "--test", "responses_headers"]
    expression = " | ".join("test(=" + name + ")" for name in cases)
    return [str(just), "test", "-p", "codex-core", *targets, "--locked", "--offline",
            "--config-file", str(config), "--profile", "test-roots-" + stage,
            "--no-tests", "fail", "--retries", "0", "--test-threads", "1",
            "--success-output", "final", "--failure-output", "final",
            "--status-level", "all", "--final-status-level", "none", "-E", expression]



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
        self.replacements = {str(source): "[CHECKOUT]", str(root): "[TASK_ROOT]",
                             os.environ.get("GITHUB_WORKSPACE", ""): "[WORKSPACE]",
                             os.environ.get("HOME", ""): "[RUNNER_HOME]",
                             os.environ.get("CODEX_HOME", ""): "[INHERITED_CODEX_HOME]"}

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
            key = "negativeSha256" if variant.startswith("negative") else "candidateSha256"
            if sha(self.source / f["path"]) != f[key]:
                raise Hold("source_variant_mismatch")
        paths = self.git("changed-paths-" + variant, "diff", "--name-only", "HEAD").decode().splitlines()
        if not set(paths) <= set(SOURCE_FILES):
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
    targets = ("all",) if stage == "negative" else ("all", "responses_headers")
    rows = {}
    for target in targets:
        paths = [p for p in (campaign.root / "target/debug/deps").glob(target + "-*")
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
            if sum(f.stat().st_size for f in campaign.binaries.iterdir()) + p.stat().st_size > 3 * MAX_BINARY:
                raise Hold("qualification_binary_total_bound")
            shutil.copyfile(retained, artifact)
        if sha(artifact) != identity:
            raise Hold("qualification_binary_copy_mismatch")
        rows["codex-core::" + target] = {"name": p.name, "sha256": identity,
            "retainedSha256": sha(retained), "artifactFile": artifact.name,
            "artifactSha256": sha(artifact), "bytes": p.stat().st_size}
    return rows



def capture_junit(campaign, stage, result):
    """Capture reports before parsing; rejected and incomplete runs retain evidence."""
    reports = result.setdefault("junitReports", {})
    if stage in reports:
        return reports[stage]
    report = campaign.root / "target/nextest" / ("test-roots-" + stage) / "junit.xml"
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
    if (m.get("schema") != "issue1120-hosted-source-v1" or m.get("baseCommit") != BASE
            or m.get("candidateContributionCommit") != CANDIDATE_COMMIT
            or len(m.get("files", [])) != 8 or {f["path"] for f in m["files"]} != set(SOURCE_FILES)
            or m.get("selectedCases") != list(CASES) or len(CASES) != 16
            or m.get("caseTargets") != CASE_TARGETS or m.get("negativeCase") != NEGATIVE_CASE
            or m.get("fullPackageQualification") is not False
            or not digest(m.get("sourcePreparationSha256"))
            or not digest(m.get("fixtureFreezeSha256"))):
        raise Hold("source_manifest_contract")
    for f in m["files"]:
        if not all(digest(f.get(k)) for k in ("originalSha256", "candidateSha256", "negativeSha256")):
            raise Hold("source_hash_unbound")
        if f["payload"] != "payload/" + Path(f["path"]).name:
            raise Hold("payload_path")
        if f["path"] == NEGATIVE_SOURCE:
            if f.get("negativePayload") != "payload/personality.negative.rs" or f["negativeSha256"] == f["candidateSha256"]:
                raise Hold("negative_variant_unbound")
        elif f["negativeSha256"] != f["candidateSha256"] or "negativePayload" in f:
            raise Hold("negative_control_changed_other_file")
    for field, path in (("patch", "payload/change.patch"), ("negativePatch", "payload/negative-control.patch")):
        if m.get(field, {}).get("path") != path or not digest(m[field].get("sha256")):
            raise Hold("patch_unbound")
    rules = m.get("redCases", [])
    if (len(rules) != 1 or rules[0].get("name") != NEGATIVE_CASE
            or rules[0].get("panicFile") != "suite/personality.rs"
            or not isinstance(rules[0].get("panicLine"), int) or not rules[0].get("requiredPatterns")):
        raise Hold("negative_assertion_oracle_unbound")
    if list(CASE_TARGETS.values()).count("codex-core::all") != 13 or list(CASE_TARGETS.values()).count("codex-core::responses_headers") != 3:
        raise Hold("target_inventory")







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
    prior_path = control / "prior-negative-evidence.json"
    if sha(prior_path) != PRIOR_NEGATIVE_SHA:
        raise Hold("prior_negative_hash")
    prior = json.loads(prior_path.read_text())
    if (prior["sourceManifestSha256"] != sha(manifest_path)
            or prior["toolsPinsSha256"] != sha(tools_path)
            or prior["candidateContributionCommit"] != CANDIDATE_COMMIT
            or prior["baseCommit"] != BASE):
        raise Hold("prior_negative_source_or_tools")
    admission = json.loads((control / "admission.json").read_text())
    if (admission.get("approved") is not True or admission.get("controllerSha256") != sha(__file__)
            or admission.get("sourceManifestSha256") != sha(manifest_path)
            or admission.get("toolsPinsSha256") != sha(tools_path)
            or admission.get("priorNegativeSha256") != PRIOR_NEGATIVE_SHA
            or admission.get("workflowSha256") != sha(control / ".github/workflows/issue1120-candidate-only-v2.yml")):
        raise Hold("admission_not_bound")
    identity = os.environ.get("GITHUB_RUN_ID", "")
    if not identity.isdecimal():
        raise Hold("run_id")
    root = Path("/tmp") / ("issue1120-candidate-v2-" + identity)
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
    result = {"schema": "issue1120-candidate-only-result-v2", "status": "INCOMPLETE", "sourceCommit": BASE,
              "candidateContributionCommit": CANDIDATE_COMMIT,
              "sourceManifestSha256": sha(manifest_path), "toolsPinsSha256": sha(tools_path),
              "controllerSha256": sha(__file__), "runId": identity, "phases": {}, "commands": c.rows,
              "rawLocalReceiptsUploaded": False, "qualified": False,
              "candidateQualified": False, "pairedQualification": False,
              "externalNegativeEvidence": prior, "externalNegativeSha256": PRIOR_NEGATIVE_SHA,
              "comparisonMode": "candidate_only_with_external_negative_evidence",
              "negativeControlIsUpstreamBaseline": False,
              "runnerIdentity": {key: os.environ.get(key) for key in
                  ("RUNNER_NAME", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "ImageOS", "ImageVersion")}}
    code = 1
    try:
        if "CODEX_SANDBOX_NETWORK_DISABLED" in c.env:
            raise Hold("inherited_network_disabled_no_body_skips_allowed")
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
        if fixture["exitCode"] != 0 or evidence["remainingCount"] or len(evidence["reapedExited"]) != 1:
            raise Hold("owned_orphan_reaping_preflight_failed")
        result["ownedProcessPreflight"] = {"passed": True, "reapedExitedCount": 1, "productTestBodiesExecuted": 0}
        if not (source / ".git").is_dir() or (source / ".git").is_symlink():
            raise Hold("fresh_real_checkout_required")
        if c.git("initial-head", "rev-parse", "HEAD").decode().strip() != BASE:
            raise Hold("wrong_base")
        if c.git("initial-status", "status", "--porcelain").strip():
            raise Hold("checkout_dirty")
        cfg = c.git("git-config", "config", "--local", "--name-only", "--list").decode()
        if re.search(r"extraheader|credential|insteadof|sshcommand|include\.|hookspath|fsmonitor", cfg, re.I):
            raise Hold("checkout_auth_config")
        def source_inputs():
            for p, expected in tools["sourceInputs"].items():
                if sha(source / p) != expected:
                    raise Hold("wrapper_or_source_input_changed")
            return {p: sha(source / p) for p in sorted(set(tools["sourceInputs"]) | set(SOURCE_FILES))}
        source_inputs()
        for f in manifest["files"]:
            if sha(source / f["path"]) != f["originalSha256"]:
                raise Hold("original_source_hash")
            payload = control / f["payload"]
            if not payload.is_file() or payload.is_symlink() or sha(payload) != f["candidateSha256"]:
                raise Hold("candidate_payload_hash")
        negative_row = next(f for f in manifest["files"] if f["path"] == NEGATIVE_SOURCE)
        negative_payload = control / negative_row["negativePayload"]
        if negative_payload.is_symlink() or sha(negative_payload) != negative_row["negativeSha256"]:
            raise Hold("negative_payload_hash")
        for field in ("patch", "negativePatch"):
            if sha(control / manifest[field]["path"]) != manifest[field]["sha256"]:
                raise Hold("patch_hash")
        patch = control / manifest["patch"]["path"]
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
        config.write_bytes(nextest_config((source / "codex-rs/.config/nextest.toml").read_bytes(), root / "target/nextest"))
        result["ownedNextestConfigSha256"] = sha(config)
        before_fmt = c.verify_source(manifest, "candidate-before-full-format")
        _, fmt = c.run("full-format-candidate", [str(just), "fmt"], 900, allow_failure=True)
        actual_diff = c.git("format-diff-candidate", "diff", "--binary", "HEAD")
        after_fmt = hashlib.sha256(actual_diff).hexdigest()
        result["phases"]["format-candidate"] = {"exitCode": fmt["exitCode"], "sourceUnchanged": before_fmt == after_fmt, "diffSha256": after_fmt}
        if before_fmt != after_fmt or fmt["exitCode"] != 0:
            (args.output / "format-candidate-actual.patch").write_bytes(normalized(actual_diff, c.replacements))
            raise Hold("full_format_failed_or_changed_source")
        c.verify_source(manifest, "candidate-after-full-format")
        c.run("fetch-locked", [str(root / "toolchain/bin/cargo"), "fetch", "--locked", "--manifest-path", str(source / "codex-rs/Cargo.toml"), "--target", "x86_64-unknown-linux-gnu"], 900)
        c.env["CARGO_NET_OFFLINE"] = "true"
        stage = "candidate"
        before = c.verify_source(manifest, stage + "-before")
        inputs_before = source_inputs()
        phase = {"sourceDiffSha256Before": before, "sourceHashesBefore": inputs_before,
                 "sourceHashesAfter": None, "qualification": None}
        result["phases"][stage] = phase
        c.run("scoped-format-check", [str(root / "toolchain/bin/cargo"), "fmt", "--manifest-path", str(source / "codex-rs/Cargo.toml"), "-p", "codex-core", "--", "--check"], 120)
        result["capacity"]["beforeClippyBytes"] = shutil.disk_usage(root).free
        if result["capacity"]["beforeClippyBytes"] < 30 * GIB:
            raise Hold("first_compile_disk_floor")
        c.run("scoped-clippy", [str(just), "clippy", "-p", "codex-core", "--locked", "--offline", "--", "-D", "warnings"], 1800)
        c.verify_source(manifest, "candidate-after-checks")
        phase["sourceHashesImmediatelyBeforeTests"] = source_inputs()
        if phase["sourceHashesImmediatelyBeforeTests"] != inputs_before:
            raise Hold("source_changed_during_static_checks")
        free = shutil.disk_usage(root).free
        result["capacity"]["beforeStage"][stage] = free
        if free < 8 * GIB:
            raise Hold("compile_disk_floor")
        report = root / "target/nextest/test-roots-candidate/junit.xml"
        if report.exists():
            raise Hold("stale_junit_report")
        raw, row = c.run("tests-candidate", test_argv(just, config, stage), 1800, allow_failure=True)
        captured = capture_junit(c, stage, result)
        # Preserve contemporaneous post-test bytes before any outcome parser can fail.
        current = c.verify_source(manifest, "candidate-after-tests")
        inputs_after = source_inputs()
        phase.update(sourceDiffSha256After=current, sourceHashesAfter=inputs_after)
        if current != before or inputs_before != inputs_after:
            raise Hold("source_changed_during_tests")
        if row["exitCode"] != 0:
            raise Hold("unexpected_wrapper_exit")
        if not captured or not captured["captureComplete"]:
            raise Hold("junit_missing_or_oversize")
        binaries = retain_binary(c, stage)
        result.setdefault("observedStageBinaries", {})[stage] = binaries
        phase["binaries"] = binaries
        outcome = classify_test(report.read_bytes(), (raw / "combined").read_text(), CASES)
        phase.update(qualification=outcome, junitRawSha256=captured["rawSha256"],
                     junitPublicSha256=captured["publicSha256"])
        result["status"] = "CANDIDATE_SIXTEEN_PASSED_EXTERNAL_NEGATIVE_LIMITATIONS"
        result["candidateQualified"], code = True, 0
    except BaseException as e:
        result["failureCode"] = str(e) if isinstance(e, Hold) else "controller_" + type(e).__name__
    finally:
        for stage in ("candidate",):
            try:
                capture_junit(c, stage, result)
            except Exception:
                result["status"], result["candidateQualified"], code = "INCOMPLETE", False, 1
                result.setdefault("captureErrors", []).append("junit-" + stage)
        result["inheritedMarkersPreserved"] = markers == {k: (k in c.env, c.env.get(k)) for k in MARKERS}
        result["inheritedHomeIdentityPreserved"] = homes == {k: (k in c.env, c.env.get(k)) for k in ("HOME", "CODEX_HOME")}
        result["ownedDescendantsGone"] = not children()
        result["freeBytesAfter"] = shutil.disk_usage(root).free
        if not result["inheritedMarkersPreserved"] or not result["ownedDescendantsGone"] or not result["inheritedHomeIdentityPreserved"]:
            result["status"], result["candidateQualified"], code = "INCOMPLETE", False, 1
        save(args.output / "qualification-result.json", result)
        print(result["status"])
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("HOSTED_VALIDATION_NOT_STARTED:" + (str(e) if isinstance(e, Hold) else type(e).__name__))
        sys.exit(1)
