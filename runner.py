"""Exact Issue 1003 qualification. No build or tests run when imported."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

HEAD = "bbe1baa51bbebc2e52afe64b348c2d6810f37c33"
TARGET = "x86_64-pc-windows-msvc"
ADMISSION_FREE = 10 * 1024 ** 3
RUN_FREE_FLOOR = 4 * 1024 ** 3
MAX_LOG_BYTES = 64 * 1024 ** 2
COMMAND_SECONDS = 1440
EXPECTED = tuple("lock_lifetime_tests::" + name for name in (
    "issue928_append_releases_lock_with_retained_descriptor",
    "issue928_trim_releases_lock_with_retained_descriptor",
    "issue928_append_error_releases_lock_with_retained_descriptor",
    "issue928_lookup_releases_shared_lock_with_retained_descriptor",
    "issue928_lookup_failure_exits_release_shared_lock",
    "issue928_concurrent_public_appends_preserve_all_entries",
    "issue928_disabled_persistence_creates_no_history_file",
))
UNIX_ONLY = "lock_lifetime_tests::issue928_native_control_duplicate_retains_lock_until_explicit_unlock"
PINS = {
    "codex-rs/message-history/src/lock_lifetime_tests.rs": "519d5dbb54ae44d06220e449ceec8d34cd3fdb6771a387e077260730fd27479d",
    "scripts/isolated_rust_tests.py": "2376d36fae0943cbbf4a0caf58109b0dece03cb226983d1276216adc90d2447c",
    "scripts/just-shell.py": "444d6b328d44abf6453b77b6acce2a0c881fc162ff30b20f352c85067797fbe9",
    "justfile": "7d668a298669ad859d874755520d3e3114c0cce2786cd4cc1bb22e2dd22e404f",
    "codex-rs/rust-toolchain.toml": "913d7e9d7adcd7abfeb0c4554c39a5a57c3cf84a694bc6a6aeae038a1f6ae33b",
    "codex-rs/Cargo.lock": "9bf3331a78a43b8d7489875db26d199d97f018f0e78cefefa928d09a306478bb",
    "codex-rs/.cargo/config.toml": "b8ae1cea341beb2d4a3c8fb81f97a96f4aee1fd53f769c57f140dfe949806a80",
    "codex-rs/.config/nextest.toml": "830c64fd157ef4bb618626c4f7aaf3de986b488289eb28ed352ff0a21e29c110",
}
ARGS = ["test", "-p", "codex-message-history", "--lib", "--locked",
        "--target", TARGET, "-E", "test(lock_lifetime_tests::)",
        "--test-threads", "2", "--retries", "0", "--success-output", "immediate",
        "--failure-output", "immediate", "--status-level", "pass",
        "--final-status-level", "fail", "--color", "never"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def reconcile(log, junit):
    """Fail closed: seven named bodies, both reporters agree, no retry or skip."""
    require(UNIX_ONLY not in log and UNIX_ONLY not in junit, "Unix-only control appeared")
    require("Test isolation: disposable profile; native keyring disabled (debug lane)" in log,
            "ordinary isolation wrapper announcement missing")
    summaries = list(re.finditer(r"^[ \t]*Summary \[[^\]\r\n]+\][ \t]*(.+?)[ \t]*$", log, re.M))
    require(len(summaries) == 1 and summaries[0].group(1) == "7 tests run: 7 passed, 12 skipped", "nextest summary differs")
    progress = log[:summaries[0].start()]
    after_summary = log[summaries[0].end():]
    require("lock_lifetime_tests::" not in after_summary, "test record after final Summary")
    starts = re.findall(r"^\s*Starting (\d+) tests across (\d+) binar(?:y|ies) \((\d+) tests skipped\)\s*$", progress, re.M)
    require(starts == [("7", "1", "12")], "selection differs from seven bodies and twelve filter exclusions")
    statuses = re.findall(r"^[ \t]*([A-Z][A-Z0-9 ]*) \[[^\]\r\n]+\][ \t]+(?:\((\d+)/(\d+)\)[ \t]+)?codex-message-history (\S+)[ \t]*$", progress, re.M)
    require(Counter(row[3] for row in statuses) == Counter(EXPECTED), "progress identities missing, duplicated, or unexpected")
    require(all(row[0] == "PASS" for row in statuses), "conflicting or non-pass progress status")
    ordinals = [(int(row[1]), int(row[2])) for row in statuses if row[1]]
    require(not ordinals or sorted(ordinals) == [(i, 7) for i in range(1, 8)], "progress ordinals differ from unique 1..7/7")
    bodies = re.findall(r"^\s*test (lock_lifetime_tests::\S+) \.\.\. ok\s*$", progress, re.M)
    require(Counter(bodies) == Counter(EXPECTED), "actual libtest body output missing, duplicated, or unexpected")
    outcomes = re.findall(r"^\s*test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;.*$", progress, re.M)
    require(outcomes == [("1", "0", "0", "0", "18")] * 7, "body summaries differ from seven native successes")
    require(not re.search(r"^\s*(?:RETRY|TRY|FLAKY|FAIL|TIMEOUT|SKIP|LEAK)\b.*lock_lifetime_tests::", log, re.M),
            "non-pass or retry status present")
    root = ET.fromstring(junit)
    require(root.tag == "testsuites", "unexpected JUnit root")
    suites = root.findall("testsuite")
    require(len(suites) == 1 and suites[0].get("name") == "codex-message-history", "unexpected JUnit binary")
    for node in (root, suites[0]):
        require(node.get("tests") == "7", "JUnit count differs")
        for field in ("failures", "errors", "skipped", "disabled"):
            require(node.get(field, "0") == "0", "JUnit non-success count: " + field)
    cases = suites[0].findall("testcase")
    require(Counter(c.get("name") for c in cases) == Counter(EXPECTED), "JUnit cases differ")
    require(all(c.get("classname") == "codex-message-history" for c in cases), "JUnit class differs")
    bad = {"failure", "error", "skipped", "flakyFailure", "flakyError", "rerunFailure", "rerunError"}
    require(not any(node.tag in bad for node in root.iter()), "JUnit failure, skip, or retry recorded")
    return {"actual_passed": 7, "selected_skipped": 0, "retries": 0,
            "filter_exclusions": 12, "unix_control_absent": True, "tests": sorted(EXPECTED)}


def normalized_xml(xml, normalize):
    """Escape normalized path labels through the XML serializer."""
    root = ET.fromstring(xml)
    for node in root.iter():
        node.attrib = {key: normalize(value) for key, value in node.attrib.items()}
        if node.text:
            node.text = normalize(node.text)
        if node.tail:
            node.tail = normalize(node.tail)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def stop_reason(elapsed, free_bytes, log_bytes):
    if elapsed >= COMMAND_SECONDS:
        return "24-minute command bound reached"
    if free_bytes < RUN_FREE_FLOOR:
        return "disposable runner free space below 4 GiB floor"
    if log_bytes >= MAX_LOG_BYTES:
        return "combined log reached 64 MiB stop threshold"
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    options = parser.parse_args()
    subject, out = options.subject.resolve(), options.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    # Disposable public-source CI output; preserve the original and portable copy.
    # No environment dump, operator profile, or provider credentials are collected.
    raw = out / "combined.raw.log"
    replacements = [(str(subject), "<SUBJECT>"), (str(out.parent), "<WORKSPACE>")]
    for key in ("RUNNER_TEMP", "USERPROFILE"):
        if os.environ.get(key):
            replacements.append((os.environ[key], "<" + key + ">"))

    def normalized(value):
        for path, label in sorted(replacements, key=lambda pair: len(pair[0]), reverse=True):
            for variant in (path, path.replace("\\", "/")):
                value = re.sub(re.escape(variant), lambda _: label, value, flags=re.I)
        return value

    def capture(command):
        return subprocess.check_output(command, cwd=subject, text=True, encoding="utf-8", errors="replace").strip()

    def identity():
        result = {"head": capture(["git", "rev-parse", "HEAD"]),
                  "tracked_status": capture(["git", "status", "--porcelain", "--untracked-files=no"]),
                  "sha256": {name: sha((subject / name).read_bytes()) for name in PINS}}
        require(result["head"] == HEAD and not result["tracked_status"], "subject identity or cleanliness differs")
        require(result["sha256"] == PINS, "source, wrapper, lockfile, or configuration hash differs")
        return result

    result = {"status": "incomplete", "started_at": utc(), "source_head": HEAD,
              "command": ["just", *ARGS], "compile_jobs": 2, "test_threads": 2,
              "ordinary_debug_lane": True, "native_credential_qualification": False}
    result["resource_bounds"] = {"admission_free_bytes": ADMISSION_FREE, "continuous_free_floor_bytes": RUN_FREE_FLOOR,
                                 "log_stop_bytes": MAX_LOG_BYTES, "command_seconds": COMMAND_SECONDS, "poll_seconds": 1,
                                 "incremental": "0", "dev_and_test_debug_symbols": "0", "debug_assertions": "true via unchanged wrapper"}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    try:
        require(os.name == "nt" and platform.machine().upper() in ("AMD64", "X86_64"), "native Windows x64 host required")
        require(os.environ.get("GITHUB_REPOSITORY") == "citadelculture/CorbanuTerminal", "wrong repository")
        require(os.environ.get("GITHUB_REF") == "refs/heads/qualification/issue1003-windows-20261021", "wrong method branch")
        require(os.environ.get("CARGO_BUILD_JOBS") == "2", "compile job bound missing")
        for name in ("CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"):
            require(os.environ.get(name) == "0", name + " bound missing")
        require(not os.environ.get("CARGO_TARGET_DIR") and not os.environ.get("CARGO_BUILD_TARGET_DIR"), "custom target directory refused")
        result["source_before"] = identity()
        target = subject / "codex-rs" / "target"
        require(not target.exists(), "fresh target directory required; no cached/reused binary")
        result["versions"] = {name: normalized(capture(command)) for name, command in {
            "rustc": ["rustc", "-vV"], "cargo": ["cargo", "--version"],
            "nextest": ["cargo", "nextest", "--version"], "just": ["just", "--version"],
            "python": [sys.executable, "--version"], "git": ["git", "--version"],
            "pwsh": ["pwsh", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
        }.items()}
        require("release: 1.99.1" in result["versions"]["rustc"] and "host: " + TARGET in result["versions"]["rustc"], "Rust release or host differs")
        require(re.match(r"cargo-nextest 0\.9\.146\b", result["versions"]["nextest"]), "nextest version differs")
        require(result["versions"]["just"] == "just 1.58.0", "just version differs")
        require(result["versions"]["python"] == "Python 3.13.0", "Python version differs")
        result["host"] = {"os": platform.system(), "release": platform.release(), "version": platform.version(), "machine": platform.machine(),
                          "runner_image": os.environ.get("ImageOS"), "runner_image_version": os.environ.get("ImageVersion")}
        result["run"] = {key: os.environ.get(key) for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
        markers = {key: os.environ.get(key) for key in ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")}
        result["sandbox_markers"] = {key: {"present": value is not None, "value_sha256": sha(value.encode()) if value is not None else None} for key, value in markers.items()}
        free = shutil.disk_usage(subject).free
        result["resource_observed"] = {"admission_free_bytes": free, "minimum_free_bytes": free, "maximum_log_bytes": 0, "samples": 0}
        require(free >= ADMISSION_FREE, "disposable runner requires 10 GiB admission space")
        with raw.open("wb") as stream:
            process = subprocess.Popen([shutil.which("just"), *ARGS], cwd=subject, stdout=stream, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            result["owned_pid"] = process.pid
            started = time.monotonic()
            try:
                while True:
                    free, size = shutil.disk_usage(subject).free, raw.stat().st_size
                    observed = result["resource_observed"]
                    observed["minimum_free_bytes"] = min(observed["minimum_free_bytes"], free)
                    observed["maximum_log_bytes"] = max(observed["maximum_log_bytes"], size)
                    observed["samples"] += 1
                    reason = stop_reason(time.monotonic() - started, free, size)
                    if reason:
                        result["stop_reason"] = reason
                        raise ValueError(reason)
                    if process.poll() is not None:
                        result["command_exit"] = process.returncode
                        break
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                if process.poll() is None:
                    # Kill only the tree started above, including monitor failures.
                    killed = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=stream, stderr=subprocess.STDOUT, timeout=30)
                    result["owned_tree_kill_exit"] = killed.returncode
                    result["command_exit"] = process.wait(timeout=30)
                    require(killed.returncode == 0, "owned process-tree cleanup failed")
        result["source_after"] = identity()
        require(markers == {key: os.environ.get(key) for key in markers}, "sandbox marker state changed")
        require(not result.get("stop_reason"), "resource or time stop reached")
        require(result["command_exit"] == 0, "ordinary test command failed")
        junit_path = target / "nextest" / "local" / "junit.xml"
        junit = junit_path.read_text(encoding="utf-8")
        shutil.copyfile(junit_path, out / "junit.raw.xml")
        (out / "junit.xml").write_text(normalized_xml(junit, normalized), encoding="utf-8")
        log = raw.read_text(encoding="utf-8", errors="replace")
        result["reconciliation"] = reconcile(log, junit)
        binaries = list((target / TARGET / "debug" / "deps").glob("codex_message_history-*.exe"))
        require(len(binaries) == 1, "expected exactly one newly built message-history library test executable")
        data = binaries[0].read_bytes()
        require(data[:2] == b"MZ", "missing PE DOS header")
        offset = struct.unpack_from("<I", data, 0x3C)[0]
        require(data[offset:offset + 4] == b"PE\0\0" and struct.unpack_from("<H", data, offset + 4)[0] == 0x8664, "test binary is not PE AMD64")
        result["test_binary"] = {"relative_path": binaries[0].relative_to(subject).as_posix(), "bytes": len(data), "sha256": sha(data), "format": "PE AMD64"}
        result["test_binary"]["copy_projected_free_bytes"] = shutil.disk_usage(out).free - len(data)
        require(result["test_binary"]["copy_projected_free_bytes"] >= RUN_FREE_FLOOR, "PE retention would breach 4 GiB floor")
        retained = out / binaries[0].name
        shutil.copyfile(binaries[0], retained)
        require(sha(retained.read_bytes()) == result["test_binary"]["sha256"], "retained PE digest differs")
        result["test_binary"]["retained_artifact"] = retained.name
        require(shutil.disk_usage(out).free >= RUN_FREE_FLOOR, "free space below 4 GiB after PE retention")
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed_or_incomplete"
        result["reason"] = normalized(str(error))
    finally:
        if "source_before" in result and "source_after" not in result:
            try:
                result["source_after"] = identity()
            except Exception as error:
                result["source_after_error"] = normalized(str(error))
        if raw.exists():
            data = raw.read_bytes()
            result["combined_raw_sha256"] = sha(data)
            log = normalized(data.decode("utf-8", errors="replace"))
            (out / "combined.log").write_text(log, encoding="utf-8")
            print(log)
        # Preserve a report on command failure too, without claiming it passed.
        junit_path = subject / "codex-rs" / "target" / "nextest" / "local" / "junit.xml"
        if junit_path.exists() and not (out / "junit.raw.xml").exists():
            shutil.copyfile(junit_path, out / "junit.raw.xml")
        if junit_path.exists() and not (out / "junit.xml").exists():
            try:
                value = normalized_xml(junit_path.read_text(encoding="utf-8"), normalized)
                (out / "junit.xml").write_text(value, encoding="utf-8")
            except Exception as error:
                result["junit_normalization_error"] = normalized(str(error))
        result["finished_at"] = utc()
        result["artifacts"] = {p.name: {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in out.iterdir() if p.name != "result.json"}
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
