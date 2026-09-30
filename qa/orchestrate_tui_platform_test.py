#!/usr/bin/env python3
"""Exercise portable evidence and failure propagation through actual matrix rows."""

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "qa/orchestrate_tui_platform.py"
MATRIX = ROOT / "qa/orchestrate_tui_matrix.sh"
spec = importlib.util.spec_from_file_location("qa_platform", HELPER)
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


def helper(*arguments):
    return subprocess.run(
        [sys.executable, str(HELPER), *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=10,
    )


def row_definition(number):
    # Execute the production row, not a duplicate of its command/guard logic.
    source = MATRIX.read_text()
    body = source.split(f"row_{number}() {{", 1)[1].split(
        f"\nrow_{number + 1}() {{", 1
    )[0]
    return f"row_{number}() {{" + body


class PlatformTests(unittest.TestCase):
    def test_clock_is_numeric_monotonic_across_processes(self):
        readings = []
        for _ in range(3):
            result = helper("now-ms")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r"^[0-9]+\n$")
            readings.append(int(result.stdout))
        self.assertEqual(readings, sorted(readings))
        time.sleep(0.01)
        elapsed = helper("elapsed-ms", readings[-1])
        self.assertEqual(elapsed.returncode, 0, elapsed.stderr)
        self.assertGreaterEqual(int(elapsed.stdout), 10)

    def test_elapsed_uses_monotonic_clock_not_wall_time(self):
        with (
            patch.object(
                platform.time,
                "monotonic_ns",
                side_effect=[1_234_000_000, 1_237_000_000],
            ),
            patch.object(
                platform.time, "time", side_effect=AssertionError("wall clock used")
            ),
            patch.object(
                platform.time, "time_ns", side_effect=AssertionError("wall clock used")
            ),
        ):
            self.assertEqual(platform.elapsed_ms(platform.monotonic_ms()), 3)

    def test_real_readonly_mode_does_not_modify_contents_or_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "copied fixture.json"
            path.write_bytes(b'{"fixture":"read only"}\n')
            path.chmod(0o444)
            before = hashlib.sha256(path.read_bytes()).digest()
            try:
                result = helper("source-mode", path)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "source_mode=444\n")
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
                self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
            finally:
                path.chmod(0o600)

    def test_invalid_evidence_fails_without_stdout(self):
        with tempfile.TemporaryDirectory() as temporary:
            cases = [
                ("elapsed-ms", "not-an-integer"),
                ("elapsed-ms", "-1"),
                ("elapsed-ms", str(10**30)),
                ("source-mode", str(Path(temporary) / "missing")),
            ]
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    result = helper(*arguments)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertTrue(result.stderr)

    def test_row14_propagates_each_clock_failure(self):
        for failed_call in range(1, 9):
            with (
                self.subTest(failed_call=failed_call),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                script = (
                    row_definition(14)
                    + r"""
start_row() { :; }
create_pane() { :; }
submit() { :; }
wait_screen() { :; }
tmux() { :; }
sleep() { :; }
capture() { :; }
fail() { return 1; }
python3() {
  local count
  count=$(cat "$COUNTER")
  count=$((count + 1))
  printf '%s' "$count" > "$COUNTER"
  [[ "$count" != "$FAILED_CALL" ]] || return 73
  "$REAL_PYTHON" "$@"
}
# Deliberately suppress errexit in the caller: explicit row guards must work.
row_14 && exit 99
status=$?
[[ "$status" == 73 ]] || exit 98
[[ ! -s "$RESULTS" ]] || exit 97
[[ "$(cat "$COUNTER")" == "$FAILED_CALL" ]] || exit 96
"""
                )
                (root / "count").write_text("0")
                result = subprocess.run(
                    ["bash", "-c", script],
                    env={
                        **os.environ,
                        "ROOT": str(ROOT),
                        "ARTIFACT_ROOT": str(root),
                        "CURRENT_SESSION": ".",
                        "RESULTS": str(root / "results"),
                        "COUNTER": str(root / "count"),
                        "FAILED_CALL": str(failed_call),
                        "REAL_PYTHON": sys.executable,
                    },
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_row15_does_not_continue_after_mode_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "source.json"
            fixture.write_text('{"codex_thread_id":"old"}\n')
            before = hashlib.sha256(fixture.read_bytes()).digest()
            script = (
                row_definition(15)
                + r"""
start_row() { :; }
layout_file() { printf '%s' "$PFTERMINAL_POLLUTED_LAYOUT"; }
tmux() { :; }
# UI/session ID and source-hash plumbing are irrelevant to this failure site.
jq() { cat "$PFTERMINAL_POLLUTED_LAYOUT"; }
sha256sum() { printf 'fixture-hash  source.json\n'; }
python3() { return 73; }
restart_current() { touch "$RESTARTED"; }
wait_layout() { :; }
capture() { :; }
snapshot_layout() { :; }
fail() { return 1; }
row_15 && exit 99
status=$?
[[ "$status" == 73 ]] || exit 98
[[ ! -e "$RESTARTED" && ! -s "$RESULTS" ]] || exit 97
! grep -q 'normalized_root_thread_id' "$ARTIFACT_ROOT/$CURRENT_SESSION/source-record.txt"
"""
            )
            result = subprocess.run(
                ["bash", "-c", script],
                env={
                    **os.environ,
                    "ROOT": str(ROOT),
                    "ARTIFACT_ROOT": str(root),
                    "CURRENT_SESSION": "row15",
                    "CURRENT_HOME": str(root / "home"),
                    "PFTERMINAL_POLLUTED_LAYOUT": str(fixture),
                    "RESULTS": str(root / "results"),
                    "RESTARTED": str(root / "restarted"),
                },
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            copied = root / "row15/read-only-source/pane-layout.json"
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o444)
            self.assertEqual(hashlib.sha256(copied.read_bytes()).digest(), before)
            self.assertEqual(hashlib.sha256(fixture.read_bytes()).digest(), before)
            copied.chmod(0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
