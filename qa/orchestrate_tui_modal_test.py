#!/usr/bin/env python3
"""Exercise the actual tmux key helper and captured live-modal states."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


HELPER = Path(
    os.environ.get(
        "ORCHESTRATE_MODAL_HELPER",
        Path(__file__).with_name("orchestrate_tui_modal.sh"),
    )
).resolve()
RECORDER = """import json, os, select, sys, termios, time, tty
from pathlib import Path
fd = sys.stdin.fileno()
old = termios.tcgetattr(fd)
data = b""
try:
    tty.setraw(fd)
    Path(sys.argv[1]).write_text("ready")
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        remaining = max(0, deadline - time.monotonic())
        if not select.select([fd], [], [], min(0.2, remaining))[0]:
            if data: break
            continue
        data += os.read(fd, 4096)
    Path(sys.argv[2]).write_text(json.dumps({"hex": data.hex()}))
finally:
    termios.tcsetattr(fd, termios.TCSANOW, old)
"""


class ModalTests(unittest.TestCase):
    def test_escape_helper_delivers_one_escape_byte(self):
        tmux = shutil.which("tmux")
        self.assertIsNotNone(tmux, "tmux is required for the real key-byte regression")
        with tempfile.TemporaryDirectory(prefix="cbkey-", dir="/tmp") as temporary:
            root = Path(temporary)
            config = root / "tmux.conf"
            config.write_text(
                "set-option -g default-shell /bin/bash\n"
                "set-option -g default-terminal xterm-256color\n"
            )
            recorder, ready, output = (
                root / name for name in ("record.py", "ready", "output")
            )
            recorder.write_text(RECORDER)
            socket = root / "tmux.sock"
            command = [tmux, "-S", str(socket), "-f", str(config)]
            wrapper = root / "tmux"
            wrapper.write_text("#!/bin/bash\nexec " + shlex.join(command) + ' "$@"\n')
            wrapper.chmod(0o755)
            environment = dict(os.environ)
            environment.pop("TMUX", None)
            environment["PATH"] = str(root) + os.pathsep + environment.get("PATH", "")
            try:
                subprocess.run(
                    command
                    + [
                        "new-session",
                        "-d",
                        "-s",
                        "probe",
                        "-x",
                        "80",
                        "-y",
                        "24",
                        shlex.join(
                            [sys.executable, str(recorder), str(ready), str(output)]
                        ),
                    ],
                    check=True,
                    timeout=5,
                    env=environment,
                )
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "raw PTY recorder did not become ready")
                subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; orchestrate_send_escape probe:0.0',
                        "bash",
                        str(HELPER),
                    ],
                    check=True,
                    timeout=5,
                    env=environment,
                )
                deadline = time.monotonic() + 4
                while not output.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(output.exists(), "raw PTY recorder produced no result")
                self.assertEqual(json.loads(output.read_text())["hex"], "1b")
            finally:
                subprocess.run(
                    command + ["kill-server"], capture_output=True, timeout=5
                )

    def test_modal_exit_requires_live_composer(self):
        ready = (
            "› Explain this codebase\n\n"
            "  qa-model via qa default · /tmp/qa · Corbanu Terminal · TPS: -- tok/s\n"
        )
        # Reproduces the row9 observation: literal Esc replaces the placeholder,
        # but the picker title and controls remain. The directory is synthetic.
        filtered = (
            "  Panes\n  Switch user panes or inspect the managed /spawn crew.\n\n"
            "  Esc\n  no matches\n\n  Enter select | F2 rename | type to search\n"
        )
        self.assertNotIn("Search panes and crew", filtered)
        cases = (
            ("composer", ready, 0),
            ("trailing blanks", ready + "\n  \n", 0),
            (
                "truncated long-directory footer",
                "› Explain this codebase\n  qa-model via qa default · /a/long/directory/…\n",
                0,
            ),
            ("filtered picker", filtered, 1),
            ("unfiltered picker", filtered.replace("Esc", "Search panes and crew"), 1),
            (
                "details modal",
                "Assignment assignment-1\nDetails\nPress esc to go back\n",
                1,
            ),
            ("old composer behind filtered picker", ready + filtered, 1),
            ("old footer before dialog selection", ready + "› 1. Select pane\n", 1),
            ("empty viewport", "\n\n", 1),
            ("prompt without footer", "› Explain this codebase\n", 1),
            (
                "quoted footer text",
                '› Explain this codebase\nQuoted "qa-model via qa default · /tmp/qa"\n',
                1,
            ),
            ("wrong provider", ready.replace("via qa", "via other"), 1),
        )
        for name, screen, expected in cases:
            with self.subTest(name=name):
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; orchestrate_modal_closed',
                        "bash",
                        str(HELPER),
                    ],
                    input=screen,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_details_escape_requires_live_parent_list(self):
        status = (
            "  Orchestrate\n"
            "  Managers continuously drive Workers through assignments.\n\n"
            "› 2. Manager Manager -> Worker Worker (current)  drafting\n\n"
            "  Enter details · d detach · p pause/resume · e extend · f mandate · t test · n new assignment\n"
        )
        details = "Assignment assignment-1\nDetails\nPress esc to go back\n"
        composer = "› Explain this codebase\n  qa-model via qa default · /tmp/qa\n"
        cases = (
            ("returned to parent list", status, 0),
            ("parent with trailing blanks", status + "\n  \n", 0),
            ("details still open", details, 1),
            ("old parent behind details", status + details, 1),
            ("old parent above composer", status + composer, 1),
            ("parent footer alone", status.splitlines()[-1] + "\n", 1),
            ("parent title without controls", "  Orchestrate\n", 1),
            (
                "quoted parent title",
                status.replace("  Orchestrate", '  "Orchestrate"'),
                1,
            ),
        )
        for name, screen, expected in cases:
            with self.subTest(name=name):
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; orchestrate_status_visible',
                        "bash",
                        str(HELPER),
                    ],
                    input=screen,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, expected, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
