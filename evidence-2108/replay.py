#!/usr/bin/env python3
"""Replay #2108: run app-server-transport lib tests inside the same disposable
profile + TMPDIR layout scripts/isolated_rust_tests.py builds (its own
test_environment()), but via `cargo test` because cargo-nextest is not
installed on this machine. Usage: replay.py <worktree> [extra cargo test args]"""
import os, subprocess, sys, tempfile
from pathlib import Path
wt = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(wt / "scripts"))
import isolated_rust_tests as iso  # noqa: E402
with tempfile.TemporaryDirectory(prefix="corbanu-tests-") as root:
    home = Path(root) / "profile"; home.mkdir(mode=0o700)
    env = iso.test_environment(dict(os.environ), home)
    scratch = Path(root) / "tmp"; scratch.mkdir(mode=0o700)
    env["TMPDIR"] = str(scratch)
    print(f"replay: TMPDIR={scratch} ({len(str(scratch))} bytes)", flush=True)
    rc = subprocess.run(["cargo", "test", "-p", "codex-app-server-transport", "--lib",
                         "--locked", "--offline", *sys.argv[2:]],
                        cwd=wt / "codex-rs", env=env).returncode
    print(f"replay: exit {rc}", flush=True)
    sys.exit(rc)
