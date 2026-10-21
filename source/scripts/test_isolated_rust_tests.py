import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import isolated_rust_tests as runner


class IsolatedRustTests(unittest.TestCase):
    def test_live_aliases_and_credentials_do_not_reach_child(self):
        with tempfile.TemporaryDirectory() as root:
            live = Path(root) / "live"
            live.mkdir()
            canary = live / "auth-canary"
            canary.write_text("synthetic-do-not-touch", encoding="utf-8")
            fixture = Path(root) / "fixture"
            fixture.mkdir()
            parent = {
                "PATH": os.environ.get("PATH", ""),
                "CORBANU_HOME": str(live),
                "PFTERMINAL_HOME": str(live),
                "CODEX_HOME": str(live),
                "CLAUDE_CODE_OAUTH_TOKEN": "synthetic-token",
                "ANTHROPIC_API_KEY": "synthetic-key",
                "OPENAI_API_KEY": "synthetic-key",
                "ZAI_API_KEY": "synthetic-key",
                "CORBANU_TEST_NO_NATIVE_KEYRING": "0",
                "CARGO_TARGET_DIR": str(Path(root) / "build-cache"),
            }
            before = parent.copy()
            env = runner.test_environment(parent, fixture)
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import json,os; print(json.dumps(dict(os.environ)))",
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            child = json.loads(result.stdout)
            self.assertEqual(child["CODEX_HOME"], str(fixture))
            self.assertEqual(child["CORBANU_TEST_NO_NATIVE_KEYRING"], "1")
            for name in (
                "CORBANU_HOME",
                "PFTERMINAL_HOME",
                "CLAUDE_CODE_OAUTH_TOKEN",
                "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY",
                "ZAI_API_KEY",
            ):
                self.assertNotIn(name, child)
            self.assertEqual(child["CARGO_TARGET_DIR"], parent["CARGO_TARGET_DIR"])
            self.assertEqual(parent, before)
            self.assertEqual(
                canary.read_text(encoding="utf-8"), "synthetic-do-not-touch"
            )

    def test_existing_fixture_can_override_codex_home_without_alias_shadowing(self):
        env = runner.test_environment({"CORBANU_HOME": "host"}, Path("run-profile"))
        env["CODEX_HOME"] = "individual-fixture"
        selected = (
            env.get("CORBANU_HOME") or env.get("PFTERMINAL_HOME") or env["CODEX_HOME"]
        )
        self.assertEqual(selected, "individual-fixture")

    def test_launch_forces_guard_preserves_exit_and_cleans_only_owned_profile(self):
        profiles = []

        def fake_cargo(argv, *, cwd, env, check):
            self.assertEqual(
                argv,
                [
                    "/synthetic/cargo",
                    "nextest",
                    "run",
                    "--no-fail-fast",
                    "-p",
                    "fixture",
                ],
            )
            self.assertEqual(cwd.name, "codex-rs")
            self.assertFalse(check)
            profiles.append(Path(env["CODEX_HOME"]))
            self.assertTrue(profiles[-1].is_dir())
            self.assertEqual(env["CORBANU_TEST_NO_NATIVE_KEYRING"], "1")
            self.assertNotIn("CORBANU_HOME", env)
            return subprocess.CompletedProcess(argv, 100)

        with (
            patch.dict(os.environ, {"CORBANU_HOME": "host-canary"}, clear=True),
            patch.object(runner.shutil, "which", return_value="/synthetic/cargo"),
            patch.object(runner.subprocess, "run", side_effect=fake_cargo),
            patch.object(runner, "remove_leaked_mount_targets"),
        ):
            self.assertEqual(runner.main(["-p", "fixture"]), 100)
            self.assertEqual(runner.main(["-p", "fixture"]), 100)
            self.assertEqual(os.environ["CORBANU_HOME"], "host-canary")
        self.assertNotEqual(profiles[0], profiles[1])
        self.assertTrue(all(not path.exists() for path in profiles))

    @unittest.skipUnless(os.name == "posix", "Unix socket path regression")
    def test_nested_socket_with_long_and_short_caller_temp_paths(self):
        real_run = subprocess.run
        child = textwrap.dedent("""\
            import json, os, socket, tempfile
            from pathlib import Path
            with tempfile.TemporaryDirectory(prefix="fixture-") as fixture:
                nested = Path(fixture) / ("nested-" + "n" * 16)
                nested.mkdir()
                address = str(nested / "fixture.sock")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                    server.settimeout(5)
                    server.bind(address)
                    server.listen(1)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.settimeout(5)
                        client.connect(address)
                        peer, _ = server.accept()
                        with peer:
                            peer.settimeout(5)
                            client.sendall(b"probe")
                            assert peer.recv(5) == b"probe"
                print(json.dumps({"temp": tempfile.gettempdir(),
                                  "bytes": len(os.fsencode(address))}))
            """)
        with tempfile.TemporaryDirectory(prefix="caller-", dir="/tmp") as caller:
            short = Path(caller)
            long = short
            while len(os.fsencode(long)) <= 512:
                long /= "\u00e9" * 36
                long.mkdir(mode=0o700)
            sentinel = long / "caller-owned"
            sentinel.write_text("keep", encoding="utf-8")
            roots = []

            def fake_cargo(argv, *, cwd, env, check):
                home, scratch = Path(env["CODEX_HOME"]), Path(env["TMPDIR"])
                root = home.parent
                roots.append(root)
                self.assertEqual(scratch.parent, root)
                for path in (root, home, scratch):
                    info = path.stat()
                    self.assertEqual(info.st_uid, os.getuid())
                    self.assertEqual(info.st_mode & 0o077, 0)
                self.assertEqual(env["CORBANU_TEST_NO_NATIVE_KEYRING"], "1")
                result = real_run(
                    [sys.executable, "-c", child],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["temp"], str(scratch))
                self.assertLess(report["bytes"], 104)
                return subprocess.CompletedProcess(argv, 0)

            for inherited in (short, long):
                with (
                    self.subTest(inherited_bytes=len(os.fsencode(inherited))),
                    patch.dict(
                        os.environ,
                        dict.fromkeys(("TMPDIR", "TMP", "TEMP"), str(inherited)),
                    ),
                    patch.object(tempfile, "tempdir", str(inherited)),
                    patch.object(
                        runner.shutil, "which", return_value="/synthetic/cargo"
                    ),
                    patch.object(runner.subprocess, "run", side_effect=fake_cargo),
                    patch.object(runner, "remove_leaked_mount_targets"),
                ):
                    before = dict(os.environ)
                    self.assertEqual(runner.main(["-p", "fixture"]), 0)
                    self.assertEqual(dict(os.environ), before)
                self.assertFalse(roots[-1].exists())
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            self.assertNotEqual(roots[0], roots[1])

    def test_cleanup_after_child_and_setup_failures(self):
        real_directory = tempfile.TemporaryDirectory
        for outcome in (0, 19, "launch-exception", "setup-exception"):
            roots = []

            def directory(*args, **kwargs):
                owned = real_directory(*args, **kwargs)
                roots.append(Path(owned.name))
                return owned

            def child(argv, **kwargs):
                scratch = Path(kwargs["env"]["TMPDIR"])
                (scratch / "child-artifact").write_text("synthetic", encoding="utf-8")
                if outcome == "launch-exception":
                    raise OSError("synthetic child launch failure")
                return subprocess.CompletedProcess(argv, outcome)

            environment = runner.test_environment
            if outcome == "setup-exception":

                def environment(parent, home):
                    self.assertTrue(home.is_dir())
                    raise OSError("synthetic setup failure")

            with (
                self.subTest(outcome=outcome),
                patch.object(
                    runner.tempfile, "TemporaryDirectory", side_effect=directory
                ),
                patch.object(runner.shutil, "which", return_value="/synthetic/cargo"),
                patch.object(runner.subprocess, "run", side_effect=child) as run,
                patch.object(runner, "test_environment", side_effect=environment),
                patch.object(runner, "remove_leaked_mount_targets"),
            ):
                before = dict(os.environ)
                if isinstance(outcome, str):
                    with self.assertRaises(OSError):
                        runner.main(["-p", "fixture"])
                else:
                    self.assertEqual(runner.main(["-p", "fixture"]), outcome)
                if outcome == "setup-exception":
                    run.assert_not_called()
                self.assertEqual(dict(os.environ), before)
            self.assertEqual(len(roots), 1)
            self.assertFalse(roots[0].exists())

    def test_unsafe_build_lane_fails_before_cargo_starts(self):
        for option in (
            "--release",
            "-r",
            "-vr",
            "-rj4",
            "--cargo-profile=release",
            "--config=x",
            "--archive-file=old.tar.zst",
            "--binaries-metadata=old.json",
        ):
            with (
                self.subTest(option=option),
                patch.object(runner.subprocess, "run") as run,
            ):
                self.assertEqual(runner.main([option]), 2)
                run.assert_not_called()

    def test_debug_assertions_override_is_rejected(self):
        for name in (
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                runner.validate_debug_run([], {name: "-Cdebug-assertions=no"})

    def test_attached_package_and_filter_values_are_not_release_flags(self):
        runner.validate_debug_run(["-pcodex-keyring-store", "-Etest(guard)", "-j4"], {})

    def test_missing_cargo_is_explicit(self):
        with patch.object(runner.shutil, "which", return_value=None):
            self.assertEqual(runner.main([]), 2)


if __name__ == "__main__":
    unittest.main()
