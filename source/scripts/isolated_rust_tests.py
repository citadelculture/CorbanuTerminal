#!/usr/bin/env python3
"""Ordinary debug tests: disposable profile and no native credential-store calls.

This is test hygiene, not an OS sandbox for hostile tests or release binaries.
See docs/development/test-isolation.md for the separate native qualification lane.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def test_environment(parent: dict[str, str], home: Path) -> dict[str, str]:
    env = parent.copy()
    for name in (
        "CORBANU_HOME",
        "PFTERMINAL_HOME",
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "ZAI_API_KEY",
        "CODEX_APP_SERVER_MANAGED_CONFIG_PATH",
    ):
        env.pop(name, None)
    # Leave the higher-priority aliases unset: existing test fixtures override
    # CODEX_HOME themselves. Setting all three here would shadow those fixtures.
    env["CODEX_HOME"] = str(home)
    env["CORBANU_TEST_NO_NATIVE_KEYRING"] = "1"
    # Debug builds read this instead of the account database, so nested-launch
    # checks never read or register the operator's real Corbanu homes.
    env["CORBANU_TEST_ACCOUNT_HOME"] = str(home / "account")
    env["CARGO_PROFILE_DEV_DEBUG_ASSERTIONS"] = "true"
    env["CARGO_PROFILE_TEST_DEBUG_ASSERTIONS"] = "true"
    env["RUST_MIN_STACK"] = "8388608"
    env["NEXTEST_PROFILE"] = "local"
    return env


def validate_debug_run(args: list[str], env: dict[str, str]) -> None:
    # The existing native-store guard is deliberately absent in release builds.
    # Do not silently offer a no-Keychain promise for a different build lane.
    for arg in args:
        # nextest accepts short-option clusters such as -vr and -rj4. Do not
        # mistake the 'r' inside an attached package/filter value for a flag.
        release_short_option = (
            arg.startswith("-")
            and not arg.startswith(("--", "-p", "-E", "-j", "-F"))
            and "r" in arg[1:]
        )
        if release_short_option or arg.split("=", 1)[0] in (
            "--release",
            "--cargo-profile",
            "--config",
            "--archive-file",
            "--binaries-metadata",
            "--cargo-metadata",
        ):
            raise ValueError(
                "Custom/reused builds require the isolated native qualification lane"
            )
    for name, value in env.items():
        if "RUSTFLAGS" in name and "debug-assertions" in value:
            raise ValueError(
                "Remove debug-assertions Rust flag overrides for ordinary tests"
            )


# Integration suites locate these binaries with `cargo_bin`, but cargo only
# builds a package's own binaries when testing it. Build them first so a
# package-scoped run does not fail on a missing sibling executable.
_SUITE_HELPERS = [
    "-p",
    "codex-cli",
    "-p",
    "codex-wallet-daemon",
    "-p",
    "codex-rmcp-client",
    "-p",
    "codex-code-mode-host",
    "--bins",
]
HELPER_BINARIES = {
    "codex-core": _SUITE_HELPERS,
    "codex-app-server": _SUITE_HELPERS,
    "codex-tui": _SUITE_HELPERS,
}


def helper_build_args(args: list[str]) -> list[str]:
    packages = [
        value for flag, value in zip(args, args[1:]) if flag in ("-p", "--package")
    ] + [arg.split("=", 1)[1] for arg in args if arg.startswith("--package=")]
    build: list[str] = []
    if any(package in HELPER_BINARIES for package in packages):
        build = list(_SUITE_HELPERS)
    if build and ("--offline" in args or "--frozen" in args):
        build.append("--offline")
    return build


# The Linux sandbox mounts empty read-only directories over missing `.git`,
# `.codex` and `.agents` below a writable cwd. When a test kills the sandbox
# helper before it cleans up, those empty mount targets are left in the crate
# directory (the tests' cwd), where they make later runs see a bogus repository
# or project config. Fixtures that use the system temp directory as their cwd
# leak there too. Remove only empty ones, before and after each run.
SANDBOX_MOUNT_TARGETS = (".git", ".codex", ".agents")


def remove_leaked_mount_targets(workspace: Path) -> None:
    # Some fixtures use the literal system temp directory as their cwd.
    system_temp = Path(tempfile.gettempdir())
    for package in [system_temp, workspace, *workspace.iterdir()]:
        if not package.is_dir():
            continue
        for name in SANDBOX_MOUNT_TARGETS:
            target = package / name
            if (
                target.is_dir()
                and not target.is_symlink()
                and not any(target.iterdir())
            ):
                try:
                    target.rmdir()
                except OSError:
                    pass


def main(args: list[str]) -> int:
    try:
        validate_debug_run(args, dict(os.environ))
    except ValueError as error:
        print(f"Test isolation: {error}", file=sys.stderr)
        return 2
    cargo = shutil.which("cargo")
    if cargo is None:
        print("Test isolation: cargo is not on PATH", file=sys.stderr)
        return 2
    workspace = Path(__file__).resolve().parents[1] / "codex-rs"
    remove_leaked_mount_targets(workspace)
    # Unix socket fixtures append their own temporary directory and socket name.
    # Inheriting a long TMPDIR (notably on macOS) can exceed sockaddr_un's small
    # path limit. Keep the private per-run root under the short Unix temp path;
    # Windows retains its normal platform-specific temporary-directory choice.
    temp_parent = "/tmp" if os.name == "posix" else None
    with tempfile.TemporaryDirectory(prefix="corbanu-tests-", dir=temp_parent) as root:
        home = Path(root) / "profile"
        home.mkdir(mode=0o700)
        env = test_environment(dict(os.environ), home)
        # Keep temp files, and anything a killed sandbox leaves in them, inside
        # this run's directory instead of the shared system temp directory.
        scratch = Path(root) / "tmp"
        scratch.mkdir(mode=0o700)
        env["TMPDIR"] = str(scratch)
        print(
            "Test isolation: disposable profile; native keyring disabled (debug lane)",
            flush=True,
        )
        helpers = helper_build_args(args)
        if helpers:
            built = subprocess.run(
                [cargo, "build", *helpers],
                cwd=workspace,
                env=env,
                check=False,
            )
            if built.returncode != 0:
                print(
                    "Test isolation: helper binaries failed to build", file=sys.stderr
                )
                return built.returncode
        try:
            return subprocess.run(
                [cargo, "nextest", "run", "--no-fail-fast", *args],
                cwd=workspace,
                env=env,
                check=False,
            ).returncode
        finally:
            remove_leaked_mount_targets(workspace)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
