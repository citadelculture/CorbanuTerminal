#!/usr/bin/env python3
"""Allow only this method's ordinary module-lock commands, in batch mode."""
import os
from pathlib import Path
import sys


def command(arguments, root):
    arguments = list(arguments)
    startup = []
    while arguments and arguments[0].startswith("--"):
        startup.append(arguments.pop(0))
    allowed_startup = {
        "--output_user_root=" + str(root / "bazel-state"),
        "--noexperimental_remote_repo_contents_cache",
    }
    if not set(startup) <= allowed_startup or len(startup) != len(set(startup)):
        raise RuntimeError("unexpected_bazel_startup_option")
    if arguments[:2] != ["mod", "deps"]:
        raise RuntimeError("only_module_dependency_commands_allowed")
    mode = [x for x in arguments[2:] if x.startswith("--lockfile_mode=")]
    if len(mode) != 1 or mode[0] not in ("--lockfile_mode=update", "--lockfile_mode=error"):
        raise RuntimeError("unexpected_lockfile_mode")
    caches = [
        "--repository_cache=" + str(root / "cache/repos"),
        "--repo_contents_cache=" + str(root / "cache/contents"),
        "--disk_cache=" + str(root / "cache/disk"),
    ]
    if not set(arguments[2:]) <= set(mode + caches):
        raise RuntimeError("unexpected_bazel_command_option")
    return [
        str(root / "tools/bin/bazel-real"), "--batch", "--nosystem_rc", "--nohome_rc",
        "--output_user_root=" + str(root / "bazel-state"),
        "--noexperimental_remote_repo_contents_cache", "mod", "deps", mode[0], *caches,
    ]


if __name__ == "__main__":
    argv = command(sys.argv[1:], Path(os.environ["PR1116_RUN_ROOT"]))
    os.execv(argv[0], argv)
