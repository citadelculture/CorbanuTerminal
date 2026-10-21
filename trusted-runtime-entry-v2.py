#!/usr/bin/env python3
"""Inert unless dispatched on the reviewed hosted route. No installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys

CLT = Path("/Library/Developer/CommandLineTools")
EXECUTABLE = CLT / "usr/bin/python3"
CONTROLLER_NAME = "capability-controller-v8.py"
CONTROLLER_SHA = "b3f5eb6a618cd3d9c848e1b91eee2a22f9e8c21889afd58076e6faf8d691860f"
PINS_SHA = "7cb355de3643ef5dea331f577126d88c77e6a81dd722fa27292a329679a35901"
BRANCH = "refs/heads/codex/network-kernel-groups-reentry-v1-20261021"


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(path):
    with Path(path).open("rb") as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
        return value.hexdigest()


def under_clt(path):
    p = Path(path)
    return p.is_absolute() and ".." not in p.parts and (p == CLT or CLT in p.parents)


def validate_runtime(record):
    """Metadata predicate, also exercised by pure negative fixtures."""
    require(record["launcher"] == str(EXECUTABLE), "fixed_clt_launcher_required")
    require(under_clt(record["executable"]), "resolved_python_outside_clt")
    require(tuple(record["version"]) >= (3, 9), "python_3_9_or_newer_required")
    require(record["flags"] == {"isolated": 1, "noSite": 1, "noBytecode": 1},
            "isolated_no_site_bootstrap_required")
    required = set()
    for path in record["runtimePaths"]:
        require(under_clt(path), "runtime_path_outside_clt")
        p = Path(path)
        required.add(str(p))
        required.update(str(x) for x in p.parents)
    require(record["executable"] in record["runtimePaths"], "executable_metadata_missing")
    rows = record["metadata"]
    require(set(rows) == required, "runtime_ancestry_metadata_incomplete")
    for path, row in rows.items():
        require(row["uid"] == 0 and row["mode"] & 0o022 == 0,
                "python_not_root_owned_immutable")
        require(row["kind"] in ("file", "directory"), "runtime_path_kind_invalid")
        if path == record["executable"]:
            require(row["kind"] == "file" and row["mode"] & 0o111,
                    "python_not_executable_file")
    require(len(record["executableSha256"]) == 64
            and all(c in "0123456789abcdef" for c in record["executableSha256"]),
            "python_digest_invalid")
    return True


def collect_runtime():
    executable = Path(sys.executable).resolve(strict=True)
    require(under_clt(executable), "resolved_python_outside_clt")
    paths = {executable, Path(sys.prefix).resolve(strict=True),
             Path(sys.base_prefix).resolve(strict=True)}
    absent = []
    for name in sys.path:
        require(name and under_clt(Path(name)), "runtime_path_outside_clt")
        path = Path(name)
        if path.exists():
            paths.add(path.resolve(strict=True))
        else:
            # A missing standard-library ZIP is a search location, not loaded code.
            absent.append(str(path))
    metadata = {}
    for path in sorted(paths):
        require(under_clt(path), "resolved_runtime_path_outside_clt")
        for item in (path, *path.parents):
            data = item.stat()
            kind = ("file" if stat.S_ISREG(data.st_mode)
                    else "directory" if stat.S_ISDIR(data.st_mode) else "other")
            metadata[str(item)] = {
                "uid": data.st_uid, "mode": stat.S_IMODE(data.st_mode), "kind": kind
            }
    return {
        "launcher": str(EXECUTABLE), "executable": str(executable),
        "executableSha256": digest(executable), "version": list(sys.version_info[:2]),
        "flags": {"isolated": sys.flags.isolated, "noSite": sys.flags.no_site,
                  "noBytecode": int(sys.dont_write_bytecode)},
        "runtimePaths": sorted(map(str, paths)), "absentSearchPaths": sorted(absent),
        "metadata": metadata,
    }


def source_bindings(here, pins_sha):
    require(pins_sha == PINS_SHA, "controller_pins_argument_changed")
    require(digest(here / CONTROLLER_NAME) == CONTROLLER_SHA, "controller_bytes_changed")
    pinsfile = here / "capability-pins-v8.json"
    require(digest(pinsfile) == PINS_SHA, "controller_pins_changed")
    pins = json.loads(pinsfile.read_text())
    for name, expected in pins["code"].items():
        require(Path(name).name == name and not (here / name).is_symlink(),
                "unsafe_code_entry")
        require(digest(here / name) == expected, "controller_helper_changed")
    return True


def hosted_guard(env):
    require(sys.platform == "darwin" and os.getuid() != 0, "nonroot_macos_required")
    require(env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("RUNNER_OS") == "macOS", "hosted_only")
    require(env.get("GITHUB_REPOSITORY") == "citadelculture/CorbanuTerminal"
            and env.get("GITHUB_REF") == BRANCH
            and env.get("GITHUB_EVENT_NAME") == "push"
            and env.get("GITHUB_RUN_ATTEMPT") == "1", "fixed_route_required")
    # Original controller independently enforces macOS15/arm64 and its admission.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dispatch", action="store_true")
    parser.add_argument("--pins-sha256")
    args = parser.parse_args()
    require(args.dispatch, "explicit_dispatch_required")
    hosted_guard(os.environ)
    here = Path(__file__).resolve().parent
    source_bindings(here, args.pins_sha256)
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    output = workspace / "trusted-runtime-evidence"
    require(output.is_dir() and not output.is_symlink()
            and output.stat().st_uid == os.getuid(), "owned_launch_evidence_required")
    report = {"schema": "network-trusted-runtime-selection-v1",
              "scope": "runtime prerequisite snapshot before controller invocation",
              "status": "HOLD_TRUSTED_RUNTIME_PREREQUISITE",
              "canaryReady": False, "controllerInvoked": False,
              "productBodiesExecuted": 0, "buildInvocations": 0, "canaryInvocations": 0}
    try:
        report["runtime"] = collect_runtime()
        validate_runtime(report["runtime"])
        report["status"] = "TRUSTED_RUNTIME_SELECTED_NOT_CAPABILITY_OR_CANARY"
    except BaseException as exc:
        report["error"] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
    with (output / "trusted-runtime-result.json").open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    if report["status"] != "TRUSTED_RUNTIME_SELECTED_NOT_CAPABILITY_OR_CANARY":
        return 2
    # Original code and every gate remain intact. No profiles or environment are rebound.
    sys.argv = [str(here / CONTROLLER_NAME), "--dispatch", "--pins-sha256", PINS_SHA,
                "--output", str(workspace / "capability-evidence")]
    runpy.run_path(str(here / CONTROLLER_NAME), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
