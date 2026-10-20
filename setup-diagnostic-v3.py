#!/usr/bin/env python3
"""Issue943 fixed hosted setup metadata only. Never launches a child or product."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import time

REPOSITORY = "citadelculture/CorbanuTerminal"
BRANCH = "refs/heads/codex/issue943-setup-diagnostic-v3-20261020"
BASE = "bfa6f7da57b55803be09ccd3613cdcdedd1c7e25"
INPUTS_SHA = "0380ce0be725869c76e6ce0cc6a9c3bc6cf949de98427934213c6309a6301d88"
PRESERVED = ("HOME", "CODEX_HOME", "CODEX_SANDBOX",
             "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_SANDBOX_USER_NAMESPACES_DENIED")
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
SYSTEM = ("/usr/bin/bwrap", "/bin/bwrap", "/usr/bin/unshare",
          "/usr/bin/pkg-config", "/usr/bin/git", "/usr/bin/python3")


class Hold(RuntimeError):
    """Messages are fixed public reason codes, never OS exception strings."""


class SourceBudgetHold(Hold):
    """Stops all subsequent source-content reads, not independent metadata."""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum=MAX_FILE, *, budget=None):
    """O_NOFOLLOW avoids opening a substituted final symlink; bound allocation."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    # Unbuffered reads avoid an internal prefetch beyond the reserved byte count.
    with os.fdopen(fd, "rb", buffering=0) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise Hold("not_regular_file")
        if info.st_size > maximum:
            raise Hold("file_size_bound")
        if budget is not None:
            if budget[0] >= MAX_TOTAL or info.st_size > MAX_TOTAL - budget[0]:
                raise SourceBudgetHold("total_read_bound")
            # Reserve before reading. Partial/failed reads are never refunded.
            budget[0] += info.st_size
        # Never use a +1 sentinel read: it could exceed the aggregate allowance.
        data = stream.read(info.st_size)
        after = os.fstat(stream.fileno())
        if (len(data) != info.st_size or after.st_size != info.st_size
                or after.st_mtime_ns != info.st_mtime_ns):
            raise Hold("file_changed_during_read")
        return data


def error_fields(exc, aliases):
    """Never serialize str(exc), private filenames, traceback, or environment."""
    result = {"exceptionType": type(exc).__name__}
    if isinstance(exc, OSError):
        result["errno"] = exc.errno
        if exc.filename is not None:
            result["errorPath"] = aliases.get(os.fsdecode(exc.filename), "<UNRECOGNIZED_PATH>")
    if isinstance(exc, Hold):
        result["reason"] = exc.args[0]
    return result


def regular_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise Hold("not_real_directory")
    return {"present": True, "realDirectory": True}


def source_file(source, relative, expected, budget):
    # Inputs are hash-pinned, but keep explicit traversal/non-regular safeguards.
    p = Path(relative)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise Hold("source_input_not_relative")
    regular_directory(source)
    for count in range(1, len(p.parts)):
        regular_directory(source.joinpath(*p.parts[:count]))
    data = read_regular(source / p, budget=budget)
    observed = sha(data)
    return {"present": True, "bytes": len(data), "sha256": observed,
            "expectedSha256": expected, "matches": observed == expected}


def system_file(path):
    """Identity metadata/hash only. No version, namespace or binary execution."""
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or not info.st_mode & stat.S_IXUSR):
        raise Hold("system_executable_identity")
    result = {"present": True, "rootOwned": True, "executable": True,
              "resolvedPath": str(resolved) if str(resolved) in SYSTEM else "<SYSTEM_RESOLVED_TARGET>",
              "bytes": info.st_size}
    if str(path) in ("/usr/bin/bwrap", "/bin/bwrap"):
        if resolved not in (Path("/usr/bin/bwrap"), Path("/bin/bwrap")):
            raise Hold("original_bwrap_resolved_path_gate")
        data = read_regular(resolved)
        if data[:4] != b"\x7fELF":
            raise Hold("system_bwrap_not_elf")
        result["sha256"] = sha(data)
    return result


def inspect(source, inputs, *, clock=time.monotonic, system_probe=system_file):
    """Aggregate safe independent metadata; identify the original failure window."""
    rows, budget, end = [], [0], clock() + 30
    source_reads_held = False

    def record(role, label, fn, aliases=None, required=True, original_window=False,
               source_content=False):
        nonlocal source_reads_held
        if clock() >= end:
            rows.append({"role": role, "path": label, "required": required,
                         "passed": False, "reason": "metadata_deadline"})
            raise Hold("metadata_deadline")
        row = {"role": role, "path": label, "required": required,
               "originalFailureWindow": original_window}
        if source_content and (source_reads_held or budget[0] >= MAX_TOTAL):
            source_reads_held = True
            row.update(passed=False, reason="source_reads_held_after_aggregate_limit")
            rows.append(row)
            return
        try:
            row.update(fn())
            row["passed"] = row.get("matches", True)
        except (OSError, Hold, RuntimeError) as exc:
            row.update(error_fields(exc, aliases or {}))
            row["passed"] = False
            if isinstance(exc, SourceBudgetHold):
                source_reads_held = True
        rows.append(row)

    aliases = {str(source): "<SOURCE>", str(source / "codex-rs"): "<SOURCE>/codex-rs",
               str(source / ".git"): "<SOURCE>/.git"}
    try:
        for relative in ("", ".git", "codex-rs"):
            path = source / relative
            record("working-directory", aliases[str(path)], lambda p=path: regular_directory(p), aliases)
        for relative, expected in inputs["sourceInputs"].items():
            label = "<SOURCE>/" + relative
            safe_paths = {str(source / p): "<SOURCE>/" + str(p)
                          for p in (Path(relative), *Path(relative).parents) if str(p) != "."}
            safe_paths[str(source)] = "<SOURCE>"
            record("original-source-input", label,
                   lambda r=relative, h=expected: source_file(source, r, h, budget),
                   safe_paths, original_window=True, source_content=True)
        for relative, expected in inputs["originalProductFiles"].items():
            label = "<SOURCE>/" + relative
            record("original-product-file", label,
                   lambda r=relative, h=expected: source_file(source, r, h, budget),
                   {str(source / relative): label}, source_content=True)
        for name in SYSTEM:
            record("system-executable", name, lambda n=name: system_probe(Path(n)),
                   {n: n for n in SYSTEM}, required=name != "/bin/bwrap",
                   original_window=name == "/usr/bin/bwrap")
    except Hold:
        pass  # A recorded deadline stops observation; it never passes.
    failures = [r for r in rows if r["required"] and not r["passed"]]
    return {"observations": rows, "requiredFailures": failures,
            "sourceReadBudgetChargedBytes": budget[0],
            "sourceReadBudgetLimitBytes": MAX_TOTAL,
            "sourceContentReadsHeld": source_reads_held,
            "metadataComplete": not any(
                r.get("reason") == "metadata_deadline" for r in rows),
            "prerequisitesPresent": not failures,
            "historicalMissingPathEstablished": False,
            "attribution": "These are this new host's observations, not a reconstruction of the old exception filename."}


def admission_check(control, env):
    if (platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0
            or sys.version_info < (3, 12) or env.get("RUNNER_OS") != "Linux"
            or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or env.get("GITHUB_REPOSITORY") != REPOSITORY or env.get("GITHUB_REF") != BRANCH
            or env.get("GITHUB_EVENT_NAME") != "push" or env.get("GITHUB_RUN_ATTEMPT") != "1"
            or not env.get("GITHUB_RUN_ID", "").isdecimal()):
        raise Hold("fixed_hosted_route_required")
    data = read_regular(control / "setup-inputs-v2.json")
    if sha(data) != INPUTS_SHA:
        raise Hold("setup_inputs_hash_mismatch")
    inputs = json.loads(data)
    if inputs["baseCommit"] != BASE:
        raise Hold("wrong_base")
    admission = json.loads(read_regular(control / "admission-v3.json"))
    if admission != {
        "schema": "issue943-setup-admission-v3", "approved": True,
        "scope": "metadata-only-no-subprocess",
        "controllerSha256": sha(read_regular(control / "setup-diagnostic-v3.py")),
        "inputsSha256": INPUTS_SHA,
        "workflowSha256": sha(read_regular(control / ".github/workflows/issue943-setup-diagnostic.yml")),
    }:
        raise Hold("admission_not_bound")
    return inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dispatch", action="store_true", required=True)
    parser.parse_args()
    result = {"schema": "issue943-setup-diagnostic-v3", "status": "HOLD_SETUP_INCOMPLETE",
              "qualified": False, "productTestsExecuted": 0, "buildInvocations": 0,
              "subprocessInvocations": 0, "networkCalls": 0, "namespaceProbes": 0,
              "historicalRun": 39423100324, "historicalProductTestsExecuted": 0,
              "nativeIncidentResolved": False, "hostOverrideDenialWaived": False}
    # The only output directory is a fresh direct child of the checkout workspace.
    output = None
    output_created = False
    before = {k: (k in os.environ, os.environ.get(k)) for k in PRESERVED}
    try:
        workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        control = workspace / "control"
        if Path(__file__).resolve().parent != control:
            raise Hold("fixed_control_directory_required")
        output = workspace / "setup-evidence"
        output.mkdir(mode=0o700)
        output_created = True
        inputs = admission_check(control, os.environ)
        result["sourceCommitExpectedByCheckout"] = BASE
        result["sourceIdentityScope"] = "Selected source-file hashes; Git HEAD is not executed or independently read."
        result["inputsSha256"] = INPUTS_SHA
        result["controllerSha256"] = sha(read_regular(Path(__file__)))
        result.update(inspect(workspace / "source", inputs))
        result["inheritedControlWouldRequireProductSkip"] = (
            "CODEX_SANDBOX_NETWORK_DISABLED" in os.environ or os.environ.get("CODEX_SANDBOX") == "seatbelt")
        if result["prerequisitesPresent"] and result["metadataComplete"]:
            result["status"] = "SETUP_METADATA_PRESENT_NOT_CAPABILITY_OR_TEST_QUALIFICATION"
    except BaseException as exc:
        result["failure"] = error_fields(exc, {})
    finally:
        result["inheritedHomesAndControlsUnchanged"] = before == {
            k: (k in os.environ, os.environ.get(k)) for k in PRESERVED}
        if not result["inheritedHomesAndControlsUnchanged"]:
            result["status"] = "HOLD_INHERITED_CONTROL_CHANGED"
        if output_created:
            with (output / "setup-result-v3.json").open("x") as f:
                json.dump(result, f, indent=2, sort_keys=True)
                f.write("\n")
    print(result["status"])
    return 0 if result["status"] == "SETUP_METADATA_PRESENT_NOT_CAPABILITY_OR_TEST_QUALIFICATION" else 1


if __name__ == "__main__":
    sys.exit(main())
