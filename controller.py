#!/usr/bin/env python3
"""Explicitly admitted parent metadata diagnostic; no provisioning continuation."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

REPO = "citadelculture/CorbanuTerminal"
BRANCH = "codex/issue943-parent-identity-v1-20261020"
LABELS = ("/", "/usr", "/usr/share", "/usr/share/keyrings")
FILES = ("controller.py", "supervisor.py", "observe_parents.py",
         ".github/workflows/issue943-parent-identity.yml")
ROW_KEYS = {"record", "pathLabel", "uid", "gid", "mode", "fileType", "device", "inode"}
SUMMARY_KEYS = {
    "record", "status", "failureCode", "parentRows", "qualified",
    "targetCreationReached", "provisioningReached", "downloadReached",
    "buildReached", "productTestsExecuted",
}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate_json_key")
        value[key] = item
    return value


def validate_package(control, admission):
    require(set(admission) == {"schema", "approved", "diagnosticOnly", "qualified",
                              "provisioningApproved", "files"}, "admission_shape")
    require(admission["schema"] == "issue943-parent-metadata-admission-v1"
            and admission["approved"] is True and admission["diagnosticOnly"] is True
            and admission["qualified"] is False and admission["provisioningApproved"] is False,
            "admission_scope")
    require(set(admission["files"]) == set(FILES), "admission_files")
    for name in FILES:
        path = control / name
        require(path.is_file() and not path.is_symlink()
                and sha(path) == admission["files"][name], "admission_file_hash")
    require(Path(__file__).resolve() == control / "controller.py", "controller_location")


def identity_passes(row):
    return (stat.S_ISDIR(row["mode"]) and row["uid"] == 0 and row["gid"] == 0
            and not row["mode"] & 0o022)


def classify(data, exit_code):
    require(type(data) is bytes and len(data) <= 4096 and data.endswith(b"\n"), "capture_bound")
    lines = data.splitlines()
    require(1 <= len(lines) <= 5, "record_count")
    records = [json.loads(line, object_pairs_hook=unique_object) for line in lines]
    rows, summary = records[:-1], records[-1]
    require(set(summary) == SUMMARY_KEYS and summary["record"] == "summary", "summary_shape")
    for index, row in enumerate(rows):
        require(set(row) == ROW_KEYS and row["record"] == "parent"
                and row["pathLabel"] == LABELS[index], "parent_shape")
        require(all(type(row[key]) is int and row[key] >= 0
                    for key in ("uid", "gid", "mode", "fileType", "device", "inode")),
                "parent_integer_fields")
        require(row["fileType"] == stat.S_IFMT(row["mode"]), "parent_type")
    require(type(summary["parentRows"]) is int and summary["parentRows"] == len(rows)
            and summary["qualified"] is False
            and all(summary[key] is False for key in
                    ("targetCreationReached", "provisioningReached", "downloadReached", "buildReached"))
            and type(summary["productTestsExecuted"]) is int and summary["productTestsExecuted"] == 0,
            "no_continuation_proof")
    all_pass = (len(rows) == 4 and all(identity_passes(row) for row in rows))
    if (exit_code == 0 and all_pass
            and summary["status"] == "PARENT_IDENTITIES_CAPTURED_NOT_PROVISIONED"
            and summary["failureCode"] is None):
        return {"status": summary["status"], "diagnosticsComplete": True,
                "parentTrustPassed": True, "qualified": False, "rows": rows}
    require(exit_code == 1 and rows and all(identity_passes(row) for row in rows[:-1])
            and not identity_passes(rows[-1])
            and summary["status"] == "HOLD_PARENT_OBSERVATION"
            and summary["failureCode"] == "keyring_parent_identity", "incomplete_observation")
    return {"status": "PARENT_TRUST_HOLD_OBSERVED", "diagnosticsComplete": True,
            "parentTrustPassed": False, "qualified": False, "rows": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dispatch", action="store_true", required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() == "x86_64"
            and os.getuid() != 0 and os.geteuid() != 0 and sys.version_info >= (3, 12)
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == REPO
            and os.environ.get("GITHUB_REF") == "refs/heads/" + BRANCH
            and os.environ.get("GITHUB_EVENT_NAME") == "push"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "fixed_hosted_route")
    identity, head = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_SHA", "")
    require(identity.isdecimal() and re.fullmatch(r"[0-9a-f]{40}", head), "run_identity")
    control = args.control.resolve(strict=True)
    admission = json.loads((control / "admission.json").read_bytes(),
                           object_pairs_hook=unique_object)
    validate_package(control, admission)
    spec = importlib.util.spec_from_file_location("parent_metadata_supervisor", control / "supervisor.py")
    supervisor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(supervisor)
    root = Path("/tmp") / ("issue943-parent-identity-" + identity)
    root.mkdir(mode=0o700)
    for name in ("raw", "private-capture", "tmp", "empty-config"):
        (root / name).mkdir(mode=0o700)
    (root / "empty-netrc").write_text("")
    args.output.mkdir(mode=0o700)
    env = supervisor.environment(root)
    homes = {key: (key in os.environ, os.environ.get(key)) for key in ("HOME", "CODEX_HOME")}
    markers = {key: (key in os.environ, os.environ.get(key)) for key in supervisor.MARKERS}
    campaign = supervisor.Campaign(root, control, env, root / "private-capture", None)
    campaign.deadline = time.monotonic() + 60
    result = {
        "schema": "issue943-parent-metadata-result-v1", "status": "HOLD_DIAGNOSTIC_INCOMPLETE",
        "runId": identity, "controlHead": head, "attempt": 1,
        "controllerSha256": sha(__file__), "admissionSha256": sha(control / "admission.json"),
        "packageFiles": admission["files"], "qualified": False, "diagnosticsComplete": False,
        "provisioningReached": False, "downloadReached": False, "buildReached": False,
        "productTestsExecuted": 0,
    }
    code = 1
    try:
        supervisor.known_skip_guard(env)
        require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0,
                "owned_child_subreaper_unavailable")
        # Same reviewed sudo/root-Python execution route. No install helper or
        # public-key material is included in this diagnostic package.
        raw, row = campaign.run(
            "parent-metadata",
            ["/usr/bin/sudo", "-n", "--", "/usr/bin/python3", "-I", "-B",
             str(control / "observe_parents.py"), "--dispatch"],
            seconds=15, allow_failure=True,
        )
        require((raw / "stderr").read_bytes() == b"", "unexpected_helper_stderr")
        observation = classify((raw / "stdout").read_bytes(), row["exitCode"])
        result.update(observation)
        code = 0 if observation["parentTrustPassed"] else 1
    except BaseException as exc:
        # Fixed public code/type only; no arbitrary exception text or paths.
        result["failureType"] = type(exc).__name__
    finally:
        result["inheritedHomesPreserved"] = homes == {
            key: (key in env, env.get(key)) for key in ("HOME", "CODEX_HOME")}
        result["inheritedMarkersPreserved"] = markers == {
            key: (key in env, env.get(key)) for key in supervisor.MARKERS}
        result["ownedDescendantsGone"] = not supervisor.children()
        if campaign.rows:
            row = campaign.rows[-1]
            result["command"] = {key: row[key] for key in
                                 ("exitCode", "seconds", "captureComplete", "stopReason", "cleanup")}
            result["capture"] = row["capture"]
            result["streams"] = {}
            for name in ("stdout", "stderr"):
                raw_path = root / "raw/parent-metadata" / name
                data = raw_path.read_bytes()
                result["streams"][name] = {"rawSha256": sha(raw_path), "bytes": len(data)}
                # Only a fully validated metadata stream can be made public.
                if name == "stdout" and result["diagnosticsComplete"]:
                    (args.output / "parent-identities.jsonl").write_bytes(data)
                    result["streams"][name]["publicSha256"] = hashlib.sha256(data).hexdigest()
                elif data:
                    result["streams"][name]["publicBytesWithheld"] = len(data)
        if not (result["inheritedHomesPreserved"] and result["inheritedMarkersPreserved"]
                and result["ownedDescendantsGone"]):
            result["status"], result["diagnosticsComplete"], code = "HOLD_DIAGNOSTIC_INCOMPLETE", False, 1
        supervisor.save(args.output / "diagnostic-result.json", result)
        print(result["status"])
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BaseException as exc:
        if isinstance(exc, SystemExit):
            raise
        print("PARENT_DIAGNOSTIC_NOT_STARTED:" + type(exc).__name__)
        sys.exit(1)
