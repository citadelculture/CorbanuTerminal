#!/usr/bin/env python3
"""Inert, bounded disposable-host controller; no product qualification."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BRANCH = "codex/pr1116-statx-bazel-lock-v2-20261021"
WORKFLOW = ".github/workflows/pr1116-statx-bazel-lock-v2.yml"
GIB = 1024**3


def need(condition, code):
    if not condition:
        raise RuntimeError(code)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024**2), b""):
            h.update(chunk)
    return h.hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def admitted(packet, admission, manifest):
    need(admission.get("approved") is True, "method_not_admitted")
    need(re.fullmatch("[a-f0-9]{64}", admission.get("reviewReceiptSha256") or ""), "missing_review_binding")
    need(admission.get("packetManifestSha256") == digest(packet / "packet-manifest.json"), "admitted_manifest_mismatch")
    for row in manifest["files"]:
        name = Path(row["path"])
        need(not name.is_absolute() and ".." not in name.parts, "packet_path_escape")
        path = packet / name
        need(path.is_file() and not path.is_symlink(), "packet_file_type")
        need(path.stat().st_size == row["bytes"] and digest(path) == row["sha256"], "packet_hash_mismatch")


def group_state(pid):
    try:
        os.killpg(pid, 0)
        return "present"
    except ProcessLookupError:
        return "absent"
    except PermissionError:
        return "unknown"


def cleanup(child):
    result = {"directChildReaped": False, "ownedGroupGone": False, "signals": []}
    for sig, grace in [(signal.SIGTERM, 10), (signal.SIGKILL, 5)]:
        state = group_state(child.pid)
        if state == "unknown":
            result["failure"] = "owned_group_state_unknown"
            break
        if state == "absent":
            break
        try:
            os.killpg(child.pid, sig)
            result["signals"].append(sig.name)
        except ProcessLookupError:
            pass
        limit = time.monotonic() + grace
        while group_state(child.pid) == "present" and time.monotonic() < limit:
            child.poll()
            time.sleep(0.2)
    try:
        child.wait(timeout=5)
        result["directChildReaped"] = True
    except subprocess.TimeoutExpired:
        result["failure"] = "direct_child_not_reaped"
    result["ownedGroupGone"] = group_state(child.pid) == "absent"
    return result


def main():
    export = HERE.parent / "pr1116-lock-evidence"
    export.mkdir(exist_ok=False)
    result = {"schema": "pr1116-lock-controller-v1", "completed": False, "productQualified": False, "failureCode": None, "nativeProductTests": 0}
    child = None
    root = None
    try:
        admitted(HERE, json.loads((HERE / "admission.json").read_text()), json.loads((HERE / "packet-manifest.json").read_text()))
        keys = ["GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF", "ImageOS", "ImageVersion"]
        identity = {key: os.environ.get(key) for key in keys}
        need(identity["GITHUB_ACTIONS"] == "true" and identity["GITHUB_REPOSITORY"] == "citadelculture/CorbanuTerminal", "wrong_host_or_repository")
        need(identity["GITHUB_EVENT_NAME"] == "push" and identity["GITHUB_REF"] == "refs/heads/" + BRANCH, "wrong_workflow_route")
        need(identity["GITHUB_RUN_ATTEMPT"] == "1", "retry_requires_fresh_review")
        need(identity["GITHUB_WORKFLOW_REF"] == identity["GITHUB_REPOSITORY"] + "/" + WORKFLOW + "@refs/heads/" + BRANCH, "wrong_workflow_identity")
        need(re.fullmatch("[0-9]+", identity["GITHUB_RUN_ID"] or "") and re.fullmatch("[a-f0-9]{40}", identity["GITHUB_SHA"] or ""), "missing_run_identity")
        need(sys.platform == "linux" and os.uname().machine == "x86_64" and os.geteuid() != 0 and identity["ImageOS"] == "ubuntu24", "wrong_platform")
        result["identity"] = identity
        checkout_head = subprocess.check_output(["git", "-C", str(HERE), "rev-parse", "HEAD"], timeout=10).decode().strip()
        need(checkout_head == identity["GITHUB_SHA"], "method_checkout_head_mismatch")
        result["packetManifestSha256"] = digest(HERE / "packet-manifest.json")
        result["admissionSha256"] = digest(HERE / "admission.json")
        root = Path(os.environ["RUNNER_TEMP"]) / ("pr1116-lock-" + identity["GITHUB_RUN_ID"])
        root.mkdir(mode=0o700, exist_ok=False)
        free = shutil.disk_usage(root).free
        need(free >= 12 * GIB, "disposable_admission_below_12GiB")
        result["resources"] = {"admissionBytes": 12 * GIB, "freeBeforeBytes": free, "continuousFloorBytes": 4 * GIB, "workSeconds": 1800, "maximumLogBytes": 64 * 1024**2, "maximumEvidenceBytes": 128 * 1024**2, "scope": "Disposable host only; owner-host limits unchanged."}
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "HOME": os.environ["HOME"]}
        env.update({key: os.environ[key] for key in ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "GITHUB_ACTIONS") if key in os.environ})
        result["inheritedSandboxGuardsPreserved"] = all(env.get(k) == os.environ.get(k) and (k in env) == (k in os.environ) for k in ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED"))
        with (export / "controller-raw.log").open("wb") as log:
            child = subprocess.Popen([sys.executable, str(HERE / "worker.py"), str(root), str(export)], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            result["ownedProcessGroup"] = child.pid
            deadline = time.monotonic() + 1800
            while child.poll() is None:
                logs = sum(p.lstat().st_size for p in export.glob("*.log") if not p.is_symlink())
                evidence_bytes = sum(p.lstat().st_size for p in export.rglob("*") if not p.is_symlink() and p.is_file())
                if time.monotonic() >= deadline:
                    result["failureCode"] = "global_deadline"
                elif shutil.disk_usage(root).free < 4 * GIB:
                    result["failureCode"] = "continuous_space_floor"
                elif logs > 64 * 1024**2 or evidence_bytes > 128 * 1024**2:
                    result["failureCode"] = "evidence_size_bound"
                if result["failureCode"]:
                    break
                time.sleep(1)
    except BaseException as error:
        result["failureCode"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        if child is not None:
            try:
                result["cleanup"] = cleanup(child)
                result["workerExitCode"] = child.returncode
            except BaseException as error:
                result["cleanup"] = {"failure": type(error).__name__, "ownedGroupGone": False, "directChildReaped": False}
        try:
            worker_result = export / "worker-result.json"
            if worker_result.is_file() and not worker_result.is_symlink():
                result["workerResultSha256"] = digest(worker_result)
                worker_data = json.loads(worker_result.read_text())
                result["completed"] = bool(worker_data.get("completed") and result.get("workerExitCode") == 0 and not result["failureCode"] and result["cleanup"].get("ownedGroupGone") and result["cleanup"].get("directChildReaped"))
                result["workerFailureCode"] = worker_data.get("failureCode")
            elif child is not None:
                result["failureCode"] = result["failureCode"] or "worker_result_missing"
        except BaseException as error:
            result["completed"] = False
            result["failureCode"] = result["failureCode"] or "worker_result_" + type(error).__name__
        # A timed-out worker may not reach its finally block. Retain only the two
        # known generated regular files after the owned group is confirmed gone.
        if child is not None and result.get("cleanup", {}).get("ownedGroupGone"):
            try:
                from worker import snapshot_generated
                result["controllerGeneratedSnapshot"] = snapshot_generated(HERE.parent / "subject", export, "controller-final-generated")
            except BaseException as error:
                result["completed"] = False
                result["snapshotFailure"] = type(error).__name__
        if root is not None:
            result["freeAfterBytes"] = shutil.disk_usage(root).free
        write(export / "controller-result.json", result)
        manifest = []
        for path in sorted(export.rglob("*")):
            if path.is_file() and not path.is_symlink():
                manifest.append({"path": str(path.relative_to(export)), "bytes": path.stat().st_size, "sha256": digest(path)})
        write(export / "evidence-manifest.json", {"files": manifest})
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    sys.exit(main())
