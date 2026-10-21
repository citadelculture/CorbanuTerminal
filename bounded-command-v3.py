#!/usr/bin/env python3
"""Fixed hosted macOS build preparation. No canary or test-body execution."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

BASE = "78dd811d6e3718140c938ad4839968d9995fd5ac"
REPO = "citadelculture/CorbanuTerminal"
BRANCH = "refs/heads/codex/network-canary-macos-combined-v4-20261020"
MARKERS = ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")
GIB = 1024 ** 3
CAPTURE_LIMIT = 8 * 1024 ** 2
WHOLE_SECONDS = 7200
BUILD_FLOOR = 30 * GIB
STOP_FLOOR = 5 * GIB
PROBES = (
    ("policy-authority-validation", "codex-security-policy", "--lib", "credential"),
    ("vault-scoped-resolution", "codex-vault", "--lib", "capability"),
    ("vault-panic-redaction", "codex-vault", "--lib", "credential_panic"),
    ("vault-profile-boundary", "codex-vault", "--lib", "home"),
    ("tui-panic-redaction", "codex-tui", "--lib", "production_panic_hook_does_not_log_scoped_credentials"),
    ("broker-boundary", "codex-network-proxy", "--lib", "credential_broker"),
    ("core-capability", "codex-core", "--lib", "credential_capability"),
    ("core-revocation", "codex-core", "--lib", "credential_authority_revoke_during_use_linearizes_after_the_active_resolution"),
    ("cli-vault-helper", "codex-cli", "--test", "vault", "vault_auth_helper"),
)


class Hold(RuntimeError):
    """Fixed public reason code; raw child diagnostics stay in the owned job."""


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_json(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def capture_chunk(state, data, limit=CAPTURE_LIMIT):
    """Pure bounded-prefix accounting; overflow never counts as complete."""
    remaining = max(0, limit - state["retainedBytes"])
    kept = data[:remaining]
    result = dict(state)
    result["observedBytes"] += len(data)
    result["retainedBytes"] += len(kept)
    result["truncated"] = state["truncated"] or len(kept) != len(data)
    return result, kept


def redacted_tail(data, root):
    text = data[-8192:].decode("utf-8", errors="replace").replace(str(root), "<OWNED>")
    text = re.sub(r"/Users/[^\s\"'<>]+", "<USER_PATH>", text)
    text = re.sub(r"(?i)(authorization|token|api[_-]?key|password|secret)(\s*[:=]\s*)\S+",
                  r"\1\2<REDACTED>", text)
    text = re.sub(r"(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,})",
                  "<REDACTED>", text)
    return text


def safe_failure_text(data, root):
    """Full bounded build failure stream, or withhold it on sensitive shapes."""
    text = data.decode("utf-8", errors="strict")
    clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    if re.search(r"(?i)\b(?:sk|ghp|gho|ghu|ghs|ghr|github_pat|xox[abprs])[-_][A-Za-z0-9_-]{8,}"
                 r"|\bBearer\s+[^\s\"']{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----", clean):
        raise Hold("failure_diagnostic_sensitive_shape")
    return re.sub(r"/Users/[^/\s\"']+", "<HOSTED_USER>", text.replace(str(root), "<OWNED>"))


def deadline_reason(started, current, command_seconds, whole_deadline):
    if current >= whole_deadline:
        return "whole_deadline"
    if current - started >= command_seconds:
        return "command_deadline"
    return None


def command_ok(row):
    return (row["exitCode"] == 0 and row["stopReason"] is None
            and row["captureComplete"] is True and row["groupGone"] is True
            and all(not v["truncated"] for v in row["capture"].values()))


def probe_argv(cargo, probe):
    # Exact harness package/target/filter; --no-run forbids test-body execution.
    return [str(cargo), "test", "--locked", "--offline", "--no-run",
            "-p", probe[1], *probe[2:]]


def classify(rows, source_unchanged, markers_preserved, artifacts_verified):
    compiled = [r["label"] for r in rows if r["label"].startswith("compile-") and r["label"] != "compile-profile-parse"]
    expected = ["compile-cli"] + ["compile-" + p[0] for p in PROBES]
    good = (compiled == expected and all(command_ok(r) for r in rows)
            and source_unchanged and markers_preserved and artifacts_verified)
    return "BUILD_PREPARATION_COMPLETE_NOT_CANARY_QUALIFICATION" if good else "BUILD_PREPARATION_INCOMPLETE"


def prebuild_ok(report, run_id, plan_sha):
    return (report.get("schema") == "network-prebuild-fixture-check-v1"
            and report.get("status") == "PREBUILD_FIXTURE_CHECK_PASSED"
            and report.get("runId") == run_id and report.get("combinedPlanSha256") == plan_sha
            and report.get("canaryInvocations") == 0
            and all(report.get(k) is True for k in ("allListenersClosed", "allTemporaryFixturesRemoved",
                                                    "sentinelUnchanged", "markersPreserved"))
            and report.get("basicControls") and all(v is True for v in report["basicControls"].values())
            and report.get("scopedFixtureControls") == {"scopedUnixFamilies": 3}
            and [r.get("label") for r in report.get("commands", [])] == ["basic-boundary", "exact-temporary-fixtures"]
            and all(command_ok(r) for r in report["commands"]))


def group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return None  # unknown, never evidence of group absence


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # No global RLIMIT_FSIZE change: it broke Xcode startup in preflight v1.


def observe():
    for name in ("SecurityAgent", "CoreAuthUI"):
        p = subprocess.run(["/usr/bin/pgrep", "-x", name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=3)
        if p.returncode == 0:
            raise Hold("native_prompt_process_observed")
        if p.returncode != 1:
            raise Hold("native_observer_unavailable")


def command(label, argv, cwd, env, raw, rows, deadline, seconds, root, profile=None, capture_limit=CAPTURE_LIMIT):
    if type(capture_limit) is not int or not 0 < capture_limit <= CAPTURE_LIMIT:
        raise Hold("invalid_capture_limit")
    started = time.monotonic()
    if deadline_reason(started, started, seconds, deadline):
        raise Hold("whole_deadline")
    observe()
    out, err = raw / (label + ".stdout"), raw / (label + ".stderr")
    capture = {n: {"observedBytes": 0, "retainedBytes": 0, "truncated": False}
               for n in ("stdout", "stderr")}
    p, reason, complete = None, None, False
    wrapped = (["/usr/bin/sandbox-exec", "-f", str(profile), *argv]
               if profile else argv)
    # No preexec_fn after listener threads start. A fresh interpreter applies CORE=0 before exec.
    wrapped = [sys.executable, "-I", "-B", str(Path(__file__).with_name("child-bootstrap-v2.py")), "--", *wrapped]
    with out.open("xb") as stdout, err.open("xb") as stderr, selectors.DefaultSelector() as selector:
        files = {"stdout": stdout, "stderr": stderr}
        try:
            p = subprocess.Popen(wrapped, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
            for name, pipe in (("stdout", p.stdout), ("stderr", p.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            checked = 0.0
            while p.poll() is None or selector.get_map():
                current = time.monotonic()
                reason = deadline_reason(started, current, seconds, deadline)
                if reason:
                    raise Hold(reason)
                if current - checked >= 3:
                    observe()
                    if shutil.disk_usage(root).free < STOP_FLOOR:
                        raise Hold("disk_stop_floor")
                    checked = current
                for key, _ in selector.select(timeout=0.2):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    name = key.data
                    capture[name], kept = capture_chunk(capture[name], data, limit=capture_limit)
                    files[name].write(kept)
                    if capture[name]["truncated"]:
                        raise Hold("capture_limit")
            p.wait()
            complete = True
            observe()
        except BaseException as exc:
            reason = str(exc) if isinstance(exc, Hold) else "controller_exception_" + type(exc).__name__
        finally:
            for key in list(selector.get_map().values()):
                selector.unregister(key.fileobj)
                key.fileobj.close()
            if p is not None and group_exists(p.pid) is not False:
                if p.poll() is not None and reason is None:
                    reason = "owned_group_survived_leader"
                for sig, timeout in ((signal.SIGTERM, 3), (signal.SIGKILL, 3)):
                    try:
                        os.killpg(p.pid, sig)
                    except ProcessLookupError:
                        break
                    except PermissionError:
                        reason = "owned_group_cleanup_permission_unknown"
                        break
                    try:
                        p.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        pass
                    if group_exists(p.pid) is False:
                        break
            if p is not None:
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    reason = "leader_not_reaped"
    row = {"label": label, "exitCode": p.returncode if p else None,
           "seconds": round(time.monotonic() - started, 3), "stopReason": reason,
           "groupGone": p is not None and group_exists(p.pid) is False,
           "captureComplete": complete, "capture": capture,
           "stdoutSha256": sha(out), "stderrSha256": sha(err),
           "stdoutBytes": out.stat().st_size, "stderrBytes": err.stat().st_size,
           "sandboxed": profile is not None}
    rows.append(row)
    write_json(raw / (label + ".result.json"), row)
    # This bounded convenience diagnostic also remains outside the upload path.
    with (raw / (label + ".redacted-tail.txt")).open("x") as stream:
        stream.write("stdout:\n" + redacted_tail(out.read_bytes(), root))
        stream.write("\nstderr:\n" + redacted_tail(err.read_bytes(), root))
    if not command_ok(row):
        raise Hold(label + "_failed")
    return out


def select_git():
    shim = Path("/usr/bin/git").resolve(strict=True)
    candidates = (
        ("/opt/homebrew/bin/git", "/opt/homebrew/Cellar/git"),
        ("/Library/Developer/CommandLineTools/usr/bin/git", "/Library/Developer/CommandLineTools/usr/bin"),
        ("/Applications/Xcode_16.4.app/Contents/Developer/usr/bin/git", "/Applications/Xcode_16.4.app/Contents/Developer/usr/bin"),
    )
    macho = {bytes.fromhex(v) for v in ("feedface", "feedfacf", "cefaedfe", "cffaedfe",
                                       "cafebabe", "bebafeca", "cafebabf", "bfbafeca")}
    for name, parent in candidates:
        p = Path(name)
        if not p.exists():
            continue
        p = p.resolve(strict=True)
        if (not p.is_file() or not os.access(p, os.X_OK)
                or Path(parent) not in p.parents or p.samefile(shim) or sha(p) == sha(shim)):
            raise Hold("git_identity_rejected")
        with p.open("rb") as stream:
            if stream.read(4) not in macho:
                raise Hold("git_not_macho")
        return p
    raise Hold("no_preinstalled_real_git")


def address_campaign_ok(campaign):
    cases, clean = campaign.get("cases", []), campaign.get("cleanup") or {}
    return (campaign.get("expectedBoundaryPassed") is True
            and campaign.get("diagnosticsComplete") is True
            and campaign.get("errors") == [] and campaign.get("contextHoldLatched") is False
            and len(cases) == 10 and len({c.get("case") for c in cases}) == 10
            and clean.get("listenersClosed") is True
            and clean.get("serverThreadStopped") is True and clean.get("serverError") is None
            and all(c.get("passed") is True and not c.get("error") and not c.get("afterError")
                    and c.get("commandResult", {}).get("completed") is True
                    and c["commandResult"].get("cleanup", {}).get("groupGone") is True
                    and c["commandResult"]["cleanup"].get("directChildReaped") is True
                    and c["commandResult"]["cleanup"].get("error") is None for c in cases))


def validate_preflight(admission, receipt, pins, driver_sha):
    if (admission.get("buildPreparationApproved") is not True
            or admission.get("canaryExecutionApproved") is not False
            or admission.get("sourceCommit") != BASE
            or admission.get("driverSha256") != driver_sha
            or admission.get("pinsSha256") != sha(pins)
            or not is_digest(admission.get("preflightControllerSha256"))
            or not is_digest(admission.get("preflightResultSha256"))
            or admission["preflightResultSha256"] != sha(receipt)):
        raise Hold("unbound_or_unapproved_admission")
    r = json.loads(Path(receipt).read_text())
    if (r.get("schema") != "network-hosted-macos-preflight-result-v4"
            or r.get("status") != "SYNTHETIC_PREFLIGHT_CONTROLS_PASSED_NOT_CANARY_ADMISSION"
            or r.get("sourceCommit") != BASE
            or r.get("runId") != admission.get("preflightRunId")
            or r.get("controllerSha256") != admission["preflightControllerSha256"]
            or r.get("canaryInvocations") != 0 or r.get("compilationInvocations") != 0
            or r.get("requiredMetadataToolsHealthy") is not True
            or r.get("parentMarkersUnchanged") is not True
            or r.get("syntheticSentinelUnchanged") is not True
            or r.get("allOwnedListenersClosed") is not True
            or not address_campaign_ok(r.get("addressCampaign", {}))
            or not r.get("controls") or not all(v is True for v in r["controls"].values())
            or r.get("failure") or not r.get("commands")
            or not all(command_ok(c) for c in r["commands"])):
        raise Hold("preflight_not_successful")
    return r


def environment(root, git):
    env = {
        "PATH": ":".join((str(root / "toolchain/bin"), str(git.parent),
                          "/usr/bin", "/bin", "/usr/sbin", "/sbin")),
        "HOME": str(root / "home"), "CODEX_HOME": str(root / "profile"),
        "CORBANU_HOME": str(root / "profile"), "PFTERMINAL_HOME": str(root / "profile"),
        "TMPDIR": str(root / "tmp"), "CARGO_HOME": str(root / "cargo-home"),
        "RUSTUP_HOME": str(root / "unused-rustup"), "CARGO_BUILD_JOBS": "2",
        "CARGO_TARGET_DIR": str(root / "source/codex-rs/target"),
        "CARGO_NET_GIT_FETCH_WITH_CLI": "true", "CARGO_NET_RETRY": "0",
        "CARGO_HTTP_TIMEOUT": "60", "CARGO_HTTP_CAINFO": str(root / "public-ca.pem"),
        "SSL_CERT_FILE": str(root / "public-ca.pem"), "CARGO_INCREMENTAL": "0",
        "CARGO_TERM_COLOR": "never", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false",
        "SSH_ASKPASS": "/usr/bin/false", "GIT_SSH_COMMAND": "/usr/bin/false",
        "GIT_SSL_CAINFO": str(root / "public-ca.pem"),
        "NETRC": str(root / "empty-netrc"), "CURL_HOME": str(root / "empty-config"),
        "XDG_CONFIG_HOME": str(root / "empty-config"), "LC_ALL": "en_US.UTF-8",
        "LANG": "en_US.UTF-8",
        "CORBANU_TEST_NO_NATIVE_KEYRING": "1",
    }
    env.update({k: os.environ[k] for k in MARKERS if k in os.environ})
    return env


def profile_text(root, acquisition):
    # Published pinned source uses the same ip/Unix address filter forms.
    # Acquisition is separate public HTTPS/DNS preparation, never measurement.
    network = ('(allow network-outbound (remote ip "*:443") (remote ip "*:53") '
               '(remote unix-socket (path-literal "/private/var/run/mDNSResponder")) '
               '(remote unix-socket (path-literal "/var/run/mDNSResponder")))') if acquisition else ""
    return f'''(version 1)
(allow default)
(deny network*)
{network}
(allow system-socket (socket-domain AF_UNIX))
(allow network-bind (local unix-socket (subpath "{root}")))
(allow network-outbound (remote unix-socket (subpath "{root}")))
(deny file-read* file-write* (subpath "/Users") (subpath "/Library/Keychains")
  (subpath "/private/var/root") (subpath "/var/root"))
(deny mach-lookup (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd.xpc") (global-name "com.apple.securityd.systemkeychain")
  (global-name-regex #".*[Ss]ecurity.*") (global-name-regex #".*secd.*")
  (global-name-regex #".*[Kk]eychain.*"))
(deny process-exec (literal "/usr/bin/sudo") (literal "/bin/su")
  (literal "/usr/bin/osascript") (literal "/usr/bin/security"))
'''


def safe_extract(archive, dest, deadline):
    """Verified official archives only; no traversal, special files or external links."""
    dest.mkdir(mode=0o700)
    with tarfile.open(archive, "r:xz") as tf:
        members = tf.getmembers()
        if len(members) > 50000 or sum(m.size for m in members) > 2 * GIB:
            raise Hold("archive_expansion_bound")
        top = set()
        for m in members:
            p = PurePosixPath(m.name)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise Hold("archive_path_rejected")
            top.add(p.parts[0])
            if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
                raise Hold("archive_special_file")
            if m.issym() or m.islnk():
                link = PurePosixPath(m.linkname)
                target = ((dest / m.name).parent / m.linkname if m.issym() else dest / m.linkname)
                if link.is_absolute() or dest not in target.resolve().parents:
                    raise Hold("archive_link_escape")
        if len(top) != 1:
            raise Hold("archive_top_level")
        for m in members:
            if time.monotonic() >= deadline:
                raise Hold("whole_deadline")
            target = dest / m.name
            if dest not in target.resolve().parents:
                raise Hold("archive_resolved_escape")
            # Ignore archive owner/privilege bits; verified data stays task-owned.
            m.mode &= 0o777
            tf.extract(m, dest, set_attrs=False)
            if not m.issym():
                os.chmod(target, m.mode)
    return dest / next(iter(top))


def copy_public_checkout(source, destination):
    total, count = 0, 0
    for base, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            p = Path(base) / name
            if p.is_symlink() and source not in p.resolve(strict=True).parents:
                raise Hold("source_symlink_escape")
            if not (p.is_dir() or p.is_file() or p.is_symlink()):
                raise Hold("source_special_file")
            if p.is_file():
                total += p.stat().st_size
                count += 1
                if total > 3 * GIB or count > 150000:
                    raise Hold("source_copy_bound")
    shutil.copytree(source, destination, symlinks=True)
    return {"bytes": total, "files": count}


def source_snapshot(source, names):
    h = hashlib.sha256()
    for name in names:
        p = source / name
        if source not in p.resolve(strict=True).parents:
            raise Hold("tracked_source_escape")
        blob = os.readlink(p).encode() if p.is_symlink() else p.read_bytes()
        h.update(name.encode() + b"\0" + hashlib.sha256(blob).digest())
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dispatch", action="store_true", required=True)
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--pins", type=Path, required=True)
    ap.add_argument("--admission", type=Path, required=True)
    ap.add_argument("--preflight-result", type=Path, required=True)
    ap.add_argument("--prebuild-result", type=Path, required=True)
    ap.add_argument("--combined-plan", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if (os.environ.get("GITHUB_REPOSITORY") != REPO
            or os.environ.get("GITHUB_REF") != BRANCH
            or os.environ.get("GITHUB_EVENT_NAME") != "push"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "macOS"
            or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
            or platform.system() != "Darwin" or platform.machine() != "arm64"):
        raise Hold("fixed_hosted_context_required")
    ids = [os.environ.get(k, "") for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    if not all(re.fullmatch(r"[0-9]+", v) for v in ids):
        raise Hold("invalid_run_identity")
    pins = json.loads(args.pins.read_text())
    if pins.get("sourceCommit") != BASE or pins.get("schema") != "network-build-pins-v1":
        raise Hold("pins_identity")
    admission = json.loads(args.admission.read_text())
    if (admission.get("combinedPlanApproved") is not True
            or not is_digest(admission.get("combinedPlanSha256"))
            or admission["combinedPlanSha256"] != sha(args.combined_plan)):
        raise Hold("same_job_combined_plan_not_bound")
    preflight = validate_preflight(admission, args.preflight_result,
                                  args.pins, sha(__file__))
    if not prebuild_ok(json.loads(args.prebuild_result.read_text()), ids[0], sha(args.combined_plan)):
        raise Hold("fresh_same_job_fixture_check_incomplete")
    if os.environ.get("CORBANU_TEST_NO_NATIVE_KEYRING", "1") != "1":
        raise Hold("conflicting_native_keyring_control")
    root = Path("/private/tmp") / ("network-build-" + "-".join(ids))
    root.mkdir(mode=0o700)  # exclusive: no resume/retry into an earlier job state
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    raw = root / "private-diagnostics"
    raw.mkdir(mode=0o700)
    for name in ("home", "profile", "tmp", "cargo-home", "unused-rustup", "empty-config",
                 "downloads", "unpacked", "toolchain"):
        (root / name).mkdir(mode=0o700)
    (root / "empty-netrc").write_text("")
    os.chmod(root / "empty-netrc", 0o600)
    markers = {k: (k in os.environ, os.environ.get(k)) for k in MARKERS}
    rows, deadline = [], time.monotonic() + WHOLE_SECONDS
    report = {"schema": "network-hosted-build-preparation-v1", "startedAt": now(),
              "status": "BUILD_PREPARATION_INCOMPLETE", "canaryReady": False,
              "canaryInvocations": 0, "testBodyInvocations": 0, "commands": rows,
              "sourceCommit": BASE, "runId": ids[0], "runAttempt": ids[1],
              "controllerSha256": sha(__file__), "pinsSha256": sha(args.pins),
              "combinedPlanSha256": sha(args.combined_plan),
              "preflightResultSha256": sha(args.preflight_result),
              "prebuildResultSha256": sha(args.prebuild_result),
              "preflightRunId": preflight["runId"], "runnerImage": os.environ.get("ImageOS"),
              "runnerImageVersion": os.environ.get("ImageVersion"),
              "rawStreamsUploaded": False, "rawStreamsRetainedInEphemeralJob": True,
              "nativeObserverIsProcessAbsenceNotUIProof": True,
              "limits": {"wholeSeconds": WHOLE_SECONDS, "capturedBytesPerStream": CAPTURE_LIMIT,
                         "initialFreeBytes": BUILD_FLOOR, "stopFreeBytes": STOP_FLOOR,
                         "cargoBuildJobs": 2, "inheritedFileSizeLimitUnchanged": True},
              "unqualified": ["No canary, test body, candidate --version or credential operation.",
                              "A fresh job needs its own actual containment checks before measurement.",
                              "Direct process-group cleanup does not independently enumerate detached sessions.",
                              "Public acquisition permits HTTPS/DNS; it is not a sealed measurement.",
                              "Build/test artifacts remain ephemeral on this job; no cross-job cache claim.",
                              "An unmet setup/resource requirement is a hold, never a skipped success."]}
    code, source_before, names = 1, None, []
    try:
        if shutil.disk_usage(root).free < BUILD_FLOOR:
            raise Hold("build_admission_capacity")
        source = args.source.resolve(strict=True)
        if not (source / ".git").is_dir() or (source / ".git").is_symlink():
            raise Hold("real_git_checkout_required")
        git = select_git()
        env = environment(root, git)
        cmd = lambda label, argv, cwd=root, seconds=30, profile=None: command(
            label, argv, cwd, env, raw, rows, deadline, seconds, root, profile)
        for relative, digest in pins["sourceFiles"].items():
            if sha(source / relative) != digest:
                raise Hold("pinned_source_hash_mismatch")
        if cmd("original-head", [str(git), "-C", str(source), "rev-parse", "HEAD"]).read_text().strip() != BASE:
            raise Hold("source_commit_mismatch")
        if cmd("original-status", [str(git), "-C", str(source), "status", "--porcelain"]).read_text().strip():
            raise Hold("source_dirty")
        config = cmd("original-config", [str(git), "-C", str(source), "config", "--local", "--list"]).read_text()
        if re.search(r"(extraheader|credential|insteadof|sshcommand|include\.|https?://[^/\s]+@)", config, re.I):
            raise Hold("source_git_auth_config")
        report["sourceCopy"] = copy_public_checkout(source, root / "source")
        staged = root / "source"
        files = cmd("tracked-files", [str(git), "-C", str(staged), "ls-files", "-z"]).read_bytes()
        names = [s.decode("utf-8") for s in files.split(b"\0") if s]
        if not names or len(names) > 100000:
            raise Hold("tracked_manifest_bound")
        source_before = source_snapshot(staged, names)
        report["trackedSourceManifestSha256"] = source_before
        report["trackedSourceFileCount"] = len(names)
        report["gitSha256"] = sha(git)
        report["pythonSha256"] = sha(Path(sys.executable).resolve())
        report["sandboxExecSha256"] = sha("/usr/bin/sandbox-exec")
        profiles = {}
        for phase, acquire in (("acquisition", True), ("compile", False)):
            p = root / (phase + ".sb")
            p.write_text(profile_text(root, acquire))
            profiles[phase] = p
        report["profileHashes"] = {n: sha(p) for n, p in profiles.items()}
        # Actual profile parse is exercised by a harmless required command.
        cmd("compile-profile-parse", ["/usr/bin/true"], profile=profiles["compile"])
        cmd("acquisition-profile-parse", ["/usr/bin/true"], profile=profiles["acquisition"])
        os_version = cmd("os", ["/usr/bin/sw_vers", "-productVersion"]).read_text().strip()
        if not os_version.startswith("15."):
            raise Hold("macos15_required")
        memory = int(cmd("memory", ["/usr/sbin/sysctl", "-n", "hw.memsize"]).read_text())
        if memory < 6 * GIB:
            raise Hold("memory_admission")
        report["osVersion"], report["memoryBytes"] = os_version, memory
        sdk = cmd("sdk", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
                  profile=profiles["compile"]).read_text().strip()
        if not sdk.startswith(("/Applications/", "/Library/Developer/")) or not Path(sdk).is_dir():
            raise Hold("sdk_identity")
        env["SDKROOT"] = sdk
        for tool in ("clang", "clang++", "ar"):
            p = cmd("resolve-" + tool.replace("+", "p"), ["/usr/bin/xcrun", "--find", tool],
                    profile=profiles["compile"]).read_text().strip()
            real = Path(p).resolve(strict=True)
            if not str(real).startswith(("/Applications/", "/Library/Developer/")) or not real.is_file():
                raise Hold("native_tool_identity")
            if tool == "clang":
                env["CC"], env["CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"] = str(real), str(real)
            elif tool == "clang++":
                env["CXX"] = str(real)
            else:
                env["AR"] = str(real)
            report.setdefault("nativeToolHashes", {})[tool] = sha(real)
        cmd("clang-version", [env["CC"], "--version"], profile=profiles["compile"])
        # Official public CA file only; no login/default keychain reads.
        if not Path("/etc/ssl/cert.pem").is_file():
            raise Hold("public_ca_bundle_missing")
        shutil.copyfile("/etc/ssl/cert.pem", root / "public-ca.pem")
        report["publicCABundleSha256"] = sha(root / "public-ca.pem")
        for item in pins["rustArchives"]:
            archive = root / "downloads" / item["filename"]
            cmd("fetch-" + item["component"], [
                "/usr/bin/curl", "-q", "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https", "--retry", "0",
                "--connect-timeout", "20", "--max-time", "300",
                "--max-filesize", str(item["bytes"]), "--cacert", str(root / "public-ca.pem"),
                "--output", str(archive), item["sourceUrl"]], seconds=310, profile=profiles["acquisition"])
            if archive.stat().st_size != item["bytes"] or sha(archive) != item["sha256"]:
                raise Hold("rust_archive_digest_mismatch")
            unpacked = safe_extract(archive, root / "unpacked" / item["component"], deadline)
            installer = unpacked / "install.sh"
            if not installer.is_file() or installer.is_symlink():
                raise Hold("rust_installer_missing")
            cmd("install-" + item["component"],
                ["/bin/sh", str(installer), "--prefix=" + str(root / "toolchain"), "--disable-ldconfig"],
                cwd=unpacked, seconds=180, profile=profiles["compile"])
        cargo = root / "toolchain/bin/cargo"
        rustc = root / "toolchain/bin/rustc"
        for tool in (cargo, rustc):
            text = cmd(tool.name + "-version", [str(tool), "--version"], profile=profiles["compile"]).read_text().strip()
            if not text.startswith(tool.name + " 1.95.0 "):
                raise Hold("rust_version_mismatch")
            report.setdefault("rustTools", {})[tool.name] = {"sha256": sha(tool), "version": text}
        env["RUSTC"], env["RUSTDOC"] = str(rustc), str(root / "toolchain/bin/rustdoc")
        cwd = staged / "codex-rs"
        # Only public locked acquisition. Build scripts are not run by cargo fetch.
        cmd("fetch-locked", [str(cargo), "fetch", "--locked", "--target", "aarch64-apple-darwin"],
            cwd=cwd, seconds=900, profile=profiles["acquisition"])
        report["freeBytesBeforeFirstCompile"] = shutil.disk_usage(root).free
        if report["freeBytesBeforeFirstCompile"] < BUILD_FLOOR:
            raise Hold("first_compile_capacity")
        env["CARGO_NET_OFFLINE"] = "true"
        cli_args = [str(cargo), "build", "--locked", "--offline", "-p", "codex-cli",
                    "--bin", "corbanu", "--target-dir", str(cwd / "target")]
        cmd("compile-cli", cli_args, cwd=cwd, seconds=3600, profile=profiles["compile"])
        for probe in PROBES:
            cmd("compile-" + probe[0], probe_argv(cargo, probe), cwd=cwd, seconds=1200, profile=profiles["compile"])
        candidate = cwd / "target/debug/corbanu"
        if not candidate.is_file() or candidate.is_symlink():
            raise Hold("candidate_artifact_missing")
        artifacts = [{"relativePath": "codex-rs/target/debug/corbanu", "bytes": candidate.stat().st_size,
                      "sha256": sha(candidate)}]
        for p in sorted((cwd / "target/debug/deps").iterdir()):
            if p.is_file() and not p.is_symlink() and p.stat().st_mode & stat.S_IXUSR:
                artifacts.append({"relativePath": str(p.relative_to(staged)),
                                  "bytes": p.stat().st_size, "sha256": sha(p)})
        write_json(raw / "compiled-artifacts.json", artifacts)
        report["compiledArtifactCount"] = len(artifacts)
        report["compiledArtifactManifestSha256"] = sha(raw / "compiled-artifacts.json")
        report["candidateSha256"] = sha(candidate)
        if cmd("final-head", [str(git), "-C", str(staged), "rev-parse", "HEAD"],
               profile=profiles["compile"]).read_text().strip() != BASE:
            raise Hold("final_source_commit_mismatch")
        if cmd("final-status", [str(git), "-C", str(staged), "status", "--porcelain"],
               profile=profiles["compile"]).read_text().strip():
            raise Hold("final_source_dirty")
        report["sourceUnchanged"] = source_snapshot(staged, names) == source_before
        report["inheritedMarkersPreserved"] = markers == {
            k: (k in os.environ, os.environ.get(k)) for k in MARKERS}
        report["status"] = classify(rows, report["sourceUnchanged"],
                                    report["inheritedMarkersPreserved"], len(artifacts) > 1)
        if report["status"] != "BUILD_PREPARATION_COMPLETE_NOT_CANARY_QUALIFICATION":
            raise Hold("final_classification_incomplete")
        code = 0
    except BaseException as exc:
        report["failureCode"] = str(exc) if isinstance(exc, Hold) else "controller_exception_" + type(exc).__name__
    finally:
        report["finishedAt"] = now()
        report["freeBytesAfter"] = shutil.disk_usage(root).free
        report["allTrackedGroupsGone"] = all(r["groupGone"] for r in rows)
        report["inheritedMarkersPreserved"] = markers == {
            k: (k in os.environ, os.environ.get(k)) for k in MARKERS}
        if source_before is not None:
            try:
                report["sourceUnchanged"] = source_snapshot(root / "source", names) == source_before
            except Exception:
                report["sourceUnchanged"] = False
        if not report["allTrackedGroupsGone"] or not report["inheritedMarkersPreserved"] or not report.get("sourceUnchanged", False):
            code = 1
            report["status"] = "BUILD_PREPARATION_INCOMPLETE"
        # Only complete bounded failure diagnostics pass the public shape scan.
        # Never expose environment values or private operator/account files.
        report["failureDiagnostics"] = []
        for row in rows:
            if command_ok(row):
                continue
            for stream in ("stdout", "stderr"):
                path = raw / (row["label"] + "." + stream)
                item = {"name": path.name, "originalSha256": sha(path)}
                try:
                    public = safe_failure_text(path.read_bytes(), root)
                    dest = output / path.name
                    dest.write_text(public)
                    item["exportedSha256"] = sha(dest)
                except Exception:
                    item["withheld"] = True
                report["failureDiagnostics"].append(item)
        write_json(output / "build-preparation-result.json", report)
        print(report["status"])
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Hold as exc:
        print("BUILD_PREPARATION_NOT_DISPATCHED:" + str(exc))
        sys.exit(1)
    except Exception as exc:
        print("BUILD_PREPARATION_CONTROLLER_ERROR:" + type(exc).__name__)
        sys.exit(1)
