"""Bounded parent engine for root's separately reviewed hosted integration.

Import has no runtime effects. There is no shell, policy generator, native canary,
or standalone network dispatcher. The caller owns policy/host admission.
"""
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import selectors
import signal
import subprocess
import sys
import time

FIXTURE_SHA256 = "3aaed3508f2b41c34eadaaa0da2358260bbd1e8f80b5c03e92d12e4e755d816c"
BOOTSTRAP_SHA256 = "bc00b77fd176d6e9a4c59eb84497b21dfda7cb3b12206de978a1f1d2f3406217"
CONTROL_KEYS = ("HOME", "CODEX_HOME", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")
MARKER_KEYS = ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")
PROFILE_KEYS = ("HOME", "CODEX_HOME", "CORBANU_HOME", "PFTERMINAL_HOME")
CAMPAIGN_SECONDS = 80.0  # Frozen fixture lifetime is 90s; cleanup is additional.
CHILD_SECONDS = 10.0
STREAM_BYTES = 65536
EVENT_LIMIT = 96
DENIAL_ERRNOS = frozenset((errno.EACCES, errno.EPERM))
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


class Held(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Held(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save_json(path, value):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
        handle.write("\n")


def markers(environment):
    data = {key: environment.get(key) for key in MARKER_KEYS}
    return digest(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def check_environment(environment, authorized_owned_root=None):
    require(isinstance(environment, dict), "Explicit child environment required")
    require(all(type(k) is str and type(v) is str for k, v in environment.items()),
            "Environment must contain strings")
    inherited = CONTROL_KEYS if authorized_owned_root is None else MARKER_KEYS
    for key in inherited:
        require(environment.get(key) == os.environ.get(key)
                and (key in environment) == (key in os.environ),
                "Inherited control changed: " + key)
    if authorized_owned_root is not None:
        root = Path(authorized_owned_root)
        require(root.is_absolute() and root.is_dir() and root.resolve() == root,
                "Owned profile root must be an existing canonical absolute directory")
        require(root.stat().st_uid == os.getuid(), "Owned profile root has different owner")
        require("HOME" in environment and "CODEX_HOME" in environment,
                "Fresh child HOME and CODEX_HOME are required")
        for key in PROFILE_KEYS:
            if key not in environment:
                continue
            path = Path(environment[key])
            require(path.is_absolute() and path.is_dir() and path.resolve() == path
                    and path != root and root in path.parents,
                    "Child profile path is outside exact owned root: " + key)
            require(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0,
                    "Child profile directory must be private and owned: " + key)
    # Root builds a secret-free allowlist; this additional guard never prints values.
    sensitive = ("TOKEN", "PASSWORD", "SECRET", "API_KEY", "ACCESS_KEY",
                 "AUTHORIZATION", "CREDENTIAL")
    for key in environment:
        require(not any(word in key.upper() for word in sensitive)
                and key not in ("SSH_AUTH_SOCK", "GIT_ASKPASS", "SSH_ASKPASS"),
                "Credential-bearing environment key is not admitted")


def group_exists(process):
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    return True  # PermissionError propagates; it never proves absence.


def cleanup_group(process, grace_seconds=1.0):
    """Only the group created for this current Popen; independent of parent exit."""
    result = {"groupGone": False, "directChildReaped": False, "signals": [],
              "error": None}

    def settle():
        end = time.monotonic() + grace_seconds
        while True:
            process.poll()  # Reap a finished direct child before checking its group.
            if not group_exists(process):
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(min(0.02, max(0, end - time.monotonic())))

    try:
        process.poll()
        if group_exists(process):
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, sig)
                    result["signals"].append(sig.name)
                except ProcessLookupError:
                    break
                if settle():
                    break
        result["groupGone"] = not group_exists(process)
    except BaseException as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        try:
            process.wait(timeout=grace_seconds)
            result["directChildReaped"] = True
        except BaseException as exc:
            text = type(exc).__name__ + ": " + str(exc)
            result["error"] = (result["error"] + "; " if result["error"] else "") + text
    return result


def run_child(argv, *, environment, output_dir, deadline_monotonic,
              timeout_seconds=CHILD_SECONDS, stream_limit=STREAM_BYTES,
              authorized_owned_root=None, health_check=None):
    """Capture one child fully, bounded by time/bytes, always clean current group.

    An output cap retains its prefix and marks capture incomplete. No successor is
    allowed by the campaign after any non-complete child result.
    """
    require(isinstance(argv, (list, tuple)) and argv
            and all(type(arg) is str and arg for arg in argv), "Invalid argv")
    require(Path(argv[0]).is_absolute(), "Child executable must be absolute")
    require(0 < timeout_seconds <= CHILD_SECONDS
            and 0 < stream_limit <= STREAM_BYTES, "Child bounds exceed method")
    check_environment(environment, authorized_owned_root)
    bootstrap = Path(__file__).resolve().with_name("child_bootstrap_v4.py")
    require(not bootstrap.is_symlink() and digest(bootstrap.read_bytes()) == BOOTSTRAP_SHA256,
            "Fixed child bootstrap changed")
    dispatch_argv = [sys.executable, "-I", "-B", str(bootstrap), *argv]
    target = Path(output_dir)
    target.mkdir(mode=0o700, parents=False, exist_ok=False)
    started = time.monotonic()
    result = {"argv": list(argv), "dispatchArgv": dispatch_argv,
              "bootstrapSha256": BOOTSTRAP_SHA256, "startedMonotonic": started, "exitCode": None,
              "completeOutput": False, "stopReason": None, "cleanup": None,
              "error": None}
    save_json(target / "intent.json", {"argv": list(argv), "dispatchArgv": dispatch_argv,
              "timeoutSeconds": timeout_seconds, "streamLimit": stream_limit})
    process = None
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    observed_eof = set()

    def healthy():
        if health_check is not None:
            try:
                health_check()
            except BaseException:
                result["stopReason"] = "health_check"
                raise

    try:
        require(started < deadline_monotonic, "Campaign deadline before child")
        healthy()
        process = subprocess.Popen(
            dispatch_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment, start_new_session=True)
        for name in buffers:
            pipe = getattr(process, name)
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        end = min(deadline_monotonic, started + timeout_seconds)
        while selector.get_map() or process.poll() is None:
            healthy()
            if time.monotonic() >= end:
                result["stopReason"] = "deadline"
                break
            for key, _ in selector.select(min(0.025, max(0, end - time.monotonic()))):
                block = os.read(key.fileobj.fileno(), 16384)
                name = key.data
                if not block:
                    observed_eof.add(name)
                    selector.unregister(key.fileobj)
                    continue
                available = stream_limit - len(buffers[name])
                buffers[name].extend(block[:available])
                if len(block) > available:
                    result["stopReason"] = "output_limit"
                    break
            if result["stopReason"]:
                break
        result["completeOutput"] = observed_eof == set(buffers) and not result["stopReason"]
        healthy()
    except BaseException as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
        result["stopReason"] = result["stopReason"] or "exception"
    finally:
        # Cleanup precedes every potentially failing evidence write.
        if process is not None:
            result["cleanup"] = cleanup_group(process)
            result["exitCode"] = process.poll()
            for pipe in (process.stdout, process.stderr):
                pipe.close()
        selector.close()
        result["finishedMonotonic"] = time.monotonic()
        result["streams"] = {}
        for name, buffer in buffers.items():
            data = bytes(buffer)
            with (target / (name + ".log")).open("xb") as handle:
                handle.write(data)
            result["streams"][name] = {"sha256": digest(data), "bytes": len(data)}
        clean = result["cleanup"]
        result["completed"] = bool(
            result["completeOutput"] and result["exitCode"] == 0
            and result["error"] is None and clean and clean["groupGone"]
            and clean["directChildReaped"] and clean["error"] is None)
        save_json(target / "result.json", result)
    return result


def decode_observation(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON observation key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise Held("Non-finite JSON observation")

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=invalid_constant)
    except (ValueError, UnicodeError) as exc:
        raise Held("Expected exactly one complete JSON observation") from exc
    require(type(value) is dict, "Observation must be an object")
    return value


def check_observation(row, case, *, subject=False):
    require(row.get("case") == case["id"]
            and row.get("transport") == case["transport"], "Wrong case/transport")
    elapsed = row.get("elapsedSeconds")
    require(type(elapsed) in (int, float) and math.isfinite(elapsed)
            and 0 <= elapsed <= CHILD_SECONDS, "Invalid probe elapsed time")
    status = row.get("status")
    require(status in ("connected", "permission_denied"), "Incomplete probe observation")
    if status == "connected":
        require(row.get("errno") is None and row.get("operation") == "receive",
                "ACK observation fields disagree")
    else:
        require(type(row.get("errno")) is int and row["errno"] in DENIAL_ERRNOS
                and row.get("operation") in ("connect", "send"),
                "Denial requires EPERM/EACCES at connect/send")
    if subject:
        require(row.get("inheritedMarkersMatched") is True
                and row.get("fixtureSha256") == FIXTURE_SHA256,
                "Subject source/control identity mismatch")
    else:
        require(status == "connected", "Parent positive control did not receive ACK")


def expected_events(case, token, connected):
    if not connected:
        return []
    label = {"allowed_ipv4": "ipv4_P", "ipv6_loopback": "ipv6_P",
             "ipv4_mapped": "ipv4_P", "owned_nonloopback": "interface_P",
             "other_port": "ipv4_Q"}[case["id"].split("_", 1)[1]]
    common = {"transport": case["transport"], "listener": label}
    rows = []
    if case["transport"] == "tcp":
        rows.append(dict(common, event="accepted", payloadSha256=EMPTY_HASH))
    rows.append(dict(common, event="received",
                     payloadSha256=digest(("NBF3:" + token).encode("ascii"))))
    return rows


class EventAccount:
    """Exact append-only accounting, including tokenless TCP acceptances."""
    def __init__(self):
        self.expected = []

    def check(self, actual):
        require(isinstance(actual, list) and len(actual) <= EVENT_LIMIT,
                "Invalid or overflowing server event list")
        require(actual == self.expected, "Unaccounted, duplicate, reordered or late server event")

    def add(self, case, token, row, before, after):
        self.check(before)
        addition = expected_events(case, token, row["status"] == "connected")
        require(after == before + addition, "Phase server events do not match exact token")
        self.expected.extend(addition)
        self.check(after)


def check_contract(cases, expectations):
    require(type(expectations) is dict and set(expectations) == {c["id"] for c in cases},
            "Explicit expectations must cover every fixed case exactly")
    require(all(v in ("allow", "deny", "observe") for v in expectations.values()),
            "Unknown expectation")
    require(expectations["tcp_allowed_ipv4"] == "allow",
            "Actual harness loopback TCP positive is required")
    # No IPv4-only, single-port, or UDP-allow assumption is embedded here.


def run_boundary_campaign(*, fixture_module, owned_ipv4, expectations, subject_argv,
                          output_dir, child_env, context_check,
                          authorized_owned_root=None, outer_deadline=None):
    """Run fixed before/subject/after observations once; never admit the canary.

    context_check is the integration's fresh interface/observer/control admission.
    subject_argv builds its fixed pinned sandbox-exec/profile/Python child argv.
    Neither callback is a replacement for reviewed host enforcement.
    """
    require(digest(Path(fixture_module.__file__).read_bytes()) == FIXTURE_SHA256,
            "Frozen fixture source mismatch")
    cases = list(fixture_module.CASES)
    require(len(cases) == 10 and len({c["id"] for c in cases}) == 10,
            "Fixed ten-case matrix changed")
    check_contract(cases, expectations)
    check_environment(child_env, authorized_owned_root)
    fixture_module.canonical_owned_ipv4(owned_ipv4)
    target = Path(output_dir)
    target.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {"schema": "network-parent-boundary-campaign-v4",
              "expectedBoundaryPassed": False, "diagnosticsComplete": False,
              "canaryAdmitted": False, "sourceFixtureSha256": FIXTURE_SHA256,
              "expectations": dict(expectations), "contexts": [], "cases": [],
              "events": [], "cleanup": None, "errors": [],
              "addressScopeClaim": "Only explicitly expected rows; no IPv4-only equivalence",
              "policyScopeLimit": "This engine does not qualify file/IPC/Mach services, "
                                  "native prompt monitoring, external egress, TLS, or canary runs."}
    account = EventAccount()
    fixture = None
    started = time.monotonic()
    require(outer_deadline is None or (type(outer_deadline) in (int, float)
            and math.isfinite(outer_deadline)), "Invalid outer deadline")
    deadline = min(started + CAMPAIGN_SECONDS,
                   outer_deadline if outer_deadline is not None else math.inf)
    controls_before = {k: (k in os.environ, os.environ.get(k)) for k in CONTROL_KEYS}
    context_held = [False]

    def live_context():
        try:
            require(not context_held[0], "Prior context hold remains latched")
            require(time.monotonic() < deadline, "Campaign deadline")
            require({k: (k in os.environ, os.environ.get(k)) for k in CONTROL_KEYS}
                    == controls_before, "Parent inherited control changed")
            check_environment(child_env, authorized_owned_root)
            facts = context_check()
            require(type(facts) is dict and facts.get("ownedIpv4") == owned_ipv4
                    and facts.get("interfaceOwnershipVerified") is True
                    and facts.get("nativeObserversHealthy") is True
                    and facts.get("inheritedControlsMatched") is True
                    and facts.get("stopRequested") is False, "Fresh integration context held")
            require(len(report["contexts"]) < 4096, "Context observation cap")
            report["contexts"].append(facts)
        except BaseException:
            context_held[0] = True
            raise

    def parent_probe(case, token, row, phase):
        live_context()
        before = fixture.snapshot()
        observation = fixture_module.probe(case, instance, token)
        row[phase] = observation
        after = fixture.snapshot()
        check_observation(observation, case)
        account.add(case, token, observation, before, after)
        require(time.monotonic() < deadline, "Campaign deadline after parent control")

    try:
        live_context()
        tokens = [secrets.token_hex(16) for _ in range(30)]
        require(len(set(tokens)) == 30, "Synthetic token collision; no allocation retry")
        fixture = fixture_module.OwnedEndpoints(owned_ipv4, tokens)
        instance = fixture.start()
        require(instance["ownedIpv4"] == owned_ipv4
                and instance["fixedCaseIds"] == [c["id"] for c in cases],
                "Started fixture identity mismatch")
        instance.update(schema="network-address-fixture-instance-v3",
                        fixtureSha256=FIXTURE_SHA256,
                        inheritedMarkersSha256=markers(child_env))
        manifest = target / "instance.json"
        save_json(manifest, instance)
        manifest_hash = digest(manifest.read_bytes())
        report["instance"] = dict(instance)
        report["instanceSha256"] = manifest_hash
        for index, case in enumerate(cases):
            row = {"case": case["id"], "expectation": expectations[case["id"]],
                   "passed": False}
            report["cases"].append(row)
            before_token, subject_token, after_token = tokens[index * 3:index * 3 + 3]
            parent_probe(case, before_token, row, "before")
            failure = None
            try:
                live_context()
                require(digest(manifest.read_bytes()) == manifest_hash,
                        "Fixture instance changed")
                before_events = fixture.snapshot()
                account.check(before_events)
                command = subject_argv(case["id"], manifest, subject_token)
                subject_dir = target / case["id"]
                try:
                    command_result = run_child(command, environment=child_env,
                                               output_dir=subject_dir,
                                               deadline_monotonic=deadline,
                                               authorized_owned_root=authorized_owned_root,
                                               health_check=live_context)
                except BaseException:
                    context_held[0] = True
                    raise
                row["commandResult"] = command_result
                if not command_result["completed"]:
                    context_held[0] = True
                require(command_result["completed"], "Subject command incomplete or failed")
                observation = decode_observation((subject_dir / "stdout.log").read_bytes())
                row["subject"] = observation
                check_observation(observation, case, subject=True)
                account.add(case, subject_token, observation, before_events, fixture.snapshot())
                expectation = expectations[case["id"]]
                wanted = {"allow": "connected", "deny": "permission_denied"}
                require(expectation == "observe" or observation["status"] == wanted[expectation],
                        "Observed endpoint outcome violates explicit expectation")
            except BaseException as exc:
                failure = type(exc).__name__ + ": " + str(exc)
            finally:
                # Only a completed child may be followed by a healthy after-control.
                # Incomplete capture/timeout/cleanup latches a hold before this point.
                try:
                    parent_probe(case, after_token, row, "after")
                except BaseException as exc:
                    row["afterError"] = type(exc).__name__ + ": " + str(exc)
                    failure = failure or row["afterError"]
            if failure:
                row["error"] = failure
                raise Held(failure)
            row["passed"] = True
        live_context()
        account.check(fixture.snapshot())
    except BaseException as exc:
        report["errors"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        if fixture is not None:
            try:
                report["cleanup"] = fixture.close()
                # Inspect final events only after join; includes events received during close.
                with fixture.lock:
                    report["events"] = [dict(event) for event in fixture.events]
                clean = report["cleanup"]
                require(clean.get("listenersClosed") is True
                        and clean.get("serverThreadStopped") is True
                        and clean.get("serverError") is None, "Fixture cleanup unresolved")
                account.check(report["events"])
            except BaseException as exc:
                report["errors"].append(type(exc).__name__ + ": " + str(exc))
        report["startedMonotonic"] = started
        report["finishedMonotonic"] = time.monotonic()
        complete = (not report["errors"] and len(report["cases"]) == 10
                    and all(row["passed"] for row in report["cases"]))
        report["diagnosticsComplete"] = complete
        report["expectedBoundaryPassed"] = complete
        report["observationOnlyCases"] = [k for k, v in expectations.items() if v == "observe"]
        report["allTenExpectationsQualified"] = complete and not report["observationOnlyCases"]
        report["contextHoldLatched"] = context_held[0]
        save_json(target / "campaign-result.json", report)
    return report


if __name__ == "__main__":
    raise SystemExit("Import the bounded API from the separately reviewed hosted integration.")
