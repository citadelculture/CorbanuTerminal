"""Same-job continuation for the unchanged pinned credential canary.

Import is inert. Only a fixed hosted push may dispatch. All source execution
inherits added Seatbelt restrictions; acquisition is over before this phase.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import sys
import time

BASE = "78dd811d6e3718140c938ad4839968d9995fd5ac"
REF = "refs/heads/codex/network-canary-macos-combined-v1-20261020"
REPO = "citadelculture/CorbanuTerminal"
REPORT_LIMIT = 32 * 1024 ** 2
WHOLE_SECONDS = 9000


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def measurement_profile(build, root, foreign):
    # The unmodified harness uses /var/tmp; two exact tests explicitly use /tmp.
    # Both lexical aliases and Darwin canonical paths are covered. No generic
    # foreign Unix-socket allowance or external IP egress is added.
    profile = build.profile_text(root, False)
    profile += """
(allow network-bind (local ip "*:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:*"))
"""
    for direction, locality in (("bind", "local"), ("inbound", "local"), ("outbound", "remote")):
        profile += f'(allow network-{direction} ({locality} unix-socket (subpath "{root}")))\n'
        for pattern in (
            r"^(/private)?/var/tmp/corbanu-credential-canary-[A-Za-z0-9_-]+/.*",
            r"^(/private)?/tmp/pf27s02-[A-Za-z0-9_-]+/.*",
            r"^(/private)?/tmp/cbk-[A-Za-z0-9_-]+/.*",
        ):
            profile += f'(allow network-{direction} ({locality} unix-socket (regex #"{pattern}")))\n'
    profile += f'(deny file-read* file-write* (literal "{foreign}"))\n'
    foreign_socket = str(foreign) + ".sock"
    for direction, locality in (("bind", "local"), ("inbound", "local"), ("outbound", "remote")):
        profile += f'(deny network-{direction} ({locality} unix-socket (literal "{foreign_socket}")))\n'
    return profile


def public_text(text, harness, root):
    # Complete source-generated reports only; withhold the whole item on a
    # credential-shaped value. Do not mask a failure into a clean pass.
    harness.assert_secret_free(text, "controller evidence export")
    if re.search(r"(?i)(?:xox[abprs]-[A-Za-z0-9-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)", text):
        raise ValueError("public_export_sensitive_shape")
    return re.sub(r"/Users/[^/\s\"']+", "<HOSTED_USER>", text.replace(str(root), "<OWNED>"))


def valid_report(report, harness, candidate_sha, prior_digests):
    if (report.get("status") != "passed" or report.get("source_commit") != BASE
            or report.get("source_dirty_paths") != []
            or report.get("host", {}).get("system") != "Darwin"
            or report.get("host", {}).get("machine") != "arm64"
            or report.get("candidate", {}).get("sha256") != candidate_sha):
        raise ValueError("report_identity_or_status")
    probes = report.get("probes", [])
    if [p.get("id") for p in probes] != [p.probe_id for p in harness.PROBES]:
        raise ValueError("probe_list_mismatch")
    for actual, expected in zip(probes, harness.PROBES):
        if actual.get("expected_tests") != list(expected.expected_tests):
            raise ValueError("expected_test_list_changed")
        value = actual["result"]
        command = harness.CommandResult(**value)
        # Reapply the unchanged source's required-test and transcript checks.
        count = harness.validate_probe_output(expected, command)
        if actual.get("executed_tests") != count:
            raise ValueError("executed_count_mismatch")
        if re.search(r"(?im)^\s*(?:warning:\s*)?(?:skipping\b|.*\bcase skipped:)", command.stdout + "\n" + command.stderr):
            raise ValueError("body_skip_observed")
    for key in ("candidate_build_command", "candidate_pre_probe_build_command", "candidate_version_command"):
        value = report.get(key, {})
        if value.get("returncode") != 0:
            raise ValueError("candidate_command_incomplete")
    parsed = harness.parse_canary_result([harness.CommandResult(**p["result"]) for p in probes])
    if report.get("canary") != parsed or parsed["canary_sha256"] in prior_digests:
        raise ValueError("dynamic_canary_not_unique_or_mismatch")
    return parsed["canary_sha256"]


def build_qualified(report, run_id, plan_sha, driver_sha):
    return (report.get("status") == "BUILD_PREPARATION_COMPLETE_NOT_CANARY_QUALIFICATION"
            and report.get("runId") == run_id and report.get("runAttempt") == "1"
            and report.get("sourceCommit") == BASE
            and report.get("combinedPlanSha256") == plan_sha
            and report.get("controllerSha256") == driver_sha
            and report.get("sourceUnchanged") is True
            and report.get("allTrackedGroupsGone") is True
            and report.get("inheritedMarkersPreserved") is True
            and report.get("canaryInvocations") == 0
            and report.get("testBodyInvocations") == 0)


def fixed_host():
    return (os.environ.get("GITHUB_REPOSITORY") == REPO
            and os.environ.get("GITHUB_REF") == REF
            and os.environ.get("GITHUB_EVENT_NAME") == "push"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", "")) is not None
            and platform.system() == "Darwin" and platform.machine() == "arm64")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dispatch", action="store_true", required=True)
    for name in ("control", "build-result", "combined-plan", "admission", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    args = ap.parse_args()
    if not fixed_host():
        raise RuntimeError("fixed_hosted_context_required")
    control = args.control.resolve(strict=True)
    build = load(control / "build-preparation-v2.py", "bounded_build")
    plan = json.loads(args.combined_plan.read_text())
    admission = json.loads(args.admission.read_text())
    if (admission.get("measurementApproved") is not True
            or admission.get("combinedPlanSha256") != build.sha(args.combined_plan)
            or admission.get("measurementControllerSha256") != build.sha(__file__)
            or plan.get("sourceCommit") != BASE or plan.get("maximumRuns") != 20
            or plan.get("sameInitialProfile") is not True):
        raise build.Hold("measurement_admission_unbound")
    for name, expected in plan["controlHashes"].items():
        if Path(name).name != name or build.sha(control / name) != expected:
            raise build.Hold("control_hash_mismatch")
    result = json.loads(args.build_result.read_text())
    run_id = os.environ["GITHUB_RUN_ID"]
    if (not build_qualified(result, run_id, build.sha(args.combined_plan),
                            build.sha(control / "build-preparation-v2.py"))
            or not result.get("commands") or not all(build.command_ok(r) for r in result["commands"])):
        raise build.Hold("build_not_qualified_for_continuation")
    root = Path("/private/tmp/network-build-" + run_id + "-1")
    source = root / "source"
    pins = json.loads((control / "build-pins-v1.json").read_text())
    for name, expected in pins["sourceFiles"].items():
        if build.sha(source / name) != expected:
            raise build.Hold("source_pin_drift")
    harness = load(source / "scripts/security_credential_canary.py", "pinned_harness")
    v4 = load(control / "hosted_macos_local_fixtures_v4.py", "preflight_primitives")
    controller = load(control / "boundary_controller_v4.py", "boundary_controller_v4")
    lane = root / "measurement"
    lane.mkdir(mode=0o700)
    allowed = lane / "allowed"
    allowed.mkdir(mode=0o700)
    for name in ("home", "profile"):
        (allowed / name).mkdir(mode=0o700)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    raw = lane / "private-diagnostics"
    raw.mkdir(mode=0o700)
    git = build.select_git()
    env = build.environment(root, git)
    env.update(HOME=str(allowed / "home"), CODEX_HOME=str(allowed / "profile"),
               CORBANU_HOME=str(allowed / "profile"), PFTERMINAL_HOME=str(allowed / "profile"),
               RUSTC=str(root / "toolchain/bin/rustc"), RUSTDOC=str(root / "toolchain/bin/rustdoc"),
               CARGO_NET_OFFLINE="true")
    # Use the same actual SDK/linker as the build; no rustup or host defaults.
    for tool, key in (("clang", "CC"), ("clangpp", "CXX"), ("ar", "AR")):
        env[key] = (root / "private-diagnostics" / ("resolve-" + tool + ".stdout")).read_text().strip()
    env["CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"] = env["CC"]
    env["SDKROOT"] = (root / "private-diagnostics/sdk.stdout").read_text().strip()
    markers = {k: (k in os.environ, os.environ.get(k)) for k in build.MARKERS}
    (allowed / "marker-values.json").write_text(json.dumps({k: env.get(k) for k in build.MARKERS}))
    for name in ("address_boundary_fixtures_v3.py", "probe_entry_v3.py"):
        shutil.copyfile(control / name, allowed / name)
    foreign = lane / "foreign"
    foreign.write_text("synthetic-tasknode-sentinel\n")
    foreign_sha = build.sha(foreign)
    profile = lane / "measurement.sb"
    profile.write_text(measurement_profile(build, root, foreign))
    (output / "measurement.sb").write_text(profile.read_text())
    deadline, rows, sockets, passes = time.monotonic() + WHOLE_SECONDS, [], [], []
    report = {"schema": "network-measured-campaign-v1", "startedAt": build.now(),
              "status": "MEASUREMENT_INCOMPLETE", "runId": run_id, "sourceCommit": BASE,
              "controllerSha256": build.sha(__file__), "profileSha256": build.sha(profile),
              "buildResultSha256": build.sha(args.build_result), "initialProfileFresh": True,
              "sameProfileAcrossRuns": True, "maximumRuns": 20, "attempts": [],
              "validPasses": 0, "canaryInvocations": 0, "commands": rows,
              "rawBuildStreamsPublished": False, "rewardClaim": False}
    code = 1
    cmd = lambda label, argv, seconds=30: build.command(
        label, argv, source, env, raw, rows, deadline, seconds, root, profile)
    try:
        cmd("measurement-profile-parse", ["/usr/bin/true"])
        # The new scopes are source-bound temporary fixture families. Existing
        # entries would make their ownership ambiguous, so fail before tests.
        for parent, prefix in ((Path("/private/tmp"), "pf27s02-"),
                               (Path("/private/tmp"), "cbk-"),
                               (Path("/private/var/tmp"), "corbanu-credential-canary-")):
            if any(parent.glob(prefix + "*")):
                raise build.Hold("preexisting_fixture_scope")
        for family, address in (
            (socket.AF_INET, ("127.0.0.1", 0)), (socket.AF_INET, ("127.0.0.1", 0)),
            (socket.AF_UNIX, str(lane / "foreign.sock")),
            (socket.AF_UNIX, str(allowed / "fixture.sock")),
        ):
            sock = socket.socket(family)
            sock.bind(address)
            sock.listen(8)
            sockets.append(sock)
        probe = allowed / "probe.py"
        probe.write_text(v4.PROBE)
        basic = cmd("fresh-boundary", [sys.executable, "-I", str(probe), str(lane),
                    str(sockets[0].getsockname()[1]), str(sockets[1].getsockname()[1])])
        report["controls"] = json.loads(basic.read_text())
        if not report["controls"] or not all(v is True for v in report["controls"].values()):
            raise build.Hold("fresh_boundary_failed")
        for sock in sockets:
            sock.close()
        fixture = load(allowed / "address_boundary_fixtures_v3.py", "fixed_address_fixture")
        interface = v4.owned_interface()
        expectations = {case["id"]: ("observe" if case["host"] in ("::ffff:127.0.0.1", "OWNED_RFC1918") else "allow")
                        for case in fixture.CASES}

        def context():
            build.observe()
            same = markers == {k: (k in os.environ, os.environ.get(k)) for k in build.MARKERS}
            if not same or v4.owned_interface() != interface:
                raise build.Hold("boundary_context_changed")
            return {"ownedIpv4": interface, "interfaceOwnershipVerified": True,
                    "nativeObserversHealthy": True, "inheritedControlsMatched": True,
                    "stopRequested": False}

        probe_env = {k: v for k, v in env.items() if k not in ("GIT_ASKPASS", "SSH_ASKPASS")}
        campaign = controller.run_boundary_campaign(
            fixture_module=fixture, owned_ipv4=interface, expectations=expectations,
            subject_argv=lambda case, manifest, token: [
                "/usr/bin/sandbox-exec", "-f", str(profile), sys.executable, "-I",
                str(allowed / "probe_entry_v3.py"), "--manifest", str(manifest),
                "--case", case, "--token", token],
            output_dir=allowed / "address-campaign", child_env=probe_env,
            context_check=context, authorized_owned_root=allowed, outer_deadline=deadline)
        report["addressCampaign"] = campaign
        if not build.address_campaign_ok(campaign):
            raise build.Hold("fresh_address_campaign_incomplete")
        # No fixture server threads remain before the command runner forks.
        tracked = cmd("tracked-files", [str(git), "-C", str(source), "ls-files", "-z"]).read_bytes()
        names = [n.decode() for n in tracked.split(b"\0") if n]
        original_sources = build.source_snapshot(source, names)
        report["trackedSourceManifestSha256"] = original_sources
        candidate = source / "codex-rs/target/debug/corbanu"
        for number in range(1, 21):
            context()
            if build.sha(foreign) != foreign_sha or build.source_snapshot(source, names) != original_sources:
                raise build.Hold("source_or_sentinel_changed")
            attempt_dir = lane / ("attempt-" + str(number))
            attempt_dir.mkdir(mode=0o700)
            attempt = {"number": number, "startedAt": build.now(), "status": "INCOMPLETE"}
            report["attempts"].append(attempt)
            report["canaryInvocations"] += 1
            try:
                cmd("canary-" + str(number), [
                    sys.executable, str(source / "scripts/security-credential-canary"),
                    "--candidate", str(candidate), "--output", str(attempt_dir)], seconds=4200)
                result_path = attempt_dir / "credential-canary-report.json"
                if not result_path.is_file() or result_path.is_symlink() or result_path.stat().st_size > REPORT_LIMIT:
                    raise build.Hold("missing_or_oversized_canary_report")
                complete = json.loads(result_path.read_text())
                digest = valid_report(complete, harness, build.sha(candidate), passes)
                if build.source_snapshot(source, names) != original_sources:
                    raise build.Hold("post_run_source_changed")
                # Exact source-generated report survives with only task-local
                # and hosted-user path normalization; provenance hashes bind both.
                public = public_text(result_path.read_text(), harness, root)
                exported = output / ("canary-" + str(number) + ".json")
                exported.write_text(public)
                attempt.update(status="VALID_PASS", originalReportSha256=build.sha(result_path),
                               exportedReportSha256=build.sha(exported),
                               candidateSha256=build.sha(candidate), canarySha256=digest)
                passes.append(digest)
                report["validPasses"] = len(passes)
            except BaseException:
                # Failure signatures are evidence only, not a pass or defect
                # verdict. Publish only if the complete bounded file is safe.
                for filename in ("credential-canary-failure.json",):
                    failure = attempt_dir / filename
                    if failure.is_file() and not failure.is_symlink() and failure.stat().st_size <= REPORT_LIMIT:
                        try:
                            clean = public_text(failure.read_text(), harness, root)
                            (output / ("failure-" + str(number) + ".json")).write_text(clean)
                            attempt["failureReportSha256"] = build.sha(failure)
                        except Exception:
                            attempt["failureReportWithheld"] = True
                raise
            finally:
                attempt["finishedAt"] = build.now()
        context()
        if build.sha(foreign) != foreign_sha or build.source_snapshot(source, names) != original_sources:
            raise build.Hold("final_identity_changed")
        report["status"] = "TWENTY_VALID_PASSES_NEGATIVE_REPRODUCTION"
        code = 0
    except BaseException as exc:
        report["failureCode"] = str(exc) if isinstance(exc, build.Hold) else "controller_" + type(exc).__name__
    finally:
        for sock in sockets:
            sock.close()
        report["finishedAt"] = build.now()
        report["allOwnedListenersClosed"] = all(s.fileno() == -1 for s in sockets)
        report["allTrackedGroupsGone"] = all(r["groupGone"] is True for r in rows)
        report["inheritedMarkersPreserved"] = markers == {k: (k in os.environ, os.environ.get(k)) for k in build.MARKERS}
        report["sentinelUnchanged"] = build.sha(foreign) == foreign_sha
        if not all(report[k] for k in ("allOwnedListenersClosed", "allTrackedGroupsGone",
                                      "inheritedMarkersPreserved", "sentinelUnchanged")):
            code = 1
            report["status"] = "MEASUREMENT_INCOMPLETE"
        # Retain complete bounded, safe console diagnostics; withheld bytes
        # remain hashed in commands. Never dump the environment.
        report["consoleExports"] = []
        for file in sorted(raw.iterdir()):
            if file.suffix in (".stdout", ".stderr") and file.is_file() and not file.is_symlink():
                item = {"name": file.name, "originalSha256": build.sha(file), "bytes": file.stat().st_size}
                try:
                    text = public_text(file.read_text(errors="strict"), harness, root)
                    target = output / file.name
                    target.write_text(text)
                    item["exportedSha256"] = build.sha(target)
                except Exception:
                    item["withheld"] = True
                report["consoleExports"].append(item)
        build.write_json(output / "campaign-result.json", report)
        print(report["status"])
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("MEASUREMENT_NOT_DISPATCHED:" + type(exc).__name__)
        sys.exit(1)
