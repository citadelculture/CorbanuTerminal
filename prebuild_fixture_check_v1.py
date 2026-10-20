"""Bounded synthetic profile check before expensive same-job compilation."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import time


def main():
    import importlib.util
    def load(path, name):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    ap = argparse.ArgumentParser()
    for name in ("control", "combined-plan", "admission", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    args = ap.parse_args()
    control = args.control.resolve(strict=True)
    build = load(control / "build-preparation-v2.py", "bounded_build")
    measured = load(control / "measured_campaign_v1.py", "measurement")
    v4 = load(control / "hosted_macos_local_fixtures_v4.py", "v4_primitives")
    plan, admission = json.loads(args.combined_plan.read_text()), json.loads(args.admission.read_text())
    if (not measured.fixed_host() or admission.get("measurementApproved") is not True
            or admission.get("combinedPlanSha256") != build.sha(args.combined_plan)):
        raise build.Hold("prebuild_admission")
    for name, digest in plan["controlHashes"].items():
        if Path(name).name != name or build.sha(control / name) != digest:
            raise build.Hold("control_hash_mismatch")
    root = Path("/private/tmp/network-prebuild-" + os.environ["GITHUB_RUN_ID"] + "-1")
    root.mkdir(mode=0o700)
    allowed, raw = root / "allowed", root / "raw"
    allowed.mkdir(mode=0o700)
    raw.mkdir(mode=0o700)
    for name in ("home", "profile"):
        (allowed / name).mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(allowed / "home"),
           "CODEX_HOME": str(allowed / "profile"), "CORBANU_HOME": str(allowed / "profile"),
           "PFTERMINAL_HOME": str(allowed / "profile"), "CORBANU_TEST_NO_NATIVE_KEYRING": "1"}
    env.update({k: os.environ[k] for k in build.MARKERS if k in os.environ})
    markers = {k: (k in os.environ, os.environ.get(k)) for k in build.MARKERS}
    (allowed / "marker-values.json").write_text(json.dumps({k: env.get(k) for k in build.MARKERS}))
    foreign = root / "foreign"
    foreign.write_text("synthetic-tasknode-sentinel\n")
    sentinel = build.sha(foreign)
    profile = root / "measurement.sb"
    profile.write_text(measured.measurement_profile(build, root, foreign))
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    rows, sockets, temporary = [], [], []
    report = {"schema": "network-prebuild-fixture-check-v1", "startedAt": build.now(),
              "status": "PREBUILD_FIXTURE_CHECK_INCOMPLETE", "commands": rows,
              "profileSha256": build.sha(profile), "canaryInvocations": 0,
              "controllerSha256": build.sha(__file__),
              "combinedPlanSha256": build.sha(args.combined_plan),
              "runId": os.environ["GITHUB_RUN_ID"]}
    deadline, code = time.monotonic() + 100, 1
    try:
        for family, address in (
            (socket.AF_INET, ("127.0.0.1", 0)), (socket.AF_INET, ("127.0.0.1", 0)),
            (socket.AF_UNIX, str(root / "foreign.sock")),
            (socket.AF_UNIX, str(allowed / "fixture.sock")),
        ):
            sock = socket.socket(family)
            sock.bind(address)
            sock.listen(8)
            sockets.append(sock)
        probe = allowed / "probe.py"
        probe.write_text(v4.PROBE)
        out = build.command("basic-boundary", [sys.executable, "-I", str(probe), str(root),
                            str(sockets[0].getsockname()[1]), str(sockets[1].getsockname()[1])],
                            root, env, raw, rows, deadline, 15, root, profile)
        report["basicControls"] = json.loads(out.read_text())
        if not report["basicControls"] or not all(v is True for v in report["basicControls"].values()):
            raise build.Hold("basic_boundary_failed")
        paths = []
        for parent, prefix in (("/private/var/tmp", "corbanu-credential-canary-"),
                               ("/private/tmp", "pf27s02-"), ("/private/tmp", "cbk-")):
            # These are synthetic owned dirs, removed before the real harness.
            if any(Path(parent).glob(prefix + "*")):
                raise build.Hold("preexisting_fixture_scope")
            directory = tempfile.TemporaryDirectory(dir=parent, prefix=prefix)
            temporary.append(directory)
            path = Path(directory.name) / "c.sock"
            sock = socket.socket(socket.AF_UNIX)
            sock.bind(str(path))
            sock.listen(2)
            sockets.append(sock)
            paths.append(str(path))
        special = allowed / "special.py"
        special.write_text(
            "import json,socket,sys\n"
            "for path in sys.argv[1:]:\n"
            " with socket.socket(socket.AF_UNIX) as s:\n"
            "  s.settimeout(2);s.connect(path)\n"
            "print(json.dumps({'scopedUnixFamilies':len(sys.argv)-1}))\n")
        out = build.command("exact-temporary-fixtures", [sys.executable, "-I", str(special), *paths],
                            root, env, raw, rows, deadline, 15, root, profile)
        report["scopedFixtureControls"] = json.loads(out.read_text())
        if report["scopedFixtureControls"] != {"scopedUnixFamilies": 3}:
            raise build.Hold("scope_test_incomplete")
        report["status"] = "PREBUILD_FIXTURE_CHECK_PASSED"
        code = 0
    except BaseException as exc:
        report["failureCode"] = str(exc) if isinstance(exc, build.Hold) else "controller_" + type(exc).__name__
    finally:
        for sock in sockets:
            sock.close()
        for directory in temporary:
            directory.cleanup()
        report["allListenersClosed"] = all(s.fileno() == -1 for s in sockets)
        report["allTemporaryFixturesRemoved"] = all(not Path(t.name).exists() for t in temporary)
        report["sentinelUnchanged"] = build.sha(foreign) == sentinel
        report["markersPreserved"] = markers == {k: (k in os.environ, os.environ.get(k)) for k in build.MARKERS}
        if not all(report[k] for k in ("allListenersClosed", "allTemporaryFixturesRemoved",
                                      "sentinelUnchanged", "markersPreserved")):
            code = 1
            report["status"] = "PREBUILD_FIXTURE_CHECK_INCOMPLETE"
        report["finishedAt"] = build.now()
        shutil.copyfile(profile, output / "measurement.sb")
        shutil.copytree(raw, output / "raw")
        build.write_json(output / "prebuild-result.json", report)
        print(report["status"])
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("PREBUILD_NOT_DISPATCHED:" + type(exc).__name__)
        sys.exit(1)
