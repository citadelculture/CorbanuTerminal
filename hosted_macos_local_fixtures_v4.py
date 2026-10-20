#!/usr/bin/env python3
"""Fixed synthetic preflight only. Never starts Cargo, the canary, or an app."""
import argparse
import datetime
import errno
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import resource
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import time

REPO = "citadelculture/CorbanuTerminal"
REF = "refs/heads/codex/network-canary-macos-local-fixtures-v4-20261020"
BASE = "78dd811d6e3718140c938ad4839968d9995fd5ac"
SOURCE_HASHES = {
    "scripts/security-credential-canary": "ddb9629ec3d6f428f19f1db73c10f544e5114f1093346cc6957bb9bdcd70bbc7",
    "scripts/security_credential_canary.py": "dac51ad02bfbde1a4d4d70c5a4ed564cba41c64cf47b59ae5090fd398a1ea05a",
    "codex-rs/rust-toolchain.toml": "570656042681cfd8795403a455baf9a33035331a07db0645e866bbcea89a3d64",
    "codex-rs/Cargo.lock": "3c62ca2fdc1d9fcc4b234dcf3ee6d0fd824faaa2e06aca8022ff418e1e051d9c",
}
MARKERS = ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")
LIMIT = 64 * 1024


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def child_limits():
    # Preserve inherited file-size limits; cap only captured pipes in the parent.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def select_git():
    # Fixed preinstalled locations only; no PATH search, shim, install or retry.
    candidates = (
        ("/opt/homebrew/bin/git", "/opt/homebrew/Cellar/git"),
        ("/Library/Developer/CommandLineTools/usr/bin/git", "/Library/Developer/CommandLineTools/usr/bin"),
        ("/Applications/Xcode_16.4.app/Contents/Developer/usr/bin/git", "/Applications/Xcode_16.4.app/Contents/Developer/usr/bin"),
    )
    shim = Path("/usr/bin/git").resolve(strict=True)
    shim_sha = sha(shim)
    observations = []
    macho = {bytes.fromhex(v) for v in (
        "feedface", "feedfacf", "cefaedfe", "cffaedfe",
        "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
    )}
    for name, allowed_root in candidates:
        candidate = Path(name)
        if not candidate.exists():
            observations.append({"candidate": name, "state": "absent"})
            continue
        real = candidate.resolve(strict=True)
        if not real.is_file() or not os.access(real, os.X_OK):
            raise RuntimeError("preinstalled Git candidate is not an executable file")
        if Path(allowed_root) not in real.parents:
            raise RuntimeError("preinstalled Git resolved outside its fixed directory")
        digest = sha(real)
        if real == shim or real.samefile(shim) or digest == shim_sha:
            raise RuntimeError("system Git launcher rejected")
        with real.open("rb") as stream:
            if stream.read(4) not in macho:
                raise RuntimeError("preinstalled Git is not a Mach-O executable")
        observations.append({"candidate": name, "resolved": str(real), "sha256": digest, "state": "selected"})
        return str(real), observations
    raise RuntimeError("no validated fixed preinstalled Git binary; no installation")


def group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def observe():
    observations = {}
    for name in ("SecurityAgent", "CoreAuthUI"):
        p = subprocess.run(
            ["/usr/bin/pgrep", "-x", name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2,
        )
        observations[name] = p.returncode
        if p.returncode not in (0, 1):
            raise RuntimeError("native observer unavailable")
        if p.returncode == 0:
            raise RuntimeError("native prompt process observed; no successor")
    return observations


def command(label, argv, env, raw, rows, deadline, native_guard=False):
    if time.monotonic() >= deadline:
        raise RuntimeError("whole preflight deadline")
    if native_guard:
        observe()
    out, err = raw / (label + ".stdout"), raw / (label + ".stderr")
    started = time.monotonic()
    p = None
    reason = None
    capture = {name: {"observedBytes": 0, "retainedBytes": 0, "truncated": False}
               for name in ("stdout", "stderr")}
    capture_complete = False
    with out.open("xb") as stdout, err.open("xb") as stderr, selectors.DefaultSelector() as selector:
        files = {"stdout": stdout, "stderr": stderr}
        try:
            p = subprocess.Popen(
                argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, preexec_fn=child_limits,
            )
            for name, pipe in (("stdout", p.stdout), ("stderr", p.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while p.poll() is None or selector.get_map():
                if time.monotonic() - started > 10 or time.monotonic() > deadline:
                    raise RuntimeError("owned command deadline")
                if native_guard:
                    observe()
                for key, _ in selector.select(timeout=0.1):
                    data = os.read(key.fd, LIMIT)
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    name = key.data
                    item = capture[name]
                    item["observedBytes"] += len(data)
                    kept = data[:max(0, LIMIT - item["retainedBytes"])]
                    files[name].write(kept)
                    item["retainedBytes"] += len(kept)
                    if len(kept) != len(data):
                        item["truncated"] = True
                        raise RuntimeError(name + " capture limit exceeded; retained prefix only")
                if not selector.get_map() and p.poll() is None:
                    time.sleep(0.1)
            p.wait()
            capture_complete = True
            if native_guard:
                observe()
        except BaseException as exc:
            reason = type(exc).__name__ + ": " + str(exc)
        finally:
            for key in list(selector.get_map().values()):
                selector.unregister(key.fileobj)
                key.fileobj.close()
            if p is not None and group_exists(p.pid):
                if p.poll() is not None and reason is None:
                    reason = "owned group survived its leader"
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    p.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
                if group_exists(p.pid):
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                p.wait(timeout=2)
    row = {
        "label": label, "exitCode": p.returncode if p else None,
        "seconds": round(time.monotonic() - started, 4),
        "stopReason": reason,
        "groupGone": p is not None and not group_exists(p.pid),
        "stdoutSha256": sha(out), "stderrSha256": sha(err),
        "stdoutBytes": out.stat().st_size, "stderrBytes": err.stat().st_size,
        "capture": capture, "captureComplete": capture_complete,
    }
    rows.append(row)
    if reason or not row["groupGone"] or not capture_complete:
        raise RuntimeError(reason or "owned group or output capture incomplete")
    if p.returncode != 0:
        raise RuntimeError(label + " failed with exit " + str(p.returncode))
    return p.returncode, out.read_text(errors="replace").strip()


PROBE = r"""
import errno, json, os, socket, subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
allowed_port, denied_port = map(int, sys.argv[2:4])
foreign, ipc = root / "foreign", root / "foreign.sock"
deny = {errno.EPERM, errno.EACCES}
def refused(fn):
    try:
        fn()
    except OSError as exc:
        return exc.errno in deny
    return False
def connect_tcp(port):
    with socket.socket() as s:
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
def connect_ipc():
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(2)
        s.connect(str(ipc))
allowed = root / "allowed" / "file"
allowed.write_text("synthetic\n")
checks = {
    "allowedFile": allowed.read_text() == "synthetic\n",
    "allowedChild": subprocess.run(["/usr/bin/true"], check=False).returncode == 0,
    "foreignReadDenied": refused(lambda: foreign.read_bytes()),
    "foreignWriteDenied": refused(lambda: foreign.write_text("changed")),
    "foreignUnixSocketDenied": refused(connect_ipc),
}
connect_tcp(allowed_port)
checks["allowedLoopback"] = True
connect_tcp(denied_port)
checks["secondDynamicLocalPortAllowed"] = True
with socket.socket() as bound:
    bound.bind(("127.0.0.1", 0))
    checks["localEphemeralBindAllowed"] = bound.getsockname()[1] > 0
with socket.socket(socket.AF_UNIX) as local_ipc:
    local_ipc.settimeout(2)
    local_ipc.connect(str(root / "allowed" / "fixture.sock"))
    checks["ownedUnixSocketAllowed"] = True
checks["markersPreservedInChild"] = {
    key: os.environ.get(key) for key in
    ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")
} == json.loads((root / "allowed" / "marker-values.json").read_text())
print(json.dumps(checks, sort_keys=True))
sys.exit(0 if all(checks.values()) else 1)
"""


def load_fixed_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def owned_interface():
    result = subprocess.run(["/sbin/ifconfig", "en0"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
    if result.returncode or len(result.stdout) > 16384 or result.stderr:
        raise RuntimeError("owned interface observation unavailable")
    candidates = []
    for line in result.stdout.decode("utf-8", errors="strict").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "inet":
            address = ipaddress.IPv4Address(parts[1])
            if any(address in ipaddress.IPv4Network(n) for n in
                   ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
                candidates.append(str(address))
    if len(candidates) != 1:
        raise RuntimeError("exactly one owned RFC1918 en0 address required")
    return candidates[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        os.environ.get("GITHUB_REPOSITORY") != REPO
        or os.environ.get("GITHUB_REF") != REF
        or os.environ.get("GITHUB_EVENT_NAME") != "push"
        or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("RUNNER_OS") != "macOS"
        or platform.system() != "Darwin"
        or platform.machine() != "arm64"
    ):
        raise RuntimeError("fixed owned hosted-macOS route required")
    identity = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    if not all(c.isdigit() or c == "-" for c in identity):
        raise RuntimeError("invalid run identity")
    root = Path("/private/tmp") / ("tasknode-network-local-fixtures-v4-" + identity)
    root.mkdir(mode=0o700)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    raw = root / "raw"
    raw.mkdir(mode=0o700)
    allowed = root / "allowed"
    allowed.mkdir(mode=0o700)
    for name in ("home", "profile", "tmp", "cargo", "rustup"):
        (allowed / name).mkdir(mode=0o700)
    markers = {key: os.environ.get(key) for key in MARKERS}
    (allowed / "marker-values.json").write_text(json.dumps(markers))
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(allowed / "home"),
        "TMPDIR": str(allowed / "tmp"),
        "CODEX_HOME": str(allowed / "profile"),
        "CORBANU_HOME": str(allowed / "profile"),
        "PFTERMINAL_HOME": str(allowed / "profile"),
        "CORBANU_TEST_NO_NATIVE_KEYRING": os.environ.get("CORBANU_TEST_NO_NATIVE_KEYRING", "1"),
        "CARGO_HOME": str(allowed / "cargo"),
        "RUSTUP_HOME": str(allowed / "rustup"),
        "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    env.update({key: os.environ[key] for key in MARKERS if key in os.environ})
    rows, sockets = [], []
    deadline = time.monotonic() + 180
    report = {
        "schema": "network-hosted-macos-preflight-result-v4", "startedAt": now(),
        "status": "PREFLIGHT_INCOMPLETE", "canaryReady": False,
        "canaryInvocations": 0, "compilationInvocations": 0,
        "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "controlCommit": os.environ["GITHUB_SHA"], "sourceCommit": BASE,
        "runnerImage": os.environ.get("ImageOS"),
        "runnerImageVersion": os.environ.get("ImageVersion"),
        "architecture": platform.machine(), "pythonVersion": platform.python_version(),
        "controllerSha256": sha(__file__), "commands": rows,
        "limits": {"preflightSeconds": 180, "commandSeconds": 10, "capturedStreamBytes": LIMIT, "inheritedFileSizeLimitUnchanged": True},
        "requiredMetadataToolsHealthy": False,
        "nativeObserverMeaning": "Process absence/health observation only, not proven UI prompt recognition.",
        "unqualified": [
            "No canary, native product, Cargo build or dependency fetch was executed.",
            "Rust1.95 closure/build capacity and five-to-twenty-run duration are unqualified.",
            "Credential-service Mach denial is configured but deliberately not probed.",
            "Denied foreign Unix socket is not a Mach credential-service test.",
            "Localhost permits dynamic local ports and both IP transports; no IPv4-only or exact-port claim. External endpoint denial remains unmeasured.",
            "Synthetic child policy is not yet admitted for the unchanged canary graph.",
            "Group checks cover directly owned groups, not independently detached sessions.",
        ],
    }
    code = 1
    try:
        source = args.source.resolve(strict=True)
        for relative, expected in SOURCE_HASHES.items():
            path = source / relative
            if path.is_symlink() or sha(path) != expected:
                raise RuntimeError("pinned public source hash mismatch: " + relative)
        git, report["gitSelection"] = select_git()
        rc, head = command("source-head", [git, "-C", str(source), "rev-parse", "HEAD"], env, raw, rows, deadline)
        if rc or head != BASE:
            raise RuntimeError("wrong public source commit")
        rc, status = command("source-status", [git, "-C", str(source), "status", "--porcelain"], env, raw, rows, deadline)
        if rc or status:
            raise RuntimeError("pinned public checkout is dirty")
        report["sourceHashes"] = SOURCE_HASHES
        report["freeBytes"] = shutil.disk_usage(root).free
        if report["freeBytes"] < 1024 ** 3:
            raise RuntimeError("less than1GiB for bounded preflight; no cleanup")
        tools = [
            ("os", ["/usr/bin/sw_vers", "-productVersion"]),
            ("memory", ["/usr/sbin/sysctl", "-n", "hw.memsize"]),
            ("sdk", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"]),
            ("clang", ["/usr/bin/clang", "--version"]),
            ("git", [git, "--version"]),
        ]
        report["toolObservations"] = {}
        for label, argv in tools:
            rc, text = command(label, argv, env, raw, rows, deadline)
            report["toolObservations"][label] = {"exitCode": rc, "text": text[:4096]}
        report["requiredMetadataToolsHealthy"] = True
        # Inspect only this exact public toolchain directory; never invoke a
        # rustup shim that could install a missing toolchain or read defaults.
        rust_bin = Path(os.environ["HOME"]) / ".rustup/toolchains/1.95.0-aarch64-apple-darwin/bin"
        report["pinnedRustToolchainPresent"] = False
        if all((rust_bin / name).is_file() and not (rust_bin / name).is_symlink() for name in ("rustc", "cargo")):
            for name in ("rustc", "cargo"):
                rc, text = command(name, [str(rust_bin / name), "--version"], env, raw, rows, deadline)
                report["toolObservations"][name] = {"exitCode": rc, "text": text[:4096], "sha256": sha(rust_bin / name)}
            report["pinnedRustToolchainPresent"] = all(
                report["toolObservations"][name]["exitCode"] == 0
                and "1.95.0" in report["toolObservations"][name]["text"]
                for name in ("rustc", "cargo")
            )
        report["pythonSha256"] = sha(Path(sys.executable).resolve())
        report["sandboxExecSha256"] = sha("/usr/bin/sandbox-exec")
        report["promptProcessesBefore"] = observe()
        foreign = root / "foreign"
        foreign.write_text("synthetic-tasknode-sentinel\n")
        foreign_sha = sha(foreign)
        for family, address in [
            (socket.AF_INET, ("127.0.0.1", 0)),
            (socket.AF_INET, ("127.0.0.1", 0)),
            (socket.AF_UNIX, str(root / "foreign.sock")),
            (socket.AF_UNIX, str(allowed / "fixture.sock")),
        ]:
            sock = socket.socket(family)
            sock.bind(address)
            sock.listen(8)
            sockets.append(sock)
            with socket.socket(family) as client:
                client.settimeout(2)
                client.connect(sock.getsockname())
            accepted, _ = sock.accept()
            accepted.close()
        allowed_port, denied_port = [sock.getsockname()[1] for sock in sockets[:2]]
        # Added child restrictions only. No system policy/privilege changes.
        profile = """(version 1)
(allow default)
(deny network*)
(allow network-bind (local ip "*:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:*"))
(allow network-bind (local unix-socket (subpath "OWNED")))
(allow network-inbound (local unix-socket (subpath "OWNED")))
(allow network-outbound (remote unix-socket (subpath "OWNED")))
(deny file-read* file-write*
  (subpath "/Users") (subpath "/Library/Keychains")
  (subpath "/private/var/root") (subpath "/var/root")
  (literal "FOREIGN"))
(deny mach-lookup
  (global-name-regex #".*[Ss]ecurity.*")
  (global-name-regex #".*secd.*")
  (global-name-regex #".*[Kk]eychain.*"))
(deny process-exec (literal "/usr/bin/sudo") (literal "/bin/su")
  (literal "/usr/bin/osascript"))
""".replace("OWNED", str(allowed)).replace("FOREIGN", str(foreign))
        profile_path = root / "preflight.sb"
        profile_path.write_text(profile)
        (output / "preflight.sb").write_text(profile)
        probe = root / "probe.py"
        probe.write_text(PROBE)
        rc, text = command(
            "synthetic-boundary",
            ["/usr/bin/sandbox-exec", "-f", str(profile_path), sys.executable, "-I",
             str(probe), str(root), str(allowed_port), str(denied_port)],
            env, raw, rows, deadline, native_guard=True,
        )
        report["controls"] = json.loads(text)
        # Frozen primitives are copied into the task-owned /private/tmp lane;
        # no operator or runner account contents are forwarded to the child.
        control = Path(__file__).resolve().parent
        helper_hashes = json.loads((control / "helper-pins.json").read_text())
        if set(helper_hashes) != {"address_boundary_fixtures_v3.py", "probe_entry_v3.py", "boundary_controller_v4.py", "child_bootstrap_v4.py"}:
            raise RuntimeError("unexpected helper manifest")
        for filename, expected in helper_hashes.items():
            fixed = control / filename
            if fixed.is_symlink() or not fixed.is_file() or sha(fixed) != expected:
                raise RuntimeError("fixed helper hash mismatch")
        report["helperHashes"] = helper_hashes
        for filename in ("address_boundary_fixtures_v3.py", "probe_entry_v3.py"):
            original = control / filename
            if original.is_symlink() or not original.is_file():
                raise RuntimeError("missing fixed fixture source")
            shutil.copyfile(original, allowed / filename)
        fixture = load_fixed_module(allowed / "address_boundary_fixtures_v3.py", "boundary_fixture_v3")
        controller = load_fixed_module(control / "boundary_controller_v4.py", "boundary_controller_v4")
        interface = owned_interface()
        expectations = {
            case["id"]: ("observe" if case["host"] in ("::ffff:127.0.0.1", "OWNED_RFC1918") else "allow")
            for case in fixture.CASES
        }
        def context_check():
            if owned_interface() != interface:
                raise RuntimeError("owned interface changed")
            native = observe()
            same = markers == {key: os.environ.get(key) for key in MARKERS}
            if not same:
                raise RuntimeError("inherited controls changed")
            return {"ownedIpv4": interface, "interfaceOwnershipVerified": True,
                    "nativeObserversHealthy": True, "nativeObserver": native,
                    "inheritedControlsMatched": same, "stopRequested": False}
        def subject_argv(case_id, manifest_path, token):
            return ["/usr/bin/sandbox-exec", "-f", str(profile_path), sys.executable,
                    "-I", str(allowed / "probe_entry_v3.py"), "--manifest", str(manifest_path),
                    "--case", case_id, "--token", token]
        campaign = controller.run_boundary_campaign(
            fixture_module=fixture, owned_ipv4=interface, expectations=expectations,
            subject_argv=subject_argv, output_dir=allowed / "address-campaign",
            child_env=env, context_check=context_check,
            authorized_owned_root=allowed, outer_deadline=deadline)
        if time.monotonic() >= deadline:
            raise RuntimeError("whole preflight deadline")
        report["addressCampaign"] = campaign
        if not campaign["expectedBoundaryPassed"] or not campaign["diagnosticsComplete"]:
            raise RuntimeError("hosted local-fixture campaign did not qualify")
        shutil.copytree(allowed / "address-campaign", output / "address-campaign")
        report["profileSha256"] = sha(profile_path)
        report["syntheticSentinelUnchanged"] = sha(foreign) == foreign_sha
        report["promptProcessesAfter"] = observe()
        report["parentMarkersUnchanged"] = markers == {key: os.environ.get(key) for key in MARKERS}
        report["sourceHashesAfter"] = {relative: sha(source / relative) for relative in SOURCE_HASHES}
        if rc or not all(report["controls"].values()) or not report["syntheticSentinelUnchanged"] or not report["parentMarkersUnchanged"] or report["sourceHashesAfter"] != SOURCE_HASHES:
            raise RuntimeError("synthetic boundary control failed")
        report["status"] = "SYNTHETIC_PREFLIGHT_CONTROLS_PASSED_NOT_CANARY_ADMISSION"
        code = 0
    except BaseException as exc:
        report["failure"] = type(exc).__name__ + ": " + str(exc)
    finally:
        for sock in sockets:
            sock.close()
        report["allOwnedListenersClosed"] = all(sock.fileno() == -1 for sock in sockets)
        if (allowed / "address-campaign").is_dir() and not (output / "address-campaign").exists():
            shutil.copytree(allowed / "address-campaign", output / "address-campaign")
        report["finishedAt"] = now()
        report["rawStreamsRetainedInEphemeralJob"] = True
        report["rawStreamsUploaded"] = True
        # These are only the fixed tool/metadata and synthetic-probe commands.
        # No environment dump, operator values, credential or native app logs.
        raw_output = output / "raw"
        raw_output.mkdir(mode=0o700)
        for path in raw.iterdir():
            if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
                raise RuntimeError("unexpected preflight stream")
            shutil.copyfile(path, raw_output / path.name)
        (output / "preflight-result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(report["status"])
    return code


if __name__ == "__main__":
    sys.exit(main())
