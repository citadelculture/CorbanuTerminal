#!/usr/bin/env python3
"""Unexecuted black-box acceptance probes; no product discovery or credentials."""
import argparse
import errno
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time


def inside(path, root):
    path, root = os.path.realpath(path), os.path.realpath(root)
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def root_record(path):
    path = os.path.abspath(path)
    info = os.stat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise AssertionError("Owned root is not a directory")
    return {
        "path": path,
        "canonical": os.path.realpath(path),
        "mode": stat.S_IMODE(info.st_mode),
        "uid": getattr(info, "st_uid", None),
    }


def receive_exact(stream, expected):
    actual = b""
    while len(actual) < len(expected):
        part = stream.recv(len(expected) - len(actual))
        if not part:
            raise AssertionError("Socket closed before byte exchange completed")
        actual += part
    if actual != expected:
        raise AssertionError("Unexpected socket bytes")


def exercise(root, portable_no_socket=False):
    result = {"root": os.path.abspath(root)}
    with tempfile.TemporaryDirectory(prefix="fixture-", dir=root) as fixture:
        nested = Path(fixture) / ("nested-" + "n" * 16)
        nested.mkdir()
        address = str(nested / "fixture.sock")
        result.update({
            "fixture": fixture,
            "address": address,
            "address_encoded_bytes": len(os.fsencode(address)),
            "address_canonical": os.path.realpath(address),
        })
        if portable_no_socket:
            result["status"] = "portable-no-socket"
            return result
        if not hasattr(socket, "AF_UNIX"):
            result["status"] = "capability-unavailable"
            return result
        stage = "create-socket"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.settimeout(5)
                stage = "bind"
                server.bind(address)
                stage = "exchange"
                server.listen(1)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(5)
                    client.connect(address)
                    peer, _ = server.accept()
                    with peer:
                        peer.settimeout(5)
                        token = b"intent-only-local-socket-control"
                        client.sendall(token)
                        receive_exact(peer, token)
                        peer.sendall(token)
                        receive_exact(client, token)
            result["status"] = "success"
        except OSError as error:
            message = str(error)
            is_length = stage == "bind" and (
                error.errno == errno.ENAMETOOLONG
                or "AF_UNIX path too long" in message
            )
            result.update({
                "status": "path-too-long" if is_length else "capability-or-io-blocked",
                "stage": stage,
                "errno": error.errno,
                "error": message,
            })
    return result


def write_report(path, report, roots):
    path = Path(path).absolute()
    if any(inside(path, item["canonical"]) for item in roots.values()):
        raise AssertionError("Report must be outside every invocation-owned root")
    # Caller owns this output destination. Never reuse another case's report.
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def parse_roots(values):
    roots = {}
    for item in values:
        label, value = item.split("=", 1)
        if label in roots or label == "effective-temp":
            raise AssertionError("Duplicate or reserved root label")
        if value.startswith("env:"):
            value = os.environ[value[4:]]
        roots[label] = root_record(value)
    if not {"profile", "scratch"}.issubset(roots):
        raise AssertionError("Supply observable profile and scratch roots")
    roots["effective-temp"] = root_record(tempfile.gettempdir())
    return roots


def require_unix_privacy(roots):
    if os.name == "nt":
        return
    for item in roots.values():
        if item["uid"] != os.getuid() or item["mode"] & 0o077:
            raise AssertionError("Root is not private to the current Unix user")


def audit(paths, phase):
    reports = [json.loads(Path(path).read_text(encoding="utf-8")) for path in paths]
    for report in reports:
        if report.get("kind") != "child":
            raise AssertionError("Expected an actual child probe report")
        if report["socket"]["status"] not in {"success", "portable-no-socket"}:
            raise AssertionError("Child socket capability was not demonstrated")
        require_unix_privacy(report["roots"])
    for index, report in enumerate(reports):
        for other in reports[index + 1:]:
            for left in report["roots"].values():
                for right in other["roots"].values():
                    if inside(left["canonical"], right["canonical"]) or inside(
                        right["canonical"], left["canonical"]
                    ):
                        raise AssertionError("Invocations share or nest owned roots")
        for previous in report["roots"].values():
            if phase == "live":
                current = root_record(previous["path"])
                if current != previous:
                    raise AssertionError("Root metadata changed while held live")
            elif os.path.lexists(previous["path"]) or os.path.lexists(previous["canonical"]):
                raise AssertionError("Owned root survived invocation cleanup")
    print(json.dumps({
        "phase": phase,
        "reports_checked": len(reports),
        "filesystem_audit": "passed",
        "socket_coverage": [
            report["socket"]["status"] for report in reports
        ],
        "privacy_coverage": "requires-Windows-oracle" if os.name == "nt" else "Unix-mode-and-owner",
    }))


def run_preserving_parent_environment(command, overrides):
    """External-process control only; does not test an in-process wrapper API."""
    original = dict(os.environ)
    child_environment = original.copy()
    for key, value in overrides.items():
        if value is None:
            child_environment.pop(key, None)
        else:
            child_environment[key] = value
    try:
        return subprocess.run(command, env=child_environment, check=False)
    finally:
        if dict(os.environ) != original:
            raise AssertionError("Calling process environment changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    long_parser = sub.add_parser("make-long-root")
    long_parser.add_argument("--base", required=True)
    control = sub.add_parser("control")
    control.add_argument("--root", required=True)
    control.add_argument("--expect", choices=["success", "path-too-long"], required=True)
    control.add_argument("--report", required=True)
    child = sub.add_parser("child")
    child.add_argument("--report", required=True)
    child.add_argument("--owned-root", action="append", default=[])
    child.add_argument("--release-file")
    child.add_argument("--outcome", choices=["success", "failure", "exception"], default="success")
    child.add_argument("--portable-no-socket", action="store_true")
    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("--phase", choices=["live", "cleaned"], required=True)
    audit_parser.add_argument("reports", nargs="+")
    args = parser.parse_args()

    if args.command == "make-long-root":
        base = Path(args.base).resolve(strict=True)
        path = Path(tempfile.mkdtemp(prefix="caller-long-", dir=base))
        while len(os.fsencode(str(path))) <= 512:
            path /= "d" * 72
            path.mkdir(mode=0o700)
        print(path)
        return 0
    if args.command == "audit":
        audit(args.reports, args.phase)
        return 0
    if args.command == "control":
        result = exercise(args.root)
        write_report(args.report, {"kind": "control", "socket": result}, {})
        if result["status"] in {"capability-unavailable", "capability-or-io-blocked"}:
            return 77
        if args.expect == "path-too-long" and result["address_encoded_bytes"] <= 512:
            raise AssertionError("Long-path control did not use the declared long address")
        return 0 if result["status"] == args.expect else 1

    roots = parse_roots(args.owned_root)
    require_unix_privacy(roots)
    if args.release_file and any(
        inside(args.release_file, item["canonical"]) for item in roots.values()
    ):
        raise AssertionError("Release file must be outside invocation-owned roots")
    if args.release_file and Path(args.release_file).exists():
        raise AssertionError("Release file must not exist at child start")
    report = {
        "kind": "child",
        "platform": sys.platform,
        "pid": os.getpid(),
        "roots": roots,
        "socket": exercise(tempfile.gettempdir(), args.portable_no_socket),
        "requested_outcome": args.outcome,
        "ready": True,
    }
    write_report(args.report, report, roots)
    expected = "portable-no-socket" if args.portable_no_socket else "success"
    if report["socket"]["status"] != expected:
        return 77 if "capability" in report["socket"]["status"] else 1
    if args.release_file:
        deadline = time.monotonic() + 60
        while not Path(args.release_file).exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("External harness did not release child")
            time.sleep(0.05)
    if args.outcome == "exception":
        raise RuntimeError("Synthetic child exception; not a wrapper exception test")
    return 19 if args.outcome == "failure" else 0


if __name__ == "__main__":
    sys.exit(main())
