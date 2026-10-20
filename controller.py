#!/usr/bin/env python3
"""Inert by default. Exact six ordinary-Jest runs on disposable hosted Linux only."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from owned_process import (Campaign, Hold, MARKERS, GIB, children, environment,
                           normalized, orphan_reaping_fixture_argv, safe_extract, save, sha)

PINS = {"base": "78dd811d6e3718140c938ad4839968d9995fd5ac",
        "head": "9f404feeb0f63347209ec5d97a277d86101921be"}
RUST_TREE = "914d20b44d7f06abb02c640c257232150a27c81e"
REPOSITORY = "citadelculture/CorbanuTerminal"
REF = "refs/heads/codex/sdk958-hosted-recovery-20261020"
TARGET = "Codex throws ThreadRunError on turn failures"
MAX_REPORT = 8 * 1024 * 1024
MAX_BINARY = 512 * 1024 * 1024


def parse_jest(data):
    """Parse actual ordinary Jest JSON. Never manufacture a product observation."""
    if len(data) > MAX_REPORT:
        raise Hold("jest_report_bound")
    report = json.loads(data)
    if (report.get("success") is not True or report.get("numPassedTests") != 1
            or report.get("numFailedTests") != 0 or report.get("numFailedTestSuites") != 0
            or report.get("numPassedTestSuites") != 1 or report.get("wasInterrupted") is True
            or len(report.get("testResults", [])) != 1):
        raise Hold("focused_jest_result_not_success")
    suite = report["testResults"][0]
    if suite.get("status") != "passed" or not suite.get("name", "").endswith("/tests/run.test.ts"):
        raise Hold("focused_suite_identity")
    selected = []
    excluded = 0
    for case in suite.get("assertionResults", []):
        if case.get("fullName") == TARGET:
            selected.append(case)
        elif case.get("status") in ("pending", "todo", "skipped"):
            excluded += 1
        else:
            raise Hold("unexpected_executed_case")
    if len(selected) != 1:
        raise Hold("focused_case_missing_or_duplicate")
    case = selected[0]
    duration = case.get("duration")
    if (case.get("status") != "passed" or case.get("failureMessages")
            or type(duration) not in (int, float) or not 0 <= duration < 5000
            or case.get("invocations", 1) != 1):
        raise Hold("case_failed_skipped_retried_or_timeout")
    return {"name": TARGET, "status": "passed", "durationMilliseconds": duration,
            "ordinaryJestTimeoutMilliseconds": 5000, "executedCases": 1,
            "filterExcludedCases": excluded, "sourceAssertionsPassed": [
                "thread.run rejects with stream disconnected before completion:",
                "recorded proxy request count equals one"],
            "assertionEvidence": "Pinned actual test source plus successful ordinary Jest case; no request/event observer injected."}


def jest_argv(node, pnpm, source, report, cache):
    return [str(node), str(pnpm), "--dir", str(source / "sdk/typescript"), "test",
            "--runInBand", "--runTestsByPath", "tests/run.test.ts", "--testNamePattern",
            "^" + TARGET + "$", "--json", "--outputFile", str(report),
            "--cacheDirectory", str(cache), "--ci", "--watch=false"]


def verify_source(c, label, pin, manifest, candidate=False):
    if c.git(label + "-head", "rev-parse", "HEAD").decode().strip() != pin:
        raise Hold("wrong_exact_source_pin")
    if c.git(label + "-rust-tree", "rev-parse", "HEAD:codex-rs").decode().strip() != RUST_TREE:
        raise Hold("native_rust_tree_mismatch")
    for name, expected in manifest["sourceInputs"].items():
        if sha(c.source / name) != expected:
            raise Hold("source_input_changed")
    if candidate:
        for item in manifest["files"]:
            if sha(c.source / item["path"]) != item["candidateSha256"]:
                raise Hold("candidate_source_changed")
    changed = c.git(label + "-status", "diff", "--name-only", "HEAD").decode().splitlines()
    allowed = {f["path"] for f in manifest["files"]} if candidate else set()
    if set(changed) != allowed:
        raise Hold("unexpected_tracked_source_changes")
    untracked = c.git(label + "-untracked", "ls-files", "--others", "--exclude-standard").strip()
    if untracked:
        raise Hold("unexpected_untracked_source")
    return hashlib.sha256(c.git(label + "-diff", "diff", "--binary", "HEAD")).hexdigest()


def acquire_tools(c, tools):
    for item in tools["archives"]:
        dest = c.root / "downloads" / item["filename"]
        c.run("fetch-" + item["id"], ["/usr/bin/curl", "-q", "--fail", "--silent", "--show-error",
              "--location", "--proto", "=https", "--proto-redir", "=https", "--retry", "0",
              "--connect-timeout", "20", "--max-time", "300", "--max-filesize", str(item["maxBytes"]),
              "--output", str(dest), item["url"]], 310)
        expected = item.get("sha256") or item["sha512"]
        digest = sha(dest) if "sha256" in item else hashlib.sha512(dest.read_bytes()).hexdigest()
        if dest.stat().st_size > item["maxBytes"] or digest != expected:
            raise Hold("download_digest_or_size_mismatch")
        if item["kind"] == "v8-asset":
            c.env[item["variable"]] = str(dest)
            continue
        unpack = c.root / "unpacked" / item["id"]
        safe_extract(dest, unpack)
        if item["kind"] == "rust-component":
            installers = list(unpack.glob("*/install.sh"))
            if len(installers) != 1:
                raise Hold("rust_installer_identity")
            c.run("install-" + item["id"], ["/bin/sh", str(installers[0]),
                  "--prefix=" + str(c.root / "toolchain"), "--disable-ldconfig"], 180)
        elif item["kind"] == "pnpm-tree":
            if not (unpack / "package/bin/pnpm.cjs").is_file():
                raise Hold("pnpm_archive_layout")
        else:
            name = "node" if item["kind"] == "node-tree" else item["binary"]
            matches = [p for p in unpack.rglob(name) if p.is_file() and not p.is_symlink()]
            if len(matches) != 1:
                raise Hold("tool_binary_identity")
            target = c.root / "bin" / name
            shutil.copyfile(matches[0], target)
            target.chmod(0o700)
    c.env["RUSTC"] = str(c.root / "toolchain/bin/rustc")
    c.env["RUSTDOC"] = str(c.root / "toolchain/bin/rustdoc")
    node = c.root / "bin/node"
    pnpm = c.root / "unpacked/pnpm/package/bin/pnpm.cjs"
    for name, version in tools["versions"].items():
        executable = c.root / ("toolchain/bin" if name in ("rustc", "cargo", "rustfmt") else "bin") / name
        args = [str(node), str(pnpm), "--version"] if name == "pnpm" else [str(executable), "--version"]
        raw, _ = c.run("version-" + name, args, 30)
        if version not in (raw / "stdout").read_text():
            raise Hold("tool_version_mismatch")
    return node, pnpm


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dispatch", action="store_true", required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.binaries = args.binaries.resolve()
    if (platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0
            or sys.version_info < (3, 12) or os.environ.get("RUNNER_OS") != "Linux"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REF") != REF or os.environ.get("GITHUB_EVENT_NAME") != "push"
            or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"):
        raise Hold("fresh_nonroot_hosted_linux_required")
    # Presence holds, including empty values. Never modify inherited host controls.
    if any(k in os.environ for k in MARKERS):
        raise Hold("inherited_security_marker_present")
    control = args.control.resolve()
    admission = json.loads((control / "admission.json").read_text())
    if admission.get("approved") is not True:
        raise Hold("method_review_pending")
    for name in ("controller.py", "owned_process.py", "source-manifest.json", "tools-pins.json"):
        if admission.get("files", {}).get(name) != sha(control / name):
            raise Hold("admission_hash_mismatch")
    manifest = json.loads((control / "source-manifest.json").read_text())
    tools = json.loads((control / "tools-pins.json").read_text())
    if (manifest.get("schema") != "sdk958-hosted-source-v1" or manifest.get("nativePins") != PINS
            or manifest.get("nativeRustTree") != RUST_TREE or manifest.get("targetTest") != TARGET
            or manifest.get("timeoutMilliseconds") != 5000 or manifest.get("runsPerPin") != 3
            or {f["path"] for f in manifest.get("files", [])} != {
                "sdk/typescript/tests/run.test.ts", "sdk/typescript/tests/testCodex.ts"}):
        raise Hold("source_manifest_contract")
    for row in manifest["files"]:
        if sha(control / row["payload"]) != row["candidateSha256"]:
            raise Hold("payload_changed")
    patch = control / manifest["patch"]["path"]
    if sha(patch) != manifest["patch"]["sha256"]:
        raise Hold("patch_changed")
    identity = os.environ.get("GITHUB_RUN_ID", "")
    if not identity.isdecimal():
        raise Hold("run_identity_missing")
    root = Path("/tmp") / ("sdk958-" + identity)
    root.mkdir(mode=0o700)
    for name in ("cargo-home", "unused-rustup", "tmp", "empty-config", "uv-cache", "dotslash-cache",
                 "bin", "toolchain", "downloads", "unpacked", "raw", "retained", "pnpm-store", "npm-cache"):
        (root / name).mkdir(mode=0o700)
    (root / "empty-netrc").write_text("")
    for name in ("empty-user.npmrc", "empty-global.npmrc"):
        (root / name).write_text("")
    args.output.mkdir(mode=0o700)
    args.binaries.mkdir(mode=0o700)
    env = environment(root)
    env.update({"CI": "true", "NPM_CONFIG_USERCONFIG": str(root / "empty-user.npmrc"),
                "NPM_CONFIG_GLOBALCONFIG": str(root / "empty-global.npmrc"),
                "NPM_CONFIG_CACHE": str(root / "npm-cache"),
                "CARGO_PROFILE_DEV_SMALL_DEBUG_ASSERTIONS": "true"})
    homes = {k: (k in os.environ, os.environ.get(k)) for k in ("HOME", "CODEX_HOME")}
    c = Campaign(root, root, env, args.output, args.binaries)
    result = {"schema": "sdk958-hosted-result-v1", "status": "INCOMPLETE", "qualified": False,
              "taskId": manifest["taskId"], "nativePins": PINS, "runId": identity,
              "controllerSha256": sha(__file__), "sourceManifestSha256": sha(control / "source-manifest.json"),
              "toolsPinsSha256": sha(control / "tools-pins.json"), "commands": c.rows,
              "runs": [], "binaries": {}, "limits": manifest["limits"],
              "nativeMacOSIncidentResolved": False, "credentialsForwarded": False,
              "rawLocalReceiptsUploaded": False, "ordinaryRunnerUnchanged": True}
    code = 1
    try:
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise Hold("owned_subreaper_unavailable")
        if shutil.disk_usage(root).free < 30 * GIB:
            raise Hold("initial_disk_floor")
        _, pre = c.run("owned-orphan-preflight", orphan_reaping_fixture_argv(), 10)
        if pre["exitCode"] != 0 or len(pre["completionDescendants"]["reapedExited"]) != 1:
            raise Hold("owned_orphan_preflight_failed")
        node, pnpm = acquire_tools(c, tools)
        sources = {}
        for label, pin in PINS.items():
            src = root / ("source-" + label)
            src.mkdir()
            c.source = src
            c.git("init-" + label, "init", "--quiet")
            c.run("fetch-source-" + label, ["/usr/bin/git", "-c", "credential.helper=", "fetch",
                  "--depth=1", "--no-tags", "https://github.com/CorbanuCore/CorbanuTerminal.git", pin], 900)
            c.git("checkout-" + label, "checkout", "--detach", pin)
            verify_source(c, "pristine-" + label, pin, manifest)
            cfg = c.git("local-config-" + label, "config", "--local", "--name-only", "--list").decode()
            if re.search(r"extraheader|credential|insteadof|sshcommand|include\.|hookspath|fsmonitor", cfg, re.I):
                raise Hold("checkout_auth_config")
            sources[label] = src
        sdk = sources["head"]
        c.source = sdk
        for item in manifest["files"]:
            if sha(sdk / item["path"]) != item["originalSha256"]:
                raise Hold("original_test_hash")
        c.git("patch-check", "apply", "--check", str(patch))
        c.git("patch-apply", "apply", str(patch))
        verify_source(c, "patched-sdk", PINS["head"], manifest, True)
        c.run("sdk-locked-install", [str(node), str(pnpm), "--dir", str(sdk), "--filter",
              "@agticorp/pfterminal-sdk", "install", "--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile",
              "--store-dir", str(root / "pnpm-store"), "--reporter=append-only", "--network-concurrency=2",
              "--fetch-retries=0", "--fetch-timeout=60000", "--config.manage-package-manager-versions=false",
              "--config.update-notifier=false", "--config.audit=false", "--config.fund=false"], 900)
        c.run("typescript-format-check", [str(node), str(pnpm), "--dir", str(sdk / "sdk/typescript"),
              "exec", "prettier", "--check", "tests/run.test.ts", "tests/testCodex.ts"], 180)
        for label, pin in PINS.items():
            c.source = sources[label]
            before = verify_source(c, label + "-pre-format", pin, manifest, label == "head")
            _, fmt = c.run("full-format-" + label, [str(root / "bin/just"), "fmt"], 900, allow_failure=True)
            delta = c.git("format-delta-" + label, "diff", "--binary", "HEAD")
            (args.output / ("format-" + label + ".patch")).write_bytes(normalized(delta, c.replacements))
            if fmt["exitCode"] != 0 or hashlib.sha256(delta).hexdigest() != before:
                raise Hold("format_changed_frozen_source")
            verify_source(c, label + "-post-format", pin, manifest, label == "head")
        for label, pin in PINS.items():
            c.source = sources[label]
            target = root / ("target-" + label)
            if target.exists():
                raise Hold("native_target_not_fresh")
            c.env["CARGO_TARGET_DIR"] = str(target)
            if shutil.disk_usage(root).free < 30 * GIB:
                raise Hold("compile_disk_floor")
            c.source = sources[label] / "codex-rs"
            c.env.pop("CARGO_NET_OFFLINE", None)
            c.run("locked-fetch-" + label, [str(root / "toolchain/bin/cargo"), "fetch", "--locked",
                  "--manifest-path", str(sources[label] / "codex-rs/Cargo.toml"),
                  "--target", "x86_64-unknown-linux-gnu"], 900)
            c.env["CARGO_NET_OFFLINE"] = "true"
            c.run("native-build-" + label, [str(root / "toolchain/bin/cargo"), "build", "--locked", "--offline",
                  "--profile", "dev-small", "--manifest-path", str(sources[label] / "codex-rs/Cargo.toml"),
                  "-p", "codex-cli", "--bin", "corbanu", "-p", "codex-code-mode-host",
                  "--bin", "codex-code-mode-host"], 4200)
            c.source = sources[label]
            verify_source(c, label + "-post-build", pin, manifest, label == "head")
            retained = args.binaries / label
            retained.mkdir()
            result["binaries"][label] = {"sourcePin": pin, "rustTree": RUST_TREE, "files": []}
            for name in ("corbanu", "codex-code-mode-host"):
                built = target / "dev-small" / name
                if built.is_symlink() or not built.is_file() or built.stat().st_size > MAX_BINARY:
                    raise Hold("native_binary_missing_or_bound")
                with built.open("rb") as handle:
                    if handle.read(4) != b"\x7fELF":
                        raise Hold("native_binary_not_elf")
                copy = retained / name
                shutil.copy2(built, copy)
                if sha(copy) != sha(built):
                    raise Hold("binary_copy_mismatch")
                result["binaries"][label]["files"].append({"name": name, "sha256": sha(copy), "bytes": copy.stat().st_size})
            c.env["CODEX_EXEC_PATH"] = str(retained / "corbanu")
            c.source = sdk
            for index in range(3):
                stage = label + ("-first-process" if index == 0 else "-warm-" + str(index))
                report = root / (stage + ".json")
                if report.exists():
                    raise Hold("stale_jest_report")
                try:
                    raw, command = c.run("jest-" + stage,
                        jest_argv(node, pnpm, sdk, report, root / ("jest-cache-" + label)), 90, allow_failure=True)
                finally:
                    # Retain bounded raw JSON even on a failed/interrupted runner.
                    if report.is_file():
                        with report.open("rb") as handle:
                            captured = handle.read(MAX_REPORT)
                        (args.output / (stage + ".jest.json")).write_bytes(normalized(captured, c.replacements))
                if command["exitCode"] != 0 or not report.is_file() or report.stat().st_size > MAX_REPORT:
                    raise Hold("jest_command_or_report_failed")
                outcome = parse_jest(report.read_bytes())
                outcome.update({"nativePin": pin, "runLabel": stage,
                                "jestJsonRawSha256": sha(report), "runnerWallSeconds": command["seconds"],
                                "nativeBinarySha256": result["binaries"][label]["files"][0]["sha256"]})
                result["runs"].append(outcome)
                verify_source(c, stage + "-post-test", PINS["head"], manifest, True)
            # Only this completed disposable build target is deleted; binaries and
            # source/log/report evidence remain. No shared target/cache is touched.
            if children() or target.parent != root or target.name != "target-" + label or target.is_symlink():
                raise Hold("owned_target_cleanup_identity")
            shutil.rmtree(target)
        if len(result["runs"]) != 6:
            raise Hold("six_actual_runs_required")
        result["status"], result["qualified"], code = "BOTH_EXACT_PINS_ORDINARY_JEST_SIX_PASSED", True, 0
    except BaseException as exc:
        result["failureCode"] = str(exc) if isinstance(exc, Hold) else "controller_" + type(exc).__name__
    finally:
        result["ownedDescendantsGone"] = not children()
        result["inheritedHomeIdentityPreserved"] = homes == {k: (k in c.env, c.env.get(k)) for k in homes}
        result["inheritedSecurityMarkersPreserved"] = all(k not in os.environ and k not in c.env for k in MARKERS)
        if not all(result[k] for k in ("ownedDescendantsGone", "inheritedHomeIdentityPreserved", "inheritedSecurityMarkersPreserved")):
            result["status"], result["qualified"], code = "INCOMPLETE", False, 1
        save(args.output / "qualification-result.json", result)
        print(result["status"])
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("HOSTED_NOT_STARTED:" + (str(exc) if isinstance(exc, Hold) else type(exc).__name__))
        sys.exit(1)
