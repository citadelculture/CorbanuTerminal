#!/usr/bin/env python3
"""Exact PR1116 lock generation and formatting; no product builds or tests."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request

from controller import digest, need, write

HERE = Path(__file__).resolve().parent


def regular(path):
    return stat.S_ISREG(path.lstat().st_mode)


def subject_path(source, relative):
    name = Path(relative)
    need(not name.is_absolute() and ".." not in name.parts, "subject_path_escape")
    current = source
    need(stat.S_ISDIR(current.lstat().st_mode), "subject_root_not_directory")
    for part in name.parts[:-1]:
        current /= part
        need(stat.S_ISDIR(current.lstat().st_mode), "subject_parent_not_directory")
    return source / name


def link_records(source, rows, pins):
    expected = {row["path"]: row for row in pins}
    actual = {}
    for row in rows.split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        if mode != "120000":
            continue
        path = os.fsdecode(name)
        need(path in expected, "unexpected_tracked_symlink")
        entry = subject_path(source, path)
        need(stat.S_ISLNK(entry.lstat().st_mode), "symlink_replaced_by_file")
        target = os.fsencode(os.readlink(entry))
        record = {"path": path, "mode": mode, "blob": blob, "targetSha256": hashlib.sha256(target).hexdigest(), "targetBytes": len(target)}
        need(record == expected[path], "symlink_identity_mismatch")
        # The pinned external credential-looking fixture is inert source data.
        # Never resolve, stat, open, copy or publish its target or target text.
        actual[path] = record
    need(set(actual) == set(expected), "tracked_symlink_inventory_mismatch")
    return list(actual.values())


def safe_extract(archive, destination):
    destination.mkdir(exist_ok=False)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        need(len(members) <= 50000 and sum(m.size for m in members) <= 2 * 1024**3, "tool_archive_expansion_bound")
        for member in members:
            name = PurePosixPath(member.name)
            need(not name.is_absolute() and ".." not in name.parts, "tool_archive_path_escape")
            need(member.isfile() or member.isdir() or member.issym() or member.islnk(), "tool_archive_special_type")
            if member.issym() or member.islnk():
                target = PurePosixPath(member.linkname)
                need(not target.is_absolute(), "tool_archive_absolute_link")
                joined = name.parent / target if member.issym() else target
                depth = 0
                for part in joined.parts:
                    depth += -1 if part == ".." else 0 if part == "." else 1
                    need(depth >= 0, "tool_archive_link_escape")
        source.extractall(destination, members=members, filter="data")


def snapshot_generated(source, export, label):
    records = {}
    for name in ("MODULE.bazel.lock", "codex-rs/Cargo.lock"):
        path = subject_path(source, name)
        need(regular(path) and path.stat().st_size <= 16 * 1024**2, "unsafe_generated_file")
        destination = export / label / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        need(digest(path) == digest(destination), "generated_copy_mismatch")
        records[name] = {"sha256": digest(destination), "bytes": destination.stat().st_size}
    write(export / (label + ".json"), records)
    return records


def check_scope(paths, allowed):
    need(set(paths) <= set(allowed), "unexpected_tracked_source_delta")


def main(root, export):
    source = HERE.parent / "subject"
    pins = json.loads((HERE / "source-pins.json").read_text())
    tools = json.loads((HERE / "tool-pins.json").read_text())
    result = {"schema": "pr1116-lock-worker-v1", "completed": False, "failureCode": None, "productQualified": False, "productBuildOrTestCommandsRequested": False, "base": pins["base"], "phases": [], "downloads": []}
    env = os.environ.copy()
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false", "GIT_NO_LAZY_FETCH": "1", "PR1116_RUN_ROOT": str(root), "CARGO_HOME": str(root / "cargo-home"), "UV_CACHE_DIR": str(root / "cache/uv"), "XDG_CACHE_HOME": str(root / "cache/xdg"), "UV_PYTHON": sys.executable, "UV_PYTHON_DOWNLOADS": "never", "BAZEL_OUTPUT_USER_ROOT": str(root / "bazel-state"), "BAZEL_REPOSITORY_CACHE": str(root / "cache/repos"), "BAZEL_REPO_CONTENTS_CACHE": str(root / "cache/contents")})
    need(not any(key in env for key in ("GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "BUILDBUDDY_API_KEY")), "unexpected_credential_environment")
    command_number = 0

    def run(argv, phase, timeout=120, capture=False, cwd=source):
        nonlocal command_number
        command_number += 1
        start = time.monotonic()
        log = export / f"{command_number:02d}-{phase}.log"
        row = {"phase": phase, "command": [str(x).replace(str(root), "<RUN_ROOT>").replace(str(source), "<SUBJECT>").replace(str(HERE), "<METHOD>") for x in argv], "exitCode": None, "log": log.name}
        result["phases"].append(row)
        write(export / "worker-progress.json", {"activePhase": phase, "command": row["command"]})
        try:
            with log.open("wb") as handle:
                process = subprocess.run(argv, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT, timeout=timeout)
            row["exitCode"] = process.returncode
        finally:
            row["elapsedSeconds"] = round(time.monotonic() - start, 3)
            row["logSha256"] = digest(log)
        need(log.stat().st_size <= 64 * 1024**2, "command_log_bound")
        need(process.returncode == 0, "command_failed_" + phase)
        return log.read_bytes() if capture else b""

    def git(*arguments):
        return run(["git", *arguments], "git-" + arguments[0], capture=True)

    def source_hashes():
        answer = {}
        for name, expected in pins["candidateFiles"].items():
            path = subject_path(source, name)
            need(regular(path), "pinned_source_not_regular")
            answer[name] = digest(path)
            need(answer[name] == expected, "candidate_source_hash_changed")
        return answer

    try:
        need(source.is_dir() and not source.is_symlink(), "subject_not_checkout")
        need(git("rev-parse", "HEAD").decode().strip() == pins["base"], "subject_head_mismatch")
        need(not git("status", "--porcelain=v1", "--untracked-files=all"), "dirty_initial_subject")
        tree = git("ls-tree", "-rz", "HEAD", "--", *[row["path"] for row in pins["symlinks"]])
        result["symlinksBefore"] = link_records(source, tree, pins["symlinks"])
        for name, expected in pins["baseFiles"].items():
            path = subject_path(source, name)
            need(regular(path) and digest(path) == expected, "baseline_source_hash_mismatch")
        snapshot_generated(source, export, "base-generated")
        need(digest(HERE / "subject.patch") == pins["patchSha256"], "patch_hash_mismatch")
        git("apply", "--check", str(HERE / "subject.patch"))
        git("apply", str(HERE / "subject.patch"))
        result["candidateBefore"] = source_hashes()
        snapshot_generated(source, export, "candidate-generated")
        prefix = root / "tools"
        binaries = prefix / "bin"
        binaries.mkdir(parents=True)
        downloads = root / "downloads"
        downloads.mkdir()
        env["PATH"] = str(binaries) + ":/usr/bin:/bin"
        env["RUSTC"] = str(binaries / "rustc")
        env["RUSTDOC"] = str(binaries / "rustdoc")
        for number, tool in enumerate(tools["downloads"]):
            need(tool["url"].startswith("https://") and tool.get("bytes") and tool["bytes"] < 256 * 1024**2, "invalid_tool_download_pin")
            archive = downloads / str(number)
            count = 0
            with urllib.request.urlopen(tool["url"], timeout=60) as response, archive.open("xb") as handle:
                while chunk := response.read(1024**2):
                    count += len(chunk)
                    need(count <= tool["bytes"], "tool_download_size_exceeded")
                    handle.write(chunk)
            need(count == tool["bytes"] and digest(archive) == tool["sha256"], "tool_download_digest_mismatch")
            result["downloads"].append({"name": tool["name"], "version": tool["version"], "url": tool["url"], "sha256": digest(archive), "bytes": count})
            write(export / "download-receipts.json", result["downloads"])
            if tool["kind"] == "raw":
                need(tool["name"] == "bazel", "unexpected_raw_tool")
                shutil.copyfile(archive, binaries / "bazel-real")
                (binaries / "bazel-real").chmod(0o755)
                continue
            extracted = root / ("unpack-" + str(number))
            safe_extract(archive, extracted)
            if tool["kind"] == "rust-component":
                component = extracted / tool["root"]
                need(regular(component / "install.sh") and regular(component / "components"), "rust_installer_layout")
                need((component / "components").read_text().strip() == tool["component_file_must_equal"], "rust_component_mismatch")
                run(["sh", str(component / "install.sh"), "--prefix=" + str(prefix), "--disable-ldconfig"], "install-" + tool["name"], timeout=120, cwd=component)
            else:
                need(tool["kind"] == "tar", "unknown_tool_archive_kind")
                matches = [p for p in extracted.rglob(tool["member"]) if p.name == tool["member"] and regular(p)]
                need(len(matches) == 1, "tool_archive_member_ambiguity")
                target = binaries / tool["executable"]
                shutil.copyfile(matches[0], target)
                target.chmod(0o755)
        shutil.copyfile(HERE / "bazel.py", binaries / "bazel")
        (binaries / "bazel").chmod(0o755)
        versions = {}
        for name, prefix_text in {"rustc": "rustc 1.99.1 ", "cargo": "cargo 1.99.1 ", "rustfmt": "rustfmt 1.10.0-", "just": "just 1.58.0", "uv": "uv 0.11.3 ", "dotslash": "DotSlash 0.5.9", "bazel-real": "bazel 9.0.0"}.items():
            path = binaries / name
            need(regular(path), "installed_tool_not_regular")
            version = run([str(path), "--version"], "version-" + name, capture=True).decode().strip()
            need(version.startswith(prefix_text) or (name == "rustfmt" and version == prefix_text.removesuffix("-")), "installed_version_mismatch_" + name)
            versions[name] = {"version": version, "sha256": digest(path)}
        for name in ("python3", "git", "bash"):
            path = Path(shutil.which(name, path=env["PATH"]))
            version = run([str(path), "--version"], "version-" + name, capture=True).decode().splitlines()[0]
            versions[name] = {"version": version, "sha256": digest(path)}
        write(export / "tool-identity.json", versions)
        run(["just", "bazel-lock-update"], "bazel-lock-update", timeout=900)
        result["afterUpdateGenerated"] = snapshot_generated(source, export, "after-update-generated")
        check_scope(git("diff", "--name-only").decode().splitlines(), pins["allowedChangedFiles"])
        result["candidateAfterUpdate"] = source_hashes()
        run(["just", "fmt"], "full-fmt", timeout=300)
        result["afterFormatGenerated"] = snapshot_generated(source, export, "after-format-generated")
        check_scope(git("diff", "--name-only").decode().splitlines(), pins["allowedChangedFiles"])
        result["candidateAfterFormat"] = source_hashes()
        run(["just", "bazel-lock-check"], "bazel-lock-check", timeout=300)
        result["afterCheckGenerated"] = snapshot_generated(source, export, "after-check-generated")
        need(result["afterFormatGenerated"] == result["afterCheckGenerated"], "lock_check_mutated_generated_files")
        result["changedFiles"] = git("diff", "--name-only").decode().splitlines()
        check_scope(result["changedFiles"], pins["allowedChangedFiles"])
        git("diff", "--check")
        result["candidateFinal"] = source_hashes()
        result["symlinksAfter"] = link_records(source, tree, pins["symlinks"])
        need(not git("ls-files", "--others", "--exclude-standard"), "unexpected_untracked_subject_files")
        (export / "complete-generated.patch").write_bytes(git("diff", "--binary"))
        result["generatedPatchSha256"] = digest(export / "complete-generated.patch")
        result["moduleLockChanged"] = "MODULE.bazel.lock" in result["changedFiles"]
        result["completed"] = True
        result["disposition"] = "Generation/check/format completed; root must inspect and adopt the actual delta. GNU/musl build and test qualification remains unexecuted."
    except BaseException as error:
        result["failureCode"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        try:
            result["finalGeneratedSnapshot"] = snapshot_generated(source, export, "final-generated")
        except BaseException as error:
            result["snapshotFailure"] = type(error).__name__
            result["completed"] = False
        write(export / "worker-result.json", result)
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
