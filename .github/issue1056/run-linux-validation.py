#!/usr/bin/env python3
"""Fixed Issue1056 hosted-Linux validation; inert until root freezes public pins."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import tarfile
import time

CASES = [
    "placeholder_journal::tests::a_path_another_run_made_is_recorded_as_used_and_nothing_else",
    "placeholder_journal::tests::a_path_another_run_was_about_to_make_is_recorded_as_used",
    "placeholder_journal::tests::a_child_of_a_pending_placeholder_folder_is_recorded_as_used",
]
BRANCH = "refs/heads/codex/issue1056-linux-validation-v2-20261020"
REPO = "citadelculture/CorbanuTerminal"
MAX_RAW_BYTES = 4 * 1024**2
MAX_ARTIFACT_BYTES = 20 * 1024**2
CONTROL_KEYS = ("HOME", "CODEX_HOME", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def group_exists(proc):
    try:
        os.killpg(proc.pid, 0)
        return True
    except ProcessLookupError:
        return False
    # PermissionError remains an error, never evidence that a group disappeared.


def cleanup(proc):
    result = {"groupGone": False, "directChildReaped": False, "error": None}
    try:
        proc.poll()
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if not group_exists(proc):
                break
            os.killpg(proc.pid, sig)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                proc.poll()
                if not group_exists(proc):
                    break
                time.sleep(0.05)
        proc.wait(timeout=5)
        result["directChildReaped"] = True
        result["groupGone"] = not group_exists(proc)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    return result


def test_results(text):
    """Separate actual status rows from Nextest's repeated final presentation."""
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    observed, presentation, summaries = {}, {}, []
    final = False
    for line in text.splitlines():
        if re.search(r"\bSummary\b", line):
            summaries.append(line)
            final = True
        for name in CASES:
            if line.rstrip().endswith("codex-linux-sandbox " + name):
                match = re.match(r"^\s*(PASS|FAIL|SKIP|FLAKY|TIMEOUT|LEAK)\s+\[", line)
                if match:
                    (presentation if final else observed).setdefault(name, []).append(match[1])
    starts = re.findall(r"Starting\s+(\d+) tests? across\s+(\d+) binar(?:y|ies)", text)
    counts = re.findall(r"Summary[^\n]*?\b(\d+) tests? run:", text)
    passes = re.findall(r"Summary[^\n]*?tests? run:\s*(\d+) passed", text)
    require(starts == [("3", "1")] and counts == ["3"] and passes == ["3"]
            and len(summaries) == 1, "Incomplete test selection/summary")
    require(observed == {name: ["PASS"] for name in CASES}, "Missing/duplicate/non-passing case")
    require(all(observed.get(name) == statuses for name, statuses in presentation.items()),
            "Final presentation conflicts with actual cases")
    require(not re.search(r"\b(?:RETRY|FLAKY|TIMEOUT|LEAK)\b|\bTRY\s+\d+|"
                          r"Sandbox-dependent test skipped:|Skipping test because", text),
            "Retry, timeout, leak or runtime-skipped body")
    return {"observedCases": observed, "finalPresentationCases": presentation,
            "summaryLines": summaries, "selectedPasses": 3, "selectedSkips": 0, "retries": 0}


class Campaign:
    def __init__(self, evidence, work, env):
        self.evidence, self.work, self.env = evidence, work, env
        self.deadline = time.monotonic() + 2400
        self.raw_bytes = 0
        self.results = []

    def run(self, name, argv, cwd, seconds, test_stage=False):
        started = time.time()
        require(time.monotonic() < self.deadline, "Whole setup/build campaign deadline")
        result = {"name": name, "command": argv, "startedAtUnix": started,
                  "exitCode": None, "stopReason": None, "completeOutput": True}
        proc = None
        execution_start = None
        starting_rows = 0
        start_buffer = ""
        try:
            with (self.evidence / (name + ".stdout")).open("xb") as stdout, \
                    (self.evidence / (name + ".stderr")).open("xb") as stderr, \
                    (self.evidence / (name + ".session")).open("xb") as session:
                session.write(("$ " + shlex.join(argv) + "\n").encode())
                proc = subprocess.Popen(argv, cwd=cwd, env=self.env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, start_new_session=True)
                deadline = min(self.deadline, time.monotonic() + seconds)
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout, selectors.EVENT_READ, stdout)
                    selector.register(proc.stderr, selectors.EVENT_READ, stderr)
                    while selector.get_map():
                        if time.monotonic() >= deadline:
                            result["stopReason"] = "command_deadline"
                            break
                        if execution_start is not None and time.monotonic() - execution_start >= 120:
                            result["stopReason"] = "execution_deadline"
                            break
                        if shutil.disk_usage(self.work).free < 4 * 1024**3:
                            result["stopReason"] = "disk_reserve"
                            break
                        for key, _ in selector.select(0.2):
                            block = os.read(key.fileobj.fileno(), 65536)
                            if not block:
                                selector.unregister(key.fileobj)
                                continue
                            key.data.write(block)
                            session.write(block)
                            self.raw_bytes += len(block)
                            if test_stage and key.fileobj is proc.stderr:
                                start_buffer += block.decode("utf-8", errors="replace")
                                lines = start_buffer.split("\n")
                                start_buffer = lines.pop()
                                for line in lines:
                                    if re.search(r"\bStarting\s+\d+\s+tests?\s+across", line):
                                        starting_rows += 1
                                        if execution_start is None:
                                            execution_start = time.monotonic()
                            if self.raw_bytes > MAX_RAW_BYTES:
                                result["stopReason"] = "captured_output_limit"
                                break
                        if result["stopReason"]:
                            break
                if result["stopReason"]:
                    result["completeOutput"] = False
                else:
                    proc.wait(timeout=max(0.1, deadline - time.monotonic()))
                result["exitCode"] = proc.poll()
                session.write(("\nexit=" + str(result["exitCode"]) + "\n").encode())
        except Exception as exc:
            result["error"] = type(exc).__name__ + ": " + str(exc)
        finally:
            if proc is not None:
                result["cleanup"] = cleanup(proc)
                result["exitCode"] = proc.returncode
                proc.stdout.close()
                proc.stderr.close()
            result["finishedAtUnix"] = time.time()
            result["startingRows"] = starting_rows
            result["executionClockObserved"] = execution_start is not None
            result["executionElapsedSeconds"] = (
                None if execution_start is None else time.monotonic() - execution_start
            )
            result["streams"] = {
                suffix: {"sha256": sha(self.evidence / (name + suffix)),
                         "bytes": (self.evidence / (name + suffix)).stat().st_size}
                for suffix in (".stdout", ".stderr", ".session")
                if (self.evidence / (name + suffix)).is_file()
            }
            save(self.evidence / (name + "-result.json"), result)
            self.results.append(result)
        require(result.get("exitCode") == 0 and not result.get("error")
                and result["stopReason"] is None and result["completeOutput"]
                and result.get("cleanup", {}).get("groupGone")
                and result["cleanup"]["directChildReaped"]
                and result["cleanup"]["error"] is None, name + " failed or cleanup unresolved")
        if test_stage:
            require(starting_rows == 1 and execution_start is not None
                    and result["executionElapsedSeconds"] < 120, "Execution clock missing/exceeded")
        return result


def main():
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Hosted Linux x86_64 only")
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_REF") == BRANCH
            and os.environ.get("GITHUB_EVENT_NAME") == "push", "Wrong CI identity")
    source = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    own = Path(os.environ["RUNNER_TEMP"]).resolve()
    evidence, work = own / "issue1056-evidence", own / "issue1056-work"
    evidence.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    result = {"qualified": False, "scope": "Three exact synthetic Linux Uses cases only",
              "sourceChanged": None, "noHistoricalFailureOrFlakeRateClaim": True}
    try:
        pins_path = source / ".github/issue1056/qualification-pins.json"
        pins = json.loads(pins_path.read_text())
        require(pins["status"] == "ROOT_APPROVED_FROZEN_CI_PINS", "Unreleased preparation")
        require(pins["cases"] == CASES and pins["runnerSha256"] == sha(__file__), "Wrong source/case pins")
        require(pins["minimumInitialFreeGiB"] == 12 and pins["stopFreeGiB"] == 4, "Capacity policy changed")
        require(shutil.disk_usage(work).free >= 12 * 1024**3, "Hosted build reserve below 12 GiB")
        workflows = sorted(p.name for p in (source / ".github/workflows").iterdir()
                           if p.suffix in (".yml", ".yaml"))
        require(workflows == ["issue1056-linux-validation.yml"], "Unrelated workflow in validation overlay")
        require(sha(source / ".github/workflows/issue1056-linux-validation.yml") == pins["workflowSha256"],
                "Workflow changed")
        env = {key: os.environ[key] for key in (
            *CONTROL_KEYS, "PATH", "LANG", "LC_ALL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"
        ) if key in os.environ}
        for name in ("cargo", "rustup", "target", "tmp", "bin", "config"):
            (work / name).mkdir(mode=0o700)
        (work / "empty.netrc").touch(mode=0o600)
        env.update(CARGO_HOME=str(work / "cargo"), RUSTUP_HOME=str(work / "rustup"),
                   CARGO_TARGET_DIR=str(work / "target"), CARGO_BUILD_JOBS="4",
                   CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
                   TMPDIR=str(work / "tmp"), XDG_CONFIG_HOME=str(work / "config"),
                   NETRC=str(work / "empty.netrc"), GIT_CONFIG_GLOBAL="/dev/null",
                   GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/usr/bin/false",
                   INSTA_UPDATE="no", INSTA_FORCE_PASS="0", CARGO_TERM_COLOR="never",
                   RUSTUP_TOOLCHAIN="1.95.0")
        require(all(env.get(k) == os.environ.get(k) for k in CONTROL_KEYS), "Inherited control changed")
        require(not any(k in env for k in ("GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN")),
                "CI token leaked to child environment")

        def git(*args):
            return subprocess.run(["git", "-C", str(source), *args], env=env, check=True,
                                  capture_output=True, timeout=15).stdout.decode().strip()

        require(git("rev-parse", "HEAD") == os.environ["GITHUB_SHA"]
                and git("rev-parse", "HEAD^") == pins["sourceCommit"], "Overlay parent/source mismatch")
        changed = git("diff", "--name-only", "HEAD^", "HEAD").splitlines()
        require(all(n.startswith(".github/workflows/") or n.startswith(".github/issue1056/")
                    for n in changed), "CI overlay changes product bytes")
        require(not git("status", "--porcelain", "--untracked-files=all"), "Checkout is not clean")

        def capture():
            require(all(not Path(name).is_absolute() and ".." not in Path(name).parts
                        for name in pins["sourceFiles"]), "Non-repository source path")
            return {name: sha(source / name) for name in pins["sourceFiles"]}

        before = capture()
        require(before == pins["sourceFiles"], "Product source identity mismatch")
        result.update(sourceCommit=pins["sourceCommit"], ciHead=os.environ["GITHUB_SHA"],
                      sourceBefore=before, controlsPreserved=True,
                      image={k: os.environ.get(k) for k in ("ImageOS", "ImageVersion")})
        campaign = Campaign(evidence, work, env)
        for tool in ("rustup", "curl", "git", "cc", "clang", "cmake", "make", "pkg-config", "perl"):
            require(shutil.which(tool, path=env["PATH"]) is not None, "Missing hosted prerequisite: " + tool)
        rustup = shutil.which("rustup", path=env["PATH"])
        campaign.run("rust-toolchain", [rustup, "toolchain", "install", "1.95.0", "--no-self-update", "--profile", "minimal",
                                       "--component", "clippy", "--component", "rustfmt",
                                       "--component", "rust-src"], work, 600)
        campaign.run("rustc-location", [rustup, "which", "--toolchain", "1.95.0", "rustc"], work, 20)
        rustbin = Path((evidence / "rustc-location.stdout").read_text().strip()).parent
        require(rustbin.is_relative_to(work / "rustup"), "Compiler outside owned toolchain")
        for tool in ("just", "cargo-nextest"):
            archive = pins["archives"][tool]
            require(archive["url"].startswith("https://github.com/"), "Wrong official archive origin")
            dest = work / (tool + ".tar.gz")
            campaign.run("download-" + tool, [
                "curl", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
                "--max-time", "120", "--retry", "0", "--output", str(dest), archive["url"]
            ], work, 150)
            require(dest.stat().st_size == archive["bytes"] and sha(dest) == archive["sha256"],
                    "Official tool archive integrity mismatch")
            with tarfile.open(dest, "r:gz") as bundle:
                members = [m for m in bundle.getmembers() if Path(m.name).name == tool and m.isfile()]
                require(len(members) == 1 and members[0].size < 100 * 1024**2, "Ambiguous archive binary")
                with bundle.extractfile(members[0]) as src, (work / "bin" / tool).open("xb") as dst:
                    shutil.copyfileobj(src, dst)
                (work / "bin" / tool).chmod(0o755)
        for variable in ("RUSTY_V8_ARCHIVE", "RUSTY_V8_SRC_BINDING_PATH"):
            asset = pins["v8Assets"][variable]
            require(asset["url"].startswith(
                "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"),
                "Wrong pinned V8 origin")
            destination = work / Path(asset["url"]).name
            campaign.run("download-" + variable.lower(), [
                "curl", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
                "--max-time", "120", "--retry", "0", "--output", str(destination), asset["url"]
            ], work, 150)
            require(destination.stat().st_size == asset["bytes"]
                    and sha(destination) == asset["sha256"], "V8 artifact integrity mismatch")
            env[variable] = str(destination)
        env["PATH"] = str(work / "bin") + ":" + str(rustbin) + ":" + env["PATH"]
        result["toolHashes"] = {n: sha(Path(shutil.which(n, path=env["PATH"])))
                                for n in ("rustc", "cargo", "just", "cargo-nextest")}
        for name, argv in (("rust-version", ["rustc", "--version"]),
                           ("just-version", ["just", "--version"]),
                           ("nextest-version", ["cargo", "nextest", "--version"])):
            campaign.run(name, argv, work, 20)
        expression = " | ".join("test(=" + n + ")" for n in CASES)
        original = (source / "codex-rs/.config/nextest.toml").read_text()
        profile = work / "nextest.toml"
        profile.write_text(original + '\n[profile.issue1056]\ninherits = "local"\nretries = 0\n'
                           'test-threads = 1\nfail-fast = false\nglobal-timeout = "120s"\n'
                           'slow-timeout = { period = "30s", terminate-after = 1, grace-period = "0s", on-timeout = "fail" }\n'
                           '\n[[profile.issue1056.overrides]]\nfilter = "' + expression + '"\nretries = 0\n'
                           'slow-timeout = { period = "30s", terminate-after = 1, grace-period = "0s", on-timeout = "fail" }\n')
        cwd = source / "codex-rs"
        common = ["-p", "codex-linux-sandbox", "--lib", "--locked", "--target-dir", str(work / "target")]
        campaign.run("scoped-format", ["cargo", "fmt", "-p", "codex-linux-sandbox", "--", "--check",
                                      "--config", "imports_granularity=Item"], cwd, 60)
        campaign.run("clippy", ["just", "clippy", *common, "--jobs", "4", "--", "-D", "warnings"], cwd, 2400)
        campaign.run("candidate", ["just", "test", *common, "-E", expression,
                                  "--config-file", str(profile), "--profile", "issue1056",
                                  "--no-tests", "fail", "--retries", "0", "--test-threads", "1",
                                  "--status-level", "all", "--failure-output", "final",
                                  "--success-output", "final"], cwd, 2400, test_stage=True)
        text = (evidence / "candidate.stderr").read_text() + (evidence / "candidate.stdout").read_text()
        cases = test_results(text)
        binaries = [p for p in (work / "target/debug/deps").glob("codex_linux_sandbox-*")
                    if re.fullmatch(r"codex_linux_sandbox-[0-9a-f]+", p.name)
                    and p.is_file() and not p.is_symlink() and os.access(p, os.X_OK)]
        require(len(binaries) == 1, "Ambiguous fresh Linux test executable")
        after = capture()
        require(after == before and not git("status", "--porcelain", "--untracked-files=all"),
                "Product source changed during qualification")
        result.update(qualified=True, sourceChanged=False, sourceAfter=after,
                      selectedCases=CASES, caseResults=cases,
                      actualClippyTargetFlags=["--tests", "--lib"],
                      testBinary={"name": binaries[0].name, "sha256": sha(binaries[0]),
                                  "bytes": binaries[0].stat().st_size},
                      stages=campaign.results)
    except Exception as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        save(evidence / "qualification-result.json", result)
        entries = [{"name": p.name, "sha256": sha(p), "bytes": p.stat().st_size}
                   for p in sorted(evidence.iterdir()) if p.is_file()]
        save(evidence / "FILES.json", entries)
        require(sum(p.stat().st_size for p in evidence.iterdir()) <= MAX_ARTIFACT_BYTES,
                "Evidence exceeds reviewed upload cap")
    print(json.dumps({"qualified": result["qualified"], "error": result.get("error")}))
    return 0 if result["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
