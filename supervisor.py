"""Pinned bounded process/capture primitives only; no product/provisioning main."""
import hashlib, json, os, re, resource, selectors, shlex, shutil, signal, stat, subprocess, time
from pathlib import Path
MAX_STREAM = 2048
GIB = 1024 ** 3
MARKERS = ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_SANDBOX_USER_NAMESPACES_DENIED")
class Hold(RuntimeError):
    pass

def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1048576), b""):
            h.update(b)
    return h.hexdigest()

def save(path, value):
    with Path(path).open("x") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")

def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

def bounded_chunk(observed, retained, data, maximum=MAX_STREAM):
    kept = data[:max(0, maximum - retained)]
    return observed + len(data), retained + len(kept), kept, len(kept) != len(data)

def normalized(data, replacements):
    text = data.decode("utf-8", "strict")
    for old, new in sorted(replacements.items(), key=lambda x: -len(x[0])):
        if old:
            text = text.replace(old, new)
    if re.search(r"(?:github_pat_[A-Za-z0-9_]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})", text):
        raise Hold("public_output_secret_shape")
    return text.encode()

def known_skip_guard(env):
    # Preserve flags; never force a body to run against an inherited restriction.
    if "CODEX_SANDBOX_NETWORK_DISABLED" in env or env.get("CODEX_SANDBOX") == "seatbelt":
        raise Hold("inherited_controls_require_test_skip")

def proc_table():
    table = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            # comm may contain spaces and parentheses: split after its final ')'.
            tail = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            table[int(entry.name)] = (int(tail[1]), int(tail[19]))
        except (OSError, ValueError, IndexError):
            pass
    return table

def children():
    table, owned = proc_table(), set()
    changed = True
    while changed:
        changed = False
        for pid, (ppid, birth) in table.items():
            if pid not in owned and (ppid == os.getpid() or ppid in owned):
                owned.add(pid)
                changed = True
    return {pid: table[pid][1] for pid in owned}

def descendant_states(owned):
    """Only process identity/state, never argv, environment or command names."""
    rows = []
    for pid, birth in sorted(owned.items()):
        try:
            tail = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
            if int(tail[19]) == birth:
                rows.append({"pid": pid, "parentPid": int(tail[1]),
                             "birthTick": birth, "state": tail[0]})
        except (OSError, ValueError, IndexError):
            pass
    return rows

def reap_exited_descendants():
    """Called only after the Popen leader is reaped. Live children still hold."""
    before = descendant_states(children())
    reaped = []
    for _ in range(8):
        progress = False
        for row in descendant_states(children()):
            # waitpid is restricted to actual adopted, already exited children.
            # Recheck the birth identity so a reused numeric PID is never reaped.
            if row["parentPid"] != os.getpid() or row["state"] not in ("Z", "X"):
                continue
            if proc_table().get(row["pid"], (None, None)) != (os.getpid(), row["birthTick"]):
                continue
            try:
                pid, _status = os.waitpid(row["pid"], os.WNOHANG)
            except (ChildProcessError, ProcessLookupError):
                continue
            if pid == row["pid"]:
                reaped.append(row)
                progress = True
        if not progress:
            break
    remaining = children()
    return {"before": before, "reapedExited": reaped,
            "remaining": descendant_states(remaining), "remainingCount": len(remaining)}

def cleanup(process):
    # Linux subreaper adopts orphaned command/test children, including new groups.
    process.poll()
    initial = children()
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, birth in children().items():
            if proc_table().get(pid, (None, None))[1] == birth:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        end = time.monotonic() + 3
        while time.monotonic() < end:
            process.poll()
            for pid in list(children()):
                if pid != process.pid:
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except (ChildProcessError, ProcessLookupError):
                        pass
            if not children():
                break
            time.sleep(0.05)
        if not children():
            break
    process.wait(timeout=3)
    return {"ownedChildrenAtCleanup": len(initial), "ownedDescendantsGone": not children(),
            "leaderReaped": process.returncode is not None}

def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

class Campaign:
    def __init__(self, root, source, env, output, binaries):
        self.root, self.source, self.env, self.output = root, source, env, output
        self.binaries = binaries
        self.deadline = time.monotonic() + 6900
        self.rows = []
        self.replacements = {str(source): "<CHECKOUT>", str(root): "<TASK_ROOT>",
                             os.environ.get("GITHUB_WORKSPACE", ""): "<WORKSPACE>",
                             os.environ.get("HOME", ""): "<RUNNER_HOME>",
                             os.environ.get("CODEX_HOME", ""): "<INHERITED_CODEX_HOME>"}

    def run(self, label, argv, seconds=600, allow_failure=False):
        raw = self.root / "raw" / label
        raw.mkdir()
        started, p, reason = time.monotonic(), None, None
        states = {n: {"observedBytes": 0, "retainedBytes": 0, "truncated": False}
                  for n in ("stdout", "stderr")}
        complete = False
        completion_descendants = None
        clean = {"ownedDescendantsGone": False, "leaderReaped": False}
        if children():
            raise Hold("unexpected_existing_child")
        with (raw / "stdout").open("xb") as out, (raw / "stderr").open("xb") as err, (raw / "combined").open("xb") as combined, selectors.DefaultSelector() as select:
            files = {"stdout": out, "stderr": err}
            try:
                if time.monotonic() >= self.deadline:
                    raise Hold("whole_deadline")
                p = subprocess.Popen(argv, cwd=self.source, env=self.env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True, preexec_fn=limits)
                for name, pipe in (("stdout", p.stdout), ("stderr", p.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    select.register(pipe, selectors.EVENT_READ, name)
                while p.poll() is None or select.get_map():
                    if time.monotonic() - started >= seconds or time.monotonic() >= self.deadline:
                        raise Hold("owned_deadline")
                    if shutil.disk_usage(self.root).free < 4 * GIB:
                        raise Hold("disk_stop_floor")
                    for key, _ in select.select(0.2):
                        b = os.read(key.fd, 65536)
                        if not b:
                            select.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        name = key.data
                        s = states[name]
                        s["observedBytes"], s["retainedBytes"], kept, s["truncated"] = bounded_chunk(
                            s["observedBytes"], s["retainedBytes"], b)
                        files[name].write(kept)
                        combined.write(kept)
                        if s["truncated"]:
                            raise Hold("output_bound")
                p.wait()
                complete = True
                completion_descendants = reap_exited_descendants()
                if completion_descendants["remainingCount"]:
                    raise Hold("child_survived_command")
            except BaseException as e:
                reason = str(e) if isinstance(e, Hold) else "controller_" + type(e).__name__
            finally:
                for key in list(select.get_map().values()):
                    select.unregister(key.fileobj)
                    key.fileobj.close()
                if p:
                    try:
                        clean = cleanup(p)
                    except Exception:
                        reason = "cleanup_incomplete"
        row = {"stage": label, "exitCode": p.returncode if p else None,
               "seconds": round(time.monotonic() - started, 3), "captureComplete": complete,
               "stopReason": reason, "capture": states, "cleanup": clean,
               "completionDescendants": completion_descendants,
               "argv": [normalized(a.encode(), self.replacements).decode() for a in argv]}
        pub = self.output / label
        pub.mkdir()
        for name in ("stdout", "stderr", "combined"):
            f = raw / name
            safe = normalized(f.read_bytes(), self.replacements)
            (pub / (name + ".log")).write_bytes(safe)
            row.setdefault("streams", {})[name] = {"rawSha256": sha(f), "rawBytes": f.stat().st_size,
                                                  "publicSha256": hashlib.sha256(safe).hexdigest(),
                                                  "publicBytes": len(safe), "omittedLines": 0}
        transcript = "$ " + shlex.join(row["argv"]) + "\n"
        transcript += (pub / "combined.log").read_text() + "\n[exitCode=" + str(row["exitCode"]) + "]\n"
        (pub / "scripted-session.log").write_text(transcript)
        row["sessionSha256"] = sha(pub / "scripted-session.log")
        self.rows.append(row)
        save(pub / "result.json", row)
        if reason or not complete or not clean["ownedDescendantsGone"] or not clean["leaderReaped"]:
            raise Hold(label + "_incomplete")
        if row["exitCode"] != 0 and not allow_failure:
            raise Hold(label + "_nonzero")
        return raw, row

def environment(root):
    e = {"PATH": str(root / "toolchain/bin") + ":" + str(root / "bin") + ":/usr/bin:/bin",
         "CARGO_HOME": str(root / "cargo-home"), "RUSTUP_HOME": str(root / "unused-rustup"),
         "CARGO_TARGET_DIR": str(root / "target"), "TMPDIR": str(root / "tmp"),
         "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
         "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
         "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS": "true", "CARGO_PROFILE_TEST_DEBUG_ASSERTIONS": "true",
         "CORBANU_TEST_NO_NATIVE_KEYRING": "1", "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
         "CARGO_NET_RETRY": "0", "CARGO_TERM_COLOR": "never", "CARGO_HTTP_TIMEOUT": "60",
         "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
         "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "gc.auto", "GIT_CONFIG_VALUE_0": "0",
         "GIT_CONFIG_KEY_1": "maintenance.auto", "GIT_CONFIG_VALUE_1": "false",
         "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/false", "SSH_ASKPASS": "/usr/bin/false",
         "GIT_SSH_COMMAND": "/usr/bin/false", "NETRC": str(root / "empty-netrc"),
         "XDG_CONFIG_HOME": str(root / "empty-config"), "CURL_HOME": str(root / "empty-config"),
         "UV_CACHE_DIR": str(root / "uv-cache"), "UV_NO_CONFIG": "1",
         "UV_PYTHON_DOWNLOADS": "never", "DOTSLASH_CACHE": str(root / "dotslash-cache"),
         "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONUNBUFFERED": "1",
         "INSTA_UPDATE": "no", "INSTA_FORCE_PASS": "0"}
    # Preserve inherited home identity. The unchanged repository just-test
    # wrapper creates the disposable CODEX_HOME used by product test processes.
    e.update({k: os.environ[k] for k in ("HOME", "CODEX_HOME", *MARKERS) if k in os.environ})
    return e
