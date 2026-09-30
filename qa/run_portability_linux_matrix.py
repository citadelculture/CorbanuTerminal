"""Run the unchanged native matrix against a pinned reusable Linux runtime."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

checkout = Path.cwd()
binary = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)
stage = Path(tempfile.mkdtemp(prefix="corbanu-native-"))
helpers = stage / "bin"
helpers.mkdir()
(stage / "user").mkdir()
(stage / "sockets").mkdir()
(stage / "logs").mkdir()
config = stage / "tmux.conf"
config.write_text("set-option -g default-shell /bin/bash\nset-option -g default-terminal xterm-256color\n")
tmux = shutil.which("tmux")
assert tmux and binary.is_file()
assert binary.read_bytes()[:4] == b"\x7fELF", "Expected the packaged Linux ELF entrypoint"
head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
rust_tree = subprocess.check_output(["git", "rev-parse", "HEAD:codex-rs"], text=True).strip()
assert rust_tree == "846755e77c6d66f826033c6e42cea4a0b99ed428"
version = subprocess.check_output([str(binary), "--version"], text=True).strip()
(helpers / "tmux").write_text("#!/bin/bash\nexec " + shlex.quote(tmux) + " -f " + shlex.quote(str(config)) + ' -L qa "$@"\n')
(helpers / "qa-terminal").write_text("#!/bin/bash\nexec " + shlex.quote(str(binary)) + " -c " + shlex.quote('log_dir=' + json.dumps(str(stage / "logs"))) + ' "$@"\n')
for path in helpers.iterdir():
    path.chmod(0o755)
env = {
    "HOME": str(stage / "user"), "USER": "qa", "LANG": "C.UTF-8",
    "PATH": str(helpers) + ":/usr/local/bin:/usr/bin:/bin",
    "TERM": "xterm-256color", "RUST_LOG": "trace",
    "TMUX_TMPDIR": str(stage / "sockets"),
    "PFTERMINAL_BINARY": str(helpers / "qa-terminal"),
    "PFTERMINAL_MATRIX_ARTIFACT_ROOT": str(stage / "artifacts"),
    "PFTERMINAL_MATRIX_PORT": "18791",
}
start = time.monotonic()
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
result = None
try:
    with (out / "matrix.log").open("w") as log:
        try:
            result = subprocess.run(["bash", "-x", "qa/orchestrate_tui_matrix.sh"], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=1500, check=False).returncode
        except subprocess.TimeoutExpired:
            result = 124
finally:
    subprocess.run([str(helpers / "tmux"), "kill-server"], env=env, capture_output=True, check=False)
    results = stage / "artifacts/results.tsv"
    if results.exists():
        shutil.copyfile(results, out / "results.tsv")
    receipt = {
        "head": head, "rust_tree": rust_tree, "started_utc": started,
        "elapsed_seconds": round(time.monotonic() - start, 3), "exit_code": result,
        "binary_version": version, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "binary_build_source": "b3453330811432918d06909c6ad1c433e727fff4",
        "runtime_artifact_id": 11095270180, "runtime_build_run": 36710366999,
        "platform": "Ubuntu 22.04 GitHub-hosted x86_64, packaged dev-small runtime",
        "environment": "Synthetic local provider and homes; dedicated tmux socket, bash/xterm config; no inherited token/provider credentials; full default rows, unchanged thresholds.",
        "results": results.read_text() if results.exists() else None,
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (out / "sha256.json").write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p.name != "sha256.json"}, indent=2) + "\n")
    print(json.dumps(receipt), flush=True)
sys.exit(result if result is not None else 1)
