#!/bin/bash
set -euo pipefail
# Runs only public provisioning and Cargo fetch, never build scripts or tests.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 cmake ninja-build pkg-config libcap-dev libssl-dev clang libclang-dev protobuf-compiler ripgrep ca-certificates curl git
rustup component add clippy rustfmt rust-src --toolchain 1.99.1
rm -rf /var/lib/apt/lists/*
curl --fail --location --retry 2 --max-time 180 -o /tmp/just.tar.gz https://github.com/casey/just/releases/download/1.58.0/just-1.58.0-x86_64-unknown-linux-musl.tar.gz
echo '4a5cc2f53e6f0f8c59092a6cc38291eb729d46a7dd95d3ae582008881b84931d  /tmp/just.tar.gz' | sha256sum --check --strict
tar -xzf /tmp/just.tar.gz -C /usr/local/bin just
curl --fail --location --retry 2 --max-time 180 -o /tmp/nextest.tar.gz https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.146/cargo-nextest-0.9.146-x86_64-unknown-linux-gnu.tar.gz
echo '682c21b777c333e96fd532e114d3a5a894e0729ab88d94c0a9f20f8419695428  /tmp/nextest.tar.gz' | sha256sum --check --strict
tar -xzf /tmp/nextest.tar.gz -C /usr/local/bin cargo-nextest
rustc --version
cargo --version
python3 --version
just --version
cargo nextest --version
cmake --version
rg --version
dpkg-query -W -f='${Package} ${Version}\n'
cd /src/codex-rs
cargo fetch --locked --target x86_64-unknown-linux-gnu
# The v8 build script defaults to this release archive even in debug builds.
# Populate its ordinary URL-keyed cache; do not change features or its downloader.
python3 - <<'PY'
import hashlib, os, pathlib, re, urllib.request
url = 'https://github.com/denoland/rusty_v8/releases/download/v150.4.0/librusty_v8_release_x86_64-unknown-linux-gnu.a.gz'
cache = pathlib.Path(os.environ['CARGO_HOME']) / '.rusty_v8'
cache.mkdir(exist_ok=True)
path = cache / re.sub('[^a-zA-Z0-9]', '_', url)
with urllib.request.urlopen(url, timeout=120) as response, path.open('xb') as out:
    while block := response.read(1024 * 1024):
        out.write(block)
actual = hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
assert actual == '5869fdb7071b1f21f200a97ce97d20125877e0f31cd802ed99de2c53f488b06c', actual
print('Official RustyV8 archive verified:', actual)
PY
rm -f /tmp/just.tar.gz /tmp/nextest.tar.gz
python3 /method/tool_manifest.py /opt/issue1094-tool-manifest.json
chmod 444 /opt/issue1094-tool-manifest.json
chown -R "${FIXTURE_UID}:${FIXTURE_GID}" /cache
