# #2108 evidence packet

- **PR:** https://github.com/CorbanuCore/CorbanuTerminal/pull/2114
- **Base:** `5c7d8ed06095fabf6aa41d496996082c3dfa4384` · **Head:** `13bb4c84a25e5cf185b44889d536af8941da346e` (DCO `Signed-off-by: citadelculture`, see `api-readback.txt`)
- **Changed:** test code only, `codex-rs/app-server-transport/src/transport/unix_socket_tests.rs` (`fix.diff`)

Environment: macOS 26 (Darwin 25.6.0) aarch64; per-user TMPDIR `/var/folders/kc/…/T/`. cargo-nextest is not installed, so `replay.py` imports `scripts/isolated_rust_tests.py`'s own `test_environment()`, rebuilds its disposable profile + `corbanu-tests-XXXX/tmp` TMPDIR (75 bytes), and runs `cargo test -p codex-app-server-transport --lib --locked --offline`.

| run | log | result |
|---|---|---|
| red: base | `red.log` | 150 passed, 2 failed, both `InvalidInput: path must be shorter than SUN_LEN`; exit 101 |
| green: head, wrapper layout | `green.log` | 153 passed; exit 0 |
| control: head, default TMPDIR | `control-default-tmpdir.log` | 153 passed; exit 0 |
| clippy `--tests -D warnings` | `clippy.log` | exit 0 |
| fmt `--check` | `fmt.log` | exit 0 |

**Assertions kept:** the 0600 socket mode check, the WebSocket upgrade/text/ping/close checks, socket removal on shutdown, and the startup-lock fixtures. No production socket path or permission changes; disposable profile and keyring denial come from the wrapper unchanged.

**Path limits:** macOS/BSD `sun_path` 104 bytes incl. NUL (limit 103), Linux 108 (limit 107). The fallback is a random 0700 `/tmp/.tmpXXXXXX` (about 61-byte socket path), removed on drop.

**Not run / limits:** Linux and Windows (left to CI; Windows fixture unchanged), `cargo nextest` itself, the full workspace suite. A killed run could leave the `/tmp` fallback directory behind, since it sits outside the wrapper's scratch dir.

`SHA256SUMS` covers every file except itself. Replay: `replay.sh` (place `replay.py` beside it).
