#!/bin/sh
# Replay #2407 item 2. Needs git + Rust 1.99.1. Run from an empty dir.
set -u
git clone -q https://github.com/CorbanuCore/CorbanuTerminal.git wt && cd wt
git fetch -q https://github.com/citadelculture/CorbanuTerminal.git 8112c24f1169b323c6a940d0c7541d94e4c06ce0 && git checkout -q 8112c24f1169b323c6a940d0c7541d94e4c06ce0
cd codex-rs
git checkout -q 5c05a8bb80359f57f589a1b9a2b558147a075650 -- tui/src/app/input.rs        # red: base production code, head tests
cargo test -p codex-tui --lib held_enter_shortcuts || echo "red failed as expected (2 failed)"
git checkout -q 8112c24f1169b323c6a940d0c7541d94e4c06ce0 -- tui/src/app/input.rs        # green
cargo test -p codex-tui --lib held_enter_shortcuts && echo "green passed (4)"
