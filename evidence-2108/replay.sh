#!/bin/sh
# Replay #2108 on macOS. Needs git, cargo, python3. Run from an empty dir.
set -eu
git clone -q https://github.com/CorbanuCore/CorbanuTerminal.git wt && cd wt
git fetch -q https://github.com/citadelculture/CorbanuTerminal.git 13bb4c84a25e5cf185b44889d536af8941da346e
git checkout -q 5c7d8ed06095fabf6aa41d496996082c3dfa4384                                   # red
python3 ../replay.py . ; echo "base exit $?  (expect 101: 2 SUN_LEN failures)" || true
git checkout -q 13bb4c84a25e5cf185b44889d536af8941da346e                                   # green
python3 ../replay.py . ; echo "head exit $?  (expect 0: 153 passed)"
