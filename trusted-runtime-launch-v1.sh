#!/bin/bash
# Hosted control-only entry. Never discovers, installs, chowns, or falls back.
set -euo pipefail
[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == macOS ]]
[[ "${GITHUB_REPOSITORY:-}" == citadelculture/CorbanuTerminal ]]
[[ "${GITHUB_REF:-}" == refs/heads/codex/network-credential-state-v1-20261020 ]]
[[ "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_RUN_ATTEMPT:-}" == 1 ]]
[[ "$(/usr/bin/id -u)" != 0 ]]
/bin/mkdir -m 700 "$GITHUB_WORKSPACE/trusted-runtime-evidence"
launch_log="$GITHUB_WORKSPACE/trusted-runtime-evidence/trusted-runtime-launch.log"
printf '%s\n' 'Fixed CLT runtime prerequisite; no installation or fallback.' > "$launch_log"
python_candidate=/Library/Developer/CommandLineTools/usr/bin/python3
if [[ ! -f "$python_candidate" || ! -x "$python_candidate" ]]; then
  printf '%s\n' 'HOLD: fixed_clt_launcher_absent_or_not_executable' >> "$launch_log"
  exit 2
fi
python_owner=$(/usr/bin/stat -L -f '%u' "$python_candidate")
python_mode=$(/usr/bin/stat -L -f '%Lp' "$python_candidate")
printf 'Observed fixed CLT executable owner=%s mode=%s\n' "$python_owner" "$python_mode" >> "$launch_log"
if [[ "$python_owner" != 0 || ! "$python_mode" =~ ^[0-7]{3,4}$ ]] ||
   (( (8#$python_mode & 8#022) != 0 )); then
  printf '%s\n' 'HOLD: python_not_root_owned_immutable' >> "$launch_log"
  exit 2
fi
# The exact CLT tool avoids /usr/bin/python3's active-Xcode launcher selection.
# -I/-S/-B avoids user/global site startup and bytecode writes.
exec "$python_candidate" -I -S -B control/trusted-runtime-entry-v1.py \
  --dispatch --pins-sha256 9922e888585971793259a7b702b271c9384b4b071bf262e4fdf5b16f6eccad74
