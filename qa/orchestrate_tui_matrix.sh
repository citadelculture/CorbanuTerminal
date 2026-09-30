#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/qa/orchestrate_tui_readiness.sh"
BINARY=${PFTERMINAL_BINARY:-"$ROOT/codex-rs/target/debug/pfterminal"}
SHA=$(git -C "$ROOT" rev-parse HEAD)
ARTIFACT_ROOT=${PFTERMINAL_MATRIX_ARTIFACT_ROOT:-"$ROOT/qa/artifacts/$SHA"}
PORT=${PFTERMINAL_MATRIX_PORT:-18766}
SERVER_SESSION="orchestrate-matrix-server-$$"
CONTROL="$ARTIFACT_ROOT/server-control"
RESULTS="$ARTIFACT_ROOT/results.tsv"
CURRENT_SESSION=""
CURRENT_HOME=""
CAPTURE_INDEX=0
PANE_COUNT=0
LAST_CAPTURE_PATH=""
TERMINAL_LABEL=${PFTERMINAL_QA_PRODUCT_LABEL:-Corbanu Terminal}
source "$ROOT/qa/orchestrate_tui_modal.sh"

mkdir -p "$ARTIFACT_ROOT/server"
: >"$CONTROL"
: >"$RESULTS"

cleanup() {
  if [[ -n "$CURRENT_SESSION" ]]; then
    tmux kill-session -t "$CURRENT_SESSION" 2>/dev/null || true
  fi
  tmux kill-session -t "$SERVER_SESSION" 2>/dev/null || true
}
trap cleanup EXIT

stop_current() {
  if [[ -n "$CURRENT_SESSION" ]]; then
    tmux kill-session -t "$CURRENT_SESSION" 2>/dev/null || true
  fi
}

fail() {
  printf 'FAIL\t%s\t%s\n' "$1" "$2" >>"$RESULTS"
  printf 'row %s failed: %s\n' "$1" "$2" >&2
  return 1
}

capture() {
  local label=$1
  CAPTURE_INDEX=$((CAPTURE_INDEX + 1))
  local path="$ARTIFACT_ROOT/$CURRENT_SESSION/$(printf '%03d' "$CAPTURE_INDEX")-$label.txt"
  tmux capture-pane -p -t "$CURRENT_SESSION":0.0 -S -200 >"$path"
  LAST_CAPTURE_PATH=$path
  printf '%s' "$path"
}

# Tmux captures preserve visual line wrapping. Flatten only line boundaries when
# asserting prose so a terminal-width wrap cannot turn visible evidence into a
# false negative.
screen_contains() {
  local path=$1
  local expected=$2
  local flattened normalized_expected
  flattened=$(tr '\n' ' ' <"$path" | tr -s '[:space:]' ' ')
  normalized_expected=$(printf '%s' "$expected" | tr -s '[:space:]' ' ')
  grep -Fq -- "$normalized_expected" <<<"$flattened"
}

wait_screen() {
  local pattern=$1
  local attempts=${2:-80}
  local capture_timeout=${3:-true}
  local output
  for ((attempt = 0; attempt < attempts; attempt++)); do
    # Poll only the live viewport. Searching scrollback can satisfy a repeated
    # dialog title (for example, "Panes") from an earlier interaction and send
    # subsequent keys to the composer instead of the intended dialog.
    output=$(tmux capture-pane -p -t "$CURRENT_SESSION":0.0)
    output=${output//$'\n'/ }
    if grep -Fq -- "$pattern" <<<"$output"; then
      return 0
    fi
    sleep 0.25
  done
  if [[ "$capture_timeout" == true ]]; then
    capture "wait-timeout" >/dev/null
  fi
  return 1
}

wait_modal_closed() {
  local attempts=${1:-80}
  local parent=${2:-none}
  local attempt output
  for ((attempt = 0; attempt < attempts; attempt++)); do
    output=$(tmux capture-pane -p -t "$CURRENT_SESSION":0.0)
    if [[ "$parent" == orchestrate ]] && orchestrate_status_visible <<<"$output"; then
      capture "details-returned-to-status" >/dev/null
      orchestrate_send_escape "$CURRENT_SESSION":0.0
      parent=none
    elif [[ "$parent" == none ]] && orchestrate_modal_closed <<<"$output"; then
      return 0
    fi
    sleep 0.25
  done
  capture "modal-close-timeout" >/dev/null
  return 1
}

wait_composer_ready() {
  local attempts=$1
  local attempt output
  for ((attempt = 0; attempt < attempts; attempt++)); do
    output=$(tmux capture-pane -p -t "$CURRENT_SESSION":0.0)
    if orchestrate_composer_ready <<<"$output"; then
      return 0
    fi
    sleep 0.25
  done
  capture "wait-timeout" >/dev/null
  return 1
}

dismiss_modal() {
  local parent=${1:-none}
  orchestrate_send_escape "$CURRENT_SESSION":0.0
  # Nested details and parent-list dismissal share the original wait budget.
  wait_modal_closed 80 "$parent"
}

wait_layout() {
  local filter=$1
  local attempts=${2:-100}
  local layout
  for ((attempt = 0; attempt < attempts; attempt++)); do
    layout=$(layout_file 2>/dev/null || true)
    # Format v2 wraps the durable pane payload in `{format_version, checksum,
    # layout}` while older fixtures expose the layout directly. Normalize at
    # the reader boundary so every row asserts the same logical document.
    if [[ -n "$layout" ]] && jq -e "(.layout // .) | $filter" "$layout" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  capture "layout-timeout" >/dev/null
  return 1
}

layout_file() {
  # Restart/resume can leave the compatibility path behind while the resumed
  # root writes its per-thread layout. Always inspect the newest durable JSON
  # across both locations instead of pinning reads to a stale compatibility
  # copy merely because it exists.
  find "$CURRENT_HOME/panes" -maxdepth 2 -type f -name '*.json' -print0 \
    | xargs -0 -r ls -1t | head -n 1
}

snapshot_layout() {
  local label=$1
  local layout
  layout=$(layout_file)
  jq --sort-keys . "$layout" >"$ARTIFACT_ROOT/$CURRENT_SESSION/$label.json"
}

literal_keys() {
  tmux send-keys -l -t "$CURRENT_SESSION":0.0 "$1"
}

submit() {
  literal_keys "$1"
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
}

submit_user() {
  literal_keys "$1"
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  sleep 1
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
}

submit_slash_wait() {
  local command=$1
  local pattern=$2
  literal_keys "$command"
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  if wait_screen "$pattern" 20 false; then
    return
  fi
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  wait_screen "$pattern"
}

select_down() {
  local steps=$1
  sleep 0.75
  for ((step = 0; step < steps; step++)); do
    tmux send-keys -t "$CURRENT_SESSION":0.0 Down
    sleep 0.75
  done
  capture "selection-before-enter" >/dev/null
  sleep 0.5
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  sleep 0.75
}

start_row() {
  local row=$1
  local cadence_s=${2:-2}
  stop_current
  CURRENT_SESSION="orchestrate-row-$row-$$"
  CURRENT_HOME="$ARTIFACT_ROOT/$CURRENT_SESSION/home"
  CAPTURE_INDEX=0
  PANE_COUNT=0
  LAST_CAPTURE_PATH=""
  : >"$CONTROL"
  mkdir -p "$CURRENT_HOME/whips" "$ARTIFACT_ROOT/$CURRENT_SESSION"
  cp "$ROOT/qa/fixtures/orchestrate-prewritten.md" "$CURRENT_HOME/whips/qa-prewritten.md"
  {
    printf 'PFTERMINAL_HOME=%s\n' "$CURRENT_HOME"
    printf 'CODEX_HOME=%s\n' "$CURRENT_HOME"
    printf 'PFTERMINAL_ORCHESTRATE_QA=1\n'
    printf 'PFTERMINAL_ORCHESTRATE_TEST_CADENCE_SECONDS=%s\n' "$cadence_s"
    printf 'model=qa-model\nmodel_provider=qa\n'
  } >"$ARTIFACT_ROOT/$CURRENT_SESSION/harness-env.txt"
  tmux new-session -d -s "$CURRENT_SESSION" -x 140 -y 45 \
    "cd '$ROOT' && export PFTERMINAL_HOME='$CURRENT_HOME' CODEX_HOME='$CURRENT_HOME' PFTERMINAL_ORCHESTRATE_QA=1 PFTERMINAL_ORCHESTRATE_QA_CONTROL='$CONTROL' PFTERMINAL_ORCHESTRATE_TEST_CADENCE_SECONDS='$cadence_s' && exec '$BINARY' -c 'model=\"qa-model\"' -c 'model_provider=\"qa\"' -c 'model_providers.qa={ name = \"QA\", base_url = \"http://127.0.0.1:$PORT/v1\", wire_api = \"responses\", requires_openai_auth = false, request_max_retries = 0, stream_max_retries = 0 }' -c 'approval_policy=\"never\"' -c 'sandbox_mode=\"workspace-write\"'"
  wait_screen "Do you trust the contents" 40
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  wait_composer_ready 80
  sleep 2
  capture "started" >/dev/null
}

restart_current() {
  local cadence_s=$1
  local root_thread_id=$2
  tmux kill-session -t "$CURRENT_SESSION" 2>/dev/null || true
  tmux new-session -d -s "$CURRENT_SESSION" -x 140 -y 45 \
    "cd '$ROOT' && export PFTERMINAL_HOME='$CURRENT_HOME' CODEX_HOME='$CURRENT_HOME' PFTERMINAL_ORCHESTRATE_QA=1 PFTERMINAL_ORCHESTRATE_QA_CONTROL='$CONTROL' PFTERMINAL_ORCHESTRATE_TEST_CADENCE_SECONDS='$cadence_s' && exec '$BINARY' -c 'model=\"qa-model\"' -c 'model_provider=\"qa\"' -c 'model_providers.qa={ name = \"QA\", base_url = \"http://127.0.0.1:$PORT/v1\", wire_api = \"responses\", requires_openai_auth = false, request_max_retries = 0, stream_max_retries = 0 }' -c 'approval_policy=\"never\"' -c 'sandbox_mode=\"workspace-write\"' resume '$root_thread_id'"
  wait_composer_ready 100
  sleep 2
}

create_pane() {
  local name=$1
  submit_slash_wait "/panes" "Panes"
  capture "panes-before-create-$name" >/dev/null
  select_down $((PANE_COUNT + 1))
  capture "after-select-create-$name" >/dev/null
  wait_screen "Name $TERMINAL_LABEL pane"
  tmux send-keys -t "$CURRENT_SESSION":0.0 C-u
  literal_keys "$name"
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  sleep 0.2
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  wait_screen "Created and switched to $TERMINAL_LABEL pane $name" 100
  PANE_COUNT=$((PANE_COUNT + 1))
  capture "created-$name" >/dev/null
}

switch_pane() {
  local name=$1
  submit_slash_wait "/panes" "Panes"
  local steps
  case "$name" in
    Worker) steps=1 ;;
    Manager) steps=2 ;;
    *) return 1 ;;
  esac
  select_down "$steps"
  wait_modal_closed
}

switch_main() {
  submit_slash_wait "/panes" "Panes"
  select_down 0
  wait_modal_closed
}

open_panes_capture() {
  local label=$1
  submit_slash_wait "/panes" "Panes"
  capture "$label"
}

guided_prewritten_create_manager() {
  create_pane "Worker"
  submit "/orchestrate attach"
  wait_screen "New Assignment - Worker"
  select_down 1
  wait_screen "New Assignment - Duration"
  select_down 3
  wait_screen "New Assignment - Spec"
  select_down 2
  wait_screen "New Assignment - Manager"
  select_down 0
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "executing"'
  # The deterministic fixture runs the minimum two productive mandate fires, then returns a plain
  # terminal response. Let that final Manager turn settle before rows send slash commands or user
  # markers to its pane.
  sleep 4
}

guided_draft_existing_manager() {
  create_pane "Worker"
  create_pane "Manager"
  submit "/orchestrate attach"
  wait_screen "New Assignment - Worker"
  select_down 2
  wait_screen "New Assignment - Duration"
  select_down 3
  wait_screen "New Assignment - Spec"
  select_down 0
  wait_screen "New Assignment - Manager"
  select_down 1
  wait_screen "Create assignment"
  select_down 0
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "drafting"'
  switch_pane "Manager"
  submit_user "QA_APPROVE_DRAFT"
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "executing"'
}

row_1() {
  # A productive Worker completion is an event-driven handoff, not a watchdog tick.
  # Keep the watchdog far in the future so two cycles prove that completion bypasses it.
  start_row 1 900
  guided_prewritten_create_manager
  sleep 6
  local panes
  open_panes_capture "panes-after-two-cycles" >/dev/null
  panes=$LAST_CAPTURE_PATH
  grep -Fq "$TERMINAL_LABEL - Worker" "$panes" || fail 1 "Worker vanished from /panes"
  screen_contains "$panes" "managed-by Manager" || fail 1 "Worker assignment label missing"
  wait_layout '.orchestrate_whips | to_entries[0].value.fires >= 2' || fail 1 "two mandate cycles did not fire"
  snapshot_layout "final-layout"
  printf 'PASS\t1\tguided prewritten create-Manager\n' >>"$RESULTS"
}

row_2() {
  start_row 2
  guided_draft_existing_manager
  sleep 4
  local panes
  open_panes_capture "draft-running-panes" >/dev/null
  panes=$LAST_CAPTURE_PATH
  grep -Fq "$TERMINAL_LABEL - Worker" "$panes" || fail 2 "Worker missing after first draft dispatch"
  wait_layout '.orchestrate_whips | to_entries[0].value.last_dispatch_result == "delivered"' \
    || fail 2 "first draft dispatch was not delivered"
  snapshot_layout "final-layout"
  printf 'PASS\t2\tdraft-with-Manager bind-existing\n' >>"$RESULTS"
}

row_3() {
  start_row 3
  create_pane "Worker"
  submit_slash_wait "/orchestrate" "New Assignment - Worker"
  select_down 1
  wait_screen "New Assignment - Manager"
  select_down 0
  wait_layout '.orchestrate_whips | to_entries[0].value.instructions == "draft-with-manager" and to_entries[0].value.kind.execution_duration_s >= 28790'
  snapshot_layout "fast-path-layout"
  capture "fast-path-running" >/dev/null
  printf 'PASS\t3\ttwo-choice fast path\n' >>"$RESULTS"
}

row_4() {
  start_row 4 900
  guided_prewritten_create_manager
  switch_pane "Manager"
  submit_user "QA_RESTATE_CONTRACT"
  wait_screen "I will use WHIP_DONE only later" 100
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "executing"'
  submit_user "QA_EMIT_DONE"
  wait_screen "• WHIP_DONE" 100
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "done"'
  local before after
  before=$(jq '(.layout // .) | .orchestrate_whips | to_entries[0].value.fires' "$(layout_file)")
  sleep 4
  after=$(jq '(.layout // .) | .orchestrate_whips | to_entries[0].value.fires' "$(layout_file)")
  [[ "$before" == "$after" ]] || fail 4 "mandates continued after done marker"
  capture "marker-done" >/dev/null
  snapshot_layout "final-layout"
  printf 'PASS\t4\tmarker discipline\n' >>"$RESULTS"
}

row_5() {
  start_row 5 900
  guided_prewritten_create_manager
  switch_pane "Manager"
  submit_user "QA_EMIT_BLOCKED"
  wait_screen "ASSIGNMENT_BLOCKED: waiting for QA approval" 100
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase.blocked.reason == "waiting for QA approval"'
  capture "blocked" >/dev/null
  submit_user "QA_CONTINUE_AFTER_BLOCK"
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "executing"'
  snapshot_layout "resumed-layout"
  printf 'PASS\t5\tblocked round-trip\n' >>"$RESULTS"
}

row_6() {
  start_row 6 900
  guided_prewritten_create_manager
  local worker_node
  worker_node=$(jq -r '(.layout // .) | .orchestrate_whips | to_entries[0].value.target' "$(layout_file)")
  printf 'unavailable=%s\n' "$worker_node" >"$CONTROL"
  switch_pane "Manager"
  submit_user "QA_BAD_DISPATCH"
  wait_layout '.orchestrate_whips | to_entries[0].value.state == "paused"'
  # The durable state transition and terminal rendering are delivered on
  # separate event paths. A fast hosted runner can observe `paused` before the
  # retry-failure notice reaches the viewport, so synchronize on both product
  # signals before capturing evidence.
  wait_screen "dispatch retry failed" 100 || fail 6 "retry failure was not visible"
  local evidence
  capture "dispatch-failure-paused" >/dev/null
  evidence=$LAST_CAPTURE_PATH
  screen_contains "$evidence" "dispatch failed: Manager" || fail 6 "first failure was not visible"
  screen_contains "$evidence" "Retrying once using durable Worker ID" || fail 6 "durable retry was not visible"
  screen_contains "$evidence" "dispatch retry failed" || fail 6 "retry failure was not visible"
  snapshot_layout "final-layout"
  : >"$CONTROL"
  printf 'PASS\t6\tdispatch failure retry and pause\n' >>"$RESULTS"
}

row_7() {
  start_row 7-worker 900
  guided_prewritten_create_manager
  local worker_node worker_evidence
  worker_node=$(jq -r '(.layout // .) | .orchestrate_whips | to_entries[0].value.target' "$(layout_file)")
  printf 'close=%s\n' "$worker_node" >"$CONTROL"
  wait_layout '.orchestrate_whips | to_entries[0].value.state == "paused"'
  capture "worker-loss-paused" >/dev/null
  worker_evidence=$LAST_CAPTURE_PATH
  grep -Fq "Worker Worker" "$worker_evidence" || fail 7 "Worker loss notice did not name Worker"

  start_row 7-manager 900
  guided_prewritten_create_manager
  local manager_node manager_evidence
  manager_node=$(jq -r '(.layout // .) | .orchestrate_whips | to_entries[0].value.holder' "$(layout_file)")
  printf 'close=%s\n' "$manager_node" >"$CONTROL"
  wait_layout '.orchestrate_whips | to_entries[0].value.state == "paused"'
  capture "manager-loss-paused" >/dev/null
  manager_evidence=$LAST_CAPTURE_PATH
  grep -Fq "Manager Manager" "$manager_evidence" || fail 7 "Manager loss notice did not name Manager"
  snapshot_layout "final-layout"
  : >"$CONTROL"
  printf 'PASS\t7\tnative Worker and Manager pane loss\n' >>"$RESULTS"
}

row_8() {
  start_row 8-resume 10
  guided_prewritten_create_manager
  local before after_delay after_cycle restart_evidence root_thread_id
  before=$(jq '(.layout // .) | .orchestrate_whips | to_entries[0].value.fires' "$(layout_file)")
  root_thread_id=$(jq -r '(.layout // .) | .codex_thread_id' "$(layout_file)")
  restart_current 10 "$root_thread_id"
  wait_screen "restored; the next Manager mandate waits one" 100
  capture "restart-resume-notice" >/dev/null
  restart_evidence=$LAST_CAPTURE_PATH
  screen_contains "$restart_evidence" "restored; the next Manager mandate" \
    || fail 8 "resume notice missing"
  sleep 3
  after_delay=$(jq '(.layout // .) | .orchestrate_whips | to_entries[0].value.fires' "$(layout_file)")
  [[ "$after_delay" == "$before" ]] || fail 8 "mandate fired before one cadence elapsed"
  sleep 8
  after_cycle=$(jq '(.layout // .) | .orchestrate_whips | to_entries[0].value.fires' "$(layout_file)")
  ((after_cycle > before)) || fail 8 "loop did not continue after restart cadence"
  snapshot_layout "resumed-layout"

  start_row 8-missing-worker 900
  guided_prewritten_create_manager
  local worker_node missing_evidence missing_root_thread_id
  worker_node=$(jq -r '(.layout // .) | .orchestrate_whips | to_entries[0].value.target' "$(layout_file)")
  missing_root_thread_id=$(jq -r '(.layout // .) | .codex_thread_id' "$(layout_file)")
  tmux kill-session -t "$CURRENT_SESSION" 2>/dev/null || true
  printf 'unavailable=%s\n' "$worker_node" >"$CONTROL"
  restart_current 900 "$missing_root_thread_id"
  wait_layout '.orchestrate_whips | to_entries[0].value.state == "paused"'
  capture "restart-missing-worker" >/dev/null
  missing_evidence=$LAST_CAPTURE_PATH
  screen_contains "$missing_evidence" "paused after restart: Worker is unavailable" \
    || fail 8 "missing Worker restart notice absent"
  snapshot_layout "missing-worker-layout"
  : >"$CONTROL"
  printf 'PASS\t8\trestart resume and missing-Worker pause\n' >>"$RESULTS"
}

row_9() {
  start_row 9 900
  guided_draft_existing_manager
  # Pause the assignment before exercising pane navigation. Productive Worker
  # completion is intentionally event-driven, so leaving it executing creates
  # an unrelated stream of Manager turns that can steal focus from /panes.
  submit_user "QA_EMIT_BLOCKED"
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase.blocked.reason == "waiting for QA approval"'
  local before after assignment_id
  open_panes_capture "pane-hygiene-before-detach" >/dev/null
  before=$LAST_CAPTURE_PATH
  grep -Fq "$TERMINAL_LABEL - Main" "$before" || fail 9 "Main pane missing"
  grep -Fq "$TERMINAL_LABEL - Worker" "$before" || fail 9 "Worker pane missing"
  grep -Fq "$TERMINAL_LABEL - Manager" "$before" || fail 9 "Manager pane missing"
  dismiss_modal
  switch_pane "Worker"
  switch_pane "Manager"
  switch_main
  assignment_id=$(jq -r '(.layout // .) | .orchestrate_whips | keys[0]' "$(layout_file)")
  submit "/orchestrate detach $assignment_id"
  wait_layout '.orchestrate_whips | length == 0'
  open_panes_capture "pane-hygiene-after-detach" >/dev/null
  after=$LAST_CAPTURE_PATH
  grep -Fq "$TERMINAL_LABEL - Worker" "$after" || fail 9 "detach removed Worker pane"
  grep -Fq "$TERMINAL_LABEL - Manager" "$after" || fail 9 "detach removed Manager pane"
  if grep -Eq 'managed-by|managing' "$after"; then
    fail 9 "detach left assignment labels on panes"
  fi
  snapshot_layout "final-layout"
  printf 'PASS\t9\tpane listing selection and detach hygiene\n' >>"$RESULTS"
}

row_10() {
  start_row 10 900
  create_pane "Worker"
  submit_slash_wait "/orchestrate" "New Assignment - Worker"
  select_down 1
  wait_screen "New Assignment - Manager"
  local candidates
  capture "manager-candidates" >/dev/null
  candidates=$LAST_CAPTURE_PATH
  grep -Fq "Create Manager pane" "$candidates" || fail 10 "create Manager option missing"
  if grep -Fq "Bind Main" "$candidates"; then
    fail 10 "$TERMINAL_LABEL Main was offered as Manager"
  fi

  start_row 10-main 900
  submit_slash_wait "/orchestrate" "New Assignment - Worker"
  select_down 0
  wait_screen "New Assignment - Manager"
  select_down 0
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "drafting"'
  local root_thread_id
  root_thread_id=$(jq -r '(.layout // .) | .codex_thread_id' "$(layout_file)")
  wait_layout ".orchestrate_whips | to_entries[0].value.target == \"thread:$root_thread_id\""
  submit_slash_wait "/panes" "Panes"
  select_down 1
  submit_user "QA_APPROVE_DRAFT"
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "executing" and to_entries[0].value.last_dispatch_result == "delivered"'
  snapshot_layout "codex-main-worker-layout"
  printf 'PASS\t10\t%s Main constraints\n' "$TERMINAL_LABEL" >>"$RESULTS"
}

row_11() {
  start_row 11 10
  guided_prewritten_create_manager
  switch_pane "Manager"
  submit_user "QA_USER_PRECEDENCE"
  wait_screen "QA_READY" 100
  local before before_due after_due
  before=$(jq '(.layout // .) | .orchestrate_whips | to_entries[0].value.fires' "$(layout_file)")
  sleep 6
  before_due=$(jq '(.layout // .) | .orchestrate_whips | to_entries[0].value.fires' "$(layout_file)")
  [[ "$before_due" == "$before" ]] || fail 11 "mandate ignored user-precedence window"
  sleep 6
  after_due=$(jq '(.layout // .) | .orchestrate_whips | to_entries[0].value.fires' "$(layout_file)")
  ((after_due > before)) || fail 11 "mandate did not resume after base cadence"
  snapshot_layout "final-layout"
  printf 'PASS\t11\tuser precedence uses base cadence\n' >>"$RESULTS"
}

row_12() {
  start_row 12 900
  create_pane "Worker"
  local worker_thread_id worker_node
  worker_thread_id=$(jq -r '(.layout // .) | .codex_user_pane_ids[-1]' "$(layout_file)")
  [[ "$worker_thread_id" != "null" && -n "$worker_thread_id" ]] \
    || fail 12 "Worker durable thread ID was not persisted in the pane layout"
  worker_node="thread:$worker_thread_id"
  submit "/orchestrate attach $worker_node keep-going --mode auto --holder none --max 2 --cooldown 2s"
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.type == "legacy_nudge"'
  wait_layout '.orchestrate_whips | to_entries[0].value.state == "exhausted" and to_entries[0].value.fires == 2' 160
  local first_id
  first_id=$(jq -r '(.layout // .) | .orchestrate_whips | keys[0]' "$(layout_file)")
  submit "/orchestrate detach $first_id"
  wait_layout '.orchestrate_whips | length == 0'
  submit "/orchestrate attach $worker_node keep-going --mode auto --holder none --max 5 --cooldown 2s"
  wait_layout '.orchestrate_whips | to_entries[0].value.fires >= 1'
  local second_id
  second_id=$(jq -r '(.layout // .) | .orchestrate_whips | keys[0]' "$(layout_file)")
  submit "/orchestrate pause $second_id"
  wait_layout '.orchestrate_whips | to_entries[0].value.state == "paused"'
  capture "legacy-capped-and-paused" >/dev/null
  snapshot_layout "final-layout"
  printf 'PASS\t12\tlegacy capped and pausable\n' >>"$RESULTS"
}

row_13() {
  start_row 13 900
  create_pane "Worker"
  create_pane "Manager"
  local -a screens=()

  submit "/orchestrate attach"
  wait_screen "New Assignment - Worker"
  capture "jargon-guided-worker" >/dev/null
  screens+=("$LAST_CAPTURE_PATH")
  select_down 2
  wait_screen "New Assignment - Duration"
  capture "jargon-guided-duration" >/dev/null
  screens+=("$LAST_CAPTURE_PATH")
  select_down 3
  wait_screen "New Assignment - Spec"
  capture "jargon-guided-spec" >/dev/null
  screens+=("$LAST_CAPTURE_PATH")
  select_down 0
  wait_screen "New Assignment - Manager"
  capture "jargon-guided-manager" >/dev/null
  screens+=("$LAST_CAPTURE_PATH")
  select_down 1
  wait_screen "Create assignment"
  capture "jargon-guided-confirm" >/dev/null
  screens+=("$LAST_CAPTURE_PATH")
  select_down 0
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "drafting"'

  switch_main
  submit_slash_wait "/orchestrate status" "Managers continuously drive Workers"
  capture "jargon-status" >/dev/null
  screens+=("$LAST_CAPTURE_PATH")
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  wait_screen "Assignment assignment-"
  capture "jargon-details" >/dev/null
  screens+=("$LAST_CAPTURE_PATH")
  dismiss_modal orchestrate
  capture "details-and-status-dismissed" >/dev/null

  local worker_node
  worker_node=$(jq -r '(.layout // .) | .orchestrate_whips | to_entries[0].value.target' "$(layout_file)")
  printf 'close=%s\n' "$worker_node" >"$CONTROL"
  wait_layout '.orchestrate_whips | to_entries[0].value.state == "paused"'
  capture "jargon-notice" >/dev/null
  screens+=("$LAST_CAPTURE_PATH")
  printf '%s\n' "${screens[@]}" >"$ARTIFACT_ROOT/$CURRENT_SESSION/jargon-screens.txt"
  if rg -ni '\b(whip|holder|target|review)\b' "${screens[@]}" \
    >"$ARTIFACT_ROOT/$CURRENT_SESSION/jargon-lint.txt"; then
    fail 13 "product jargon appeared in guided flow, status, details, or notices"
  fi
  snapshot_layout "final-layout"
  : >"$CONTROL"
  printf 'PASS\t13\tproduct-language lint\n' >>"$RESULTS"
}

row_14() {
  start_row 14 900
  create_pane "Worker"
  local latency_file="$ARTIFACT_ROOT/$CURRENT_SESSION/popup-latency.tsv"
  : >"$latency_file"
  local started elapsed
  started=$(python3 "$ROOT/qa/orchestrate_tui_platform.py" now-ms) || return
  submit "/orchestrate attach"
  wait_screen "New Assignment - Worker"
  elapsed=$(python3 "$ROOT/qa/orchestrate_tui_platform.py" elapsed-ms "$started") || return
  printf 'worker\t%s\n' "$elapsed" >>"$latency_file"
  ((elapsed < 2000)) || fail 14 "Worker popup exceeded 2s"
  started=$(python3 "$ROOT/qa/orchestrate_tui_platform.py" now-ms) || return
  tmux send-keys -t "$CURRENT_SESSION":0.0 Down
  sleep 0.2
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  wait_screen "New Assignment - Duration"
  elapsed=$(python3 "$ROOT/qa/orchestrate_tui_platform.py" elapsed-ms "$started") || return
  printf 'duration\t%s\n' "$elapsed" >>"$latency_file"
  ((elapsed < 2500)) || fail 14 "Duration popup exceeded 2.5s"
  started=$(python3 "$ROOT/qa/orchestrate_tui_platform.py" now-ms) || return
  tmux send-keys -t "$CURRENT_SESSION":0.0 Down
  sleep 0.15
  tmux send-keys -t "$CURRENT_SESSION":0.0 Down
  sleep 0.15
  tmux send-keys -t "$CURRENT_SESSION":0.0 Down
  sleep 0.2
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  wait_screen "New Assignment - Spec"
  elapsed=$(python3 "$ROOT/qa/orchestrate_tui_platform.py" elapsed-ms "$started") || return
  printf 'spec\t%s\n' "$elapsed" >>"$latency_file"
  ((elapsed < 2500)) || fail 14 "Spec popup exceeded 2.5s"
  started=$(python3 "$ROOT/qa/orchestrate_tui_platform.py" now-ms) || return
  tmux send-keys -t "$CURRENT_SESSION":0.0 Enter
  wait_screen "New Assignment - Manager"
  elapsed=$(python3 "$ROOT/qa/orchestrate_tui_platform.py" elapsed-ms "$started") || return
  printf 'manager\t%s\n' "$elapsed" >>"$latency_file"
  ((elapsed < 2500)) || fail 14 "Manager popup exceeded 2.5s"
  capture "responsive-manager-popup" >/dev/null
  printf 'PASS\t14\tpopup responsiveness\n' >>"$RESULTS"
}

row_15() {
  start_row 15-polluted 900
  local source_layout=${PFTERMINAL_POLLUTED_LAYOUT:-"$ROOT/qa/fixtures/polluted-pane-layout.json"}
  local evidence_dir="$ARTIFACT_ROOT/$CURRENT_SESSION"
  local root_thread_id
  root_thread_id=$(jq -r '(.layout // .) | .codex_thread_id' "$(layout_file)")
  tmux kill-session -t "$CURRENT_SESSION" 2>/dev/null || true
  mkdir -p "$CURRENT_HOME/panes/pane-layouts" "$evidence_dir/read-only-source"
  cp "$source_layout" "$evidence_dir/read-only-source/pane-layout.json"
  chmod 0444 "$evidence_dir/read-only-source/pane-layout.json"
  jq --arg root "$root_thread_id" '.codex_thread_id = $root' \
    "$evidence_dir/read-only-source/pane-layout.json" \
    >"$CURRENT_HOME/panes/pane-layout.json"
  cp "$CURRENT_HOME/panes/pane-layout.json" \
    "$CURRENT_HOME/panes/pane-layouts/$root_thread_id.json"
  local source_hash
  source_hash=$(sha256sum "$source_layout" | awk '{print $1}')
  {
    printf 'source=%s\n' "$source_layout"
    printf 'source_sha256=%s\n' "$source_hash"
    python3 "$ROOT/qa/orchestrate_tui_platform.py" source-mode \
      "$evidence_dir/read-only-source/pane-layout.json" || return
    printf 'normalized_root_thread_id=%s\n' "$root_thread_id"
  } >"$evidence_dir/source-record.txt"

  restart_current 900 "$root_thread_id"
  wait_layout '.orchestrate_whips | to_entries[0].value.state == "paused"' 120
  capture "polluted-layout-recovered" >/dev/null
  grep -Eq "Assignment .* paused(:| after restart:)" "$LAST_CAPTURE_PATH" \
    || fail 15 "polluted assignment did not produce a visible recovery notice"
  [[ "$(sha256sum "$source_layout" | awk '{print $1}')" == "$source_hash" ]] \
    || fail 15 "source polluted layout was modified"
  snapshot_layout "recovered-layout"
  printf 'PASS\t15\tread-only polluted-layout recovery\n' >>"$RESULTS"
}

row_16() {
  start_row 16 900
  create_pane "Worker"
  create_pane "Manager"
  submit "/orchestrate attach"
  wait_screen "New Assignment - Worker"
  select_down 2
  wait_screen "New Assignment - Duration"
  select_down 3
  wait_screen "New Assignment - Spec"
  select_down 0
  wait_screen "New Assignment - Manager"
  select_down 1
  wait_screen "Create assignment"
  select_down 0
  wait_layout '.orchestrate_whips | to_entries[0].value.kind.phase == "drafting"'
  switch_pane "Manager"
  submit_user "QA_EMPTY_MANAGER"
  wait_layout '.orchestrate_whips | to_entries[0].value.empty_output_fires == 0 and to_entries[0].value.kind.phase == "executing" and to_entries[0].value.last_dispatch_result == "delivered"' 160 \
    || fail 16 "empty Manager completion did not recover and dispatch"
  local evidence panes
  capture "empty-manager-recovered" >/dev/null
  evidence=$LAST_CAPTURE_PATH
  screen_contains "$evidence" "retrying once with the existing conversation context" \
    || fail 16 "empty Manager recovery was not visible"
  open_panes_capture "pane-model-labels" >/dev/null
  panes=$LAST_CAPTURE_PATH
  grep -Fq "qa-model;" "$panes" || fail 16 "native pane model was not displayed"
  if grep -Fq "model unknown" "$panes"; then
    fail 16 "native panes still displayed model unknown"
  fi
  snapshot_layout "final-layout"
  printf 'PASS\t16\tempty Manager recovery and model metadata\n' >>"$RESULTS"
}

tmux new-session -d -s "$SERVER_SESSION" \
  "python3 '$ROOT/qa/orchestrate_mock_responses.py' --port '$PORT' --artifacts '$ARTIFACT_ROOT/server' --control '$CONTROL'"
sleep 0.5

read -r -a rows <<<"${PFTERMINAL_MATRIX_ROWS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16}"
for row in "${rows[@]}"; do
  "row_$row"
done

{
  printf '# Orchestrate TUI Matrix\n\n'
  printf 'Release SHA: `%s`  \n' "$SHA"
  printf 'Binary SHA-256: `%s`\n\n' "$(sha256sum "$BINARY" | awk '{print $1}')"
  printf '| Row | Result | Workflow |\n|---:|:---:|---|\n'
  while IFS=$'\t' read -r result row description; do
    printf '| %s | %s | %s |\n' "$row" "$result" "$description"
  done <"$RESULTS"
} >"$ARTIFACT_ROOT/PASS_TABLE.md"

test "$(awk -F '\t' '$1 == "PASS" {count++} END {print count + 0}' "$RESULTS")" -eq "${#rows[@]}"
