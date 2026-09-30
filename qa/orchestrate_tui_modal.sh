#!/usr/bin/env bash

orchestrate_send_escape() {
  tmux send-keys -t "$1" Escape
}

# A filtered picker loses its search placeholder while remaining open. Require
# the composer's footer below its prompt, with no later modal controls instead.
# The caller supplies only the live viewport, never scrollback.
# Use the stable QA prefix: a long directory can truncate the app/TPS suffix.
orchestrate_modal_closed() {
  awk '
    /[^[:space:]]/ { last_nonblank = NR }
    /^[[:space:]]*›[[:space:]]/ { prompt = NR; footer = 0 }
    /^[[:space:]]*qa-model via qa default[[:space:]]+·/ {
      if (prompt) footer = NR
    }
    END { exit !(prompt > 0 && footer > prompt && footer == last_nonblank) }
  '
}

# Assignment details is stacked above this list. Confirm its live return before
# sending the second Escape that closes the list itself.
orchestrate_status_visible() {
  awk '
    /[^[:space:]]/ { last_nonblank = NR }
    /^[[:space:]]*Orchestrate[[:space:]]*$/ { title = NR; subtitle = 0; footer = 0 }
    /^[[:space:]]*Managers continuously drive Workers through assignments\.[[:space:]]*$/ {
      if (title) subtitle = NR
    }
    /^[[:space:]]*Enter details · d detach · p pause\/resume · e extend · f mandate · t test · n new assignment[[:space:]]*$/ {
      if (subtitle > title) footer = NR
    }
    END { exit !(title > 0 && subtitle > title && footer > subtitle && footer == last_nonblank) }
  '
}
