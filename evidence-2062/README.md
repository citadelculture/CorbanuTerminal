# #2062 item 3: stop-closeout evidence

- `excerpt-4440-4640.txt`: an unelided, line-numbered excerpt of `codex-rs/tui/src/app/event_dispatch.rs` at commit `9379813e560518baca9b4bce5145a865ff2e6a5a`.
  It shows the full `AppEvent::EnableWindowsSandboxForAgentMode` arm (L4465). Its body sits under `#[cfg(target_os = "windows")]` (L4470), and the non-Windows counterpart (L4634–L4637) is just `let _ = (preset, mode, profile_selection);`.
- Both "Sandbox ready" lines (L4575, L4607) are inside the Windows-only block.
- **Reproduce:** `git show 9379813e560518baca9b4bce5145a865ff2e6a5a:codex-rs/tui/src/app/event_dispatch.rs | sed -n 4440,4640p`
- `installed-targets.txt`: the only Rust target on this machine (`aarch64-apple-darwin`).
