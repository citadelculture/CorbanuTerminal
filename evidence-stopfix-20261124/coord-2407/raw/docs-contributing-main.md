# Contributing

Corbanu Terminal changes must preserve a coherent product, not merely compile.
Before starting work, read the [Corbanu Terminal development skill](corbanu-terminal-development-skill.md),
the repository-root `AGENTS.md`, and the relevant nested `AGENTS.md` files.

## Start with product intent

- Identify the exact heading and requirement excerpt in the
  [product specification](corbanu-product-spec.md).
- Classify the change as routine, bounded fix, product initiative, or release.
- Use an active plan for a product initiative. At most two product initiatives
  may be active at once.
- Select one single-feature [current sprint](sprints/index.md). Do not implement
  directly from plan prose.
- Record the implementation worktree, branch, base commit, owner, and scope in
  both the plan and the executable sprint.

If the product specification does not authorize the outcome, obtain the
required product decision before implementation.

## Keep changes focused

- Work on one classified outcome at a time.
- Work only the selected sprint's `Remaining` checklist; move verified items to
  `Done` as evidence changes.
- Preserve unrelated changes already present in the worktree.
- Fix failed behavior at the responsible boundary instead of hard-coding the
  reported example.
- Add regression coverage for the general failure class.
- Follow the nearest scoped engineering guidance for every changed path.

## Prove the final tree

Run the affected formatting, lint, unit, integration, and snapshot checks after
the last code-changing tool. User-facing interactive behavior also requires a
real Corbanu Terminal TUI run in a PTY with actual keys sent. Smoke tests and
non-interactive `exec` runs are supporting evidence, not substitutes.

Use the [tmux TUI harness](tmuxHarness.md) for isolated, key-driven terminal
scenarios, stable viewport assertions, cleanup, and failure artifacts.

Release candidates additionally require live workflows in TensorCash and
Isometric Game, named human acceptance, current user documentation, and the
benchmark and coding-performance gate when due.

## Document only finished behavior

User documentation explains the pain solved and the finished user flow.
Unfinished product contracts belong in the product specification or a plan.
Mechanical work in progress belongs in `docs/sprints/current/`; raw release
evidence belongs under `qa/release/<version>/`. Completed sprint records move to
the excluded archive and leave the documentation navigation.

Every feature page cites the exact product-spec heading and short requirement
excerpt it implements.

## Pull requests

A reviewable pull request includes:

- the change class and product citation;
- the plan link when required;
- the sprint id, status, and exact worktree when required;
- a focused explanation of the user outcome;
- final-tree test results;
- true-TUI and live-repository evidence when required;
- documentation changes;
- a release-note fragment for a change users will notice (see below); and
- any release blocker that remains.

### Release notes

Add a fragment file under `qa/release/unreleased/notes/`, named
`<pr-or-issue-number>-<short-slug>.md`, that starts with a `## ` section
heading (copy an existing heading to add to that section). Don't edit a
shared release-notes file: there isn't one, and CI fails if
`qa/release/unreleased/RELEASE_NOTES.md` comes back. Details and the checker:
[`qa/release/unreleased/README.md`](../qa/release/unreleased/README.md).

Do not mark work complete while required evidence is missing.

## Licence of contributions

Corbanu Terminal is licensed under [Apache-2.0](license.md), and contributions
come in under the same licence: anything you submit for inclusion is licensed
under Apache-2.0 unless you explicitly say otherwise (section 5 of the
licence). There is no contributor licence agreement (CLA) to sign, and a DCO
`Signed-off-by` line is not required.

## Security reports

Do not place credentials, wallet seeds, private keys, protected financial data,
or exploitable details in a public issue. Use the repository's private security
reporting channel and provide the smallest safe reproduction that identifies
the failed boundary.
