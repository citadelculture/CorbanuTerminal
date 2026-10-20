# Issue1056: bounded placeholder cleanup

This contribution addresses the successful-removal cap suggested in [Issue1056](https://github.com/CorbanuCore/CorbanuTerminal/issues/1056).

A sweep removes at most 64 recorded placeholders across all ended-run records. Remaining entries stay recorded for a later sweep. When removing a child changed a deferred parent, the patch persists only the parent identity that the existing child-removal checks already validated. A later external change still prevents removal.

The existing ownership, live-use, mount, identity and no-symlink checks stay in force. The journal format does not change. This budget limits successful removals, not total inspection time; it does not guarantee that every sweep finishes within ten seconds.

Base commit: `bec9e5fb774ab984ce0d53eb82cf13113eb6b181`.

Validation must show all three new regressions failing at their expected assertions with original production, passing with the patch, and the final placeholder-journal suite passing on Linux. The original test bodies are preserved. All runtime results are pending until the hosted campaign returns verified evidence. Formatting alone is not a behavioral pass.

This scope excludes the Uses-filter boundary tests already contributed in PR1079 and the separate cleanup changes in PR1062. No merge, adoption, or completion is claimed here.

This second control branch preserves the first setup failure as unqualified. It adds birth-checked exited-child reaping and an actual synthetic orphan preflight; live descendants still stop the campaign. Optional automatic Git maintenance is disabled only for task subprocesses. Product sources, assertions and tool pins are unchanged.
