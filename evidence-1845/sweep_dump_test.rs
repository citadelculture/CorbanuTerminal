// Temporary test used for the sweep (appended to tainted_action_tests.rs,
// run once with main's code_tables.rs and once with the PR's; not committed).
#[test]
#[ignore = "sweep dump"]
fn issue1845_sweep_dump() {
    let (Ok(input), Ok(output)) = (std::env::var("SWEEP_FILE"), std::env::var("SWEEP_OUT")) else {
        return;
    };
    let mut out = String::new();
    for line in std::fs::read_to_string(input).expect("sweep file").lines() {
        for shell in ["/bin/bash", "/bin/zsh"] {
            out.push_str(&format!("{shell}\t{:?}\t{line}\n", kind(&[shell, "-lc", line])));
        }
    }
    std::fs::write(output, out).expect("sweep out");
}
// SWEEP_FILE=sweep-lines.txt SWEEP_OUT=sweep-head.tsv \
//   cargo test -p codex-core --lib issue1845_sweep_dump -- --ignored
