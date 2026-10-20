//! Git's history/diff output files use the same protected-path checks as
//! shell redirections. This is deliberately not a general Git option parser
//! or a list of output options for other programs.

use super::work;

/// Borrowed operands; global `-C` folders apply in order to every output.
#[derive(Default)]
pub(super) struct OutputFiles<'a> {
    pub(super) directories: Vec<&'a str>,
    pub(super) paths: Vec<&'a str>,
}

/// Known output operands after the resolved Git command word, with quotes
/// removed and known variables substituted by the existing shell reading.
pub(super) fn files(args: &[String]) -> OutputFiles<'_> {
    let mut words = args.iter();
    let mut found = OutputFiles::default();
    loop {
        let Some(word) = words.next() else {
            return OutputFiles::default();
        };
        work::step();
        match word.as_str() {
            "-C" => {
                if let Some(directory) = words.next() {
                    found.directories.push(directory);
                }
            }
            option if option.starts_with("-C") => {
                found.directories.push(&option[2..]);
            }
            // Global options whose separate value is not a subcommand.
            "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env"
            | "--super-prefix" | "--attr-source" => {
                words.next();
            }
            "--" => return OutputFiles::default(),
            "log" | "diff" | "show" => break,
            option if option.starts_with('-') => {}
            _ => return OutputFiles::default(),
        }
    }
    while let Some(word) = words.next() {
        work::step();
        match word.as_str() {
            // After this marker, even an output-looking path is data.
            "--" => break,
            "--output" => {
                if let Some(path) = words.next() {
                    found.paths.push(path);
                }
            }
            option if option.starts_with("--output=") => {
                found.paths.push(&option["--output=".len()..]);
            }
            // Required separate option values can themselves look like an
            // output option. Attached values are already a single word.
            "-n"
            | "-L"
            | "-S"
            | "-G"
            | "-O"
            | "--max-count"
            | "--skip"
            | "--since"
            | "--after"
            | "--since-as-filter"
            | "--until"
            | "--before"
            | "--author"
            | "--committer"
            | "--grep"
            | "--grep-reflog"
            | "--encoding"
            | "--date"
            | "--diff-filter"
            | "--find-object"
            | "--diff-algorithm"
            | "--anchored"
            | "--word-diff-regex"
            | "--src-prefix"
            | "--dst-prefix"
            | "--line-prefix"
            | "--output-indicator-new"
            | "--output-indicator-old"
            | "--output-indicator-context"
            | "--stat-width"
            | "--stat-name-width"
            | "--stat-graph-width"
            | "--stat-count"
            | "--rotate-to"
            | "--skip-to" => {
                words.next();
            }
            _ => {}
        }
    }
    if found.paths.is_empty() {
        found.directories.clear();
    }
    found
}
