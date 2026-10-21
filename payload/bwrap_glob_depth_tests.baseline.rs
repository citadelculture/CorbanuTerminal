//! #732: leaf database patterns scan their folder, not unrelated descendants.
//! These tests only list owned temporary files; they never launch bubblewrap.

use super::expand_unreadable_globs_with_ripgrep;
use super::expand_unreadable_globs_with_scanner;
use super::glob_files;
use codex_protocol::error::Result;
use codex_utils_absolute_path::AbsolutePathBuf;
use pretty_assertions::assert_eq;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn require_ripgrep() {
    assert!(
        Command::new("rg")
            .arg("--version")
            .output()
            .expect("the Linux qualification lane provides ripgrep")
            .status
            .success(),
        "ripgrep must be available; missing prerequisites are not a pass",
    );
}

// Exercise the ordinary ripgrep entry point and the real fallback walker with
// the same grouping/depth logic, without mutating PATH or simulating rg output.
fn scan_with_both(
    patterns: &[String],
    root: &Path,
    max_depth: Option<usize>,
) -> [Result<Vec<AbsolutePathBuf>>; 2] {
    [
        expand_unreadable_globs_with_ripgrep(patterns, root, max_depth),
        expand_unreadable_globs_with_scanner(patterns, root, max_depth, glob_files),
    ]
}

#[test]
fn issue_732_leaf_database_glob_stays_shallow_beside_recursive_globs() {
    require_ripgrep();
    let temp = TempDir::new().expect("temporary scan root");
    let root = temp.path().canonicalize().expect("absolute root");
    fs::create_dir(root.join("child")).expect("child folder");
    for name in ["a.sqlite", "b.env", "child/c.env", "child/project.sqlite"] {
        fs::write(root.join(name), "synthetic").expect("fixture file");
    }
    let patterns = vec![
        format!("{}/*.sqlite*", root.display()),
        format!("{}/**/*.env", root.display()),
    ];
    let actual = scan_with_both(&patterns, &root, /*max_depth*/ None)
        .map(|result| result.expect("scan the owned tree"));
    let expected = ["a.sqlite", "b.env", "child/c.env"]
        .map(|name| AbsolutePathBuf::from_absolute_path(root.join(name)).expect("absolute path"))
        .to_vec();
    assert_eq!(
        actual,
        [expected.clone(), expected],
        "leaf database patterns must stay at their declared folder",
    );
}

struct RestoreDirectoryMode<'a>(&'a Path, fs::Permissions);

impl Drop for RestoreDirectoryMode<'_> {
    fn drop(&mut self) {
        fs::set_permissions(self.0, self.1.clone()).expect("restore owned directory permissions");
    }
}

#[test]
fn issue_732_leaf_database_glob_does_not_enter_unreadable_children() {
    require_ripgrep();
    // SAFETY: geteuid has no preconditions and only reads this process's uid.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "this fixture requires a non-root test process"
    );
    let temp = TempDir::new().expect("temporary scan root");
    let root = temp.path().canonicalize().expect("absolute root");
    let database = root.join("runtime.sqlite");
    fs::write(&database, "synthetic").expect("runtime database");
    let child = root.join("unrelated");
    fs::create_dir(&child).expect("unrelated folder");
    fs::write(child.join("project.sqlite"), "synthetic").expect("unrelated database");
    let mode = RestoreDirectoryMode(
        &child,
        fs::metadata(&child).expect("child metadata").permissions(),
    );
    fs::set_permissions(&child, fs::Permissions::from_mode(0o000))
        .expect("make owned child unreadable");
    assert!(
        fs::read_dir(&child).is_err(),
        "the unreadable-child prerequisite must hold"
    );
    let results = scan_with_both(
        &[format!("{}/*.sqlite*", root.display())],
        &root,
        /*max_depth*/ None,
    );
    assert!(
        results.iter().all(Result::is_ok),
        "a leaf database scan must not enter an unreadable child: {results:?}"
    );
    let expected = vec![AbsolutePathBuf::from_absolute_path(database).expect("absolute database")];
    assert_eq!(
        results.map(|result| result.expect("bounded scan")),
        [expected.clone(), expected],
    );
    drop(mode);
}

#[test]
fn issue_732_explicit_recursive_database_glob_keeps_its_depth() {
    require_ripgrep();
    let temp = TempDir::new().expect("temporary scan root");
    let root = temp.path().canonicalize().expect("absolute root");
    fs::create_dir_all(root.join("child/deep")).expect("nested folders");
    for name in ["a.sqlite", "child/b.sqlite", "child/deep/c.sqlite"] {
        fs::write(root.join(name), "synthetic").expect("fixture database");
    }
    let actual = scan_with_both(
        &[format!("{}/**/*.sqlite*", root.display())],
        &root,
        Some(2),
    )
    .map(|result| result.expect("recursive scan"));
    let expected = ["a.sqlite", "child/b.sqlite"]
        .map(|name| AbsolutePathBuf::from_absolute_path(root.join(name)).expect("absolute path"))
        .to_vec();
    assert_eq!(
        actual,
        [expected.clone(), expected],
        "explicit recursion retains its configured depth"
    );
}
