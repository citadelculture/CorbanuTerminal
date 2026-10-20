//! #885: what the word lexer cannot see because it removes quotes. A nested
//! shell's script (`bash -c "sh -c './x.sh'"`) is judged like a command
//! line of its own, and a sed program is judged whole: one that may run a
//! shell command, or that saves what it outputs to a file the same line
//! runs, is code the host cannot read.
//!
//! Quoted text is judged wherever it is (as the word lexer does), so a
//! misreading of which text is data cannot hide anything; and a shell or
//! sed command the word lexer finds that this reading does not fails
//! closed.

use super::Classifier;
use super::FileText;
use super::Folders;
use super::ProtectedActionKind;
use super::WRITERS;
use super::indirect;
use super::invocation;
use super::invocation::Code;
use super::outbound;
use super::quoted;
use super::quoted::Command;
use super::quoted::Word;
use super::sed;
use super::shell::SHELLS;
use super::shell::basename;
use super::work;
use std::collections::HashMap;
use std::collections::HashSet;

/// Levels of quoted text read for nested commands. Deeper text is still
/// split by the word lexer, and a command only it sees fails closed.
const MAX_QUOTED_LEVEL: usize = 4;

/// Nested scripts judged for one action; more fail closed.
const MAX_NESTED_SCRIPTS: usize = 256;

/// Scripts, sed calls and written files one reading collects (#1065);
/// more fail closed.
const MAX_COLLECTED: usize = 4096;

/// Pipeline stages followed from one command for the files they write
/// (#1065): following every stage from every stage is quadratic. Past it
/// the pipeline writes a file the classifier cannot name.
const MAX_PIPELINE_STAGES: usize = 64;

/// Pipeline stages that save their input to the files they are given.
const PIPE_WRITERS: &[&str] = &["tee", "dd", "sponge", "cp", "install"];

/// Pipeline stages that only print a transform of their input. Any other
/// stage (`awk`, `sh -c`, `python3`, `while read`) may write it to a file.
/// `sort` and `uniq` may also save it (`sort -o f`, `uniq - f`).
const PURE_FILTERS: &[&str] = &[
    "cat", "column", "cut", "fmt", "fold", "grep", "egrep", "fgrep", "head", "jq", "nl", "rg",
    "sed", "gsed", "sort", "tac", "tail", "tr", "uniq", "wc",
];

/// What the pass found in one command line.
#[derive(Default)]
struct Found {
    /// Scripts that nested shells run, with the folder they run in.
    scripts: Vec<(String, String)>,
    seds: Vec<Sed>,
    /// sed commands found (each may be read more than one way).
    sed_commands: usize,
    /// Shells given a `-c` script.
    shell_commands: usize,
    /// Text it could not read in full: substitutions nested too deeply, a
    /// quote left open, or too many places a command may start.
    unreadable: bool,
    /// Files the line writes (`None`: one it cannot name).
    written: Vec<Option<String>>,
    /// A command other than sed writes a file (a copy, move, download or
    /// redirection), which may carry what sed output.
    other_writes: bool,
    /// Redirections and pipes of compound commands (`{ ...; } > f`,
    /// `done | tee f`, `exec 3> f`): any command's output may go there.
    shared_targets: Vec<Option<String>>,
    /// An interpreter runs code that may write files the classifier does
    /// not see (`python3 -c "open('x','w')..."`).
    runs_code: bool,
}

/// One reading of a sed invocation and where it runs.
struct Sed {
    call: sed::Call,
    cwd: String,
    /// Where its output is saved besides in place: its redirections and
    /// the files later pipeline stages write.
    saved_to: Vec<Option<String>>,
    /// It runs inside a substitution: its output is part of another
    /// command's words.
    substituted: bool,
    /// It gets more arguments at run time (`xargs sed`, `parallel sed`)...
    fed: bool,
    /// ...that may go into its words (`xargs -I{}`, `{}`).
    replaced: bool,
}

/// What quoted text is to the command that gets it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Text that may be code (or data, which is judged the same way).
    Code,
    /// A nested shell's script, judged as a line by `script`.
    Script,
}

fn name(word: &str) -> String {
    basename(&word.to_lowercase()).to_string()
}

/// A word's text when the classifier knows it.
fn known(word: &Word) -> Option<String> {
    (!word.dynamic).then(|| word.text.clone())
}

/// A file a command names, when the classifier can name it: not an
/// expansion and not a pattern (`*.sh`, `r.{a,b}`).
fn target(text: Option<String>) -> Option<String> {
    text.filter(|text| !text.contains(['*', '?', '[', '{']))
}

/// How many shells the word lexer's command runs with a `-c` script.
pub(super) fn shell_commands(words: &[String]) -> usize {
    let (starts, _) = sed::command_starts(words);
    let mut resolved = HashSet::new();
    starts
        .into_iter()
        .filter_map(|start| {
            let (index, shell) = indirect::command_word(&words[start..])?;
            let at = start + index;
            let inline = SHELLS.contains(&shell.as_str())
                && matches!(
                    invocation::parse(&shell, &words[at + 1..]).map(|invocation| invocation.code),
                    Some(Code::Inline(_))
                );
            (inline && resolved.insert(at)).then_some(())
        })
        .count()
}

impl Classifier {
    /// `lexed`: how many sed commands and shells with a `-c` script the
    /// word lexer found in the line.
    pub(super) fn quoted_pass(
        &mut self,
        command: &[String],
        cwd: &str,
        depth: usize,
        lexed: (usize, usize),
    ) {
        // The words as given, and a shell's `-c` script as a line of its
        // own, as the word lexer reads them.
        let mut argv = Command::default();
        let mut scripts = Vec::new();
        let mut previous: Option<&str> = None;
        for arg in command {
            work::step();
            let in_shell = argv
                .words
                .iter()
                .any(|word| SHELLS.contains(&name(&word.text).as_str()));
            let script = in_shell
                && previous.is_some_and(|flag| {
                    flag.starts_with('-') && !flag.starts_with("--") && flag.contains('c')
                });
            if script {
                scripts.push(arg.as_str());
            } else {
                argv.words.push(Word {
                    text: arg.clone(),
                    quoted: true,
                    ..Word::default()
                });
            }
            previous = Some(arg);
        }
        let mut folders = Folders {
            cwd: cwd.to_string(),
            previous: cwd.to_string(),
            stack: std::rc::Rc::default(),
            unfollowed: false,
        };
        let mut found = Found::default();
        self.walk(&[argv], &mut folders, /*level*/ 0, &mut found);
        // Shell text a shell would refuse may split differently from this
        // reading (text of other languages is read loosely).
        let strict = self.not_shell == 0 && self.rebuilt == 0;
        for script in scripts {
            work::step();
            let reading = quoted::commands(script);
            found.unreadable |=
                reading.too_deep || reading.unsure || (strict && reading.unterminated);
            self.walk(
                &reading.commands,
                &mut folders,
                /*level*/ 0,
                &mut found,
            );
        }
        if found.unreadable || folders.unfollowed {
            self.note(ProtectedActionKind::UnseenCode);
        }
        self.written.extend(found.written.iter().cloned());
        let mut judged = HashSet::new();
        for (script, cwd) in std::mem::take(&mut found.scripts) {
            work::step();
            if !judged.insert((script.clone(), cwd.clone())) {
                continue;
            }
            self.nested_scripts += 1;
            if self.nested_scripts > MAX_NESTED_SCRIPTS {
                self.note(ProtectedActionKind::UnseenCode);
                break;
            }
            self.script(&script, &cwd, depth + 1);
        }
        for sed in std::mem::take(&mut found.seds) {
            work::step();
            self.judge_sed(sed, &found, depth);
        }
        // A command the word lexer finds that this reading does not
        // (spelled through a variable, braces or `$IFS`) fails closed.
        let (lexed_seds, lexed_shells) = lexed;
        if lexed_seds > found.sed_commands || lexed_shells > found.shell_commands {
            self.note(ProtectedActionKind::UnseenCode);
        }
    }

    /// Collect nested scripts, sed invocations and written files from
    /// `commands` and the quoted text in them, following `cd`.
    fn walk(&self, commands: &[Command], folders: &mut Folders, level: usize, found: &mut Found) {
        for command in commands {
            work::step();
            if found.scripts.len()
                + found.seds.len()
                + found.shared_targets.len()
                + found.written.len()
                > MAX_COLLECTED
            {
                found.unreadable = true;
                return;
            }
            let texts: Vec<String> = command.words.iter().map(|word| word.text.clone()).collect();
            // A substitution's `cd` does not move this line.
            if !command.substituted
                && let Some((index, name)) = indirect::command_word(&texts)
            {
                self.change_folder(&name, &texts[index + 1..], folders, &mut HashMap::new());
            }
            let first = texts.first().map(|word| name(word));
            let compound = first
                .as_deref()
                .is_none_or(|first| matches!(first, "done" | "fi" | "esac" | "exec"));
            let mut targets: Vec<Option<String>> = command
                .writes_to
                .iter()
                .map(|word| target(known(word)))
                .collect();
            if command.writes_descriptor {
                targets.push(None);
            }
            if compound {
                found.shared_targets.extend(targets.iter().cloned());
                found
                    .shared_targets
                    .extend(pipeline_targets(commands, command));
            }
            found.written.extend(targets);
            let (starts, overflow) = sed::command_starts(&texts);
            found.unreadable |= overflow;
            let mut roles = vec![Role::Code; texts.len()];
            let mut input_role = Role::Code;
            let mut resolved = HashSet::new();
            let mut wrappers_checked = HashSet::new();
            let mut runners = 0;
            let mut watched = false;
            let mut sed_command = false;
            for start in starts {
                work::step();
                let Some((index, resolved_name)) = indirect::command_word(&texts[start..]) else {
                    continue;
                };
                let at = start + index;
                // Wrappers that run a string as a shell line (`watch`,
                // `su -c`, `flock f -c`, `env -S`). Only the outermost
                // `watch` counts: an inner one is part of its line.
                for wrapper in start..=at {
                    work::step();
                    if !wrappers_checked.insert(wrapper) {
                        continue;
                    }
                    let is_watch = name(&texts[wrapper]) == "watch";
                    if is_watch && std::mem::replace(&mut watched, true) {
                        continue;
                    }
                    for (word, script) in runner_scripts(&texts, wrapper) {
                        work::step();
                        roles[word] = Role::Script;
                        found.scripts.push((script, folders.cwd.clone()));
                        runners += 1;
                    }
                    // Too many shell strings in one command: fail closed.
                    if runners > outbound::MAX_JUDGED_POSITIONS {
                        found.unreadable = true;
                        break;
                    }
                }
                if !resolved.insert(at) {
                    continue;
                }
                if sed::NAMES.contains(&resolved_name.as_str()) {
                    sed_command = true;
                } else if WRITERS.contains(&resolved_name.as_str()) || !command.writes_to.is_empty()
                {
                    found.other_writes = true;
                    found.written.extend(
                        texts[at + 1..]
                            .iter()
                            .filter(|word| !word.starts_with('-'))
                            .map(|word| target(Some(file_operand(word).to_string()))),
                    );
                }
                if resolved_name == "eval" {
                    continue;
                }
                let shell = SHELLS.contains(&resolved_name.as_str());
                let code = invocation::parse(&resolved_name, &texts[at + 1..])
                    .map(|invocation| invocation.code);
                found.runs_code |= code.is_some() && !shell;
                match code {
                    Some(Code::Inline(inline)) if shell => {
                        found.shell_commands += 1;
                        let Some(inline) = inline else {
                            continue;
                        };
                        let Some(first) = word_holding(&texts, at + 1, inline) else {
                            continue;
                        };
                        // After `-c`, bash reads further options (`-o
                        // pipefail`) and runs the first operand; other
                        // shells run the word after `-c`. Every word that
                        // may be the script is judged.
                        let candidates: Vec<usize> = if texts[first].starts_with(['-', '+']) {
                            (first..texts.len())
                                .filter(|&index| !texts[index].starts_with(['-', '+']))
                                .collect()
                        } else {
                            vec![first]
                        };
                        for candidate in candidates {
                            work::step();
                            roles[candidate] = Role::Script;
                            found
                                .scripts
                                .push((texts[candidate].clone(), folders.cwd.clone()));
                        }
                    }
                    // A here-string or here-document the shell reads.
                    Some(Code::Stdin) if shell => {
                        input_role = Role::Script;
                        for input in &command.input {
                            work::step();
                            found
                                .scripts
                                .push((input.text.clone(), folders.cwd.clone()));
                        }
                    }
                    _ => {}
                }
            }
            if sed_command {
                collect_seds(commands, command, &texts, folders, found);
            }
            if level >= MAX_QUOTED_LEVEL {
                continue;
            }
            // Also redirection files, comments and other text the shell
            // does not pass on as words.
            let quoted = command
                .words
                .iter()
                .zip(roles)
                .filter(|(word, _)| word.quoted)
                .chain(command.input.iter().map(|input| (input, input_role)))
                .chain(
                    command
                        .writes_to
                        .iter()
                        .filter(|word| word.quoted)
                        .chain(&command.other_text)
                        .map(|word| (word, Role::Code)),
                );
            for (word, role) in quoted {
                work::step();
                // Quoted text runs in a shell of its own, if at all: its
                // `cd` does not move this line.
                let mut inner = Folders {
                    cwd: folders.cwd.clone(),
                    previous: folders.previous.clone(),
                    stack: folders.stack.clone(),
                    unfollowed: false,
                };
                let reading = quoted::commands(&word.text);
                found.unreadable |= reading.too_deep || reading.unsure;
                if role == Role::Code {
                    // Commands in data the word lexer does not read as
                    // command lines do not count: a decoy (`echo 'sed p'`)
                    // must not make up for a command this reading missed.
                    let counts = (found.sed_commands, found.shell_commands);
                    self.walk(&reading.commands, &mut inner, level + 1, found);
                    found.unreadable |= inner.unfollowed;
                    if !word.lines {
                        (found.sed_commands, found.shell_commands) = counts;
                    }
                    continue;
                }
                // A nested shell's script is judged when `script` reads
                // it: here its commands are only counted (unless the word
                // lexer keeps it as one word, `bash -c $'...'`).
                let mut counted = Found::default();
                self.walk(&reading.commands, &mut inner, level + 1, &mut counted);
                if !word.whole {
                    found.sed_commands += counted.sed_commands;
                    found.shell_commands += counted.shell_commands;
                }
                found.unreadable |= counted.unreadable || inner.unfollowed;
            }
        }
    }

    /// A sed that may run a shell command, whose program or options the
    /// classifier cannot read, or that saves what it outputs to a file the
    /// line runs is code the host cannot read; an in-place edit that only
    /// keeps, drops or adds lines has the text it adds judged instead.
    fn judge_sed(&mut self, sed: Sed, line: &Found, depth: usize) {
        let call = &sed.call;
        let dynamic = call
            .programs
            .iter()
            .chain(&call.files)
            .any(|word| word.dynamic);
        // Arguments added at run time may be the program or options
        // (GNU sed reads options anywhere before `--`).
        let fed = sed.fed
            && !call.bsd
            && (sed.replaced
                || !call.options_ended
                || (call.programs.is_empty() && call.files.is_empty()));
        if call.unknown || fed || (dynamic && self.rebuilt == 0) {
            self.note(ProtectedActionKind::UnseenCode);
            return;
        }
        let mut chunks: Vec<String> = call.programs.iter().map(|word| word.text.clone()).collect();
        for file in &call.files {
            work::step();
            // A script file the action writes, or that code the classifier
            // cannot follow may write, may differ when sed runs.
            let rewritten = line.runs_code
                || !self.ran.is_empty()
                || self.written.iter().any(|written| {
                    written
                        .as_deref()
                        .is_none_or(|written| name(written) == name(&file.text))
                });
            let path = self.homes.resolve(&file.text, &sed.cwd);
            match (rewritten, self.read_file(&path)) {
                (false, FileText::Text(text)) => chunks.push(text),
                _ => {
                    self.note(ProtectedActionKind::UnseenCode);
                    return;
                }
            }
        }
        // GNU sed joins the pieces with newlines; each is also read alone.
        let mut readings = vec![sed::program(&chunks.join("\n"))];
        if chunks.len() > 1 {
            readings.extend(chunks.iter().map(|chunk| sed::program(chunk)));
        }
        if readings.iter().any(|reading| reading.runs) {
            self.note(ProtectedActionKind::UnseenCode);
            return;
        }
        let mut targets = sed.saved_to.clone();
        targets.extend(line.shared_targets.iter().cloned());
        targets.extend(readings.iter().flat_map(|reading| {
            reading
                .writes
                .iter()
                .cloned()
                .map(|file| target(Some(file)))
        }));
        // Output captured into another command's words.
        if sed.substituted && line.other_writes {
            targets.push(None);
        }
        let elsewhere = !targets.is_empty();
        if !elsewhere && !call.in_place {
            return;
        }
        // Another command may copy or move what sed saved.
        if line.other_writes {
            targets.push(None);
        }
        if call.in_place {
            targets.extend(call.operands.iter().map(|word| target(known(word))));
        }
        if !targets.iter().any(|target| self.may_run(target.as_deref())) {
            return;
        }
        if elsewhere || !readings.iter().all(|reading| reading.keeps_lines) {
            self.note(ProtectedActionKind::UnseenCode);
            return;
        }
        // The edited file holds its own lines and this text: running the
        // file reads the former, the text is judged here.
        let texts: Vec<String> = readings
            .iter()
            .flat_map(|reading| reading.texts.iter().cloned())
            .collect();
        for text in texts {
            work::step();
            self.script(&text, &sed.cwd, depth + 1);
        }
    }

    /// Whether the action runs a script that may be `target` (by name;
    /// `None` is a file the classifier cannot name).
    fn may_run(&self, target: Option<&str>) -> bool {
        if self.ran_unknown {
            return true;
        }
        match target {
            None => !self.ran.is_empty(),
            Some(target) => {
                let target = name(target);
                self.ran.iter().any(|ran| name(ran) == target)
            }
        }
    }
}

fn collect_seds(
    commands: &[Command],
    command: &Command,
    texts: &[String],
    folders: &Folders,
    found: &mut Found,
) {
    // Where its output goes: its redirections, then the later stages of
    // its pipeline.
    let mut saved_to: Vec<Option<String>> = command
        .writes_to
        .iter()
        .map(|word| target(known(word)))
        .collect();
    if command.writes_descriptor {
        saved_to.push(None);
    }
    saved_to.extend(pipeline_targets(commands, command));
    for at in sed::positions(texts) {
        work::step();
        found.sed_commands += 1;
        let fed = texts[..at]
            .iter()
            .any(|word| matches!(name(word).as_str(), "xargs" | "parallel"));
        let replaced = fed
            && (texts[..at].iter().any(|word| {
                ["-I", "-i", "-J", "--replace"]
                    .iter()
                    .any(|flag| word.starts_with(flag))
            }) || texts[at + 1..].iter().any(|word| word.contains("{}")));
        for call in sed::calls(&command.words[at + 1..]) {
            work::step();
            found.seds.push(Sed {
                call,
                cwd: folders.cwd.clone(),
                saved_to: saved_to.clone(),
                substituted: command.substituted,
                fed,
                replaced,
            });
        }
    }
}

/// Files the later stages of `command`'s pipeline may write what it
/// outputs to (`None`: ones the classifier cannot name).
fn pipeline_targets(commands: &[Command], command: &Command) -> Vec<Option<String>> {
    let mut targets = Vec::new();
    if command.piped && command.pipe_to.is_none() {
        targets.push(None);
    }
    let mut stage = command.pipe_to;
    let mut steps = 0;
    while let Some(index) = stage
        && steps < commands.len()
    {
        work::step();
        if steps == MAX_PIPELINE_STAGES {
            targets.push(None);
            break;
        }
        steps += 1;
        let Some(consumer) = commands.get(index) else {
            targets.push(None);
            break;
        };
        targets.extend(consumer.writes_to.iter().map(|word| target(known(word))));
        if consumer.writes_descriptor {
            targets.push(None);
        }
        let texts: Vec<String> = consumer
            .words
            .iter()
            .map(|word| word.text.clone())
            .collect();
        match indirect::command_word(&texts) {
            Some((at, consumer_name)) if PIPE_WRITERS.contains(&consumer_name.as_str()) => {
                targets.extend(
                    consumer.words[at + 1..]
                        .iter()
                        .filter(|word| !word.text.starts_with('-'))
                        .map(|word| {
                            target(known(word).map(|text| file_operand(&text).to_string()))
                        }),
                );
            }
            Some((at, consumer_name)) if PURE_FILTERS.contains(&consumer_name.as_str()) => {
                if filter_saves(&consumer_name, &texts[at + 1..]) {
                    targets.push(None);
                }
            }
            // A stage that may write what it reads anywhere.
            _ => targets.push(None),
        }
        stage = consumer.pipe_to;
    }
    targets
}

/// Whether a pure filter's arguments may save its output to a file:
/// `sort -o f` (also in a group of short options, or `--output`, or a
/// `--compress-program` it runs, or any `--c` abbreviation but `--check`), or `uniq`'s second operand. Option values
/// may be read as operands here (fail closed).
fn filter_saves(filter: &str, args: &[String]) -> bool {
    match filter {
        "sort" => args.iter().take_while(|arg| *arg != "--").any(|arg| {
            arg.starts_with("--o")
                || (arg.starts_with("--c") && !arg.starts_with("--check"))
                || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('o'))
        }),
        "uniq" => {
            let mut operands = 0;
            let mut options_ended = false;
            for arg in args {
                work::step();
                if !options_ended && arg == "--" {
                    options_ended = true;
                } else if options_ended || arg == "-" || !arg.starts_with('-') {
                    operands += 1;
                }
            }
            operands > 1
        }
        _ => false,
    }
}

/// The word from `from` on that ends with `inline` (an attached `-c$X`
/// ends its option word).
fn word_holding(texts: &[String], from: usize, inline: &str) -> Option<usize> {
    (from..texts.len()).find(|&index| {
        let word = texts[index].as_str();
        word.len() >= inline.len() && std::ptr::eq(&word[word.len() - inline.len()..], inline)
    })
}

/// The file in an operand such as `of=r.sh`.
fn file_operand(word: &str) -> &str {
    word.rsplit_once('=').map_or(word, |(_, file)| file)
}

/// Scripts a wrapper at `at` runs as a shell line, with the word that
/// holds each: `watch CMD...`, `su -c CMD`, `runuser -c`, `flock F -c`,
/// `script -c`, `env -S STRING`, also in a group of short options
/// (`su -lc`, `script -qc`). Options are looked for among the next
/// `MAX_JUDGED_POSITIONS` words.
fn runner_scripts(texts: &[String], at: usize) -> Vec<(usize, String)> {
    let wrapper = name(&texts[at]);
    let args = at + 1..texts.len().min(at + 1 + outbound::MAX_JUDGED_POSITIONS);
    match wrapper.as_str() {
        "watch" => {
            // Its options, then the command, joined into one shell line.
            let mut index = at + 1;
            while let Some(word) = texts.get(index)
                && word.starts_with('-')
            {
                work::step();
                let valued = matches!(word.as_str(), "-n" | "--interval" | "-q" | "--equexit");
                index += 1 + usize::from(valued);
            }
            if index >= texts.len() {
                return Vec::new();
            }
            vec![(index, texts[index..].join(" "))]
        }
        "su" | "runuser" | "flock" | "script" | "env" => {
            let (letter, long) = if wrapper == "env" {
                ('S', "--split-string")
            } else {
                ('c', "--command")
            };
            let mut scripts = Vec::new();
            for index in args {
                work::step();
                let word = &texts[index];
                let next = || texts.get(index + 1).map(|next| (index + 1, next.clone()));
                if word == long {
                    scripts.extend(next());
                } else if let Some(attached) = word.strip_prefix(&format!("{long}=")) {
                    scripts.push((index, attached.to_string()));
                } else if let Some(cluster) = word.strip_prefix('-')
                    && !cluster.starts_with('-')
                    && let Some((at_letter, _)) =
                        cluster.char_indices().find(|(_, ch)| *ch == letter)
                {
                    // The letter's value is the rest of the group, or the
                    // next word.
                    let rest = &cluster[at_letter + 1..];
                    if rest.is_empty() {
                        scripts.extend(next());
                    } else {
                        scripts.push((index, rest.to_string()));
                    }
                }
            }
            scripts
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    /// #1065: each command follows a bounded number of pipeline stages, so
    /// a long pipeline (`tee f|tee f|...`) is linear. Counted, not timed.
    #[test]
    fn issue_1065_pipeline_targets_are_bounded() {
        let reading = quoted::commands(&"tee f|".repeat(1000));
        assert_eq!(reading.commands.len(), 1000);
        let longest = reading
            .commands
            .iter()
            .map(|command| pipeline_targets(&reading.commands, command).len())
            .max();
        assert_eq!(longest, Some(MAX_PIPELINE_STAGES + 1));
    }
}
