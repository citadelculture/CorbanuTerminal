//! Explicit writes to environment variables that a later command runs as
//! code (#1142). Read quoted words so `GIT_PAGER='touch marker'` stays one
//! assignment. This does not consult the host environment or execute a
//! pager: a known consumer of a written command asks as `UnseenCode`.

use super::indirect;
use super::quoted::Word;
use super::shell::basename;
use super::work;

const GIT: u8 = 1;
const LESS: u8 = 2;
const MAN: u8 = 4;

/// Name-only, constant-size state. Writes are sticky: an `unset` or later
/// assignment may be conditional, so it cannot prove an earlier write safe.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(super) struct Writes(u8);

impl Writes {
    pub(super) fn inherit(&mut self, parent: Self) {
        self.0 |= parent.0;
    }

    fn name(&mut self, name: &str, value: Option<&str>) {
        let consumers = match name {
            "GIT_PAGER"
            | "GIT_EDITOR"
            | "GIT_SEQUENCE_EDITOR"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_ASKPASS" => GIT,
            "PAGER" => GIT | MAN,
            "EDITOR" | "VISUAL" => GIT | LESS,
            // Git and man may invoke less as their pager, which in turn
            // runs its input preprocessor or closing command.
            "LESSOPEN" | "LESSCLOSE" => GIT | LESS | MAN,
            "MANPAGER" => MAN,
            _ => return,
        };
        // Git documents empty/cat as disabling its pager. Do not turn the
        // ordinary unified-exec defaults into a command-execution finding.
        // Other writers (printf/read/+=/expansions) do not prove this value.
        if matches!(name, "GIT_PAGER" | "PAGER") && matches!(value, Some("" | "cat")) {
            return;
        }
        self.0 |= consumers;
    }

    fn assignment(&mut self, word: &Word) -> bool {
        let Some((name, value)) = word.text.split_once('=') else {
            return false;
        };
        let append = name.ends_with('+');
        let name = name.strip_suffix('+').unwrap_or(name);
        self.name(name, (!word.dynamic && !append).then_some(value));
        true
    }

    /// Return the environment inherited by this command's nested scripts
    /// and whether a known program may run one of its written values.
    /// Prefix assignments belong to this command, not subsequent commands.
    pub(super) fn command(&mut self, words: &[Word], texts: &[String]) -> (Self, bool) {
        let resolved = indirect::command_word(texts);
        let prefix = resolved.as_ref().map_or(words.len(), |(at, _)| *at);
        let mut current = *self;
        let mut option_value = false;
        for word in &words[..prefix] {
            work::step();
            if option_value {
                option_value = false;
                continue;
            }
            // An env path/unset name or exec argv[0] is an operand even
            // when it happens to contain a watched NAME=value spelling.
            if matches!(
                word.text.as_str(),
                "-u" | "-C" | "--unset" | "--chdir" | "-a"
            ) {
                option_value = true;
            } else {
                current.assignment(word);
            }
        }
        let Some((at, command)) = resolved else {
            // Bare shell assignments persist. `env NAME=value` merely
            // prints an environment, so its writes must not escape.
            if words.iter().all(|word| word.text.contains('=')) {
                *self = current;
            }
            return (current, false);
        };
        let args = &words[at + 1..];
        let inspection = inspection_wrapper(&texts[..at]);
        // env/timeout/sudo and similar wrappers start another process. A
        // writer inside one cannot change this shell's later environment.
        let writer = if same_shell(&texts[..at]) && !inspection {
            command.as_str()
        } else {
            ""
        };
        match writer {
            "export" | "declare" | "typeset" | "local" | "readonly" => {
                let inspection = args
                    .iter()
                    .any(|word| word.text.starts_with('-') && word.text.contains(['p', 'f', 'F']));
                for word in args {
                    work::step();
                    if !self.assignment(word) && !inspection && !word.text.starts_with('-') {
                        self.name(&word.text, None);
                    }
                }
            }
            "printf" => {
                if let Some(option) = args.first() {
                    let target = if option.text == "-v" {
                        args.get(1).map(|word| word.text.as_str())
                    } else {
                        option.text.strip_prefix("-v")
                    };
                    if let Some(target) = target {
                        self.name(target, None);
                    }
                }
            }
            "read" => {
                let mut at = 0;
                let mut options = true;
                while let Some(word) = args.get(at) {
                    work::step();
                    at += 1;
                    if options && word.text == "--" {
                        options = false;
                    } else if options && word.text == "-a" {
                        if let Some(target) = args.get(at) {
                            self.name(&target.text, None);
                        }
                        at += 1;
                    } else if options
                        && matches!(word.text.as_str(), "-d" | "-n" | "-N" | "-p" | "-t" | "-u")
                    {
                        at += 1;
                    } else if !options || !word.text.starts_with('-') {
                        options = false;
                        self.name(&word.text, None);
                    }
                }
            }
            _ => {}
        }
        current.0 |= self.0;
        let consumer = match command.as_str() {
            "git" => GIT,
            "less" => LESS,
            "man" => MAN,
            _ => 0,
        };
        (current, current.0 & consumer != 0 && !inspection)
    }
}

/// `command -v/-V` describes an operand; `env --help/--version` prints
/// information. The general wrapper reader deliberately over-matches these,
/// but they do not run the command-valued environment being tracked here.
fn inspection_wrapper(prefix: &[String]) -> bool {
    for (at, word) in prefix.iter().enumerate() {
        work::step();
        let wrapper = basename(word);
        if !matches!(wrapper, "command" | "env") {
            continue;
        }
        for option in &prefix[at + 1..] {
            work::step();
            if option == "--" || !option.starts_with('-') {
                break;
            }
            if (wrapper == "command" && option.contains(['v', 'V']))
                || (wrapper == "env" && matches!(option.as_str(), "--help" | "--version"))
            {
                return true;
            }
        }
    }
    false
}

fn same_shell(prefix: &[String]) -> bool {
    prefix.iter().all(|word| {
        work::step();
        word.contains('=')
            || word.starts_with('-')
            || matches!(
                word.as_str(),
                "!" | "if"
                    | "then"
                    | "elif"
                    | "else"
                    | "do"
                    | "while"
                    | "until"
                    | "command"
                    | "builtin"
            )
    })
}
