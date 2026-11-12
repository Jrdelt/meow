//! Command-line interface definitions (`clap` derive).
//!
//! `meow` and `meow <name>` start a session; every subcommand is a helper
//! that targets an existing session, named by `$MEOW_SESSION` (exported inside
//! a session shell) or by `--session`.

use std::fmt;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Environment variable exported inside an active session shell.
pub const SESSION_ENV: &str = "MEOW_SESSION";

const NAME_MAX: usize = 64;

/// Device names Windows refuses as file or directory names.
const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

#[derive(Debug, Parser)]
#[command(
    name = "meow",
    version,
    about,
    args_conflicts_with_subcommands = true,
    after_help = "Run `meow` with no arguments to list saved workspaces."
)]
pub struct Cli {
    /// Workspace to create or resume (~/.meow/workspaces/<NAME>/)
    #[arg(value_name = "NAME", value_parser = parse_workspace_name)]
    pub name: Option<String>,

    /// Keep the workspace in ./.meow/ instead of ~/.meow/workspaces/
    #[arg(long, requires = "name")]
    pub local: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Switch the discovery load/rate profile of the session
    Mode {
        #[arg(value_enum)]
        mode: Mode,
        #[command(flatten)]
        session: SessionArg,
    },
    /// Queue an authorized asset and service inventory of <TARGET>
    Recon {
        /// Host, IP address or CIDR range you are authorized to scan
        target: String,
        /// Extra nmap flags, given after `--`
        #[arg(last = true, value_name = "NMAP_FLAGS")]
        nmap_flags: Vec<String>,
        #[command(flatten)]
        session: SessionArg,
    },
    /// Open the live topology map in the default browser
    Map {
        #[command(flatten)]
        session: SessionArg,
    },
    /// Attach the companion TUI panel
    Hud {
        #[command(flatten)]
        session: SessionArg,
    },
    /// Import an Nmap XML, JSONL, log or git-diff file into the workspace
    Add {
        file: PathBuf,
        #[command(flatten)]
        session: SessionArg,
    },
    /// Compile the workspace into REPORT.md
    Report {
        #[command(flatten)]
        session: SessionArg,
    },
}

/// Which session a helper subcommand targets.
#[derive(Debug, Clone, Default, Args)]
pub struct SessionArg {
    /// Session to target (defaults to the session of the current shell)
    #[arg(long, value_name = "NAME", env = SESSION_ENV)]
    pub session: Option<String>,
}

/// Discovery load/rate profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Passive only: zero outbound packets (default)
    Light,
    /// Rate-limited active discovery
    Mild,
    /// Auto-tuned active discovery
    Aggressive,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Light => "light",
            Mode::Mild => "mild",
            Mode::Aggressive => "aggressive",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Command {
    /// The subcommand as the user typed it, for messages.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Mode { .. } => "mode",
            Command::Recon { .. } => "recon",
            Command::Map { .. } => "map",
            Command::Hud { .. } => "hud",
            Command::Add { .. } => "add",
            Command::Report { .. } => "report",
        }
    }

    fn session_arg(&self) -> &SessionArg {
        match self {
            Command::Mode { session, .. }
            | Command::Recon { session, .. }
            | Command::Map { session }
            | Command::Hud { session }
            | Command::Add { session, .. }
            | Command::Report { session } => session,
        }
    }

    /// Resolves and validates the session this helper targets.
    pub fn session(&self) -> Result<String, String> {
        match self.session_arg().session.as_deref() {
            None | Some("") => Err(format!(
                "No active meow session. Run `meow {}` inside `meow <name>`, or pass --session <name>.",
                self.name()
            )),
            Some(name) => parse_workspace_name(name),
        }
    }
}

impl Cli {
    /// True for `meow` and `meow <name>`, which take over the terminal.
    pub fn starts_session(&self) -> bool {
        self.command.is_none()
    }

    /// Returns the refusal message when this invocation would start a session
    /// inside another one. `active` is the value of `$MEOW_SESSION`.
    pub fn nesting_error(&self, active: Option<&str>) -> Option<String> {
        match active {
            Some(active) if !active.is_empty() && self.starts_session() => Some(format!(
                "Nested meow sessions are disabled (active: {active})"
            )),
            _ => None,
        }
    }
}

/// Validates a workspace name so it is a safe single directory name on
/// macOS, Linux and Windows.
pub fn parse_workspace_name(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.len() > NAME_MAX {
        return Err(format!("name must be 1-{NAME_MAX} characters"));
    }
    let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    if !raw.chars().all(valid_char) {
        return Err("name may contain only letters, digits, '-', '_' and '.'".into());
    }
    if !raw.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err("name must start with a letter or digit".into());
    }
    if raw.ends_with('.') {
        return Err("name must not end with '.'".into());
    }
    let stem = raw.split('.').next().unwrap_or(raw).to_ascii_lowercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        return Err(format!("'{raw}' is a reserved device name on Windows"));
    }
    Ok(raw.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("meow").chain(args.iter().copied()))
    }

    #[test]
    fn clap_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_invocation_lists_workspaces() {
        let cli = parse(&[]).unwrap();
        assert!(cli.name.is_none() && cli.command.is_none() && !cli.local);
        assert!(cli.starts_session());
    }

    #[test]
    fn name_opens_a_workspace() {
        let cli = parse(&["acme-lab"]).unwrap();
        assert_eq!(cli.name.as_deref(), Some("acme-lab"));
        assert!(cli.starts_session());

        let cli = parse(&["acme-lab", "--local"]).unwrap();
        assert!(cli.local);
    }

    #[test]
    fn local_requires_a_name() {
        let err = parse(&["--local"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn subcommand_words_are_not_workspace_names() {
        for word in ["map", "hud", "report"] {
            let cli = parse(&[word, "--session", "x"]).unwrap();
            assert!(cli.name.is_none(), "{word} parsed as a workspace name");
            assert_eq!(cli.command.as_ref().unwrap().name(), word);
            assert!(!cli.starts_session());
        }
    }

    #[test]
    fn name_and_subcommand_cannot_be_combined() {
        assert!(parse(&["acme", "report"]).is_err());
    }

    #[test]
    fn mode_accepts_only_known_profiles() {
        for (word, mode) in [
            ("light", Mode::Light),
            ("mild", Mode::Mild),
            ("aggressive", Mode::Aggressive),
        ] {
            match parse(&["mode", word, "--session", "x"]).unwrap().command {
                Some(Command::Mode { mode: parsed, .. }) => {
                    assert_eq!(parsed, mode);
                    assert_eq!(parsed.to_string(), word);
                }
                other => panic!("unexpected parse: {other:?}"),
            }
        }
        assert_eq!(
            parse(&["mode", "insane"]).unwrap_err().kind(),
            ErrorKind::InvalidValue
        );
        assert!(parse(&["mode"]).is_err());
    }

    #[test]
    fn recon_collects_nmap_flags_after_double_dash() {
        let cli = parse(&[
            "recon",
            "--session",
            "x",
            "10.0.0.0/24",
            "--",
            "-p",
            "80,443",
            "-T3",
            "--open",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Recon {
                target, nmap_flags, ..
            }) => {
                assert_eq!(target, "10.0.0.0/24");
                assert_eq!(nmap_flags, ["-p", "80,443", "-T3", "--open"]);
            }
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[test]
    fn recon_rejects_nmap_flags_without_double_dash() {
        assert!(parse(&["recon", "10.0.0.5", "-T4"]).is_err());
        assert!(parse(&["recon"]).is_err());
    }

    #[test]
    fn add_takes_a_file_path() {
        match parse(&["add", "scans/out.xml", "--session", "x"])
            .unwrap()
            .command
        {
            Some(Command::Add { file, .. }) => assert_eq!(file, PathBuf::from("scans/out.xml")),
            other => panic!("unexpected parse: {other:?}"),
        }
        assert!(parse(&["add"]).is_err());
    }

    #[test]
    fn helper_session_is_resolved_and_validated() {
        let command = parse(&["report", "--session", "acme"])
            .unwrap()
            .command
            .unwrap();
        assert_eq!(command.session().as_deref(), Ok("acme"));

        let command = parse(&["report", "--session", "../etc"])
            .unwrap()
            .command
            .unwrap();
        assert!(command.session().is_err());

        let command = Command::Hud {
            session: SessionArg::default(),
        };
        let message = command.session().unwrap_err();
        assert!(message.contains("No active meow session"), "{message}");
        assert!(message.contains("meow hud"), "{message}");
    }

    #[test]
    fn nesting_is_refused_only_for_session_starters() {
        let expected = "Nested meow sessions are disabled (active: acme)";
        assert_eq!(
            parse(&[]).unwrap().nesting_error(Some("acme")).as_deref(),
            Some(expected)
        );
        assert_eq!(
            parse(&["other"])
                .unwrap()
                .nesting_error(Some("acme"))
                .as_deref(),
            Some(expected)
        );
        let helper = parse(&["report", "--session", "acme"]).unwrap();
        assert_eq!(helper.nesting_error(Some("acme")), None);
        assert_eq!(parse(&["other"]).unwrap().nesting_error(None), None);
        assert_eq!(parse(&["other"]).unwrap().nesting_error(Some("")), None);
    }

    #[test]
    fn workspace_names_are_single_safe_directory_names() {
        for good in ["a", "acme-lab", "client_2026.q4", "HTB.box-01", "7days"] {
            assert_eq!(parse_workspace_name(good).as_deref(), Ok(good));
        }
        let too_long = "a".repeat(65);
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "-flag",
            "a/b",
            "a\\b",
            "a b",
            "caf\u{e9}",
            "trailing.",
            "nul",
            "CON",
            "com1.txt",
            "~",
            "a:b",
            too_long.as_str(),
        ] {
            assert!(parse_workspace_name(bad).is_err(), "accepted {bad:?}");
        }
        assert!(parse(&["../../etc"]).is_err());
    }
}
