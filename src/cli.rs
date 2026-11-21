//! Command-line interface definitions (`clap` derive).
//!
//! `meow` and `meow <name>` start a session (a new one asks where to save
//! it); `meow list` shows every saved workspace and `meow delete` removes
//! one; every other subcommand is a helper that targets an existing
//! workspace: `--local`, `--session`, or the session of the current shell
//! (`$MEOW_WORKSPACE` / `$MEOW_SESSION`).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

pub use crate::mode::Mode;
use crate::workspace::validate_name;

#[derive(Debug, Parser)]
#[command(
    name = "meow",
    version,
    about,
    before_help = crate::wizard::CAT_CLI_BANNER,
    args_conflicts_with_subcommands = true,
    after_help = "Run `meow setup` to change the setup."
)]
pub struct Cli {
    /// Session to open; a new one asks where to save it (./meow/<NAME>/ here by default)
    #[arg(value_name = "NAME", value_parser = validate_name)]
    pub name: Option<String>,

    /// Save or open it in ./meow/<NAME>/ of this folder without asking
    #[arg(long, requires = "name", conflicts_with = "home")]
    pub local: bool,

    /// Save or open it in ~/.meow/workspaces/<NAME>/ without asking
    #[arg(long, requires = "name")]
    pub home: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List every saved workspace and whether its session is running
    #[command(visible_aliases = ["ls", "status"])]
    List,
    /// Set up the default mode, local AI, cloud AI and lookups
    Setup {
        /// Show the AI setup (a key is never printed)
        #[arg(long)]
        show: bool,
        /// Test the local AI server and the cloud AI key
        #[arg(long)]
        check: bool,
        /// Line menu for the AI setup
        #[arg(long)]
        plain: bool,
        /// Local AI server, e.g. http://localhost:11434/v1
        #[arg(long, value_name = "URL")]
        local_url: Option<String>,
        /// Local AI model ("": the server's choice)
        #[arg(long, value_name = "NAME")]
        local_model: Option<String>,
        /// Cloud AI service: claude or openrouter
        #[arg(
            long,
            value_parser = ["claude", "anthropic", "openrouter", "openai"],
            hide_possible_values = true
        )]
        provider: Option<String>,
        /// Claude API: models asked when one declines ("": API chooses)
        #[arg(long, value_name = "A,B")]
        fallback_models: Option<String>,
        /// URL of another OpenAI-style cloud AI service
        #[arg(long, value_name = "URL")]
        cloud_url: Option<String>,
        /// Cloud AI triage model
        #[arg(long, value_name = "NAME")]
        cloud_model: Option<String>,
        /// Cloud AI research model
        #[arg(long, value_name = "NAME")]
        research_model: Option<String>,
        /// Read the key from standard input, not arguments
        #[arg(long, conflicts_with = "forget_key")]
        api_key_stdin: bool,
        /// Remove the stored key
        #[arg(long)]
        forget_key: bool,
    },
    /// Show the tools `meow recon` uses and install the missing ones
    Tools {
        /// Install without asking first
        #[arg(long)]
        yes: bool,
    },
    /// Upgrade meow (via SHA-256 verified GitHub Release or source checkout) and its companion tools
    Update {
        /// Only show what is new; change nothing
        #[arg(long)]
        check: bool,
        /// The meow checkout to update (default: the folder meow was built from)
        #[arg(long, value_name = "DIR")]
        source: Option<std::path::PathBuf>,
    },
    /// Delete a saved workspace and everything in it
    #[command(visible_alias = "rm")]
    Delete {
        /// Workspace to delete (found as `meow <NAME>` finds it)
        #[arg(
            value_name = "NAME",
            value_parser = validate_name,
            required_unless_present = "local",
            conflicts_with = "local"
        )]
        name: Option<String>,
        /// Delete the session in ./meow/ (or ./.meow/) of this folder
        #[arg(long)]
        local: bool,
        /// Do not ask for confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },
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
        /// Install a missing scanner or wordlist without asking first
        #[arg(long)]
        install_tools: bool,
        /// Extra nmap flags, given after `--`
        #[arg(last = true, value_name = "NMAP_FLAGS")]
        nmap_flags: Vec<String>,
        #[command(flatten)]
        session: SessionArg,
    },
    /// Open the live topology map in the default browser
    Map {
        /// Print the map URL instead of opening a browser
        #[arg(long)]
        no_open: bool,
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
        /// Skip the CVE lookups (NVD, OSV.dev, CISA KEV) after importing
        #[arg(long)]
        no_cve: bool,
        #[command(flatten)]
        session: SessionArg,
    },
    /// Compile the workspace into REPORT.md
    Report {
        #[command(flatten)]
        session: SessionArg,
    },
}

/// Which workspace a helper subcommand targets. Without either flag it is
/// the session of the current shell.
#[derive(Debug, Clone, Default, Args)]
pub struct SessionArg {
    /// Target the session in ./meow/ (or ./.meow/) of this folder
    #[arg(long, conflicts_with = "session")]
    pub local: bool,

    /// Target the workspace <NAME>
    #[arg(long, value_name = "NAME", value_parser = validate_name)]
    pub session: Option<String>,
}

impl Command {
    /// The subcommand as the user typed it, for messages.
    pub fn name(&self) -> &'static str {
        match self {
            Command::List => "list",
            Command::Delete { .. } => "delete",
            Command::Setup { .. } => "setup",
            Command::Update { .. } => "update",
            Command::Tools { .. } => "tools",
            Command::Mode { .. } => "mode",
            Command::Recon { .. } => "recon",
            Command::Map { .. } => "map",
            Command::Hud { .. } => "hud",
            Command::Add { .. } => "add",
            Command::Report { .. } => "report",
        }
    }

    /// The workspace a helper targets. `None` for `list`, `delete`,
    /// `setup`, `tools` and `update`, which are not helpers of a session.
    pub fn session_arg(&self) -> Option<&SessionArg> {
        match self {
            Command::List
            | Command::Delete { .. }
            | Command::Setup { .. }
            | Command::Update { .. }
            | Command::Tools { .. } => None,
            Command::Mode { session, .. }
            | Command::Recon { session, .. }
            | Command::Map { session, .. }
            | Command::Hud { session }
            | Command::Add { session, .. }
            | Command::Report { session } => Some(session),
        }
    }
}

impl Cli {
    /// True for `meow` and `meow <name>`, which take over the terminal.
    pub fn starts_session(&self) -> bool {
        self.command.is_none()
    }

    /// Returns the refusal message when this invocation would start a session
    /// inside another one. `active` is `SessionEnv::active_label()`.
    pub fn nesting_error(&self, active: Option<&str>) -> Option<String> {
        match active {
            Some(active) if !active.is_empty() && self.starts_session() => {
                let clean = crate::evidence::sanitize(active, 120);
                let shown = if clean.is_empty() {
                    "unknown"
                } else {
                    clean.as_str()
                };
                Some(format!(
                    "Nested meow sessions are disabled (active: {shown})"
                ))
            }
            _ => None,
        }
    }
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
        assert!(cli.name.is_none() && cli.command.is_none() && !cli.local && !cli.home);
        assert!(cli.starts_session());
    }

    #[test]
    fn name_opens_a_workspace() {
        let cli = parse(&["acme-lab"]).unwrap();
        assert_eq!(cli.name.as_deref(), Some("acme-lab"));
        assert!(cli.starts_session());

        let cli = parse(&["acme-lab", "--local"]).unwrap();
        assert!(cli.local && !cli.home);

        let cli = parse(&["acme-lab", "--home"]).unwrap();
        assert!(cli.home && !cli.local);
        assert_eq!(
            parse(&["acme-lab", "--home", "--local"])
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn local_and_home_require_a_name() {
        for flag in ["--local", "--home"] {
            let err = parse(&[flag]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument, "{flag}");
        }
        assert!(parse(&["report", "--home"]).is_err());
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
    fn list_and_ls_show_the_listing_without_starting_a_session() {
        for word in ["list", "ls", "status"] {
            let cli = parse(&[word]).unwrap();
            assert!(cli.name.is_none(), "{word} parsed as a workspace name");
            assert!(matches!(cli.command, Some(Command::List)));
            let command = cli.command.as_ref().unwrap();
            assert_eq!(command.name(), "list");
            assert!(command.session_arg().is_none());
            // Allowed inside a session, unlike a bare `meow`.
            assert!(!cli.starts_session());
            assert_eq!(cli.nesting_error(Some("acme")), None);
        }
        assert!(parse(&["list", "--session", "x"]).is_err());
    }

    #[test]
    fn delete_takes_one_workspace_name_or_local() {
        let delete = |args: &[&str]| match parse(args).map(|cli| cli.command) {
            Ok(Some(Command::Delete { name, local, yes })) => Ok((name, local, yes)),
            Ok(other) => panic!("unexpected parse: {other:?}"),
            Err(error) => Err(error.kind()),
        };
        assert_eq!(
            delete(&["delete", "acme"]),
            Ok((Some("acme".to_owned()), false, false))
        );
        assert_eq!(
            delete(&["rm", "acme", "--yes"]),
            Ok((Some("acme".to_owned()), false, true))
        );
        assert_eq!(delete(&["delete", "-y", "--local"]), Ok((None, true, true)));
        assert_eq!(delete(&["delete"]), Err(ErrorKind::MissingRequiredArgument));
        assert_eq!(
            delete(&["delete", "acme", "--local"]),
            Err(ErrorKind::ArgumentConflict)
        );
        assert!(delete(&["delete", "../../etc"]).is_err());
        assert!(delete(&["delete", "a", "b"]).is_err());

        let cli = parse(&["delete", "acme"]).unwrap();
        let command = cli.command.as_ref().unwrap();
        assert_eq!(command.name(), "delete");
        assert!(command.session_arg().is_none());
        // Deleting another workspace from inside a session is allowed.
        assert_eq!(cli.nesting_error(Some("other")), None);
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
    fn helpers_accept_session_or_local_but_not_both() {
        let arg = |args: &[&str]| {
            let command = parse(args).unwrap().command.unwrap();
            command.session_arg().unwrap().clone()
        };

        let named = arg(&["report", "--session", "acme"]);
        assert_eq!(
            (named.local, named.session.as_deref()),
            (false, Some("acme"))
        );
        let local = arg(&["hud", "--local"]);
        assert_eq!((local.local, local.session), (true, None));
        let bare = arg(&["map"]);
        assert_eq!((bare.local, bare.session), (false, None));

        assert_eq!(
            parse(&["report", "--local", "--session", "acme"])
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict
        );
        assert!(parse(&["report", "--session", "../etc"]).is_err());
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
        assert_eq!(
            parse(&[])
                .unwrap()
                .nesting_error(Some("acme\x1b]52;c;X\x07\u{202e}"))
                .as_deref(),
            Some("Nested meow sessions are disabled (active: acme]52;c;X)")
        );
        assert_eq!(
            parse(&[])
                .unwrap()
                .nesting_error(Some("\x1b\u{202e}"))
                .as_deref(),
            Some("Nested meow sessions are disabled (active: unknown)")
        );
    }

    #[test]
    fn workspace_name_is_validated_at_parse_time() {
        assert!(parse(&["../../etc"]).is_err());
        assert!(parse(&["nul"]).is_err());
    }
}
