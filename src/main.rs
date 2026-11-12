//! `meow` entry point: parse the command line, refuse nested sessions, then
//! dispatch.

use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use meow::cli::{Cli, Command};
use meow::lock::{LockError, SessionLock};
use meow::workspace::{
    format_listing, list_workspaces, resolve_helper_dir, Config, MeowHome, SessionEnv, Workspace,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[!] {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    // Must come first: a nested `meow` exits before any terminal state changes.
    let env = SessionEnv::from_process();
    if let Some(message) = cli.nesting_error(env.active_label().as_deref()) {
        bail!(message);
    }

    let home = MeowHome::from_env()?;
    let cwd = std::env::current_dir().context("cannot determine the current directory")?;

    let Some(command) = &cli.command else {
        return match &cli.name {
            None => {
                let workspaces = list_workspaces(&home, &cwd)?;
                print!("{}", format_listing(&workspaces, SystemTime::now()));
                Ok(())
            }
            Some(name) => {
                let config = Config::load_or_create(&home)?;
                let (mut workspace, created) =
                    Workspace::open_or_create(&home, &cwd, name, cli.local, config.default_mode)?;
                let _lock =
                    SessionLock::acquire(&workspace.lock_path()).map_err(|error| match error {
                        LockError::Held { .. } => {
                            anyhow!("Workspace '{}' is {error}", workspace.name)
                        }
                        LockError::Io(_) => anyhow!("Workspace '{}': {error}", workspace.name),
                    })?;
                workspace.record_open()?;
                println!(
                    "[+] {} workspace '{}' at {} (mode: {})",
                    if created { "Created" } else { "Resumed" },
                    workspace.name,
                    workspace.dir.display(),
                    workspace.profile.mode
                );
                Err(unavailable(
                    &format!("meow {name}"),
                    "the session shell",
                    "Phase 1, Steps 6-7",
                ))
            }
        };
    };

    let target = command.session_arg();
    let dir = resolve_helper_dir(&home, &cwd, target.local, target.session.as_deref(), &env)?;
    let mut workspace = Workspace::load(&dir)?;
    match command {
        Command::Mode { mode, .. } => {
            workspace.set_mode(*mode)?;
            println!("[+] Mode set to {mode} (session: {})", workspace.name);
            Ok(())
        }
        other => {
            let planned = match other {
                Command::Add { .. } => "Phase 2",
                Command::Report { .. } => "Phase 4",
                _ => "Phase 3",
            };
            Err(unavailable(
                &format!("meow {}", other.name()),
                &format!("this command (session: {})", workspace.name),
                planned,
            ))
        }
    }
}

fn unavailable(invocation: &str, what: &str, planned: &str) -> anyhow::Error {
    anyhow!("`{invocation}`: {what} is not built yet (planned: {planned})")
}
