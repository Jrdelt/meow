//! `meow` entry point: parse the command line, refuse nested sessions, then
//! dispatch.

use std::process::ExitCode;

use clap::Parser;
use meow::cli::{Cli, SESSION_ENV};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("[!] {message}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    // Must come first: a nested `meow` exits before any terminal state changes.
    let active = std::env::var(SESSION_ENV).ok();
    if let Some(message) = cli.nesting_error(active.as_deref()) {
        return Err(message);
    }

    match &cli.command {
        None => match &cli.name {
            None => Err(unavailable("meow", "workspace listing", "Phase 1, Step 4")),
            Some(name) => Err(unavailable(
                &format!("meow {name}"),
                "the session shell",
                "Phase 1, Steps 4-6",
            )),
        },
        Some(command) => {
            let session = command.session()?;
            let phase = match command.name() {
                "add" => "Phase 2",
                "report" => "Phase 4",
                _ => "Phase 3",
            };
            Err(unavailable(
                &format!("meow {}", command.name()),
                &format!("this command (session: {session})"),
                phase,
            ))
        }
    }
}

fn unavailable(invocation: &str, what: &str, planned: &str) -> String {
    format!("`{invocation}`: {what} is not built yet (planned: {planned})")
}
