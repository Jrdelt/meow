//! `meow` entry point: parse the command line, refuse nested sessions, then
//! dispatch.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use meow::cli::{Cli, Command};
use meow::cve::{self, CveClient, CveSettings};
use meow::db::Db;
use meow::graph::Graph;
use meow::lock::{LockError, SessionLock};
use meow::observer;
use meow::parsers;
use meow::pty::{self, LineSink, SessionSpec};
use meow::shims;
use meow::workspace::{
    format_listing, list_workspaces, private_open_options, resolve_helper_dir, Config, MeowHome,
    SessionEnv, Workspace,
};

/// Debug aid: when set to a file path, the clean lines produced by the
/// analysis tap are appended to that file.
const TAP_LOG_ENV: &str = "MEOW_TAP_LOG";

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("[!] {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
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
                Ok(ExitCode::SUCCESS)
            }
            Some(name) => start_session(&home, &cwd, name, cli.local),
        };
    };

    let target = command.session_arg();
    let dir = resolve_helper_dir(&home, &cwd, target.local, target.session.as_deref(), &env)?;
    let mut workspace = Workspace::load(&dir)?;
    match command {
        Command::Mode { mode, .. } => {
            workspace.set_mode(*mode)?;
            println!("[+] Mode set to {mode} (session: {})", workspace.name);
            Ok(ExitCode::SUCCESS)
        }
        Command::Add { file, no_cve, .. } => {
            let parsed = parsers::parse_file(file)?;
            let path = workspace.graph_path();
            let mut graph = Graph::load(&path)?;
            let total = parsed.observations.len();
            let changed = graph.apply_all(parsed.observations);
            graph.save(&path)?;
            println!(
                "[+] {} ({}): {total} facts parsed, {changed} new or updated{}",
                file.display(),
                parsed.format,
                match parsed.skipped {
                    0 => String::new(),
                    n => format!(", {n} lines skipped"),
                }
            );
            println!(
                "[+] Session '{}' now has {} hosts",
                workspace.name,
                graph.hosts.len()
            );
            let config = Config::load_or_create(&home)?;
            if config.cve.enabled && !no_cve {
                ground_cves(&workspace, &mut graph, config.cve)?;
                graph.save(&path)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        other => {
            let planned = match other {
                Command::Report { .. } => "Phase 4",
                _ => "Phase 3",
            };
            Err(anyhow!(
                "`meow {}`: this command (session: {}) is not built yet (planned: {planned})",
                other.name(),
                workspace.name
            ))
        }
    }
}

/// `meow <name>`: open the workspace, take its lock and run the shell until
/// it exits. The process exit code is the shell's.
fn start_session(home: &MeowHome, cwd: &Path, name: &str, local: bool) -> Result<ExitCode> {
    let config = Config::load_or_create(home)?;
    let (mut workspace, created) =
        Workspace::open_or_create(home, cwd, name, local, config.default_mode)?;
    let _lock = SessionLock::acquire(&workspace.lock_path()).map_err(|error| match error {
        LockError::Held { .. } => anyhow!("Workspace '{}' is {error}", workspace.name),
        LockError::Io(_) => anyhow!("Workspace '{}': {error}", workspace.name),
    })?;
    workspace.record_open()?;

    let program = pty::resolve_shell(
        config.shell.as_deref(),
        std::env::var("SHELL").ok().as_deref(),
    );
    let launch = shims::prepare(&workspace, &program, std::env::var_os("ZDOTDIR"))?;
    let mut env = workspace.session_env();
    env.extend(launch.env.iter().cloned());
    let spec = SessionSpec {
        program,
        args: launch.args.clone(),
        cwd: workspace
            .restored_cwd()
            .unwrap_or_else(|| cwd.to_path_buf()),
        env,
    };
    let sink = tap_sink()?;

    println!(
        "[+] {} workspace '{}' at {} (mode: {})",
        if created { "Created" } else { "Resumed" },
        workspace.name,
        workspace.dir.display(),
        workspace.profile.mode
    );
    println!(
        "[+] Session shell: {} (exit the shell to leave)",
        spec.program
    );
    if !launch.hooked() {
        println!(
            "[!] No replay hooks for this shell (only zsh, bash and PowerShell): \
             commands will not be logged to replay.sh"
        );
    }

    // Passive, zero-packet look at the local network tables.
    let graph_path = workspace.graph_path();
    let mut graph = Graph::load(&graph_path)?;
    graph.local = observer::observe(&graph.target_ips());
    graph.save(&graph_path)?;
    println!("[+] Local network: {}", observer::summary(&graph.local));
    for warning in &graph.local.warnings {
        println!("[!] {warning}");
    }

    let outcome = pty::run_session(&spec, sink)?;

    println!("[+] Session '{}' closed", workspace.name);
    Ok(ExitCode::from(u8::try_from(outcome.exit_code).unwrap_or(1)))
}

/// Looks up CVEs for every host with versioned software and merges the
/// matches into the graph as unverified hypotheses.
fn ground_cves(workspace: &Workspace, graph: &mut Graph, settings: CveSettings) -> Result<()> {
    let lookups: Vec<cve::Lookup> = graph.hosts.values().flat_map(cve::plan).collect();
    if lookups.is_empty() {
        return Ok(());
    }
    let db = Arc::new(Mutex::new(Db::open(&workspace.state_db_path())?));
    let client = CveClient::new(settings, db)?;
    println!(
        "[+] CVE lookups: {} to run, at most {} s (cached answers are instant; --no-cve skips this)",
        lookups.len(),
        client.estimate(&lookups).as_secs()
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    let summary = runtime.block_on(cve::ground_graph(&client, graph));
    for error in &summary.errors {
        println!("[!] CVE lookup failed: {error}");
    }
    println!(
        "[+] CVE lookups: {} new advisories ({} in CISA KEV), all stored as UnverifiedHypothesis; {} in total",
        summary.new_advisories,
        summary.kev,
        graph.advisory_count()
    );
    Ok(())
}

fn tap_sink() -> Result<LineSink> {
    let Some(path) = std::env::var_os(TAP_LOG_ENV).filter(|value| !value.is_empty()) else {
        return Ok(Box::new(|_line| {}));
    };
    let mut file = private_open_options()
        .append(true)
        .create(true)
        .open(&path)
        .with_context(|| {
            format!(
                "cannot open ${TAP_LOG_ENV} ({})",
                Path::new(&path).display()
            )
        })?;
    Ok(Box::new(move |line| {
        let _ = writeln!(file, "{line}");
    }))
}
