//! `meow` entry point: parse the command line, refuse nested sessions, then
//! dispatch.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use meow::cli::{Cli, Command};
use meow::coordinator::{self, Command as Request, Coordinator};
use meow::cve::{self, CveClient, CveSettings};
use meow::db::Db;
use meow::graph::Graph;
use meow::hud;
use meow::ipc;
use meow::lock::{LockError, SessionLock};
use meow::mode::Mode;
use meow::observer;
use meow::parsers;
use meow::pty::{self, LineSink, SessionSpec};
use meow::queue;
use meow::report;
use meow::shims;
use meow::webui;
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
            // A live session applies the change itself; otherwise write the
            // profile directly.
            if ipc::send(&workspace, &Request::SetMode { mode: *mode })?.is_none() {
                workspace.set_mode(*mode)?;
            }
            println!("[+] Mode set to {mode} (session: {})", workspace.name);
            Ok(ExitCode::SUCCESS)
        }
        Command::Add { file, no_cve, .. } => {
            let parsed = parsers::parse_file(file)?;
            let skipped = match parsed.skipped {
                0 => String::new(),
                n => format!(", {n} lines skipped"),
            };
            let total = parsed.observations.len();
            let live = ipc::send(
                &workspace,
                &Request::Observations {
                    items: parsed.observations.clone(),
                    ground: !no_cve,
                },
            )?;
            if let Some(result) = live {
                println!(
                    "[+] {} ({}): {total} facts parsed, {} new or updated{skipped}",
                    file.display(),
                    parsed.format,
                    result["changed"]
                );
                println!(
                    "[+] Session '{}' now has {} hosts",
                    workspace.name, result["hosts"]
                );
                if result["grounding"] == true {
                    println!("[+] CVE lookups are running in the session (see `meow hud`)");
                }
                return Ok(ExitCode::SUCCESS);
            }

            // No live session: work on the files directly.
            let path = workspace.graph_path();
            let mut graph = Graph::load(&path)?;
            let changed = graph.apply_all(parsed.observations);
            graph.save(&path)?;
            println!(
                "[+] {} ({}): {total} facts parsed, {changed} new or updated{skipped}",
                file.display(),
                parsed.format,
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
        Command::Recon {
            target, nmap_flags, ..
        } => {
            let request = Request::Recon {
                target: target.clone(),
                flags: nmap_flags.clone(),
            };
            let Some(result) = ipc::send(&workspace, &request)? else {
                bail!(
                    "`meow recon` needs a live session: start `meow {}` first; \
                     the scan runs in the background of that session",
                    workspace.name
                );
            };
            let ahead = match result["ahead"].as_u64().unwrap_or(0) {
                0 => String::new(),
                n => format!(", {n} task(s) ahead of it"),
            };
            println!(
                "[+] Recon of {} queued as task {} ({} mode{ahead})",
                result["target"].as_str().unwrap_or(target),
                result["task"],
                result["mode"].as_str().unwrap_or("?"),
            );
            println!("[+] Stages run one at a time in the session; follow them with `meow hud`");
            Ok(ExitCode::SUCCESS)
        }
        Command::Map { no_open, .. } => {
            let live = ipc::send(&workspace, &Request::Ping)?.is_some();
            let Some(info) = ipc::runtime_info(&workspace).filter(|_| live) else {
                bail!(
                    "`meow map` needs a live session: start `meow {}` first",
                    workspace.name
                );
            };
            let url = webui::map_url(info.port, &info.token);
            if !no_open && webui::open_in_browser(&url) {
                println!(
                    "[+] Opened the topology map of '{}' in your browser (127.0.0.1:{})",
                    workspace.name, info.port
                );
            } else {
                println!("[+] Open this URL in a browser on this machine (it contains the session token):");
                println!("    {url}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Hud { .. } => {
            hud::run(&workspace)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Report { .. } => {
            let path = report::write(&workspace)?;
            println!("[+] Report written to {}", path.display());
            println!("[+] It is not masked: review it before sharing");
            Ok(ExitCode::SUCCESS)
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
    println!(
        "[+] {} workspace '{}' at {} (mode: {})",
        if created { "Created" } else { "Resumed" },
        workspace.name,
        workspace.dir.display(),
        workspace.profile.mode
    );

    // The coordinator owns the graph, the database and the loopback server
    // for as long as the shell runs.
    let coordinator = Coordinator::start(workspace.clone(), config)?;
    let state = coordinator.state();
    println!(
        "[+] Coordinator on 127.0.0.1:{} (`meow map`, `meow hud`)",
        state.port
    );
    {
        // Passive, zero-packet look at the local network tables.
        let graph = state.graph();
        println!("[+] Local network: {}", observer::summary(&graph.local));
        for warning in &graph.local.warnings {
            println!("[!] {warning}");
        }
    }
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

    offer_resume(&state)?;

    let sink = tee_sink(coordinator.tap_sink(), debug_tap_log()?);
    let outcome = pty::run_session(&spec, sink);
    coordinator.shutdown();
    let outcome = outcome?;

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

/// Background tasks left unfinished by an earlier session: ask whether to
/// resume them. Without a terminal nothing is started unattended.
fn offer_resume(state: &coordinator::State) -> Result<()> {
    let unfinished = queue::unfinished(&state.db_lock())?;
    if unfinished.is_empty() {
        return Ok(());
    }
    println!("[!] {} unfinished background task(s):", unfinished.len());
    for task in &unfinished {
        println!("      {}", task.describe());
    }
    if !std::io::stdin().is_terminal() {
        println!(
            "[!] Not resumed (no terminal to ask on); they continue when the mode \
             is set to mild or aggressive"
        );
        return Ok(());
    }
    print!("[?] Resume? [Y/n] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    if answer.trim().to_ascii_lowercase().starts_with('n') {
        for task in &unfinished {
            queue::decline(&state.db_lock(), task.id)?;
        }
        println!("[+] Not resumed; the remaining stages are marked skipped");
    } else {
        state.resume_unfinished()?;
        if state.mode() == Mode::Light {
            println!(
                "[!] Light mode sends no packets: the tasks stay paused until \
                 `meow mode mild` (or aggressive)"
            );
        } else {
            println!("[+] Resumed in the background");
        }
    }
    Ok(())
}

/// Sends every tap line to both sinks.
fn tee_sink(mut first: LineSink, second: Option<LineSink>) -> LineSink {
    match second {
        None => first,
        Some(mut second) => Box::new(move |line| {
            first(line);
            second(line);
        }),
    }
}

/// `$MEOW_TAP_LOG`: a file that receives the tap's clean lines.
fn debug_tap_log() -> Result<Option<LineSink>> {
    let Some(path) = std::env::var_os(TAP_LOG_ENV).filter(|value| !value.is_empty()) else {
        return Ok(None);
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
    Ok(Some(Box::new(move |line| {
        let _ = writeln!(file, "{line}");
    })))
}
