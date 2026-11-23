//! `meow` entry point: parse the command line, refuse nested sessions, then
//! dispatch.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use meow::cli::{Cli, Command};
use meow::coordinator::{Command as Request, Coordinator};
use meow::cve::{self, CveClient, CveSettings};
use meow::db::Db;
use meow::graph::Graph;
use meow::hud;
use meow::ipc;
use meow::lineedit;
use meow::lock::{LockError, SessionLock};
use meow::mode::Mode;
use meow::observer;
use meow::parsers;
use meow::pty::{self, LineSink, SessionSpec};
use meow::report;
use meow::setup;
use meow::shims;
use meow::tools;
use meow::update;
use meow::webui;
use meow::wizard::{self, WizardOutcome};
use meow::workspace::{
    self, format_listing, list_workspaces, private_open_options, resolve_helper_dir, Config,
    Location, MeowHome, SessionEnv, SessionState, Workspace,
};

/// Debug aid: when set to a file path, the clean lines produced by the
/// analysis tap are appended to that file.
const TAP_LOG_ENV: &str = "MEOW_TAP_LOG";

fn sanitize_terminal_block(text: &str, max_chars: usize) -> String {
    let cleaned: String = text
        .chars()
        .filter(|c| !meow::evidence::is_hidden(*c))
        .collect();
    meow::evidence::sanitize_block(&cleaned, max_chars)
}

fn sanitize_terminal_line(text: &str, max_chars: usize) -> String {
    meow::evidence::sanitize(text, max_chars)
}

fn sanitize_path_display(path: &Path) -> String {
    sanitize_terminal_line(&path.display().to_string(), 1024)
}

#[cfg(windows)]
fn harden_windows_dll_search_path() {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetDllDirectoryW(lp_path_name: *const u16) -> i32;
        fn SetDefaultDllDirectories(directory_flags: u32) -> i32;
    }
    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
    let empty: [u16; 1] = [0];
    // SAFETY: `empty` is a valid NUL-terminated UTF-16 empty string, which
    // removes the current working directory from legacy `LoadLibrary` searches;
    // `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS` restricts default searches to the
    // application directory and `%SystemRoot%\System32` (never CWD or `PATH`).
    unsafe {
        let _ = SetDllDirectoryW(empty.as_ptr());
        let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    }
}

fn main() -> ExitCode {
    #[cfg(windows)]
    harden_windows_dll_search_path();
    let cli = Cli::parse();
    // Before anything is read or made: the guard only watches its pipe.
    if matches!(cli.command, Some(Command::Guard)) {
        return ExitCode::from(meow::procs::guard_main());
    }
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            // Whatever a file, a repository or a server put into the text
            // of an error is printed as text: no control characters, no
            // characters that hide or reorder what follows.
            let said = sanitize_terminal_block(&format!("{error:#}"), 4000);
            // Not `eprintln!`: with the terminal gone that would panic.
            let _ = writeln!(std::io::stderr().lock(), "[!] {said}");
            ExitCode::from(1)
        }
    }
}

/// `meow list` and a bare `meow`: every session, wherever it is saved, and
/// which of them have a session open right now.
fn print_listing(home: &MeowHome, cwd: &Path, env: &SessionEnv) -> Result<ExitCode> {
    say_swept(&home.root().join(meow::procs::RUN_DIR));
    let mut workspaces = list_workspaces(home, cwd)?;
    for workspace in &mut workspaces {
        workspace.state = if workspace.state == SessionState::NotYours {
            // Came with the folder: nothing in it is read or contacted.
            SessionState::NotYours
        } else if env.workspace.as_deref() == Some(workspace.dir.as_path()) {
            SessionState::Current
        } else if ipc::is_live(&workspace.dir) {
            SessionState::Running
        } else {
            SessionState::Closed
        };
    }
    if std::io::stdout().is_terminal() {
        print!("{}", wizard::CAT_LIST_HEADER);
    }
    print!("{}", format_listing(&workspaces, SystemTime::now()));
    Ok(ExitCode::SUCCESS)
}

/// True on a brand-new installation in an interactive terminal before
/// `config.toml`, `ai.toml` or any workspace exists.
fn should_run_first_setup(home: &MeowHome, cwd: &Path) -> Result<bool> {
    if !wizard::can_run_tui() {
        return Ok(false);
    }
    if std::fs::symlink_metadata(home.config_path()).is_ok()
        || std::fs::symlink_metadata(home.ai_path()).is_ok()
    {
        return Ok(false);
    }
    Ok(list_workspaces(home, cwd)?.is_empty())
}

/// Handles a bare `meow` invocation: launches the Interactive First-Time Cat
/// Setup GUI on a brand-new terminal setup, or lists saved workspaces.
fn open_bare(home: &MeowHome, cwd: &Path, env: &SessionEnv) -> Result<ExitCode> {
    if should_run_first_setup(home, cwd)? {
        match wizard::run_first_time(home)? {
            WizardOutcome::Cancelled => {}
            WizardOutcome::Saved {
                launch_workspace: Some(name),
            } => {
                // Spawn a fresh `meow <name>` process so the PTY host process
                // has never initialized `crossterm::event::read()`.
                let exe = std::env::current_exe().context("cannot locate the meow binary")?;
                let status = std::process::Command::new(exe)
                    .arg(&name)
                    .current_dir(cwd)
                    .status()
                    .with_context(|| format!("cannot launch session '{name}'"))?;
                let code = status
                    .code()
                    .and_then(|c| u8::try_from(c).ok())
                    .unwrap_or(1);
                return Ok(ExitCode::from(code));
            }
            WizardOutcome::Saved {
                launch_workspace: None,
            } => {
                println!(
                    "[+] Setup saved to {} & {}",
                    sanitize_path_display(&home.config_path()),
                    sanitize_path_display(&home.ai_path())
                );
                println!("[+] Ready to prowl! Start a session with: meow <name>");
                return Ok(ExitCode::SUCCESS);
            }
        }
    }
    print_listing(home, cwd, env)
}

/// `meow delete`: says what would go, asks, then removes the workspace.
/// `name` is `None` for `--local`.
fn delete_workspace(
    home: &MeowHome,
    cwd: &Path,
    env: &SessionEnv,
    name: Option<&str>,
    yes: bool,
) -> Result<ExitCode> {
    let target = workspace::find_for_deletion(home, cwd, name)?;
    let safe_name = sanitize_terminal_line(&target.name, 64);
    let safe_dir = sanitize_path_display(&target.dir);
    let label = format!("workspace '{safe_name}'");
    if env.workspace.as_deref() == Some(target.dir.as_path()) {
        bail!("You are inside the session of {label}; exit it first");
    }
    // Before asking, so nobody confirms a deletion that is then refused.
    workspace::ensure_closed(&target)?;

    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!("Not deleting {label} without confirmation: run this in a terminal or add --yes");
        }
        println!("[!] This deletes {label} for good:");
        println!("      {safe_dir}");
        println!(
            "      {} host(s), its command log, notes, AI chats and report",
            target.hosts
        );
        print!("[?] Delete it? [y/N] ");
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("cannot read the answer")?;
        if !answer.trim().to_ascii_lowercase().starts_with('y') {
            println!("[+] Nothing deleted");
            return Ok(ExitCode::from(1));
        }
    }
    workspace::delete(home, &target)?;
    println!("[+] Deleted {label} ({safe_dir})");
    Ok(ExitCode::SUCCESS)
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
            None => open_bare(&home, &cwd, &env),
            Some(name) => start_session(&home, &cwd, name, cli.local, cli.home),
        };
    };
    let Some(target) = command.session_arg() else {
        return match command {
            Command::Delete { name, yes, .. } => {
                delete_workspace(&home, &cwd, &env, name.as_deref(), *yes)
            }
            Command::Setup {
                show,
                check,
                plain,
                local_url,
                local_model,
                cloud_url,
                cloud_model,
                research_model,
                provider,
                fallback_models,
                api_key_stdin,
                forget_key,
                cloud_off,
            } => setup::run(
                &home,
                &setup::SetupArgs {
                    show: *show,
                    check: *check,
                    plain: *plain,
                    local_url: local_url.clone(),
                    local_model: local_model.clone(),
                    cloud_url: cloud_url.clone(),
                    cloud_model: cloud_model.clone(),
                    research_model: research_model.clone(),
                    provider: provider.clone(),
                    fallback_models: fallback_models.clone(),
                    api_key_stdin: *api_key_stdin,
                    forget_key: *forget_key,
                    cloud_off: *cloud_off,
                },
            ),
            Command::Tools { yes } => {
                let config = Config::load_or_create(&home)?;
                tools::run(&config.recon, Some(&config.location.database), *yes)?;
                Ok(ExitCode::SUCCESS)
            }
            Command::Update { check, source } => update::run(&update::UpdateArgs {
                check: *check,
                source: source.clone(),
            }),
            _ => print_listing(&home, &cwd, &env),
        };
    };

    let dir = resolve_helper_dir(&home, &cwd, target.local, target.session.as_deref(), &env)?;
    let mut workspace = Workspace::load(&dir)?;
    workspace.ensure_own(&home, &cwd)?;
    // A command that may write the files meow reads back (the graph, the
    // database) does so itself only while no session runs, and keeps
    // sessions out until they are recorded.
    let writes = match command {
        Command::Add { .. } => Some("meow add"),
        Command::Report { .. } => Some("meow report"),
        _ => None,
    };
    let alone = match writes {
        Some(command) => workspace.write_alone(&home, &cwd, command)?,
        None => None,
    };
    let alone_here = alone.is_some();
    // What the command writes there is recorded as meow's own when it ends.
    let _files = workspace::SessionFiles::for_helper(&home, &workspace, alone);
    match command {
        Command::List
        | Command::Delete { .. }
        | Command::Setup { .. }
        | Command::Update { .. }
        | Command::Tools { .. }
        | Command::Guard => {
            unreachable!(
                "`list`, `delete`, `setup`, `tools` and `update` are not session helpers and returned above"
            )
        }
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
            // Handed over, not copied: a large import is held once. It
            // comes back if no session took it.
            let request = Request::Observations {
                items: parsed.observations,
                ground: !no_cve,
            };
            let live = if alone_here {
                None
            } else {
                Some(send_to_session(&workspace, &request, "add")?)
            };
            let Request::Observations {
                items: observations,
                ..
            } = request
            else {
                unreachable!("built above");
            };
            if let Some(result) = live {
                if result["full"] == true {
                    println!(
                        "[!] This workspace's graph is full: not everything in the file was recorded. Open a new workspace for further targets."
                    );
                }
                println!(
                    "[+] {} ({}): {total} facts parsed, {} new or updated{skipped}",
                    sanitize_path_display(file),
                    parsed.format,
                    result["changed"]
                );
                println!(
                    "[+] Session '{}' now has {} hosts",
                    sanitize_terminal_line(&workspace.name, 64),
                    result["hosts"]
                );
                if result["grounding"] == true {
                    println!("[+] CVE lookups are running in the session (see `meow hud`)");
                }
                return Ok(ExitCode::SUCCESS);
            }

            // No live session: work on the files directly.
            let path = workspace.graph_path();
            let mut graph = Graph::load(&path)?;
            let changed = graph.apply_all(observations);
            graph.save(&path)?;
            if graph.is_full() {
                println!(
                    "[!] This workspace's graph is full: not everything in the file was recorded. Open a new workspace for further targets."
                );
            }
            println!(
                "[+] {} ({}): {total} facts parsed, {changed} new or updated{skipped}",
                sanitize_path_display(file),
                parsed.format,
            );
            println!(
                "[+] Session '{}' now has {} hosts",
                sanitize_terminal_line(&workspace.name, 64),
                meow::topology::map_host_count(&graph)
            );
            let config = Config::load_or_create(&home)?;
            if config.cve.enabled && !no_cve {
                ground_cves(&workspace, &mut graph, config.cve)?;
                graph.save(&path)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Recon {
            target,
            nmap_flags,
            install_tools,
            ..
        } => {
            let needs_session = || {
                if let Some(pid) = SessionLock::holder_pid(&workspace.lock_path()) {
                    anyhow!(
                        "session '{}' (pid {pid}) is not responding; resume or exit it first, \
                         then run `meow recon` again",
                        workspace.name
                    )
                } else {
                    anyhow!(
                        "`meow recon` needs a live session: start `meow {}` first; \
                         the scan runs in the background of that session",
                        workspace.name
                    )
                }
            };
            if ipc::send(&workspace, &Request::Ping)?.is_none() {
                return Err(needs_session());
            }
            // Light mode refuses recon anyway; otherwise say now what is
            // missing and offer to install it, before any stage starts.
            if workspace.profile.mode != meow::mode::Mode::Light {
                let config = Config::load_or_create(&home)?;
                tools::offer(
                    &config.recon,
                    Some(&config.location.database),
                    *install_tools,
                )?;
            }
            let request = Request::Recon {
                target: target.clone(),
                flags: nmap_flags.clone(),
            };
            let Some(result) = ipc::send(&workspace, &request)? else {
                return Err(needs_session());
            };
            let ahead = match result["ahead"].as_u64().unwrap_or(0) {
                0 => String::new(),
                n => format!(", {n} task(s) ahead of it"),
            };
            println!(
                "[+] Recon of {} queued as task {} ({} mode{ahead})",
                sanitize_terminal_line(result["target"].as_str().unwrap_or(target), 200),
                result["task"],
                sanitize_terminal_line(result["mode"].as_str().unwrap_or("?"), 32),
            );
            println!("[+] Stages run one at a time in the session; follow them with `meow hud`");
            Ok(ExitCode::SUCCESS)
        }
        Command::Map { no_open, .. } => {
            let live = ipc::send(&workspace, &Request::Ping)?.is_some();
            let Some(info) = ipc::runtime_info(&workspace).filter(|_| live) else {
                if let Some(pid) = SessionLock::holder_pid(&workspace.lock_path()) {
                    bail!(
                        "session '{}' (pid {pid}) is not responding; resume or exit it first, \
                         then run `meow map` again",
                        workspace.name
                    );
                }
                bail!(
                    "`meow map` needs a live session: start `meow {}` first",
                    workspace.name
                );
            };
            if info.port == 0
                || info.token.len() != 64
                || !info.token.chars().all(|c| c.is_ascii_hexdigit())
            {
                bail!("`meow map` found an invalid session runtime record");
            }
            let url = webui::map_url(info.port, &info.token);
            // The opener gets the path of a private page that leads to the
            // map, never the URL: program arguments are visible to every
            // user on the machine, and the URL holds the session token.
            let opened = !no_open
                && webui::write_bootstrap(&workspace.tmp_dir(), &url)
                    .map(|page| webui::open_in_browser(&page.to_string_lossy()))
                    .unwrap_or(false);
            if opened {
                println!(
                    "[+] Map of '{}' opened (127.0.0.1:{}) \u{b7} no tab? `meow map --no-open`",
                    sanitize_terminal_line(&workspace.name, 64),
                    info.port
                );
            } else {
                println!("[+] Map URL \u{b7} this machine only \u{b7} holds the session token:");
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
            println!("[+] Report written to {}", sanitize_path_display(&path));
            println!("[+] It is not masked: review it before sharing");
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// How long a helper waits for a session that holds the lock of its
/// workspace to answer: one that is starting is not listening yet.
const SESSION_ANSWER_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Sends `request` to the session that holds the lock of `workspace`, for
/// `meow <command>`. Never falls back to the files: the session writes them.
fn send_to_session(
    workspace: &Workspace,
    request: &Request,
    command: &str,
) -> Result<serde_json::Value> {
    let until = std::time::Instant::now() + SESSION_ANSWER_WAIT;
    loop {
        if let Some(answer) = ipc::send(workspace, request)? {
            return Ok(answer);
        }
        let lock = workspace.lock_path();
        if !SessionLock::is_held(&lock) {
            bail!(
                "session '{}' ended meanwhile; run `meow {command}` again",
                workspace.name
            );
        }
        if std::time::Instant::now() >= until {
            let pid = SessionLock::holder_pid(&lock)
                .map(|pid| format!(" (pid {pid})"))
                .unwrap_or_default();
            bail!(
                "session '{}'{pid} is not responding; resume or exit it first, \
                 then run `meow {command}` again",
                workspace.name
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Whether there is someone at a terminal to ask.
fn can_ask() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Asks where to save the new session `name`: a folder, which gets
/// `meow/<name>/`. `None` when the user cancels. Without a terminal the
/// current folder is used if it can hold the session.
fn choose_folder(home: &MeowHome, cwd: &Path, name: &str) -> Result<Option<PathBuf>> {
    let warn_if_synced = |folder: &Path| {
        if workspace::looks_cloud_synced(folder) {
            println!(
                "[!] This folder looks synced to a cloud service: scan data would be uploaded with it."
            );
        }
    };
    if !can_ask() {
        if let Err(reason) = workspace::check_new_folder(home, cwd, name) {
            bail!(
                "Cannot save '{name}' in {}: {reason}. Run meow from a project folder, or add --home",
                sanitize_path_display(cwd)
            );
        }
        warn_if_synced(cwd);
        return Ok(Some(cwd.to_path_buf()));
    }
    println!("[?] Save session '{name}' in:");
    let user_home = dirs::home_dir();
    let mut default = cwd.display().to_string();
    loop {
        let Some(answer) =
            lineedit::ask("    Folder", &default).context("cannot read the answer")?
        else {
            return Ok(None);
        };
        let folder = match workspace::folder_from_answer(cwd, &answer, user_home.as_deref()) {
            Ok(folder) => folder,
            Err(reason) => {
                println!("[!] {reason}");
                continue;
            }
        };
        default = folder.display().to_string();
        println!(
            "    -> {}",
            sanitize_path_display(&workspace::sessions_dir(&folder).join(name))
        );
        if let Err(reason) = workspace::check_new_folder(home, &folder, name) {
            println!("[!] Not there: {reason}");
            continue;
        }
        if std::fs::symlink_metadata(&folder).is_err() {
            print!("[?] It does not exist yet. Create it? [Y/n] ");
            std::io::stdout().flush().ok();
            let mut yes = String::new();
            let read = std::io::stdin()
                .read_line(&mut yes)
                .context("cannot read the answer")?;
            if read == 0 {
                return Ok(None);
            }
            if yes.trim().to_ascii_lowercase().starts_with('n') {
                continue;
            }
            if let Err(error) = workspace::create_folder(&folder) {
                let said = sanitize_terminal_line(&error.to_string(), 300);
                println!("[!] Cannot create it: {said}");
                continue;
            }
            if let Err(reason) = workspace::check_new_folder(home, &folder, name) {
                println!("[!] Not there: {reason}");
                continue;
            }
        }
        if workspace::prepare_sessions_dir(&folder).is_err() {
            println!("[!] Not there: cannot write to it");
            continue;
        }
        warn_if_synced(&folder);
        return Ok(Some(folder));
    }
}

/// Where `meow <name>` opens: `--home`, `--local`, an existing session of
/// that name, or a new one in the folder the user picks. `None` when the
/// user cancels.
fn session_location(
    home: &MeowHome,
    cwd: &Path,
    name: &str,
    local: bool,
    at_home: bool,
) -> Result<Option<Location>> {
    if at_home {
        return workspace::home_location(home, cwd, name).map(Some);
    }
    if local {
        return workspace::local_location(home, cwd, name).map(Some);
    }
    if let Some(found) = workspace::find_session(home, cwd, name)? {
        if let Some(other) = workspace::foreign_here(home, cwd, name)
            .filter(|other| found.dir(home, name).is_ok_and(|dir| dir != *other))
        {
            println!(
                "[!] {} came with this folder; opening your own '{name}' (`meow {name} --local` opens the other)",
                sanitize_path_display(&other)
            );
        }
        return Ok(Some(found));
    }
    if let Some(away) = workspace::unreachable_session(home, name) {
        let said = format!(
            "Session '{name}' is saved at {}, which cannot be reached now",
            sanitize_path_display(&away)
        );
        if !can_ask() {
            bail!("{said}. Connect it, or use --local or --home for a new one");
        }
        println!("[!] {said}.");
    }
    Ok(choose_folder(home, cwd, name)?.map(Location::Folder))
}

/// `meow <name>`: open the workspace, take its lock and run the shell until
/// it exits. The process exit code is the shell's.
fn start_session(
    home: &MeowHome,
    cwd: &Path,
    name: &str,
    local: bool,
    at_home: bool,
) -> Result<ExitCode> {
    let Some(location) = session_location(home, cwd, name, local, at_home)? else {
        println!("[+] Nothing created");
        return Ok(ExitCode::from(1));
    };
    let config = Config::load_or_create(home)?;
    let (mut workspace, created) = Workspace::open_at(home, &location, name, config.default_mode)?;
    let mut foreign = workspace.is_foreign(home);
    if foreign {
        // The user's own session in a folder they moved keeps all it has.
        if let Some(old) = workspace.moved_from(home) {
            workspace.take_moved(home, &old)?;
            println!("[+] Session moved from {}", sanitize_path_display(&old));
            foreign = false;
        } else {
            accept_foreign_workspace(home, cwd, &mut workspace, config.default_mode)?;
        }
    }
    let _lock = SessionLock::acquire(&workspace.lock_path()).map_err(|error| match error {
        LockError::Held { .. } => anyhow!("Workspace '{}' is {error}", workspace.name),
        LockError::Io(_) => anyhow!("Workspace '{}': {error}", workspace.name),
    })?;
    // A helper writing its files with no session (`meow add`) ends first.
    workspace.wait_for_helpers()?;
    let seen = if created || foreign {
        workspace::FilesSeen::AsLeft
    } else {
        workspace.files_seen(home)
    };
    // Session files a pull made git track, or let in.
    let mut git = workspace::GitWatch::default();
    let git_notes = git.check(&workspace.dir);
    // Files a pull or an unpacked archive replaced are not the user's: no
    // planted history or start folder. (A scan queued in them never runs:
    // no session runs what it did not queue itself.) After an end meow did
    // not see, files it rewrites whole cannot be told from planted ones:
    // then git's word decides.
    let files_changed = match seen {
        workspace::FilesSeen::Changed => true,
        workspace::FilesSeen::Unclean => git.files_doubtful(),
        workspace::FilesSeen::AsLeft => false,
    };
    if files_changed {
        println!("[!] Files changed outside meow: shell history and last folder not used");
        workspace.drop_carried_files();
    } else if seen == workspace::FilesSeen::Unclean {
        println!("[!] meow did not end cleanly last time");
    }
    for note in git_notes {
        println!("[!] {}", sanitize_terminal_line(&note, 400));
    }
    // Recorded once the shell and the coordinator have stopped; as meow's
    // own only if the session gets that far.
    let doubtful = foreign || files_changed;
    let mut files = workspace::SessionFiles::for_session(home, &workspace, doubtful);
    if created || foreign {
        // A list fish kept for an earlier workspace in this place is not
        // this one's.
        shims::forget_fish_history(&workspace.dir);
    }
    workspace.forget_last_session();
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
    // Once per machine: offer the scanners, wordlist and location database.
    if let Err(error) =
        tools::first_run_offer(home.root(), &config.recon, Some(&config.location.database))
    {
        let said = sanitize_terminal_block(&format!("{error:#}"), 1000);
        println!("[!] Could not offer the extras: {said}");
    }
    // On a terminal the header says the name, new or not, and the mode.
    if std::io::stdout().is_terminal() {
        print!(
            "{}",
            wizard::session_header(&workspace.name, workspace.profile.mode, created)
        );
        println!("[+] Saved in {}", sanitize_path_display(&workspace.dir));
    } else {
        println!(
            "[+] {} '{}' \u{b7} {} \u{b7} {}",
            if created { "New session" } else { "Session" },
            sanitize_terminal_line(&workspace.name, 64),
            workspace.profile.mode,
            sanitize_path_display(&workspace.dir),
        );
    }

    // The coordinator owns the graph, the database and the loopback server
    // for as long as the shell runs.
    let records = home.root().join(meow::procs::RUN_DIR);
    // Before this session runs or clears anything: what a session that was
    // killed with its guard left running is stopped.
    say_swept(&records);
    let coordinator = Coordinator::start_guarded(
        workspace.clone(),
        config,
        std::env::current_exe(),
        Some(records),
    )?;
    let state = coordinator.state();
    {
        // Passive, zero-packet look at the local network tables.
        let graph = state.graph();
        let summary = observer::summary(&graph.local);
        if !summary.is_empty() {
            println!("[+] Network: {}", sanitize_terminal_line(&summary, 300));
        }
        // The tools that are missing on one line; any other note on its own.
        const MISSING: &str = " is not installed in the system directories";
        let (missing, other): (Vec<&String>, Vec<&String>) = graph
            .local
            .notes
            .iter()
            .partition(|note| note.ends_with(MISSING));
        let tools: Vec<&str> = missing
            .iter()
            .map(|note| note.trim_end_matches(MISSING))
            .collect();
        let said = (!tools.is_empty()).then(|| format!("{} not installed", tools.join(", ")));
        for note in said.iter().chain(other) {
            println!(
                "[!] Network partly read: {}",
                sanitize_terminal_line(note, 300)
            );
        }
        for warning in &graph.local.warnings {
            println!("[!] {}", sanitize_terminal_line(warning, 300));
        }
    }
    println!("[+] Live view: `meow map` \u{b7} `meow hud`");
    let shell = Path::new(&spec.program)
        .file_name()
        .map_or(spec.program.clone(), |name| {
            name.to_string_lossy().into_owned()
        });
    println!(
        "[+] Shell: {} \u{b7} `exit` to leave",
        sanitize_terminal_line(&shell, 200)
    );
    if !launch.hooked() {
        println!("[!] No replay hooks for this shell: replay.sh stays empty");
    }

    say_left_recons(&coordinator, !doubtful);

    let sink = tee_sink(coordinator.tap_sink(), debug_tap_log()?);
    files.started();
    let outcome = pty::run_session(&spec, sink);
    // A pull while it ran, up to its last moment, may have put files in
    // the session.
    state.check_git();
    let skipped = coordinator.shutdown();
    if state.files_doubtful() {
        files.changed_outside();
    }
    // The database closes with its last handle; then the files are recorded.
    drop(state);
    drop(files);
    // A console window that is being closed may end the process now.
    pty::cleaned_up();
    // The window may be gone by now (it was closed): then nobody is told,
    // and that is no error.
    if !skipped.is_empty() {
        say_if_possible(&format!(
            "[!] Skipped on exit (stuck): {}",
            skipped.join(", ")
        ));
    }
    let outcome = outcome?;

    say_if_possible(&format!(
        "[+] Session '{}' closed",
        sanitize_terminal_line(&workspace.name, 64)
    ));
    Ok(ExitCode::from(u8::try_from(outcome.exit_code).unwrap_or(1)))
}

/// Prints a line where there may be no terminal left to print on: unlike
/// `println!`, a failed write is not a panic.
fn say_if_possible(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Looks up CVEs for every host with versioned software and adds them to
/// the graph.
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
        println!(
            "[!] CVE lookup failed: {}",
            sanitize_terminal_line(error, 300)
        );
    }
    if summary.dropped > 0 {
        println!(
            "[+] CVE lookups: {} earlier matches no longer apply and were removed",
            summary.dropped
        );
    }
    println!(
        "[+] CVE lookups: {} new {} ({} known exploited), found by software version; {} in total",
        summary.new_advisories,
        if summary.new_advisories == 1 {
            "CVE"
        } else {
            "CVEs"
        },
        summary.kev,
        graph.advisory_count()
    );
    for host in graph.hosts.values() {
        for fix in cve::fix_plan(host) {
            println!(
                "[+] {}: {} (fixes {})",
                sanitize_terminal_line(&host.address, 128),
                sanitize_terminal_line(&fix.action, 240),
                fix.counts()
            );
        }
    }
    Ok(())
}

/// A session that was already in the folder, made by someone else: says
/// what it would bring and opens it only on an explicit yes.
fn accept_foreign_workspace(
    home: &MeowHome,
    cwd: &Path,
    workspace: &mut Workspace,
    default_mode: Mode,
) -> Result<()> {
    // Said before asking: accepting it under a name already taken fails.
    workspace.check_name_free(home)?;
    let size = |name: &str| {
        std::fs::symlink_metadata(workspace.dir.join(name))
            .ok()
            .filter(|meta| meta.is_file())
            .map(|meta| meta.len())
    };
    println!(
        "[!] {} is a meow session from elsewhere: it came with this folder, or the folder was moved or copied.",
        sanitize_path_display(&workspace.dir)
    );
    println!(
        "    Its own mode is {}{}; if you accept it, it opens in your default mode ({default_mode}).",
        workspace.profile.mode,
        if workspace.profile.recon.is_empty() {
            ""
        } else {
            ", with its own scan settings"
        }
    );
    let histories = workspace::HISTORY_SHELLS.map(|shell| format!("{shell}_history"));
    let carried = [
        ("state.db", "queued scans and cached lookups"),
        ("graph.json", "hosts and findings"),
        ("replay.sh", "a log of commands"),
        ("last_cwd", "the directory its shell starts in"),
    ];
    let histories = histories
        .iter()
        .map(|file| (file.as_str(), "shell history"));
    let mut drops = false;
    for (file, what) in carried.into_iter().chain(histories) {
        if let Some(bytes) = size(file) {
            println!(
                "    It carries {what} ({file}, {} KB).",
                bytes.div_ceil(1024)
            );
            drops |= file == "last_cwd" || file.ends_with("_history");
        }
    }
    if drops {
        println!("    Accepting it drops its shell history and start folder.");
    }
    println!("    Scans queued in it are dropped: none of them runs.");
    // Only a command that leads back to this folder: `meow delete <name>`
    // finds the user's own session of that name first.
    let (remove, removes) =
        match workspace::commands_for(home, cwd, &workspace.dir, &workspace.name).1 {
            Some(delete) => (
                format!("remove it with `{delete}`"),
                format!("`{delete}` removes it"),
            ),
            None => (
                "delete that folder".to_owned(),
                "Deleting that folder removes it".to_owned(),
            ),
        };
    if !std::io::stdin().is_terminal() {
        bail!(
            "Not opened: there is no terminal to ask on. Run this in a terminal to accept it, \
             or {remove}"
        );
    }
    print!("[?] Use it as your own? [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    if !answer.trim().to_ascii_lowercase().starts_with('y') {
        bail!("Not opened. {removes}");
    }
    workspace.adopt(home, default_mode)
}

/// Stops the scans a session left running when it and its guard were
/// killed together, and says so in one line.
fn say_swept(records: &Path) {
    let stopped = meow::procs::sweep(records);
    let what = match stopped.len() {
        0 => return,
        1 => "a scan".to_owned(),
        n => format!("{n} scans"),
    };
    println!(
        "[!] Stopped {what} left running by a session that was killed ({})",
        sanitize_terminal_line(&stopped.join(", "), 200)
    );
}

/// Says once what the end of the last session did to its recons: the
/// running stage was stopped and the rest left out. Nothing of them runs
/// again by itself. `own`: the session's files are the user's own.
fn say_left_recons(coordinator: &Coordinator, own: bool) {
    let (left, more) = coordinator.left_recons();
    for task in left {
        println!("[!] {}", sanitize_terminal_line(&task.left_line(own), 300));
    }
    if more > 0 {
        println!("[!] +{more} more recons cut short");
    }
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

fn open_tap_log_file(path: &Path) -> Result<std::fs::File> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!(
                "cannot open ${TAP_LOG_ENV} ({}): refusing to follow a symbolic link",
                path.display()
            );
        }
        if !meta.is_file() {
            bail!(
                "cannot open ${TAP_LOG_ENV} ({}): not a regular file",
                path.display()
            );
        }
    }
    let file = private_open_options()
        .append(true)
        .create(true)
        .open(path)
        .with_context(|| format!("cannot open ${TAP_LOG_ENV} ({})", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("cannot inspect ${TAP_LOG_ENV} ({})", path.display()))?;
    if !meta.is_file() {
        bail!(
            "cannot open ${TAP_LOG_ENV} ({}): not a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            bail!(
                "cannot open ${TAP_LOG_ENV} ({}): refusing file with multiple hard links",
                path.display()
            );
        }
    }
    Ok(file)
}

/// `$MEOW_TAP_LOG`: a file that receives the tap's clean lines.
fn debug_tap_log() -> Result<Option<LineSink>> {
    let Some(path) = std::env::var_os(TAP_LOG_ENV).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let mut file = open_tap_log_file(Path::new(&path))?;
    Ok(Some(Box::new(move |line| {
        let _ = writeln!(file, "{line}");
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_error_sanitizer_strips_controls_bidi_alm_and_unicode_tags() {
        let raw =
            "bad \x1b]52;c;pwn\x07\u{202e}gnp.exe\u{061c}\u{2060}\u{e0041}\u{e007f}\nline2\r\nok";
        let cleaned = sanitize_terminal_block(raw, 4000);
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
        assert!(!cleaned.contains('\u{202e}'));
        assert!(!cleaned.contains('\u{061c}'));
        assert!(!cleaned.contains('\u{2060}'));
        assert!(!cleaned.contains('\u{e0041}'));
        assert!(cleaned.contains('\n'));
        assert!(cleaned.ends_with("\nline2\nok"), "{cleaned:?}");
    }

    #[test]
    fn tap_log_file_refuses_directories_symlinks_and_hardlinks() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open_tap_log_file(dir.path()).is_err());

        let log = dir.path().join("tap.log");
        assert!(open_tap_log_file(&log).is_ok());

        #[cfg(unix)]
        {
            let outside = dir.path().join("outside.txt");
            std::fs::write(&outside, "secret").unwrap();
            let sym = dir.path().join("sym.log");
            std::os::unix::fs::symlink(&outside, &sym).unwrap();
            assert!(open_tap_log_file(&sym).is_err());

            let hard = dir.path().join("hard.log");
            std::fs::hard_link(&outside, &hard).unwrap();
            assert!(open_tap_log_file(&hard).is_err());
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
        }
    }
}
