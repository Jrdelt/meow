//! The external tools `meow recon` drives (nmap, katana, feroxbuster), its
//! wordlist, and the map's location database: checked before a recon is
//! queued and offered once on the first session, and installed on request
//! with the tool part of `install.sh`, of which meow carries its own copy so
//! no source folder (and no clone) is needed.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::queue::{find_wordlist, ReconSettings};

/// The installer, as built into this binary.
const INSTALLER: &str = include_str!("../install.sh");

/// A tool or the wordlist that is not there, and what is lost without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub name: String,
    pub stage: &'static str,
}

/// The program `name` would run: a path as given, else the first match on
/// `PATH`. `None` when there is nothing to run.
pub fn find_program(name: &str) -> Option<PathBuf> {
    let runnable = |path: &Path| {
        path.is_file() && {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                path.metadata()
                    .is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
    };
    let given = Path::new(name);
    if given.components().count() > 1 {
        return runnable(given).then(|| given.to_path_buf());
    }
    let exe = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(&exe))
        .find(|path| runnable(path))
}

/// What `meow recon` would have to skip on this machine.
pub fn gaps(settings: &ReconSettings) -> Vec<Gap> {
    let mut out = Vec::new();
    for (program, stage) in [
        (
            &settings.nmap,
            "the port and service stages (recon cannot run without it)",
        ),
        (&settings.katana, "the web crawl"),
        (&settings.feroxbuster, "the directory stage"),
    ] {
        if find_program(program).is_none() {
            out.push(Gap {
                name: program.clone(),
                stage,
            });
        }
    }
    if find_wordlist(
        settings.wordlist_path.as_deref(),
        settings.wordlist_dir.as_deref(),
    )
    .is_none()
    {
        out.push(Gap {
            name: "a wordlist".to_owned(),
            stage: "the directory stage",
        });
    }
    if !location_database_installed() {
        out.push(Gap {
            name: "the location database".to_owned(),
            stage: "placing scanned servers on the map",
        });
    }
    out
}

/// Whether `install.sh` has put the location database in `~/.meow/geo`.
fn location_database_installed() -> bool {
    crate::workspace::MeowHome::from_env()
        .map(|home| crate::geoip::GeoDb::new(&home.root().join(crate::geoip::DIR)).available())
        .unwrap_or(false)
}

/// Marks that the first session on this machine has offered the extras.
pub const OFFERED_FILE: &str = "extras-offered";

/// The first session on a machine lists what recon and the map can use
/// that is missing (scanners, wordlist, location database) and offers to
/// install it, once. Later, `meow tools` does the same on request.
pub fn first_run_offer(home: &Path, settings: &ReconSettings) -> Result<()> {
    let marker = home.join(OFFERED_FILE);
    if marker.exists() || !std::io::stdin().is_terminal() {
        return Ok(());
    }
    crate::workspace::write_private_atomic(&marker, b"offered\n")?;
    if gaps(settings).is_empty() {
        return Ok(());
    }
    println!("[+] First session on this machine: meow recon and the map can use a few extras.");
    offer(settings, false)
}

fn show(gaps: &[Gap]) {
    println!("[!] Not installed on this machine:");
    for gap in gaps {
        println!("    {:<12} without it meow skips {}", gap.name, gap.stage);
    }
}

/// Runs the tool part of the installer. It shows its own plan and may ask
/// for a sudo password. Returns false where it cannot run (Windows).
pub fn install() -> Result<bool> {
    if cfg!(windows) {
        println!(
            "[!] Install them yourself on Windows: nmap from https://nmap.org/download, \
             katana and feroxbuster from their GitHub releases."
        );
        return Ok(false);
    }
    // /bin/sh is on every macOS and Linux system, whatever PATH holds.
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(INSTALLER)
        .arg("install.sh")
        .args(["--tools-only", "--yes"])
        // Not in the folder the user happens to be in: rustup's cargo and
        // rustc obey a rust-toolchain.toml found there.
        .current_dir("/")
        .status()
        .context("cannot run the installer (sh)")?;
    Ok(status.success())
}

fn yes(question: &str) -> Result<bool> {
    print!("[?] {question} [Y/n] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer.is_empty() || answer.starts_with('y'))
}

/// Before a recon: lists what is missing and, on a terminal, offers to
/// install it. `assume_yes` installs without asking. Never fails the recon:
/// whatever is still missing afterwards is skipped as before.
pub fn offer(settings: &ReconSettings, assume_yes: bool) -> Result<()> {
    let missing = gaps(settings);
    if missing.is_empty() {
        return Ok(());
    }
    show(&missing);
    let interactive = std::io::stdin().is_terminal();
    if !assume_yes && !interactive {
        println!("[!] Not on a terminal, so nothing is installed; run `meow tools` to add them.");
        return Ok(());
    }
    if !assume_yes && !yes("Install them now?")? {
        println!("[+] Going ahead without them; `meow tools` installs them later.");
        return Ok(());
    }
    install()?;
    let (map, recon): (Vec<Gap>, Vec<Gap>) = gaps(settings)
        .into_iter()
        .partition(|gap| gap.name == "the location database");
    if recon.is_empty() {
        println!("[+] Every tool recon uses is installed.");
    } else {
        show(&recon);
        println!("[!] Those stages will be skipped; the messages above say why.");
    }
    if !map.is_empty() {
        println!(
            "[!] The location database is not installed yet, so the map places only your own machine; `meow tools` tries again."
        );
    }
    Ok(())
}

/// `meow tools`: what recon uses and whether it is there, then the offer.
pub fn run(settings: &ReconSettings, assume_yes: bool) -> Result<()> {
    for program in [&settings.nmap, &settings.katana, &settings.feroxbuster] {
        match find_program(program) {
            Some(path) => println!("[+] {program:<12} {}", path.display()),
            None => println!("[!] {program:<12} not installed"),
        }
    }
    match find_wordlist(
        settings.wordlist_path.as_deref(),
        settings.wordlist_dir.as_deref(),
    ) {
        Some(path) => println!("[+] {:<12} {}", "wordlist", path.display()),
        None => println!("[!] {:<12} none found", "wordlist"),
    }
    if location_database_installed() {
        println!("[+] {:<12} installed", "location db");
    } else {
        println!(
            "[!] {:<12} not installed (the map places only your own machine)",
            "location db"
        );
    }
    offer(settings, assume_yes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_are_found_by_path_or_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir
            .path()
            .join(format!("meow-test-tool{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Not runnable yet: not a program.
            assert_eq!(find_program(tool.to_str().unwrap()), None);
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(find_program(tool.to_str().unwrap()), Some(tool.clone()));
        assert_eq!(find_program("meow-no-such-program-anywhere"), None);
    }

    #[test]
    fn every_missing_piece_says_what_it_costs() {
        let dir = tempfile::tempdir().unwrap();
        let settings = ReconSettings {
            nmap: "meow-no-such-nmap".into(),
            katana: "meow-no-such-katana".into(),
            feroxbuster: "meow-no-such-ferox".into(),
            wordlist_path: Some(dir.path().join("none.txt").to_string_lossy().into_owned()),
            wordlist_dir: Some(dir.path().join("empty")),
            ..ReconSettings::default()
        };
        let names: Vec<String> = gaps(&settings).into_iter().map(|g| g.name).collect();
        let wordlist_installed = crate::queue::find_wordlist(None, None).is_some();
        let mut expected = vec![
            "meow-no-such-nmap",
            "meow-no-such-katana",
            "meow-no-such-ferox",
        ];
        if !wordlist_installed {
            expected.push("a wordlist");
        }
        if !location_database_installed() {
            expected.push("the location database");
        }
        assert_eq!(names, expected);
    }

    #[test]
    fn the_built_in_installer_has_a_tools_only_mode() {
        assert!(INSTALLER.contains("--tools-only) tools_only=yes ;;"));
    }
}
