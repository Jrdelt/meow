//! The external tools `meow recon` drives (nmap, katana, feroxbuster), its
//! wordlist, and the map's location database: checked before a recon is
//! queued and offered once on the first session, and installed on request
//! with the tool part of `install.sh`, of which meow carries its own copy so
//! no source folder (and no clone) is needed.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::evidence::sanitize;
use crate::queue::{find_wordlist, ReconSettings};

/// The installer, as built into this binary.
#[cfg(not(windows))]
const INSTALLER: &str = include_str!("../install.sh");
#[cfg(windows)]
const INSTALLER_PS1: &str = include_str!("../install.ps1");

/// A tool or the wordlist that is not there, and what is lost without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub name: String,
    pub stage: &'static str,
}

fn program_file_name(name: &str, suffix: &str) -> String {
    let has_suffix = !suffix.is_empty()
        && name
            .get(name.len().saturating_sub(suffix.len())..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix));
    if has_suffix {
        name.to_owned()
    } else {
        format!("{name}{suffix}")
    }
}

/// The program `name` would run: an absolute path as given, else the first
/// match on an absolute `PATH` directory. `None` when there is nothing to run.
pub fn find_program(name: &str) -> Option<PathBuf> {
    find_program_in(name, std::env::var_os("PATH").as_deref())
}

fn find_program_in(name: &str, path_env: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    if name.is_empty() || matches!(name, "." | "..") {
        return None;
    }
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
    if given.components().count() > 1 || name.contains('/') || name.contains('\\') {
        let safe_abs = given.is_absolute()
            && !given
                .components()
                .any(|c| matches!(c, Component::ParentDir));
        return (safe_abs && runnable(given)).then(|| given.to_path_buf());
    }
    let exe = program_file_name(name, std::env::consts::EXE_SUFFIX);
    std::env::split_paths(path_env?)
        .filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute())
        .map(|dir| dir.join(&exe))
        .find(|path| runnable(path))
}

fn sanitized_path_env() -> Option<std::ffi::OsString> {
    let raw = std::env::var_os("PATH")?;
    let clean: Vec<PathBuf> = std::env::split_paths(&raw)
        .filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute())
        .collect();
    std::env::join_paths(clean).ok()
}

/// What `meow recon` would have to skip on this machine.
pub fn gaps(settings: &ReconSettings) -> Vec<Gap> {
    gaps_with_db(settings, None)
}

/// What `meow recon` and the map would have to skip, honoring any configured
/// `[location] database` path override.
pub fn gaps_with_db(settings: &ReconSettings, location_db: Option<&str>) -> Vec<Gap> {
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
    if !location_database_installed(location_db) {
        out.push(Gap {
            name: "the location database".to_owned(),
            stage: "placing scanned servers on the map",
        });
    }
    out
}

/// Whether the location database is installed at `location_db` (when set) or `~/.meow/geo`.
fn location_database_installed(location_db: Option<&str>) -> bool {
    if let Some(configured) = location_db.map(str::trim).filter(|s| !s.is_empty()) {
        let p = Path::new(configured);
        let resolved = if p.is_absolute() {
            p.to_path_buf()
        } else {
            crate::workspace::MeowHome::from_env()
                .map(|home| home.root().join(p))
                .unwrap_or_else(|_| p.to_path_buf())
        };
        let dir = if resolved.extension().and_then(|e| e.to_str()) == Some("mmdb") {
            resolved.parent().map(Path::to_path_buf).unwrap_or(resolved)
        } else {
            resolved
        };
        return crate::geoip::GeoDb::new(&dir).available();
    }
    crate::workspace::MeowHome::from_env()
        .map(|home| crate::geoip::GeoDb::new(&home.root().join(crate::geoip::DIR)).available())
        .unwrap_or(false)
}

fn is_interactive_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Marks that the first session on this machine has offered the extras.
pub const OFFERED_FILE: &str = "extras-offered";

/// The first session on a machine lists what recon and the map can use
/// that is missing (scanners, wordlist, location database) and offers to
/// install it, once. Later, `meow tools` does the same on request.
pub fn first_run_offer(
    home: &Path,
    settings: &ReconSettings,
    location_db: Option<&str>,
) -> Result<()> {
    let marker = home.join(OFFERED_FILE);
    if marker.exists() || !is_interactive_terminal() {
        return Ok(());
    }
    crate::workspace::write_private_atomic(&marker, b"offered\n")?;
    if gaps_with_db(settings, location_db).is_empty() {
        return Ok(());
    }
    println!("[+] First session on this machine: meow recon and the map can use a few extras.");
    offer(settings, location_db, false)
}

fn show(gaps: &[Gap]) {
    println!("[!] Not installed on this machine:");
    for gap in gaps {
        let safe_name = sanitize(&gap.name, 80);
        println!("    {safe_name:<12} without it meow skips {}", gap.stage);
    }
}

#[cfg(windows)]
pub(crate) fn windows_powershell_exe() -> Option<PathBuf> {
    use std::path::Prefix;
    let root = PathBuf::from(std::env::var_os("SystemRoot")?);
    let mut comps = root.components();
    let valid_disk = matches!(
        (comps.next(), comps.next()),
        (Some(Component::Prefix(p)), Some(Component::RootDir))
            if matches!(p.kind(), Prefix::Disk(_))
    ) && comps.all(|c| matches!(c, Component::Normal(_)));
    if !valid_disk {
        return None;
    }
    let exe = root
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    exe.is_file().then_some(exe)
}

/// Runs the tool part of the installer. It shows its own plan and may ask
/// for elevation when system packages are needed.
pub fn install() -> Result<bool> {
    #[cfg(windows)]
    {
        let Some(ps) = windows_powershell_exe() else {
            println!(
                "[!] Install them yourself on Windows: nmap from https://nmap.org/download, \
                 katana and feroxbuster from their GitHub releases."
            );
            return Ok(false);
        };
        let dir = tempfile::tempdir().context("cannot create temporary installer directory")?;
        let script = dir.path().join("install.ps1");
        let mut bytes = Vec::with_capacity(3 + INSTALLER_PS1.len());
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        bytes.extend_from_slice(INSTALLER_PS1.as_bytes());
        std::fs::write(&script, bytes).context("cannot stage temporary install.ps1")?;
        let mut cmd = Command::new(ps);
        cmd.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&script)
            .args(["-ToolsOnly", "-Yes"])
            // Never run in the folder the user happens to be in: rustup's
            // cargo and rustc obey a rust-toolchain.toml found there.
            .current_dir(dir.path());
        if let Some(clean_path) = sanitized_path_env() {
            cmd.env("PATH", clean_path);
        } else {
            cmd.env_remove("PATH");
        }
        let status = cmd
            .status()
            .context("cannot run the installer (powershell)")?;
        Ok(status.success())
    }
    #[cfg(not(windows))]
    {
        // /bin/sh is on every macOS and Linux system, whatever PATH holds.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(INSTALLER)
            .arg("install.sh")
            .args(["--tools-only", "--yes"])
            // Not in the folder the user happens to be in: rustup's cargo and
            // rustc obey a rust-toolchain.toml found there.
            .current_dir("/");
        if let Some(clean_path) = sanitized_path_env() {
            cmd.env("PATH", clean_path);
        } else {
            cmd.env_remove("PATH");
        }
        let status = cmd.status().context("cannot run the installer (sh)")?;
        Ok(status.success())
    }
}

fn yes(question: &str) -> Result<bool> {
    print!("[?] {question} [Y/n] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    let bytes = std::io::stdin()
        .lock()
        .take(256)
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    if bytes == 0 {
        return Ok(false);
    }
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer.is_empty() || answer.starts_with('y'))
}

/// Before a recon: lists what is missing and, on a terminal, offers to
/// install it. `assume_yes` installs without asking. Never fails the recon:
/// whatever is still missing afterwards is skipped as before.
pub fn offer(settings: &ReconSettings, location_db: Option<&str>, assume_yes: bool) -> Result<()> {
    let missing = gaps_with_db(settings, location_db);
    if missing.is_empty() {
        return Ok(());
    }
    show(&missing);
    let interactive = is_interactive_terminal();
    if !assume_yes && !interactive {
        println!("[!] Not on a terminal, so nothing is installed; run `meow tools` to add them.");
        return Ok(());
    }
    if !assume_yes && !yes("Install them now?")? {
        println!("[+] Going ahead without them; `meow tools` installs them later.");
        return Ok(());
    }
    if !install()? {
        return Ok(());
    }
    let (map, recon): (Vec<Gap>, Vec<Gap>) = gaps_with_db(settings, location_db)
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
pub fn run(settings: &ReconSettings, location_db: Option<&str>, assume_yes: bool) -> Result<()> {
    for program in [&settings.nmap, &settings.katana, &settings.feroxbuster] {
        let safe_prog = sanitize(program, 80);
        match find_program(program) {
            Some(path) => println!(
                "[+] {safe_prog:<12} {}",
                sanitize(&path.display().to_string(), 400)
            ),
            None => println!("[!] {safe_prog:<12} not installed"),
        }
    }
    match find_wordlist(
        settings.wordlist_path.as_deref(),
        settings.wordlist_dir.as_deref(),
    ) {
        Some(path) => println!(
            "[+] {:<12} {}",
            "wordlist",
            sanitize(&path.display().to_string(), 400)
        ),
        None => println!("[!] {:<12} none found", "wordlist"),
    }
    if location_database_installed(location_db) {
        println!("[+] {:<12} installed", "location db");
    } else {
        println!(
            "[!] {:<12} not installed (the map places only your own machine)",
            "location db"
        );
    }
    offer(settings, location_db, assume_yes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_are_found_by_path_or_on_path() {
        assert_eq!(program_file_name("nmap", ".exe"), "nmap.exe");
        assert_eq!(program_file_name("nmap.exe", ".exe"), "nmap.exe");
        assert_eq!(program_file_name("NMAP.EXE", ".exe"), "NMAP.EXE");
        assert_eq!(program_file_name("nmap", ""), "nmap");

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
        assert_eq!(find_program("./meow-test-tool"), None);
        assert_eq!(find_program("sub/meow-test-tool"), None);
        let parent_traversal = format!("{}/../meow-test-tool", dir.path().display());
        assert_eq!(find_program(&parent_traversal), None);
        let path_with_rel =
            std::env::join_paths([Path::new(""), Path::new("."), dir.path()]).unwrap();
        assert_eq!(
            find_program_in("meow-test-tool", Some(&path_with_rel)),
            Some(tool)
        );
        let rel_only = std::env::join_paths([Path::new(""), Path::new("relative/bin")]).unwrap();
        assert_eq!(find_program_in("meow-test-tool", Some(&rel_only)), None);
        assert_eq!(find_program("meow-no-such-program-anywhere"), None);
    }

    #[test]
    fn every_missing_piece_says_what_it_costs() {
        let dir = tempfile::tempdir().unwrap();
        let custom_geo = dir.path().join("custom-geo");
        let settings = ReconSettings {
            nmap: "meow-no-such-nmap".into(),
            katana: "meow-no-such-katana".into(),
            feroxbuster: "meow-no-such-ferox".into(),
            wordlist_path: Some(dir.path().join("none.txt").to_string_lossy().into_owned()),
            wordlist_dir: Some(dir.path().join("empty")),
            ..ReconSettings::default()
        };
        let names: Vec<String> = gaps_with_db(&settings, Some(&custom_geo.to_string_lossy()))
            .into_iter()
            .map(|g| g.name)
            .collect();
        let wordlist_installed = crate::queue::find_wordlist(None, None).is_some();
        let mut expected = vec![
            "meow-no-such-nmap",
            "meow-no-such-katana",
            "meow-no-such-ferox",
        ];
        if !wordlist_installed {
            expected.push("a wordlist");
        }
        expected.push("the location database");
        assert_eq!(names, expected);
    }

    #[test]
    fn installers_and_formula_pin_digests_bounds_and_msrv() {
        let unix = include_str!("../install.sh");
        let windows = include_str!("../install.ps1");
        let formula = include_str!("../Formula/meow.rb");
        let manifest = include_str!("../Cargo.toml");

        assert!(unix.contains("--tools-only) tools_only=yes ;;"));
        for line in [
            "trap cleanup EXIT",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
            "--no-modify-path",
            "wget --https-only --max-redirect=0",
            "GEO_MAX_PACKED=209715200",
            "GEO_MAX_BYTES=536870912",
            "cargo install feroxbuster --locked --version",
        ] {
            assert!(unix.contains(line), "install.sh missing: {line}");
        }
        assert!(!unix.contains("@latest"));
        assert!(!unix.contains("/SecLists/master/"));
        assert!(!unix.contains("MEOW_WORDLIST_SHA256"));

        let minor = unix
            .lines()
            .find_map(|l| l.strip_prefix("MIN_RUST_MINOR="))
            .unwrap();
        assert!(manifest.contains(&format!("rust-version = \"1.{minor}\"")));

        let extract = |prefix: &str| -> String {
            unix.lines()
                .find_map(|l| l.strip_prefix(prefix))
                .unwrap()
                .trim_matches('"')
                .to_owned()
        };
        let wordlist_url = extract("WORDLIST_URL=");
        let katana_go = extract("KATANA_GO=");
        let sha256 = "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a";

        for needle in [
            wordlist_url.as_str(),
            sha256,
            katana_go.as_str(),
            "--no-modify-path",
            "MIN_RUST_MINOR = 89",
            "GEO_MAX_PACKED = 209715200",
            "GEO_MAX_BYTES = 536870912",
            "cargo install feroxbuster --locked --version",
        ] {
            assert!(windows.contains(needle), "install.ps1 missing: {needle}");
        }
        assert!(!windows.contains("MEOW_WORDLIST_SHA256"));

        let expected_tag = format!("tag: \"v{}\"", env!("CARGO_PKG_VERSION"));
        assert!(formula.contains(&wordlist_url));
        assert!(formula.contains(sha256));
        assert!(formula.contains("std_cargo_args"));
        assert!(formula.contains(&expected_tag));
        assert!(formula.contains("(pkgshare/\"wordlists\").install \"common.txt\""));
    }
}
