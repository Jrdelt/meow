//! `meow update` for a meow installed from a GitHub Release (the macOS
//! `.pkg` or an archive): asks GitHub for the newest release, downloads this
//! system's archive and its `.sha256`, checks it, and puts the new meow in
//! place of this one. The requests name nothing about the user or their
//! work. A meow built from a checkout updates with git instead (`update.rs`).

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// GitHub's answer for the newest published release.
pub const LATEST_URL: &str = "https://api.github.com/repos/Jrdelt/meow/releases/latest";
/// Overrides `LATEST_URL` (tests).
pub const URL_ENV: &str = "MEOW_RELEASES_URL";
/// Which release file this build is, set by `.github/workflows/release.yml`
/// (`macos-arm64`, `linux-x86_64`, ...); `None` for a build from a checkout.
pub const BUILD: Option<&str> = option_env!("MEOW_RELEASE_BUILD");
/// An archive is a few megabytes; nothing near this is one.
const DOWNLOAD_MAX: usize = 200 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

fn numbers(version: &str) -> Option<Vec<u64>> {
    version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(|part| part.parse().ok())
        .collect()
}

/// Whether `candidate` (`v1.2.3` or `1.2.3`) is newer than `current`.
pub fn is_newer(current: &str, candidate: &str) -> bool {
    match (numbers(current), numbers(candidate)) {
        (Some(current), Some(candidate)) => candidate > current,
        _ => false,
    }
}

/// The archive file for `build` in release `version`.
pub fn archive_name(version: &str, build: &str) -> String {
    let version = version.trim_start_matches('v');
    if build.starts_with("windows") {
        format!("meow-{version}-{build}.zip")
    } else {
        format!("meow-{version}-{build}.tar.gz")
    }
}

/// Checks `bytes` against a `sha256sum` line (`<hex>  <file>`).
pub fn check_sha256(bytes: &[u8], sum_file: &str) -> Result<()> {
    let expected = sum_file
        .split_whitespace()
        .next()
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .context("the checksum file holds no SHA-256 digest")?
        .to_ascii_lowercase();
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != expected {
        bail!("the download does not match its checksum, so nothing was replaced");
    }
    Ok(())
}

async fn get(http: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let mut response = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GitHub did not answer ({url})"))?;
    if !response.status().is_success() {
        bail!("GitHub answered HTTP {} for {url}", response.status());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("a download was cut off")? {
        if bytes.len() + chunk.len() > DOWNLOAD_MAX {
            bail!("a download from {url} was far larger than meow");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// The system's own `tar`, which also unpacks `.zip` files on Windows.
fn tar() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(root).join("System32").join("tar.exe")
    } else {
        ["/usr/bin/tar", "/bin/tar"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from("/usr/bin/tar"))
    }
}

/// Unpacks the archive at `archive` into `into` and returns the new meow.
fn unpack(archive: &Path, into: &Path) -> Result<PathBuf> {
    let status = Command::new(tar())
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .status()
        .context("cannot run tar to unpack the download")?;
    if !status.success() {
        bail!("the download could not be unpacked");
    }
    let program = into.join(format!("meow{}", std::env::consts::EXE_SUFFIX));
    if !program.is_file() {
        bail!("the download holds no meow program");
    }
    Ok(program)
}

/// Puts `new` where `exe` is. A folder this user cannot write to (the
/// `.pkg` installs to `/usr/local/bin`) is written with sudo, which asks
/// for the password on the terminal.
fn replace(new: &Path, exe: &Path) -> Result<()> {
    let dir = exe.parent().context("meow's own folder is not known")?;
    let staged = dir.join(format!(".meow-update-{}", std::process::id()));
    if std::fs::copy(new, &staged).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        }
        if cfg!(windows) {
            // A running program cannot be overwritten, but it can be moved.
            let old = exe.with_extension("old.exe");
            let _ = std::fs::remove_file(&old);
            std::fs::rename(exe, &old).context("cannot move the running meow aside")?;
        }
        return std::fs::rename(&staged, exe)
            .with_context(|| format!("cannot put the new meow at {}", exe.display()));
    }
    if cfg!(windows) {
        bail!(
            "cannot write to {}; run meow update as an administrator",
            dir.display()
        );
    }
    println!(
        "[+] {} needs administrator rights: sudo asks for your password",
        dir.display()
    );
    let status = Command::new("/usr/bin/sudo")
        .arg("/usr/bin/install")
        .args(["-m", "0755"])
        .arg(new)
        .arg(exe)
        .status()
        .context("cannot run sudo")?;
    if !status.success() {
        bail!("the new meow could not be put at {}", exe.display());
    }
    Ok(())
}

/// `meow update` for a release install.
pub fn run(check: bool) -> Result<ExitCode> {
    let build = BUILD.context("this meow was not installed from a release")?;
    let url = std::env::var(URL_ENV)
        .ok()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| LATEST_URL.to_owned());
    let exe = std::env::current_exe().context("cannot tell where this meow is")?;
    let exe = exe.canonicalize().unwrap_or(exe);
    run_with(&url, build, env!("CARGO_PKG_VERSION"), &exe, check)
}

/// The update itself, with everything that differs in tests passed in.
pub fn run_with(
    url: &str,
    build: &str,
    current: &str,
    exe: &Path,
    check: bool,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the downloader")?;
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .user_agent("meow")
        .build()
        .context("cannot create the HTTP client")?;
    println!("[+] Checking GitHub for a newer meow (this is {current})");
    let release: Release = serde_json::from_slice(&runtime.block_on(get(&http, url))?)
        .context("GitHub's answer about the newest release could not be read")?;
    if !is_newer(current, &release.tag_name) {
        println!("[+] Already up to date: meow {current} is the newest release.");
        return Ok(ExitCode::SUCCESS);
    }
    println!("[+] meow {} is out.", release.tag_name);
    if check {
        println!("[+] Run `meow update` to install it.");
        return Ok(ExitCode::SUCCESS);
    }
    let name = archive_name(&release.tag_name, build);
    let find = |wanted: &str| {
        release
            .assets
            .iter()
            .find(|asset| asset.name == wanted)
            .map(|asset| asset.browser_download_url.clone())
            .with_context(|| format!("the release has no {wanted}"))
    };
    let archive_url = find(&name)?;
    let sum_url = find(&format!("{name}.sha256"))?;
    println!("[+] Downloading {name}");
    let archive = runtime.block_on(get(&http, &archive_url))?;
    let sum = runtime.block_on(get(&http, &sum_url))?;
    check_sha256(&archive, &String::from_utf8_lossy(&sum))?;

    let work = tempfile::tempdir().context("cannot make a folder to unpack in")?;
    let archive_path = work.path().join(&name);
    std::fs::write(&archive_path, &archive).context("cannot save the download")?;
    let unpacked = work.path().join("unpacked");
    std::fs::create_dir(&unpacked)?;
    let new = unpack(&archive_path, &unpacked)?;
    replace(&new, exe)?;
    println!(
        "[+] Updated to meow {} at {}. Sessions that are open keep the old version until you close and reopen them.",
        release.tag_name,
        exe.display()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number() {
        assert!(is_newer("0.1.1", "v0.1.2"));
        assert!(is_newer("0.1.9", "v0.1.10"));
        assert!(is_newer("0.9.0", "1.0.0"));
        assert!(!is_newer("0.1.1", "v0.1.1"));
        assert!(!is_newer("0.2.0", "v0.1.9"));
        assert!(!is_newer("0.1.1", "nightly"));
        assert_eq!(
            archive_name("v0.1.2", "macos-arm64"),
            "meow-0.1.2-macos-arm64.tar.gz"
        );
        assert_eq!(
            archive_name("0.1.2", "windows-x86_64"),
            "meow-0.1.2-windows-x86_64.zip"
        );
    }

    #[test]
    fn checksums_are_checked_before_anything_is_replaced() {
        let sum = "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52  meow.tar.gz\n";
        assert!(check_sha256(b"meow", sum).is_ok());
        assert!(check_sha256(b"evil", sum).is_err());
        assert!(check_sha256(b"meow", "not a digest").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_newer_release_is_downloaded_checked_and_put_in_place() {
        use axum::routing::get;
        let dir = tempfile::tempdir().unwrap();
        // The release archive: a stand-in meow, packed the way release.yml does.
        let packed = dir.path().join("packed");
        std::fs::create_dir(&packed).unwrap();
        std::fs::write(packed.join("meow"), "#!/bin/sh\necho meow 0.2.0\n").unwrap();
        let archive = dir.path().join("meow-0.2.0-linux-x86_64.tar.gz");
        assert!(Command::new(tar())
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&packed)
            .arg("meow")
            .status()
            .unwrap()
            .success());
        let bytes = std::fs::read(&archive).unwrap();
        let hex: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let sum = format!("{hex}  meow-0.2.0-linux-x86_64.tar.gz\n");

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let latest = serde_json::json!({ "tag_name": "v0.2.0", "assets": [
            { "name": "meow-0.2.0-linux-x86_64.tar.gz", "browser_download_url": format!("{base}/archive") },
            { "name": "meow-0.2.0-linux-x86_64.tar.gz.sha256", "browser_download_url": format!("{base}/sum") },
        ]});
        let app = axum::Router::new()
            .route("/latest", get(move || async move { axum::Json(latest) }))
            .route("/archive", get(move || async move { bytes }))
            .route("/sum", get(move || async move { sum }));
        runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });

        let exe = dir.path().join("bin").join("meow");
        std::fs::create_dir(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "old").unwrap();
        let url = format!("{base}/latest");
        // Up to date already: nothing changes.
        let _ = run_with(&url, "linux-x86_64", "0.2.0", &exe, false).unwrap();
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old");
        // --check only says so.
        let _ = run_with(&url, "linux-x86_64", "0.1.1", &exe, true).unwrap();
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old");
        // An update puts the new program in place, runnable.
        let _ = run_with(&url, "linux-x86_64", "0.1.1", &exe, false).unwrap();
        assert!(std::fs::read_to_string(&exe)
            .unwrap()
            .contains("meow 0.2.0"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
            0o755
        );
        // A release without a file for this system says so.
        let error = run_with(&url, "linux-riscv64", "0.1.1", &exe, false).unwrap_err();
        assert!(format!("{error:#}").contains("no meow-0.2.0-linux-riscv64.tar.gz"));
    }
}
