//! `meow update` for a meow installed from a GitHub Release (the macOS
//! `.pkg` or an archive): asks GitHub for the newest release, downloads this
//! system's archive and its `.sha256`, checks it, and puts the new meow in
//! place of this one. The requests name nothing about the user or their
//! work. A meow built from a checkout updates with git instead (`update.rs`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::evidence::sanitize;

/// GitHub's answer for the newest published release.
pub const LATEST_URL: &str = "https://api.github.com/repos/Jrdelt/meow/releases/latest";
/// Which release file this build is, set by `.github/workflows/release.yml`
/// (`macos-arm64`, `linux-x86_64`, ...); `None` for a build from a checkout.
pub const BUILD: Option<&str> = option_env!("MEOW_RELEASE_BUILD");
/// Release metadata JSON is a few kilobytes.
const API_MAX: usize = 2 * 1024 * 1024;
/// A `.sha256` checksum file is a single short line.
const SUM_MAX: usize = 64 * 1024;
/// An archive is a few megabytes; nothing near this is one.
const DOWNLOAD_MAX: usize = 200 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

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

#[derive(Debug, PartialEq, Eq)]
struct ParsedVersion<'a> {
    core: Vec<u64>,
    pre: Option<&'a str>,
}

fn is_valid_dot_identifiers(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|seg| {
            !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn parse_version(version: &str) -> Option<ParsedVersion<'_>> {
    let trimmed = version.trim();
    let stripped = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    let without_build = match stripped.split_once('+') {
        Some((before, build)) => {
            if !is_valid_dot_identifiers(build) {
                return None;
            }
            before
        }
        None => stripped,
    };
    if without_build.is_empty() {
        return None;
    }
    let (core_str, pre) = match without_build.split_once('-') {
        Some((core, pre)) => {
            if !is_valid_dot_identifiers(pre) {
                return None;
            }
            (core, Some(pre))
        }
        None => (without_build, None),
    };
    let parts: Vec<&str> = core_str.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let core: Option<Vec<u64>> = parts.into_iter().map(|part| part.parse().ok()).collect();
    Some(ParsedVersion { core: core?, pre })
}

fn cmp_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    for (pa, pb) in a.split('.').zip(b.split('.')) {
        let ord = match (pa.parse::<u64>(), pb.parse::<u64>()) {
            (Ok(na), Ok(nb)) => na.cmp(&nb),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => pa.cmp(pb),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    a.split('.').count().cmp(&b.split('.').count())
}

/// Whether `candidate` (`v1.2.3` or `1.2.3`) is newer than `current`.
pub fn is_newer(current: &str, candidate: &str) -> bool {
    let (Some(cur), Some(cand)) = (parse_version(current), parse_version(candidate)) else {
        return false;
    };
    let width = cur.core.len().max(cand.core.len());
    for i in 0..width {
        let a = cur.core.get(i).copied().unwrap_or(0);
        let b = cand.core.get(i).copied().unwrap_or(0);
        if a != b {
            return b > a;
        }
    }
    match (cur.pre, cand.pre) {
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => cmp_prerelease(b, a) == std::cmp::Ordering::Greater,
        (None, None) => false,
    }
}

fn validate_version_token(version: &str) -> Result<&str> {
    let trimmed = version.trim();
    let v = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    if v.is_empty()
        || v.len() > 64
        || v.starts_with('-')
        || v.starts_with('.')
        || v.contains("..")
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    {
        bail!("GitHub returned an unsafe release tag");
    }
    Ok(v)
}

fn validate_build_token(build: &str) -> Result<()> {
    if build.is_empty()
        || build.len() > 64
        || build.starts_with('-')
        || !build
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        bail!("unsafe release target identifier");
    }
    Ok(())
}

/// The archive file for `build` in release `version`.
pub fn archive_name(version: &str, build: &str) -> String {
    let version = version
        .trim()
        .strip_prefix('v')
        .or_else(|| version.trim().strip_prefix('V'))
        .unwrap_or_else(|| version.trim());
    if build.starts_with("windows") {
        format!("meow-{version}-{build}.zip")
    } else {
        format!("meow-{version}-{build}.tar.gz")
    }
}

/// Checks `bytes` against a `sha256sum` line (`<hex>  <file>`).
pub fn check_sha256(bytes: &[u8], sum_file: &str) -> Result<()> {
    check_sha256_for(bytes, sum_file, None)
}

fn check_sha256_for(bytes: &[u8], sum_file: &str, expected_file: Option<&str>) -> Result<()> {
    let cleaned = sum_file.trim_start_matches('\u{feff}');
    let line = cleaned
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .context("the checksum file holds no SHA-256 digest")?;
    let mut parts = line.split_whitespace();
    let expected = parts
        .next()
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .context("the checksum file holds no SHA-256 digest")?
        .to_ascii_lowercase();
    if let Some(wanted) = expected_file {
        let recorded = parts
            .next()
            .context("the checksum file does not name the release archive")?;
        let recorded = recorded.trim_start_matches('*');
        let recorded = recorded.strip_prefix("./").unwrap_or(recorded);
        if recorded != wanted {
            bail!(
                "the checksum file names '{}' instead of '{}'",
                sanitize(recorded, 120),
                sanitize(wanted, 120)
            );
        }
    }
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != expected {
        bail!("the download does not match its checksum, so nothing was replaced");
    }
    Ok(())
}

fn has_no_credentials(url: &url::Url) -> bool {
    url.username().is_empty() && url.password().is_none()
}

fn is_loopback_release_url(raw: &str) -> bool {
    url::Url::parse(raw.trim()).is_ok_and(|url| {
        has_no_credentials(&url)
            && matches!(url.scheme(), "http" | "https")
            && crate::ai::is_loopback_url(url.as_str())
    })
}

fn is_trusted_github_url(url: &url::Url, allow_api: bool) -> bool {
    if !has_no_credentials(url) || url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let path = url.path().to_ascii_lowercase();
    match host.to_ascii_lowercase().as_str() {
        "api.github.com" => allow_api && path.starts_with("/repos/jrdelt/meow/"),
        "github.com" => path.starts_with("/jrdelt/meow/releases/download/"),
        "objects.githubusercontent.com" | "release-assets.githubusercontent.com" => true,
        _ => false,
    }
}

/// A release file is fetched only from GitHub over https (or, for a
/// stand-in release address under test, from this machine).
fn trusted_download(raw: &str, stand_in: bool) -> bool {
    if stand_in {
        return is_loopback_release_url(raw);
    }
    url::Url::parse(raw.trim()).is_ok_and(|url| is_trusted_github_url(&url, false))
}

fn is_trusted_endpoint_url(url: &url::Url, stand_in: bool) -> bool {
    if stand_in {
        has_no_credentials(url)
            && matches!(url.scheme(), "http" | "https")
            && crate::ai::is_loopback_url(url.as_str())
    } else {
        is_trusted_github_url(url, true)
    }
}

fn validate_release_url(raw: &str, stand_in: bool) -> Result<url::Url> {
    let parsed =
        url::Url::parse(raw.trim()).map_err(|_| anyhow::anyhow!("refusing invalid release URL"))?;
    if !is_trusted_endpoint_url(&parsed, stand_in) {
        bail!(
            "refusing untrusted release URL '{}' (must use HTTPS on github.com/githubusercontent.com)",
            sanitize(raw, 120)
        );
    }
    Ok(parsed)
}

fn build_http_client(stand_in: bool) -> Result<reqwest::Client> {
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many HTTP redirects");
        }
        let target = attempt.url();
        if attempt
            .previous()
            .last()
            .is_some_and(|prev| prev.scheme() == "https")
            && target.scheme() != "https"
        {
            return attempt.error("refusing HTTPS downgrade redirect");
        }
        if !is_trusted_endpoint_url(target, stand_in) {
            return attempt.error("refusing redirect to untrusted host");
        }
        attempt.follow()
    });
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        // Every request and every redirect stays on https. A loopback
        // release address (a stand-in under test) is the one exception.
        .https_only(!stand_in)
        .redirect(policy)
        .user_agent("meow")
        .build()
        .context("cannot create the HTTP client")
}

async fn get(
    http: &reqwest::Client,
    url: &str,
    stand_in: bool,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let validated = validate_release_url(url, stand_in)?;
    let display = sanitize(validated.as_str(), 120);
    let mut response = http
        .get(validated)
        .send()
        .await
        .with_context(|| format!("GitHub did not answer ({display})"))?;
    if !response.status().is_success() {
        bail!("GitHub answered HTTP {} for {display}", response.status());
    }
    if response
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        bail!("a download from {display} was far larger than expected");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("a download was cut off")? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            bail!("a download from {display} was far larger than expected");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(windows)]
fn windows_system_root() -> PathBuf {
    use std::path::{Component, Prefix};
    if let Some(raw) = std::env::var_os("SystemRoot") {
        let candidate = PathBuf::from(raw);
        let mut comps = candidate.components();
        let valid_disk = matches!(
            (comps.next(), comps.next()),
            (Some(Component::Prefix(p)), Some(Component::RootDir))
                if matches!(p.kind(), Prefix::Disk(_))
        ) && comps.all(|c| matches!(c, Component::Normal(_)));
        if valid_disk {
            return candidate;
        }
    }
    PathBuf::from(r"C:\Windows")
}

/// The system's own `tar`, which also unpacks `.zip` files on Windows.
fn tar() -> PathBuf {
    #[cfg(windows)]
    {
        windows_system_root().join("System32").join("tar.exe")
    }
    #[cfg(not(windows))]
    {
        ["/usr/bin/tar", "/bin/tar"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from("/usr/bin/tar"))
    }
}

fn is_safe_archive_entry_path(raw: &str) -> bool {
    use std::path::Component;
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.contains(':')
    {
        return false;
    }
    let normalized = trimmed.replace('\\', "/");
    Path::new(&normalized)
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// Unpacks the archive at `archive` into `into` and returns the new meow.
fn unpack(archive: &Path, into: &Path) -> Result<PathBuf> {
    let listing = Command::new(tar())
        .env_remove("TAPE")
        .env_remove("RSH")
        .arg("-tf")
        .arg(archive)
        .stdin(Stdio::null())
        .output()
        .context("cannot inspect the download archive")?;
    if !listing.status.success() {
        bail!("the download archive could not be inspected");
    }
    let entries = String::from_utf8(listing.stdout)
        .map_err(|_| anyhow::anyhow!("the download archive contains non-UTF-8 entry names"))?;
    for entry in entries.lines() {
        if !is_safe_archive_entry_path(entry) {
            bail!("refusing archive with unsafe entry path");
        }
    }

    let mut cmd = Command::new(tar());
    cmd.env_remove("TAPE")
        .env_remove("RSH")
        .stdin(Stdio::null());
    #[cfg(unix)]
    cmd.arg("-o");
    let status = cmd
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
    // A regular file of its own: an archive can also hold a link, which
    // would name some other file to install.
    let meta = std::fs::symlink_metadata(&program)
        .map_err(|_| anyhow::anyhow!("the download holds no meow program"))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() == 0 {
        bail!("refusing unpacked meow binary because it is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            bail!("refusing unpacked meow binary with multiple hard links");
        }
    }
    Ok(program)
}

#[cfg(windows)]
fn select_windows_backup_path(exe: &Path, dir: &Path) -> PathBuf {
    // Sweep any stale backup binaries left behind by closed sessions.
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if name.starts_with(".meow-old-") && name.ends_with(".exe") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let primary = exe.with_extension("old.exe");
    let _ = std::fs::remove_file(&primary);
    if std::fs::symlink_metadata(&primary).is_err() {
        return primary;
    }
    // `meow.old.exe` is still held open by an earlier running session; pick
    // an unused sibling name so another update can still proceed.
    let pid = std::process::id();
    for seq in 0..1024u32 {
        let candidate = dir.join(format!(".meow-old-{pid}-{seq}.exe"));
        if std::fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
    }
    dir.join(format!(".meow-old-{pid}.exe"))
}

/// Puts `new` where `exe` is. A folder this user cannot write to (the
/// `.pkg` installs to `/usr/local/bin`) is written with sudo, which asks
/// for the password on the terminal.
fn replace(new: &Path, exe: &Path) -> Result<()> {
    if !new.is_absolute() || !exe.is_absolute() {
        bail!("refusing relative binary path during update");
    }
    let new_meta =
        std::fs::symlink_metadata(new).context("cannot inspect the unpacked meow binary")?;
    if new_meta.file_type().is_symlink() || !new_meta.file_type().is_file() {
        bail!("refusing to install a non-regular file");
    }
    let dir = exe.parent().context("meow's own folder is not known")?;
    let dir_meta = std::fs::symlink_metadata(dir).with_context(|| {
        format!(
            "cannot inspect {}",
            sanitize(&dir.display().to_string(), 400)
        )
    })?;
    if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
        bail!("refusing to install into a symbolic link directory");
    }
    if let Ok(exe_meta) = std::fs::symlink_metadata(exe) {
        if exe_meta.file_type().is_symlink() {
            bail!(
                "refusing to overwrite a symbolic link at {}",
                sanitize(&exe.display().to_string(), 400)
            );
        }
    }
    // Staged beside the program under a random name made for this run: a
    // guessable name could already be there as a link to another file.
    match tempfile::Builder::new()
        .prefix(".meow-update-")
        .tempfile_in(dir)
    {
        Ok(mut staged) => {
            let mut src = std::fs::File::open(new).context("cannot read unpacked meow binary")?;
            std::io::copy(&mut src, staged.as_file_mut())
                .context("cannot write staged meow binary")?;
            staged
                .as_file_mut()
                .flush()
                .context("cannot flush staged meow binary")?;
            staged
                .as_file()
                .sync_all()
                .context("cannot sync staged meow binary")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                staged
                    .as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o755))?;
            }
            #[cfg(windows)]
            {
                // A running program cannot be overwritten, but it can be moved.
                let old = select_windows_backup_path(exe, dir);
                std::fs::rename(exe, &old).context("cannot move the running meow aside")?;
                if let Err(err) = staged.persist(exe) {
                    let _ = std::fs::rename(&old, exe);
                    bail!(
                        "cannot put the new meow at {}: {}",
                        sanitize(&exe.display().to_string(), 400),
                        err.error
                    );
                }
                Ok(())
            }
            #[cfg(not(windows))]
            {
                staged
                    .persist(exe)
                    .map(|_| ())
                    .map_err(|err| err.error)
                    .with_context(|| {
                        format!(
                            "cannot put the new meow at {}",
                            sanitize(&exe.display().to_string(), 400)
                        )
                    })
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let safe_dir = sanitize(&dir.display().to_string(), 400);
            if cfg!(windows) {
                bail!("cannot write to {safe_dir}; run meow update as an administrator");
            }
            println!("[+] {safe_dir} needs administrator rights: sudo asks for your password");
            let status = Command::new("/usr/bin/sudo")
                .arg("/usr/bin/install")
                .args(["-m", "0755", "--"])
                .arg(new)
                .arg(exe)
                .status()
                .context("cannot run sudo")?;
            if !status.success() {
                bail!(
                    "the new meow could not be put at {}",
                    sanitize(&exe.display().to_string(), 400)
                );
            }
            Ok(())
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "cannot stage update in {}",
                sanitize(&dir.display().to_string(), 400)
            )
        }),
    }
}

fn clean_current_exe_path(exe: PathBuf) -> PathBuf {
    #[cfg(target_os = "linux")]
    let exe = match exe.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
        Some(stripped) => PathBuf::from(stripped),
        None => exe,
    };
    if let Ok(canon) = exe.canonicalize() {
        return canon;
    }
    if let (Some(parent), Some(name)) = (exe.parent(), exe.file_name()) {
        if let Ok(canon_parent) = parent.canonicalize() {
            return canon_parent.join(name);
        }
    }
    exe
}

fn resolve_current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot tell where this meow is")?;
    Ok(clean_current_exe_path(exe))
}

/// `meow update` for a release install.
pub fn run(check: bool) -> Result<ExitCode> {
    let build = BUILD.context("this meow was not installed from a release")?;
    let exe = resolve_current_exe()?;
    run_with(LATEST_URL, build, env!("CARGO_PKG_VERSION"), &exe, check)
}

/// The update itself, with everything that differs in tests passed in.
pub fn run_with(
    url: &str,
    build: &str,
    current: &str,
    exe: &Path,
    check: bool,
) -> Result<ExitCode> {
    validate_build_token(build)?;
    let stand_in = is_loopback_release_url(url);
    validate_release_url(url, stand_in)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the downloader")?;
    let http = build_http_client(stand_in)?;
    let safe_current = sanitize(current, 64);
    println!("[+] Checking GitHub for a newer meow (this is {safe_current})");
    let release: Release =
        serde_json::from_slice(&runtime.block_on(get(&http, url, stand_in, API_MAX))?)
            .context("GitHub's answer about the newest release could not be read")?;
    validate_version_token(&release.tag_name)?;
    let safe_tag = sanitize(&release.tag_name, 64);
    if !is_newer(current, &release.tag_name) {
        println!("[+] Already up to date: meow {safe_current} is the newest release.");
        return Ok(ExitCode::SUCCESS);
    }
    println!("[+] meow {safe_tag} is out.");
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
            .with_context(|| format!("the release has no {}", sanitize(wanted, 120)))
    };
    let archive_url = find(&name)?;
    let sum_url = find(&format!("{name}.sha256"))?;
    for asset in [&archive_url, &sum_url] {
        if !trusted_download(asset, stand_in) {
            bail!(
                "the release names a download that is not on GitHub ({}); nothing was fetched",
                sanitize(asset, 120)
            );
        }
    }
    let safe_name = sanitize(&name, 120);
    println!("[+] Downloading {safe_name}");
    let archive = runtime.block_on(get(&http, &archive_url, stand_in, DOWNLOAD_MAX))?;
    let sum = runtime.block_on(get(&http, &sum_url, stand_in, SUM_MAX))?;
    check_sha256_for(&archive, &String::from_utf8_lossy(&sum), Some(&name))?;

    let work = tempfile::tempdir().context("cannot make a folder to unpack in")?;
    let archive_path = work.path().join(&name);
    std::fs::write(&archive_path, &archive).context("cannot save the download")?;
    let unpacked = work.path().join("unpacked");
    std::fs::create_dir(&unpacked)?;
    let new = unpack(&archive_path, &unpacked)?;
    replace(&new, exe)?;
    println!(
        "[+] Updated to meow {safe_tag} at {}. Sessions that are open keep the old version until you close and reopen them.",
        sanitize(&exe.display().to_string(), 400)
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number_and_prerelease() {
        assert!(is_newer("0.1.1", "v0.1.2"));
        assert!(is_newer("0.1.9", "v0.1.10"));
        assert!(is_newer("0.9.0", "1.0.0"));
        assert!(is_newer("0.1.1-rc.1", "0.1.1"));
        assert!(is_newer("0.1.1-rc.1", "0.1.1-rc.2"));
        assert!(is_newer("0.1.1-rc.2", "0.1.1-rc.10"));
        assert!(is_newer("0.2", "0.2.1"));
        assert!(!is_newer("0.2.0", "v0.2"));
        assert!(!is_newer("0.1.1", "v0.1.1"));
        assert!(!is_newer("0.1.1", "0.1.1-rc.1"));
        assert!(!is_newer("0.1.1", "v0.1.1+build42"));
        assert!(!is_newer("0.1.1", "v0.1.2-rc..1"));
        assert!(!is_newer("0.1.1", "v0.1.2+"));
        assert!(!is_newer("0.2.0", "v0.1.9"));
        assert!(!is_newer("0.1.1", "nightly"));
        assert!(validate_version_token("v0.1.2").is_ok());
        assert!(validate_version_token("-v0.1.2").is_err());
        assert!(validate_version_token("../0.1.2").is_err());
        assert!(validate_build_token("linux-x86_64").is_ok());
        assert!(validate_build_token("../evil").is_err());
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
    fn release_files_come_from_github_over_https_only() {
        for (url, trusted) in [
            (
                "https://github.com/Jrdelt/meow/releases/download/v0.1.2/meow.tar.gz",
                true,
            ),
            (
                "https://objects.githubusercontent.com/github-production-release-asset/x",
                true,
            ),
            ("https://release-assets.githubusercontent.com/x", true),
            (
                "http://github.com/Jrdelt/meow/releases/download/v0.1.2/meow.tar.gz",
                false,
            ),
            (
                "https://user:pass@github.com/Jrdelt/meow/releases/download/v0.1.2/meow.tar.gz",
                false,
            ),
            ("https://downloads.example.com/meow.tar.gz", false),
            (
                "https://github.com/other/repo/releases/download/v0.1.2/meow.tar.gz",
                false,
            ),
            (
                "https://raw.githubusercontent.com/Jrdelt/meow/main/meow.tar.gz",
                false,
            ),
            ("https://github.com.example.com/meow.tar.gz", false),
            ("https://notgithubusercontent.com/meow.tar.gz", false),
            ("http://127.0.0.1:8000/meow.tar.gz", false),
            ("https://127.0.0.1:8443/meow.tar.gz", false),
            ("https://localhost:8443/meow.tar.gz", false),
            ("file:///tmp/meow.tar.gz", false),
            ("not a url", false),
        ] {
            assert_eq!(trusted_download(url, false), trusted, "{url}");
        }
        // Under test the release address is on this machine, and so must
        // its files be.
        assert!(trusted_download("http://127.0.0.1:8000/meow.tar.gz", true));
        assert!(!trusted_download(
            "http://user:pass@127.0.0.1:8000/meow.tar.gz",
            true
        ));
        assert!(!trusted_download("https://github.com/x", true));
    }

    #[test]
    fn checksums_and_release_urls_are_validated() {
        let sum = "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52  meow.tar.gz\n";
        assert!(check_sha256(b"meow", sum).is_ok());
        assert!(check_sha256(
            b"meow",
            "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52\n"
        )
        .is_ok());
        // When an archive filename is expected, a bare hash without a filename is refused.
        assert!(check_sha256_for(
            b"meow",
            "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52\n",
            Some("meow.tar.gz")
        )
        .is_err());
        assert!(is_safe_archive_entry_path("meow"));
        assert!(is_safe_archive_entry_path("./meow.exe"));
        assert!(!is_safe_archive_entry_path("../meow"));
        assert!(!is_safe_archive_entry_path("/usr/local/bin/meow"));
        assert!(!is_safe_archive_entry_path("C:\\meow.exe"));
        assert!(check_sha256_for(b"meow", &format!("\u{feff}{sum}"), Some("meow.tar.gz")).is_ok());
        assert!(check_sha256_for(
            b"meow",
            "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52 *./meow.tar.gz\n",
            Some("meow.tar.gz")
        )
        .is_ok());
        let bad_name_err = check_sha256_for(
            b"meow",
            "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52  other\u{1b}]0;pwn\u{7}.tar.gz\n",
            Some("meow.tar.gz"),
        )
        .unwrap_err()
        .to_string();
        assert!(!bad_name_err.bytes().any(|b| b < 0x20));
        assert!(check_sha256(b"evil", sum).is_err());
        assert!(check_sha256(b"meow", "not a digest").is_err());

        assert!(validate_release_url(LATEST_URL, false).is_ok());
        assert!(validate_release_url(
            "https://objects.githubusercontent.com/github-production-release-asset/123",
            false
        )
        .is_ok());
        // Production mode rejects loopback URLs (no SSRF to local services).
        assert!(validate_release_url("http://127.0.0.1:8080/latest", false).is_err());
        assert!(validate_release_url("https://localhost:8443/latest", false).is_err());
        // Stand-in mode allows loopback and rejects external hosts.
        assert!(validate_release_url("http://127.0.0.1:8080/latest", true).is_ok());
        assert!(validate_release_url(LATEST_URL, true).is_err());
        assert!(validate_release_url(
            "http://api.github.com/repos/Jrdelt/meow/releases/latest",
            false
        )
        .is_err());
        assert!(validate_release_url("https://evil.example/meow.tar.gz", false).is_err());
        assert!(validate_release_url("https://user:pass@api.github.com/latest", false).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deleted_proc_self_exe_suffix_is_stripped_before_canonicalizing() {
        let dir = tempfile::tempdir().unwrap();
        let fake_deleted = dir.path().join("meow (deleted)");
        let cleaned = clean_current_exe_path(fake_deleted);
        assert_eq!(cleaned.file_name().unwrap(), "meow");
        assert!(!cleaned.to_string_lossy().ends_with(" (deleted)"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_archive_and_symlink_destination_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let packed = dir.path().join("packed");
        std::fs::create_dir(&packed).unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "secret").unwrap();
        std::os::unix::fs::symlink(&victim, packed.join("meow")).unwrap();
        let archive = dir.path().join("bad.tar.gz");
        assert!(Command::new(tar())
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&packed)
            .arg("meow")
            .status()
            .unwrap()
            .success());
        let unpacked = dir.path().join("unpacked");
        std::fs::create_dir(&unpacked).unwrap();
        assert!(unpack(&archive, &unpacked).is_err());

        // Refuses overwriting a symlinked binary destination.
        let real_new = dir.path().join("new-meow");
        std::fs::write(&real_new, "#!/bin/sh\necho hi\n").unwrap();
        let sym_exe = dir.path().join("sym-meow");
        std::os::unix::fs::symlink(&victim, &sym_exe).unwrap();
        assert!(replace(&real_new, &sym_exe).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "secret");
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
        // Someone guessed the name the new program used to be staged under
        // and left a link there to a file of the user's.
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, "keep me").unwrap();
        std::os::unix::fs::symlink(
            &victim,
            exe.parent()
                .unwrap()
                .join(format!(".meow-update-{}", std::process::id())),
        )
        .unwrap();
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
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
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
