//! The commit meow is built from (`MEOW_BUILD_COMMIT`), so `meow update`
//! can tell when the checkout has moved on since. Part of build.rs, not of
//! meow itself; empty outside a git checkout.

/// Set by `meow update` to the commit it builds. A new value makes cargo
/// run build.rs again in the build folder it keeps, whatever git changed
/// to get there (with reftable, or a branch only in `packed-refs`, no
/// file below watches the move).
const SOURCE_COMMIT_ENV: &str = "MEOW_SOURCE_COMMIT";

/// What git changes when the checkout moves to another commit: `HEAD`,
/// the packed refs, the log of `HEAD` (a fast-forward of the branch adds
/// a line to it) and, with reftable, its list of tables.
const WATCHED: [&str; 4] = [
    ".git/HEAD",
    ".git/packed-refs",
    ".git/logs/HEAD",
    ".git/reftable/tables.list",
];

/// Tells cargo when to run build.rs again, and gives meow the commit.
pub fn emit() {
    println!("cargo:rerun-if-env-changed={SOURCE_COMMIT_ENV}");
    // A path that does not exist would rerun this script on every build.
    let has_git = std::path::Path::new(".git").exists();
    for watched in WATCHED {
        if std::path::Path::new(watched).exists() {
            println!("cargo:rerun-if-changed={watched}");
        }
    }
    if let Ok(head) = std::fs::read_to_string(".git/HEAD") {
        if let Some(rel) = head.trim().strip_prefix("ref:") {
            let rel = rel.trim();
            if rel.starts_with("refs/") && !rel.contains("..") && !rel.contains('\\') {
                let target = std::path::Path::new(".git").join(rel);
                if target.is_file() {
                    println!("cargo:rerun-if-changed={}", target.display());
                }
            }
        }
    }
    let hooks_arg = if cfg!(windows) {
        "core.hooksPath=NUL"
    } else {
        "core.hooksPath=/dev/null"
    };
    let commit = if has_git {
        std::process::Command::new("git")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_EXEC_PATH")
            .args([
                "-c",
                hooks_arg,
                "-c",
                "core.fsmonitor=false",
                "rev-parse",
                "HEAD",
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|text| text.trim().to_owned())
            .filter(|hex| {
                (7..=64).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_hexdigit())
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    println!("cargo:rustc-env=MEOW_BUILD_COMMIT={commit}");
}
