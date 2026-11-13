//! `meow update` against a real git repository standing in for GitHub: a
//! bare "origin", a clone meow pulls into, and an install.sh that only
//! records that it ran.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MEOW: &str = env!("CARGO_BIN_EXE_meow");

struct Repos {
    tmp: tempfile::TempDir,
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=meow-test",
            "-c",
            "user.email=test@example.invalid",
        ])
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "advice.detachedHead=false",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

impl Repos {
    /// `origin` (bare), `clone` (where meow was "built"), and `work`, a
    /// second clone used to push new commits.
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let repos = Self { tmp };
        let work = repos.path("work");
        std::fs::create_dir(&work).unwrap();
        git(&work, &["init", "-q"]);
        std::fs::write(work.join("Cargo.toml"), "[package]\nname = \"meow\"\n").unwrap();
        std::fs::write(
            work.join("install.sh"),
            "echo \"installer ran with $* in $(pwd)\" >> \"$INSTALL_LOG\"\n",
        )
        .unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-qm", "first"]);
        git(
            repos.tmp.path(),
            &["clone", "-q", "--bare", "work", "origin.git"],
        );
        git(&work, &["remote", "add", "origin", "../origin.git"]);
        git(&work, &["fetch", "-q", "origin"]);
        git(&work, &["branch", "-q", "--set-upstream-to=origin/main"]);
        git(repos.tmp.path(), &["clone", "-q", "origin.git", "clone"]);
        repos
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    fn push_change(&self, name: &str) {
        let work = self.path("work");
        std::fs::write(work.join(name), name).unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-qm", &format!("add {name}")]);
        git(&work, &["push", "-q", "origin", "HEAD:main"]);
    }

    fn update(&self, extra: &[&str]) -> Output {
        Command::new(MEOW)
            .arg("update")
            .arg("--source")
            .arg(self.path("clone"))
            .args(extra)
            .env("MEOW_HOME", self.path("home"))
            .env("INSTALL_LOG", self.path("install.log"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap()
    }

    fn installs(&self) -> String {
        std::fs::read_to_string(self.path("install.log")).unwrap_or_default()
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn update_pulls_what_was_pushed_and_runs_the_installer() {
    let repos = Repos::new();
    repos.push_change("new-feature.txt");

    // --check says what is new and changes nothing.
    let output = repos.update(&["--check"]);
    let shown = text(&output);
    assert!(output.status.success(), "{shown}");
    assert!(shown.contains("1 new on origin/main:"), "{shown}");
    assert!(shown.contains("add new-feature.txt"), "{shown}");
    assert!(!repos.path("clone/new-feature.txt").exists());
    assert!(repos.installs().is_empty());

    let output = repos.update(&[]);
    let shown = text(&output);
    assert!(output.status.success(), "{shown}");
    assert!(repos.path("clone/new-feature.txt").exists(), "{shown}");
    let installs = repos.installs();
    assert!(
        installs.starts_with("installer ran with --yes in "),
        "{installs}"
    );
    assert!(shown.contains("[+] Updated."), "{shown}");
}

#[test]
fn local_changes_are_never_pulled_over() {
    let repos = Repos::new();
    repos.push_change("upstream.txt");
    std::fs::write(repos.path("clone/install.sh"), "echo edited by hand\n").unwrap();
    let output = repos.update(&[]);
    let shown = text(&output);
    assert!(!output.status.success(), "{shown}");
    assert!(
        shown.contains("has local changes, so nothing was pulled"),
        "{shown}"
    );
    assert!(shown.contains("install.sh"), "{shown}");
    assert!(!repos.path("clone/upstream.txt").exists());
    assert!(repos.installs().is_empty());
}

#[test]
fn a_folder_that_is_not_a_meow_checkout_is_refused() {
    let repos = Repos::new();
    let output = Command::new(MEOW)
        .args(["update", "--source"])
        .arg(repos.path("nowhere"))
        .env("MEOW_HOME", repos.path("home"))
        .output()
        .unwrap();
    let shown = text(&output);
    assert!(!output.status.success());
    assert!(shown.contains("is not a meow git checkout"), "{shown}");
}
