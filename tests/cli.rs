//! End-to-end checks of the `meow` binary: argument handling, exit codes,
//! workspace creation and helper targeting. Every run uses a throwaway
//! `MEOW_HOME`, so the real `~/.meow` is never touched.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox {
    tmp: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("project")).unwrap();
        Self { tmp }
    }

    fn home(&self) -> PathBuf {
        self.tmp.path().join("meow-home")
    }

    fn project(&self) -> PathBuf {
        self.tmp.path().join("project")
    }

    fn workspace(&self, name: &str) -> PathBuf {
        self.home().join("workspaces").join(name)
    }

    /// Runs `meow` from the project directory with only the given session
    /// variables set.
    fn run_in(&self, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_meow"));
        command
            .args(args)
            .current_dir(cwd)
            .env("MEOW_HOME", self.home())
            .env_remove("MEOW_SESSION")
            .env_remove("MEOW_WORKSPACE");
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().expect("failed to run meow")
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.run_in(&self.project(), args, env)
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn profile(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("profile.toml")).unwrap()
}

#[test]
fn nested_session_is_refused_with_exit_code_1() {
    let sandbox = Sandbox::new();
    for args in [&[][..], &["other"][..], &["other", "--local"][..]] {
        let output = sandbox.run(args, &[("MEOW_SESSION", "acme")]);
        assert_eq!(output.status.code(), Some(1), "args {args:?}");
        assert_eq!(
            stderr(&output).trim(),
            "[!] Nested meow sessions are disabled (active: acme)"
        );
        assert!(output.stdout.is_empty());
    }
    assert!(
        !sandbox.home().exists(),
        "a refused run must create nothing"
    );
}

#[test]
fn workspace_variable_alone_also_blocks_nesting() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["other"], &[("MEOW_WORKSPACE", "/w/acme")]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr(&output).trim(),
        "[!] Nested meow sessions are disabled (active: /w/acme)"
    );
    assert!(!sandbox.home().exists());
}

#[test]
fn bare_meow_lists_workspaces() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&[], &[]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("No workspaces yet"));
    assert!(!sandbox.home().exists(), "listing must not create ~/.meow");

    sandbox.run(&["acme"], &[]);
    sandbox.run(&["webapp", "--local"], &[]);
    let listing = stdout(&sandbox.run(&[], &[]));
    assert!(listing.starts_with("NAME"), "{listing}");
    assert!(listing.contains("acme "), "{listing}");
    assert!(listing.contains("webapp (local)"), "{listing}");

    // The local workspace belongs to the project directory only.
    let elsewhere = stdout(&sandbox.run_in(sandbox.tmp.path(), &[], &[]));
    assert!(!elsewhere.contains("webapp"), "{elsewhere}");
}

#[test]
fn opening_a_name_creates_then_resumes_the_workspace() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["acme"], &[]);
    assert!(
        stdout(&output).contains("[+] Created workspace 'acme'"),
        "{}",
        stdout(&output)
    );
    let dir = sandbox.workspace("acme");
    assert!(dir.join("tmp").is_dir() && dir.join("chats").is_dir());
    assert!(profile(&dir).contains("mode = \"light\""));
    assert!(sandbox.home().join("config.toml").is_file());

    let output = sandbox.run(&["acme"], &[]);
    assert!(stdout(&output).contains("[+] Resumed workspace 'acme'"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("profile.toml")), 0o600);
        assert_eq!(mode(&sandbox.home().join("config.toml")), 0o600);
    }
}

#[test]
fn second_session_on_a_locked_workspace_is_refused() {
    let sandbox = Sandbox::new();
    sandbox.run(&["webapp", "--local"], &[]);
    let local = sandbox.project().join(".meow");
    assert!(local.join("session.lock").is_file());

    // This test process plays the live session that owns the workspace.
    let held = meow::lock::SessionLock::acquire(&local.join("session.lock")).unwrap();
    let output = sandbox.run(&["renamed", "--local"], &[]);
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(
        text.contains("[!] Workspace 'renamed' is already open in another meow session"),
        "{text}"
    );
    #[cfg(unix)]
    assert!(
        text.contains(&format!("(pid {})", std::process::id())),
        "{text}"
    );
    assert!(output.stdout.is_empty(), "{}", stdout(&output));
    // The refused run must not relabel the live session's workspace.
    assert!(profile(&local).contains("name = \"webapp\""));

    // Helpers do not take the session lock.
    let output = sandbox.run(&["mode", "mild", "--local"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    drop(held);
    let output = sandbox.run(&["renamed", "--local"], &[]);
    assert!(stdout(&output).contains("[+] Resumed workspace 'renamed'"));
    assert!(profile(&local).contains("name = \"renamed\""));
    assert!(profile(&local).contains("mode = \"mild\""));
}

#[test]
fn local_workspace_is_created_in_the_current_directory() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["webapp", "--local"], &[]);
    let local = sandbox.project().join(".meow");
    assert!(local.join("profile.toml").is_file(), "{}", stderr(&output));
    assert!(!sandbox.home().join("workspaces").exists());
}

#[test]
fn mode_persists_to_the_targeted_workspace() {
    let sandbox = Sandbox::new();
    sandbox.run(&["acme"], &[]);
    sandbox.run(&["other"], &[]);
    sandbox.run(&["webapp", "--local"], &[]);
    let acme = sandbox.workspace("acme");
    let other = sandbox.workspace("other");
    let local = sandbox.project().join(".meow");

    // $MEOW_SESSION alone maps to ~/.meow/workspaces/<name>.
    let output = sandbox.run(&["mode", "mild"], &[("MEOW_SESSION", "acme")]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output).trim(),
        "[+] Mode set to mild (session: acme)"
    );
    assert!(profile(&acme).contains("mode = \"mild\""));

    // $MEOW_WORKSPACE wins over $MEOW_SESSION, from any directory.
    let local_str = local.to_str().unwrap();
    let both = [("MEOW_SESSION", "acme"), ("MEOW_WORKSPACE", local_str)];
    let output = sandbox.run_in(sandbox.tmp.path(), &["mode", "aggressive"], &both);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(profile(&local).contains("mode = \"aggressive\""));
    assert!(profile(&acme).contains("mode = \"mild\""));

    // Explicit flags win over both variables.
    let output = sandbox.run(&["mode", "aggressive", "--session", "other"], &both);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(profile(&other).contains("mode = \"aggressive\""));

    let env = [("MEOW_WORKSPACE", acme.to_str().unwrap())];
    let output = sandbox.run(&["mode", "light", "--local"], &env);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(profile(&local).contains("mode = \"light\""));
    assert!(profile(&acme).contains("mode = \"mild\""));
}

#[test]
fn helpers_need_an_existing_workspace() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["hud"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("No active meow session"));

    let output = sandbox.run(&["hud", "--session", "ghost"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("no meow workspace"));

    let output = sandbox.run(&["hud"], &[("MEOW_SESSION", "../escape")]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("invalid workspace name"));
    assert!(
        !sandbox.home().exists(),
        "failed helpers must create nothing"
    );

    sandbox.run(&["acme"], &[]);
    let output = sandbox.run(&["report"], &[("MEOW_SESSION", "acme")]);
    let text = stderr(&output);
    assert!(!text.contains("Nested"), "{text}");
    assert!(text.contains("session: acme"), "{text}");
}

#[test]
fn usage_errors_exit_with_code_2() {
    let sandbox = Sandbox::new();
    for args in [
        &["--local"][..],
        &["mode", "insane"][..],
        &["bad/name"][..],
        &["report", "--local", "--session", "x"][..],
    ] {
        let code = sandbox.run(args, &[]).status.code();
        assert_eq!(code, Some(2), "args {args:?}");
    }
}

#[test]
fn version_and_help_succeed() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["--version"], &[]);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output).trim(),
        concat!("meow ", env!("CARGO_PKG_VERSION"))
    );

    let output = sandbox.run(&["--help"], &[("MEOW_SESSION", "acme")]);
    assert!(output.status.success());
    let help = stdout(&output);
    for word in ["mode", "recon", "map", "hud", "add", "report", "--local"] {
        assert!(help.contains(word), "help is missing {word}");
    }
}
