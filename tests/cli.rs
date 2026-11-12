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
            .env("SHELL", "/bin/sh")
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
fn list_and_ls_show_every_workspace_also_from_inside_a_session() {
    let sandbox = Sandbox::new();
    let empty = sandbox.run(&["list"], &[]);
    assert!(empty.status.success());
    assert!(stdout(&empty).contains("No workspaces yet"));
    assert!(!sandbox.home().exists(), "listing must not create ~/.meow");

    sandbox.run(&["acme"], &[]);
    sandbox.run(&["beta"], &[]);
    sandbox.run(&["webapp", "--local"], &[]);
    let bare = stdout(&sandbox.run(&[], &[]));
    let listing = stdout(&sandbox.run(&["list"], &[]));
    assert_eq!(listing, bare);
    assert_eq!(stdout(&sandbox.run(&["ls"], &[])), bare);
    assert!(listing.starts_with("NAME"), "{listing}");
    let row = |name: &str| -> Vec<String> {
        let line = listing.lines().find(|l| l.starts_with(name)).unwrap();
        line.split("  ")
            .filter(|cell| !cell.is_empty())
            .map(|cell| cell.trim().to_owned())
            .collect()
    };
    // No session is open on any of them.
    for name in ["acme", "beta", "webapp (local)"] {
        assert_eq!(row(name)[1], "-", "{listing}");
    }
    // The words are commands now, not workspace names.
    assert!(!sandbox.workspace("list").exists());
    assert!(!sandbox.workspace("ls").exists());

    // A bare `meow` is refused inside a session; `meow list` is not, and it
    // marks the session it was asked from. A connection file left behind by
    // a crashed session does not count as running.
    let beta = sandbox.workspace("beta");
    std::fs::write(
        beta.join("runtime.json"),
        r#"{"pid":1,"port":9,"token":"0000"}"#,
    )
    .unwrap();
    let acme = sandbox.workspace("acme");
    let inside = [
        ("MEOW_SESSION", "acme"),
        ("MEOW_WORKSPACE", acme.to_str().unwrap()),
    ];
    assert_eq!(sandbox.run(&[], &inside).status.code(), Some(1));
    let output = sandbox.run(&["list"], &inside);
    assert!(output.status.success(), "{}", stderr(&output));
    let listing = stdout(&output);
    let state = |name: &str| {
        let line = listing.lines().find(|l| l.starts_with(name)).unwrap();
        line.contains("this session")
    };
    assert!(state("acme"), "{listing}");
    assert!(!state("beta") && !listing.contains("running"), "{listing}");
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
    assert!(stdout(&output).contains("[+] Local network: "));
    let graph: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("graph.json")).unwrap()).unwrap();
    assert!(graph["local"]["observed_utc"]
        .as_str()
        .unwrap()
        .ends_with('Z'));
    assert!(graph["local"]["interfaces"].is_array());

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
    // With the session variable set, a helper is allowed (it is not a
    // nested shell) and finds the workspace.
    let output = sandbox.run(&["report"], &[("MEOW_SESSION", "acme")]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stderr(&output).contains("Nested"));
    assert!(stdout(&output).contains("[+] Report written to "));
}

/// Drives a whole session through a pipe: the shell runs inside the PTY,
/// stdin is not a terminal, so no raw mode is involved.
#[cfg(unix)]
#[test]
fn piped_session_runs_the_shell_with_session_variables() {
    use std::io::Write;
    use std::process::Stdio;

    let sandbox = Sandbox::new();
    let tap_log = sandbox.tmp.path().join("tap.log");
    let script = r#"echo "S=$MEOW_SESSION M=$MEOW_MODE"
echo "W=$MEOW_WORKSPACE"
cd / && "$MEOW_BIN" other; echo "nested-rc=$?"
"$MEOW_BIN" mode mild
printf 'tap-\033[31mmark\033[0m-%s\n' "$((40+2))"
exit 7
"#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_meow"))
        .arg("acme")
        .current_dir(sandbox.project())
        .env("MEOW_HOME", sandbox.home())
        .env("SHELL", "/bin/sh")
        .env("MEOW_BIN", env!("CARGO_BIN_EXE_meow"))
        .env("MEOW_TAP_LOG", &tap_log)
        .env_remove("MEOW_SESSION")
        .env_remove("MEOW_WORKSPACE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let text = stdout(&output);
    let workspace = sandbox.workspace("acme");

    assert_eq!(output.status.code(), Some(7), "{text}");
    assert!(text.contains("S=acme M=light"), "{text}");
    assert!(
        text.contains(&format!("W={}", workspace.display())),
        "{text}"
    );
    // Inside the session a second shell is refused, from any directory...
    assert!(
        text.contains("Nested meow sessions are disabled (active: acme)"),
        "{text}"
    );
    assert!(text.contains("nested-rc=1"), "{text}");
    // ...while helpers find the workspace through $MEOW_WORKSPACE.
    assert!(
        text.contains("[+] Mode set to mild (session: acme)"),
        "{text}"
    );
    assert!(profile(&workspace).contains("mode = \"mild\""));
    // Display path: escape sequences reach stdout untouched.
    assert!(text.contains("tap-\x1b[31mmark\x1b[0m-42"), "{text:?}");
    assert!(text.contains("[+] Session 'acme' closed"), "{text}");
    // No terminal was involved, so no reset sequence is emitted.
    assert!(!text.contains("\x1b[?1049l"), "{text:?}");

    // Analysis tap: the same line arrives without escape sequences.
    let tap = std::fs::read_to_string(&tap_log).unwrap();
    assert!(
        tap.lines().any(|line| line.ends_with("tap-mark-42")),
        "{tap}"
    );
    assert!(!tap.contains('\x1b'), "{tap:?}");
}

/// Inside a live session, helpers go through the coordinator and terminal
/// output is mined for facts.
#[cfg(unix)]
#[test]
fn live_session_serves_helpers_and_mines_terminal_output() {
    use std::io::Write;
    use std::process::Stdio;

    let sandbox = Sandbox::new();
    std::fs::create_dir_all(sandbox.home()).unwrap();
    std::fs::write(
        sandbox.home().join("config.toml"),
        "[cve]\nenabled = false\n",
    )
    .unwrap();
    std::fs::write(
        sandbox.project().join("scan.xml"),
        r#"<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>"#,
    )
    .unwrap();
    let script = r#"cat "$MEOW_WORKSPACE/runtime.json"; echo
"$MEOW_BIN" add scan.xml
"$MEOW_BIN" mode mild
"$MEOW_BIN" map --no-open
"$MEOW_BIN" list | sed 's/^/inside: /'
env -u MEOW_SESSION -u MEOW_WORKSPACE "$MEOW_BIN" list | sed 's/^/outside: /'
echo "Discovered open port 8443/tcp on 10.0.0.77"
exit
"#;
    let mut child = Command::new(env!("CARGO_BIN_EXE_meow"))
        .arg("acme")
        .current_dir(sandbox.project())
        .env("MEOW_HOME", sandbox.home())
        .env("SHELL", "/bin/sh")
        .env("MEOW_BIN", env!("CARGO_BIN_EXE_meow"))
        .env_remove("MEOW_SESSION")
        .env_remove("MEOW_WORKSPACE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let text = stdout(&output);
    let workspace = sandbox.workspace("acme");

    assert!(output.status.success(), "{text}");
    assert!(text.contains("[+] Coordinator on 127.0.0.1:"), "{text}");
    assert!(
        text.contains("\"pid\":"),
        "runtime.json was not readable in the session: {text}"
    );
    assert!(text.contains("\"token\":\""), "{text}");
    assert!(
        text.contains("scan.xml (Nmap XML): 2 facts parsed, 2 new or updated"),
        "{text}"
    );
    assert!(
        text.contains("[+] Mode set to mild (session: acme)"),
        "{text}"
    );
    // `meow list` asks the session itself: from its own shell it is "this
    // session", from any other terminal it is "running".
    let listed = |prefix: &str| {
        text.lines()
            .find(|l| l.starts_with(prefix) && l.contains("acme"))
            .unwrap_or_else(|| panic!("no {prefix} row for acme: {text}"))
            .to_owned()
    };
    assert!(listed("inside: ").contains("this session"), "{text}");
    assert!(listed("outside: ").contains("running"), "{text}");
    let url_at = text
        .find("http://127.0.0.1:")
        .expect("map URL was not printed");
    let url: String = text[url_at..]
        .chars()
        .take_while(|c| !c.is_whitespace())
        .collect();
    let token = url
        .split("/?token=")
        .nth(1)
        .expect("no token in the map URL");
    assert_eq!(token.len(), 64, "{url}");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "{url}");

    // The session is over: its connection details are gone, its data is not.
    assert!(!workspace.join("runtime.json").exists());
    assert!(profile(&workspace).contains("mode = \"mild\""));
    let graph: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(workspace.join("graph.json")).unwrap())
            .unwrap();
    assert_eq!(
        graph["hosts"]["10.0.0.5"]["ports"]["80/tcp"]["facts"][0]["source"],
        "nmap_xml"
    );
    let mined = &graph["hosts"]["10.0.0.77"]["ports"]["8443/tcp"];
    assert_eq!(mined["state"], "open", "{graph:#}");
    assert_eq!(mined["facts"][0]["source"], "pty_regex");
    assert_eq!(mined["facts"][0]["verification_status"], "Observed");
}

/// Shells with line editing ignore an EOF that arrives while they start up;
/// the session must still end when its input does.
#[cfg(unix)]
#[test]
fn session_ends_when_input_ends_even_with_a_line_editing_shell() {
    if !Path::new("/bin/bash").exists() {
        return;
    }
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["acme"], &[("SHELL", "/bin/bash")]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("[+] Session 'acme' closed"));
}

#[cfg(unix)]
#[test]
fn session_starts_in_the_restored_directory() {
    let sandbox = Sandbox::new();
    sandbox.run(&["acme"], &[]);
    let remembered = sandbox.tmp.path().join("remembered");
    std::fs::create_dir(&remembered).unwrap();
    std::fs::write(
        sandbox.workspace("acme").join("last_cwd"),
        format!("{}\n", remembered.display()),
    )
    .unwrap();

    let marker = remembered.join("was-here");
    assert!(!marker.exists());
    // With stdin at EOF the shell exits at once; its startup directory is
    // observed through $ENV, which POSIX sh runs when interactive.
    let rc = sandbox.tmp.path().join("rc");
    std::fs::write(&rc, "touch was-here\n").unwrap();
    let output = sandbox.run(&["acme"], &[("ENV", rc.to_str().unwrap())]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(marker.exists(), "shell did not start in the restored cwd");
}

#[test]
fn unknown_shell_is_reported_and_releases_the_workspace() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["acme"], &[("SHELL", "/no/such/shell")]);
    // Windows ignores $SHELL, so only Unix can observe the failure.
    #[cfg(unix)]
    {
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr(&output).contains("/no/such/shell"),
            "{}",
            stderr(&output)
        );
        let retry = sandbox.run(&["acme"], &[]);
        assert!(retry.status.success(), "{}", stderr(&retry));
    }
    let _ = output;
}

#[test]
fn add_imports_files_into_the_graph() {
    let sandbox = Sandbox::new();
    sandbox.run(&["acme"], &[]);
    let graph_path = sandbox.workspace("acme").join("graph.json");
    let write = |name: &str, body: &str| {
        let path = sandbox.project().join(name);
        std::fs::write(&path, body).unwrap();
        path
    };
    let graph = || -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(&graph_path).unwrap()).unwrap()
    };
    let env = [("MEOW_SESSION", "acme")];

    write(
        "scan.xml",
        r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0" method="probed" conf="10"><cpe>cpe:/a:nginx:nginx:1.18.0</cpe></service></port>
</ports></host></nmaprun>"#,
    );
    let output = sandbox.run(&["add", "scan.xml", "--no-cve"], &env);
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("scan.xml (Nmap XML): 2 facts parsed, 2 new"),
        "{out}"
    );
    assert!(out.contains("now has 1 hosts"), "{out}");
    let port = &graph()["hosts"]["10.0.0.5"]["ports"]["80/tcp"];
    assert_eq!(port["product"], "nginx");
    assert_eq!(
        port["cpes"][0],
        "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    );
    assert_eq!(port["facts"][0]["source"], "nmap_xml");
    assert_eq!(port["facts"][0]["verification_status"], "Observed");

    // Importing the same file again changes nothing.
    let out = stdout(&sandbox.run(&["add", "scan.xml", "--no-cve"], &env));
    assert!(out.contains("2 facts parsed, 0 new"), "{out}");

    write(
        "ferox.jsonl",
        "{\"type\":\"response\",\"url\":\"http://10.0.0.5/admin/\",\"status\":401}\n{\"type\":\"statistics\"}\n",
    );
    let out = stdout(&sandbox.run(&["add", "ferox.jsonl", "--no-cve"], &env));
    assert!(
        out.contains("(JSON Lines): 1 facts parsed, 1 new or updated, 1 lines skipped"),
        "{out}"
    );
    assert_eq!(
        graph()["hosts"]["10.0.0.5"]["ports"]["80/tcp"]["paths"]["children"]["admin"]["status"],
        401
    );

    write("notes.log", "Discovered open port 22/tcp on 10.0.0.9\n");
    write(
        "fix.diff",
        "--- a/x.conf\n+++ b/x.conf\n@@ -1 +1 @@\n-tokens on\n+tokens off\n",
    );
    assert!(stdout(&sandbox.run(&["add", "notes.log", "--no-cve"], &env)).contains("(text log)"));
    assert!(stdout(&sandbox.run(&["add", "fix.diff", "--no-cve"], &env)).contains("(git diff)"));
    let graph = graph();
    assert_eq!(graph["hosts"].as_object().unwrap().len(), 2);
    assert_eq!(graph["notes"][0]["claim"], "git diff: x.conf (+1 -1)");
    assert_eq!(graph["notes"][0]["source"], "git_diff");

    let output = sandbox.run(&["add", "missing.xml"], &env);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("missing.xml"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&graph_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn recon_needs_a_live_session_that_is_not_in_light_mode() {
    let sandbox = Sandbox::new();
    sandbox.run(&["acme"], &[]);
    // No session is running: nothing can host the scan.
    let output = sandbox.run(&["recon", "10.0.0.5", "--session", "acme"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("`meow recon` needs a live session: start `meow acme` first"),
        "{}",
        stderr(&output)
    );
    let output = sandbox.run(&["map", "--no-open", "--session", "acme"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("`meow map` needs a live session"));
    // The listing shows the new columns for the idle workspace.
    let listing = stdout(&sandbox.run(&[], &[]));
    assert!(
        listing.contains("HOSTS") && listing.contains("TASKS"),
        "{listing}"
    );
}

#[cfg(unix)]
#[test]
fn recon_inside_a_light_session_is_refused_with_the_reason() {
    use std::io::Write;
    use std::process::Stdio;

    let sandbox = Sandbox::new();
    let script = "\"$MEOW_BIN\" recon 10.0.0.0/24 -- -T4; echo \"recon-rc=$?\"\nexit\n";
    let mut child = Command::new(env!("CARGO_BIN_EXE_meow"))
        .arg("acme")
        .current_dir(sandbox.project())
        .env("MEOW_HOME", sandbox.home())
        .env("SHELL", "/bin/sh")
        .env("MEOW_BIN", env!("CARGO_BIN_EXE_meow"))
        .env_remove("MEOW_SESSION")
        .env_remove("MEOW_WORKSPACE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let text = stdout(&child.wait_with_output().unwrap());
    assert!(
        text.contains("[!] light mode sends no packets, so recon is refused"),
        "{text}"
    );
    assert!(text.contains("recon-rc=1"), "{text}");
}

#[test]
fn report_compiles_the_workspace_without_a_session() {
    let sandbox = Sandbox::new();
    sandbox.run(&["acme"], &[]);
    std::fs::write(
        sandbox.project().join("scan.xml"),
        r#"<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port></ports></host></nmaprun>"#,
    )
    .unwrap();
    let env = [("MEOW_SESSION", "acme")];
    assert!(sandbox
        .run(&["add", "scan.xml", "--no-cve"], &env)
        .status
        .success());

    let output = sandbox.run(&["report"], &env);
    assert!(output.status.success(), "{}", stderr(&output));
    let report_path = sandbox.workspace("acme").join("REPORT.md");
    assert!(stdout(&output).contains(&format!("[+] Report written to {}", report_path.display())));
    let report = std::fs::read_to_string(&report_path).unwrap();
    assert!(report.starts_with("# Audit report: acme\n"), "{report}");
    assert!(report.contains("```mermaid\ngraph LR\n"), "{report}");
    assert!(
        report.contains("| 80/tcp | open | http | nginx | 1.18.0 |"),
        "{report}"
    );
    assert!(
        report.contains("## Confirmed findings\n\nNone."),
        "{report}"
    );
    assert!(
        report.contains("## Unverified hypotheses\n\nNone."),
        "{report}"
    );

    let output = sandbox.run(&["report", "--session", "ghost"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("no meow workspace"));
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
