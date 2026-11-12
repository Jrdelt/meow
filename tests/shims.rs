//! Runs real bash and zsh sessions through `meow` and checks what the
//! generated shims write to `replay.sh` and `last_cwd`. A shell that is not
//! installed is skipped with a note.
#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const HEADER_LINES: usize = 4;

struct Sandbox {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        // The shell reports its directory with symlinks resolved (on macOS
        // the temp directory is under /var, a link to /private/var), so the
        // expected paths must be the resolved ones too.
        let root = tmp.path().canonicalize().unwrap();
        for dir in ["project", "other", "user-home"] {
            std::fs::create_dir(root.join(dir)).unwrap();
        }
        Self { _tmp: tmp, root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn workspace(&self) -> PathBuf {
        self.path("meow-home").join("workspaces").join("acme")
    }

    /// The replay log without its header, one entry per element.
    fn replay(&self) -> Vec<String> {
        let text = std::fs::read_to_string(self.workspace().join("replay.sh")).unwrap();
        text.lines().skip(HEADER_LINES).map(str::to_owned).collect()
    }

    fn last_cwd(&self) -> String {
        std::fs::read_to_string(self.workspace().join("last_cwd")).unwrap()
    }

    /// Runs `meow acme` with `shell`, typing `script` into it.
    fn session(&self, shell: &str, script: &str, env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_meow"));
        command
            .arg("acme")
            .current_dir(self.path("project"))
            .env("MEOW_HOME", self.path("meow-home"))
            .env("MEOW_BIN", env!("CARGO_BIN_EXE_meow"))
            .env("HOME", self.path("user-home"))
            .env("SHELL", shell)
            .env_remove("MEOW_SESSION")
            .env_remove("MEOW_WORKSPACE")
            .env_remove("MEOW_BASH_LEGACY")
            .env_remove("ZDOTDIR")
            .env_remove("ENV")
            .env_remove("PROMPT_COMMAND")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

/// Finds a shell by name in the usual places (zsh is /bin/zsh on macOS and
/// /usr/bin/zsh on most Linux systems).
fn find_shell(name: &str) -> Option<String> {
    let found = ["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]
        .iter()
        .map(|dir| format!("{dir}/{name}"))
        .find(|path| Path::new(path).exists());
    if found.is_none() {
        eprintln!("note: {name} is not installed; skipping");
    }
    found
}

/// Bash gained `PS0` (the hook that runs before a command) in 4.4. The bash
/// that ships with macOS is 3.2, which only supports the later-logging path.
fn bash_with_ps0() -> Option<String> {
    let bash = find_shell("bash")?;
    let version = Command::new(&bash)
        .args(["-c", "echo ${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&version.stdout).into_owned();
    let mut parts = text
        .split_whitespace()
        .filter_map(|p| p.parse::<u32>().ok());
    let (major, minor) = (parts.next()?, parts.next()?);
    if major > 4 || (major == 4 && minor >= 4) {
        Some(bash)
    } else {
        eprintln!("note: {bash} is version {major}.{minor}, older than 4.4 (no PS0); skipping");
        None
    }
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn entry(cwd: &Path, command: &str, exit: Option<i32>) -> Vec<String> {
    let mut lines = vec![format!("# [CWD] {}", cwd.display()), command.to_owned()];
    lines.extend(exit.map(|code| format!("# [EXIT] {code}")));
    lines
}

const UNRECORDED: &str = "# [UNRECORDED] command kept out of the shell history";

/// The same typed session must produce the same log in bash and zsh.
fn check_full_session(shell: &str, rc_name: &str, rc_body: &str) {
    let sandbox = Sandbox::new();
    let rc_path = sandbox.path("user-home").join(rc_name);
    std::fs::write(&rc_path, rc_body).unwrap();
    let project = sandbox.path("project");
    let other = sandbox.path("other");

    let script = format!(
        r#"echo "rc=$MEOW_TEST_RC zd=${{ZDOTDIR-unset}}"
cd {other}
false
echo "seen=$_user_rc"
echo dup
echo dup
 echo spaced
"$MEOW_BIN" mode mild
echo "mode=$MEOW_MODE"
exit 5
"#,
        other = other.display()
    );
    let output = sandbox.session(shell, &script, &[]);
    let out = text(&output);

    assert_eq!(output.status.code(), Some(5), "{out}");
    // The user's own rc file was loaded first and is left exactly as it was.
    assert!(out.contains("rc=loaded zd=unset"), "{out}");
    assert_eq!(std::fs::read_to_string(&rc_path).unwrap(), rc_body);
    // The user's own prompt hook still sees the command's exit code.
    assert!(out.contains("seen=1"), "{out}");
    // $MEOW_MODE follows `meow mode` without restarting the shell.
    assert!(out.contains("mode=mild"), "{out}");
    assert!(!out.contains("No replay hooks"), "{out}");

    let expected: Vec<String> = [
        entry(
            &project,
            r#"echo "rc=$MEOW_TEST_RC zd=${ZDOTDIR-unset}""#,
            Some(0),
        ),
        entry(&project, &format!("cd {}", other.display()), Some(0)),
        entry(&other, "false", Some(1)),
        entry(&other, r#"echo "seen=$_user_rc""#, Some(0)),
        entry(&other, "echo dup", Some(0)),
        entry(&other, "echo dup", Some(0)),
        entry(&other, UNRECORDED, Some(0)),
        entry(&other, r#""$MEOW_BIN" mode mild"#, Some(0)),
        entry(&other, r#"echo "mode=$MEOW_MODE""#, Some(0)),
        // Stage 1 ran, the shell exited before stage 2.
        entry(&other, "exit 5", None),
    ]
    .concat();
    assert_eq!(sandbox.replay(), expected);
    assert_eq!(sandbox.last_cwd(), format!("{}\n", other.display()));

    // The next session starts where this one ended and appends to the log.
    let output = sandbox.session(shell, "pwd\nexit\n", &[]);
    assert!(
        text(&output).contains(&format!("{}\r\n", other.display())),
        "{}",
        text(&output)
    );
    let replay = sandbox.replay();
    assert_eq!(replay[..expected.len()], expected[..]);
    assert_eq!(
        replay[expected.len()..],
        [entry(&other, "pwd", Some(0)), entry(&other, "exit", None)].concat()[..]
    );
}

#[test]
fn bash_session_is_logged_in_two_stages() {
    let Some(bash) = bash_with_ps0() else {
        return;
    };
    check_full_session(
        &bash,
        ".bashrc",
        "export MEOW_TEST_RC=loaded\n\
         HISTCONTROL=ignoreboth\n\
         PS1='$ '\n\
         PROMPT_COMMAND='_user_rc=$?'\n",
    );
}

#[test]
fn zsh_session_is_logged_in_two_stages() {
    let Some(zsh) = find_shell("zsh") else {
        return;
    };
    check_full_session(
        &zsh,
        ".zshrc",
        "export MEOW_TEST_RC=loaded\n\
         setopt hist_ignore_space\n\
         PS1='%% '\n\
         autoload -Uz add-zsh-hook\n\
         _user_precmd() { _user_rc=$? }\n\
         add-zsh-hook precmd _user_precmd\n",
    );
}

#[test]
fn zsh_keeps_the_users_own_zdotdir() {
    let Some(zsh) = find_shell("zsh") else {
        return;
    };
    let sandbox = Sandbox::new();
    let zdot = sandbox.path("user-home").join("zdot");
    std::fs::create_dir(&zdot).unwrap();
    std::fs::write(zdot.join(".zshenv"), "export FROM_ZSHENV=yes\n").unwrap();
    std::fs::write(zdot.join(".zshrc"), "export FROM_ZSHRC=yes\nPS1='%% '\n").unwrap();
    // A decoy in $HOME that must not be read when ZDOTDIR points elsewhere.
    std::fs::write(
        sandbox.path("user-home").join(".zshrc"),
        "export FROM_ZSHRC=wrong\n",
    )
    .unwrap();

    let script = "echo \"env=$FROM_ZSHENV rc=$FROM_ZSHRC zd=$ZDOTDIR\"\n\
                  zsh -ic 'echo nested=$ZDOTDIR'\n\
                  exit\n";
    let output = sandbox.session(&zsh, script, &[("ZDOTDIR", zdot.to_str().unwrap())]);
    let out = text(&output);
    let expected = format!("env=yes rc=yes zd={}", zdot.display());
    assert!(out.contains(&expected), "{out}");
    // A zsh started inside the session is not hooked a second time.
    assert!(out.contains(&format!("nested={}", zdot.display())), "{out}");
    let logged = sandbox.replay();
    assert_eq!(logged.iter().filter(|l| l.contains("nested=")).count(), 1);
}

#[test]
fn bash_without_ps0_logs_each_command_when_it_finishes() {
    // Any bash will do: the variable forces the path that old versions take.
    let Some(bash) = find_shell("bash") else {
        return;
    };
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.path("user-home").join(".bashrc"), "PS1='$ '\n").unwrap();
    let project = sandbox.path("project");
    let other = sandbox.path("other");
    let script = format!("cd {}\nfalse\necho dup\necho dup\nexit\n", other.display());
    let output = sandbox.session(&bash, &script, &[("MEOW_BASH_LEGACY", "1")]);
    assert!(output.status.success(), "{}", text(&output));

    let expected: Vec<String> = [
        entry(&project, &format!("cd {}", other.display()), Some(0)),
        entry(&other, "false", Some(1)),
        entry(&other, "echo dup", Some(0)),
        entry(&other, "echo dup", Some(0)),
    ]
    .concat();
    assert_eq!(sandbox.replay(), expected);
    assert_eq!(sandbox.last_cwd(), format!("{}\n", other.display()));
}

#[test]
fn multi_line_commands_are_logged_whole() {
    let Some(bash) = bash_with_ps0() else {
        return;
    };
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.path("user-home").join(".bashrc"), "PS1='$ '\n").unwrap();
    let script = "for i in 1 2; do\necho \"n=$i\"\ndone\nexit\n";
    let output = sandbox.session(&bash, script, &[]);
    assert!(text(&output).contains("n=2"), "{}", text(&output));

    let replay = sandbox.replay().join("\n");
    assert!(replay.contains("for i in 1 2; do"), "{replay}");
    assert!(replay.contains("done\n# [EXIT] 0"), "{replay}");
    assert_eq!(replay.matches("# [CWD]").count(), 2, "{replay}");
}

#[test]
fn unsupported_shell_runs_unhooked_with_a_notice() {
    let sandbox = Sandbox::new();
    let output = sandbox.session("/bin/sh", "echo hi-$((1+1))\nexit\n", &[]);
    let out = text(&output);
    assert!(output.status.success(), "{out}");
    assert!(out.contains("hi-2"), "{out}");
    assert!(out.contains("[!] No replay hooks for this shell"), "{out}");
    assert!(!sandbox.workspace().join("replay.sh").exists());
}

/// Light mode cannot stop a command typed by hand, but it warns before a
/// high-rate scan starts.
fn check_rate_warning(shell: &str, rc_name: &str) {
    let sandbox = Sandbox::new();
    std::fs::write(sandbox.path("user-home").join(rc_name), "PS1='$ '\n").unwrap();
    let script = "echo nmap -sS -T4 10.0.0.5\n\
                  echo nmap -sT 10.0.0.5\n\
                  \"$MEOW_BIN\" mode mild\n\
                  echo nmap -A 10.0.0.5\n\
                  exit\n";
    let output = sandbox.session(shell, script, &[]);
    let out = text(&output);
    assert_eq!(
        out.matches("[meow] light mode: this command uses a high-rate scan flag")
            .count(),
        1,
        "exactly the -T4 command in light mode should warn:\n{out}"
    );
    // The warning comes before the command's own output.
    let warning = out.find("[meow] light mode").unwrap();
    let ran = out.rfind("nmap -sS -T4 10.0.0.5\r\n").unwrap();
    assert!(warning < ran, "{out}");
}

#[test]
fn bash_warns_about_high_rate_flags_in_light_mode() {
    if let Some(bash) = bash_with_ps0() {
        check_rate_warning(&bash, ".bashrc");
    }
}

#[test]
fn zsh_warns_about_high_rate_flags_in_light_mode() {
    if let Some(zsh) = find_shell("zsh") {
        check_rate_warning(&zsh, ".zshrc");
    }
}
