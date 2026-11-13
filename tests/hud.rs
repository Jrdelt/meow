//! `meow hud` running in a real pseudo-terminal, attached to a live session
//! and then, read-only, to the files that session left behind.
#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, Child, CommandBuilder, PtySize};

const PATIENCE: Duration = Duration::from_secs(20);

const SCAN: &str = r#"<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/></port></ports></host></nmaprun>"#;

fn meow(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_meow"));
    command
        .current_dir(root)
        .env("MEOW_HOME", root.join("meow-home"))
        .env("SHELL", "/bin/sh")
        .env_remove("MEOW_SESSION")
        .env_remove("MEOW_WORKSPACE");
    command
}

const ROWS: usize = 45;
const COLS: usize = 150;

/// Replays terminal output into a character grid. Ratatui only redraws the
/// cells that changed and jumps over the rest with cursor moves, so the raw
/// byte stream does not contain the screen text contiguously. Only what the
/// panel uses is understood: cursor positioning and printable characters.
fn screen(bytes: &[u8], rows: usize, cols: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut grid = vec![vec![' '; cols]; rows];
    let (mut row, mut col) = (0usize, 0usize);
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\u{1b}' => {
                if chars.peek() != Some(&'[') {
                    chars.next(); // two-character escape
                    continue;
                }
                chars.next();
                let mut params = String::new();
                let mut last = ' ';
                for c in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c) {
                        last = c;
                        break;
                    }
                    params.push(c);
                }
                match last {
                    'H' | 'f' => {
                        let mut parts = params.split(';').map(|p| p.parse::<usize>().unwrap_or(1));
                        row = parts.next().unwrap_or(1).saturating_sub(1).min(rows - 1);
                        col = parts.next().unwrap_or(1).saturating_sub(1).min(cols - 1);
                    }
                    'J' if params == "2" || params == "3" => grid = vec![vec![' '; cols]; rows],
                    _ => {}
                }
            }
            '\r' => col = 0,
            '\n' => row = (row + 1).min(rows - 1),
            c if c.is_control() => {}
            c => {
                if col < cols {
                    grid[row][col] = c;
                    col += 1;
                }
            }
        }
    }
    grid.into_iter()
        .map(|line| line.into_iter().collect::<String>().trim_end().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The HUD in an outer PTY the test can type into and read from.
struct Panel {
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
    output: Receiver<Vec<u8>>,
    seen: Vec<u8>,
}

impl Panel {
    fn open(root: &Path) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: ROWS as u16,
                cols: COLS as u16,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_meow"));
        command.args(["hud", "--session", "acme"]);
        command.cwd(root);
        command.env("MEOW_HOME", root.join("meow-home"));
        command.env("TERM", "xterm-256color");
        command.env_remove("MEOW_SESSION");
        command.env_remove("MEOW_WORKSPACE");
        let child = pair.slave.spawn_command(command).unwrap();
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().unwrap();
        let writer = pair.master.take_writer().unwrap();
        let (tx, output) = mpsc::channel();
        thread::spawn(move || {
            // The master must stay open while the reader runs.
            let _master = pair.master;
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            writer,
            child,
            output,
            seen: Vec::new(),
        }
    }

    fn send(&mut self, text: &str) {
        self.writer.write_all(text.as_bytes()).unwrap();
        self.writer.flush().unwrap();
    }

    /// True if the text is on the screen right now.
    fn has(&self, needle: &str) -> bool {
        screen(&self.seen, ROWS, COLS).contains(needle)
    }

    /// True if these bytes were ever written (for escape sequences).
    fn wrote(&self, needle: &str) -> bool {
        self.seen
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + PATIENCE;
        while !self.has(needle) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(left) {
                Ok(chunk) => self.seen.extend_from_slice(&chunk),
                Err(_) => panic!(
                    "the panel never showed {needle:?}:\n{}",
                    screen(&self.seen, ROWS, COLS)
                ),
            }
        }
    }

    fn quit(mut self) -> Vec<u8> {
        self.send("q");
        let deadline = Instant::now() + PATIENCE;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the panel did not quit");
            if let Ok(chunk) = self.output.recv_timeout(Duration::from_millis(20)) {
                self.seen.extend_from_slice(&chunk);
            }
        };
        while let Ok(chunk) = self.output.recv_timeout(Duration::from_millis(200)) {
            self.seen.extend_from_slice(&chunk);
        }
        assert_eq!(status.exit_code(), 0);
        self.seen
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + PATIENCE;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn hud_attaches_to_a_live_session_then_reads_its_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let workspace: PathBuf = root.join("meow-home/workspaces/acme");
    std::fs::create_dir_all(root.join("meow-home")).unwrap();
    std::fs::write(
        root.join("meow-home/config.toml"),
        "[cve]\nenabled = false\n",
    )
    .unwrap();
    std::fs::write(root.join("scan.xml"), SCAN).unwrap();

    // A live session whose shell waits on a pipe the test holds open.
    let mut session = meow(root)
        .arg("acme")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut session_input = session.stdin.take().unwrap();
    let mut session_output = session.stdout.take().unwrap();
    thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = session_output.read_to_end(&mut sink);
    });
    wait_for_file(&workspace.join("runtime.json"));
    let added = meow(root)
        .args(["add", "scan.xml", "--no-cve", "--session", "acme"])
        .output()
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    let mut panel = Panel::open(root);
    panel.wait_for("meow hud");
    panel.wait_for("10.0.0.5");
    panel.wait_for("live");
    panel.wait_for("80/tcp http nginx 1.18.0 open");
    assert!(
        panel.wrote("\x1b[?1049h"),
        "the panel should use the alternate screen"
    );

    // Catch-up note, typed into the box and saved by the session.
    panel.send("n");
    panel.wait_for("note for 10.0.0.5>");
    panel.send("admin panel found by hand");
    panel.send("\r");
    panel.wait_for("[manual_note / Medium]");
    // Mode switch from the panel.
    panel.send("2");
    panel.wait_for("mode set to mild");
    let seen = panel.quit();
    let tail = String::from_utf8_lossy(&seen[seen.len().saturating_sub(200)..]).into_owned();
    assert!(
        tail.contains("\x1b[?1049l"),
        "terminal was not restored: {tail:?}"
    );

    session_input.write_all(b"exit\n").unwrap();
    drop(session_input);
    assert!(session.wait().unwrap().success());

    // What the panel did is in the workspace files.
    let graph: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(workspace.join("graph.json")).unwrap())
            .unwrap();
    let note = graph["hosts"]["10.0.0.5"]["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["source"] == "manual_note")
        .expect("the note was not stored");
    assert_eq!(note["claim"], "admin panel found by hand");
    assert_eq!(note["verification_status"], "Observed");
    let profile = std::fs::read_to_string(workspace.join("profile.toml")).unwrap();
    assert!(profile.contains("mode = \"mild\""), "{profile}");

    // With the session gone the panel opens the files read-only.
    let mut panel = Panel::open(root);
    panel.wait_for("read-only (no session running)");
    panel.wait_for("10.0.0.5");
    panel.send("n");
    panel.send("x\r");
    panel.wait_for("read-only: no session is running");
    panel.quit();
}

#[test]
fn hud_without_a_terminal_fails_with_a_clear_message() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(meow(tmp.path())
        .arg("acme")
        .stdin(Stdio::null())
        .output()
        .unwrap()
        .status
        .success());
    let output = meow(tmp.path())
        .args(["hud", "--session", "acme"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("cannot take over the terminal"), "{error}");

    // Even inside a real PTY (/dev/tty present, stdin is a TTY), redirecting
    // stdout must refuse HUD takeover and leave `meow setup` non-interactive.
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: ROWS as u16,
            cols: COLS as u16,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut command = CommandBuilder::new("/bin/sh");
    command.args([
        "-c",
        "\"$MEOW_BIN\" hud --session acme > hud.out 2> hud.err; echo hud=$? > status; \
         \"$MEOW_BIN\" setup > setup.out; echo setup=$? >> status",
    ]);
    command.cwd(tmp.path());
    command.env("MEOW_BIN", env!("CARGO_BIN_EXE_meow"));
    command.env("MEOW_HOME", tmp.path().join("meow-home"));
    command.env_remove("MEOW_SESSION");
    command.env_remove("MEOW_WORKSPACE");
    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let drain = thread::spawn(move || {
        let _master = pair.master;
        let mut sink = Vec::new();
        let _ = reader.read_to_end(&mut sink);
    });
    assert!(child.wait().unwrap().success());
    drain.join().unwrap();

    let status = std::fs::read_to_string(tmp.path().join("status")).unwrap();
    assert_eq!(status, "hud=1\nsetup=0\n", "{status}");
    assert_eq!(std::fs::read(tmp.path().join("hud.out")).unwrap(), b"");
    let hud_err = std::fs::read_to_string(tmp.path().join("hud.err")).unwrap();
    assert!(
        hud_err.contains("cannot take over the terminal"),
        "{hud_err}"
    );
    let setup_out = std::fs::read_to_string(tmp.path().join("setup.out")).unwrap();
    assert!(
        setup_out.contains("Run `meow setup` in a terminal"),
        "{setup_out}"
    );
}
