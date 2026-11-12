//! Runs the real `meow` binary inside a pseudo-terminal, the way a user's
//! terminal emulator would, to check raw mode, the reset sequence written on
//! exit, window-resize propagation and signal handling.
#![cfg(unix)]

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

const RESET: &[u8] = b"\x1b[?1049l\x1b[?1000l\x1b[?2004l\x1b[?25h";
const PATIENCE: Duration = Duration::from_secs(20);

fn size(rows: u16, cols: u16) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// A `meow <name>` session attached to an outer PTY that the test controls.
struct Hosted {
    _tmp: tempfile::TempDir,
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
    output: Receiver<Vec<u8>>,
    seen: Vec<u8>,
}

impl Hosted {
    fn start(name: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let pair = native_pty_system().openpty(size(24, 80)).unwrap();
        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_meow"));
        command.arg(name);
        command.cwd(tmp.path());
        command.env("MEOW_HOME", tmp.path().join("meow-home"));
        command.env("SHELL", "/bin/sh");
        command.env("TERM", "xterm-256color");
        command.env("PS1", "ready> ");
        command.env_remove("MEOW_SESSION");
        command.env_remove("MEOW_WORKSPACE");
        command.env_remove("ENV");
        let child = pair.slave.spawn_command(command).unwrap();
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().unwrap();
        let writer = pair.master.take_writer().unwrap();
        let (tx, output) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let mut hosted = Self {
            _tmp: tmp,
            master: pair.master,
            writer,
            child,
            output,
            seen: Vec::new(),
        };
        assert!(hosted.wait_for(b"ready> ", PATIENCE), "{}", hosted.dump());
        hosted
    }

    fn workspace(&self, name: &str) -> std::path::PathBuf {
        self._tmp
            .path()
            .join("meow-home")
            .join("workspaces")
            .join(name)
    }

    fn send(&mut self, text: &str) {
        self.writer.write_all(text.as_bytes()).unwrap();
        self.writer.flush().unwrap();
    }

    fn contains(&self, needle: &[u8]) -> bool {
        count(&self.seen, needle) > 0
    }

    /// Reads output until `needle` has appeared or `timeout` passes.
    fn wait_for(&mut self, needle: &[u8], timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while !self.contains(needle) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(left) {
                Ok(chunk) => self.seen.extend_from_slice(&chunk),
                Err(_) => return self.contains(needle),
            }
        }
        true
    }

    /// Waits for `meow` to exit and collects everything it still wrote.
    fn finish(mut self) -> (u32, Vec<u8>) {
        let deadline = Instant::now() + PATIENCE;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "meow did not exit: {}",
                self.dump()
            );
            if let Ok(chunk) = self.output.recv_timeout(Duration::from_millis(20)) {
                self.seen.extend_from_slice(&chunk);
            }
        };
        while let Ok(chunk) = self.output.recv_timeout(Duration::from_millis(300)) {
            self.seen.extend_from_slice(&chunk);
        }
        (status.exit_code(), self.seen)
    }

    fn dump(&self) -> String {
        String::from_utf8_lossy(&self.seen).into_owned()
    }
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn interactive_session_uses_raw_mode_and_resets_the_terminal_on_exit() {
    let mut hosted = Hosted::start("acme");

    // In raw mode the outer terminal does not echo; the only echo comes from
    // the shell's own PTY. A cooked outer terminal would show the text twice.
    hosted.send("echo once-$((20+3))\r");
    assert!(hosted.wait_for(b"once-23", PATIENCE), "{}", hosted.dump());
    assert_eq!(
        count(&hosted.seen, b"echo once-$((20+3))"),
        1,
        "{}",
        hosted.dump()
    );

    // Ctrl-C is a byte for the shell, not a signal that kills meow.
    hosted.send("sleep 30\r");
    thread::sleep(Duration::from_millis(300));
    hosted.send("\x03");
    hosted.send("echo alive-$((1+1))\r");
    assert!(hosted.wait_for(b"alive-2", PATIENCE), "{}", hosted.dump());

    let lock = hosted.workspace("acme").join("session.lock");
    assert!(lock.is_file());

    hosted.send("exit 3\r");
    let (code, seen) = hosted.finish();
    assert_eq!(code, 3, "{}", text(&seen));
    assert_eq!(count(&seen, RESET), 1, "{}", text(&seen));
    let reset_at = seen.windows(RESET.len()).position(|w| w == RESET).unwrap();
    let after = text(&seen[reset_at + RESET.len()..]);
    assert!(after.contains("[+] Session 'acme' closed"), "{after:?}");
    // Once the terminal is back in cooked mode, lines end with CR LF again.
    assert!(after.ends_with("closed\r\n"), "{after:?}");
}

#[test]
fn window_resize_reaches_the_shell() {
    let mut hosted = Hosted::start("acme");
    hosted.send("stty size\r");
    assert!(hosted.wait_for(b"24 80", PATIENCE), "{}", hosted.dump());

    hosted.master.resize(size(41, 123)).unwrap();
    let deadline = Instant::now() + PATIENCE;
    while !hosted.contains(b"41 123") {
        assert!(Instant::now() < deadline, "{}", hosted.dump());
        hosted.send("stty size\r");
        hosted.wait_for(b"41 123", Duration::from_millis(300));
    }

    hosted.send("exit\r");
    let (code, _) = hosted.finish();
    assert_eq!(code, 0);
}

#[test]
fn sigterm_ends_the_session_and_still_resets_the_terminal() {
    let mut hosted = Hosted::start("acme");
    // Leave the terminal in the states the reset sequence must clear.
    hosted.send("printf '\\033[?1049h\\033[?1000h\\033[?25l'; sleep 60\r");
    assert!(hosted.wait_for(b"\x1b[?25l", PATIENCE), "{}", hosted.dump());

    let pid = hosted.child.process_id().unwrap().to_string();
    let killed = std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap();
    assert!(killed.success());

    let (_, seen) = hosted.finish();
    assert_eq!(count(&seen, RESET), 1, "{}", text(&seen));
    assert!(seen.ends_with(b"closed\r\n"), "{}", text(&seen));
}
