//! Dual-stream PTY host for the session shell.
//!
//! * **Display fast-path:** bytes read from the PTY are written to `stdout`
//!   untouched, so full-screen programs behave exactly as they would without
//!   `meow`.
//! * **Analysis tap:** a copy of each chunk is offered to a [`TapFilter`]
//!   worker through a bounded channel with `try_send`. When the worker falls
//!   behind, chunks are dropped; the terminal never waits for analysis.
//! * **Input:** `std::io::stdin()` is the only reader of user input.
//!   `crossterm::event::read()` is never used here.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use ratatui::crossterm::terminal;

use crate::tap::{TapFilter, TapStats};

/// Written to `stdout` when the session ends or panics: leave the alternate
/// screen, stop mouse tracking, stop bracketed paste, show the cursor.
pub const TERMINAL_RESET: &[u8] = b"\x1b[?1049l\x1b[?1000l\x1b[?2004l\x1b[?25h";

const READ_CHUNK: usize = 4096;
/// Chunks the tap may queue before new ones are dropped (about 1 MiB).
const TAP_QUEUE: usize = 256;
/// How long to keep draining output after the shell has exited.
const DRAIN_GRACE: Duration = Duration::from_millis(500);

type SharedMaster = Arc<Mutex<Box<dyn MasterPty + Send>>>;

/// Receives each clean text line produced by the analysis tap.
pub type LineSink = Box<dyn FnMut(&str) + Send>;

pub struct SessionSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    /// Variables added to the inherited environment.
    pub env: Vec<(String, OsString)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionOutcome {
    pub exit_code: u32,
    pub tap: TapStats,
    /// Chunks the tap skipped because its queue was full.
    pub tap_chunks_dropped: u64,
}

/// Chooses the shell: the `config.toml` override, then `$SHELL` (Unix), then
/// the platform default.
pub fn resolve_shell(configured: Option<&str>, env_shell: Option<&str>) -> String {
    fn non_empty(value: Option<&str>) -> Option<&str> {
        value
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.chars().any(char::is_control))
    }
    if let Some(shell) = non_empty(configured) {
        return shell.to_owned();
    }
    if cfg!(unix) {
        if let Some(shell) = non_empty(env_shell) {
            return shell.to_owned();
        }
    }
    let default = if cfg!(windows) {
        "powershell.exe"
    } else if cfg!(target_os = "macos") {
        "/bin/zsh"
    } else {
        "/bin/bash"
    };
    default.to_owned()
}

// ---------------------------------------------------------------------------
// Terminal state
// ---------------------------------------------------------------------------

static RAW_ACTIVE: AtomicBool = AtomicBool::new(false);
static PANIC_HOOK: Once = Once::new();

/// Puts the real terminal into raw mode and restores it on drop. A panic on
/// any thread restores it too, before the panic message is printed.
struct TerminalGuard;

impl TerminalGuard {
    /// Returns `None` when stdin or stdout is not a terminal (pipes, tests):
    /// input is then forwarded as-is and no terminal state is touched.
    fn enter() -> Result<Option<Self>> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Ok(None);
        }
        PANIC_HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                restore_terminal();
                previous(info);
            }));
        });
        #[cfg(windows)]
        console::save_modes();
        terminal::enable_raw_mode().context("cannot switch the terminal to raw mode")?;
        RAW_ACTIVE.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        console::enable_virtual_terminal();
        Ok(Some(Self))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Idempotent: only the first call after raw mode was enabled does anything.
fn restore_terminal() {
    if !RAW_ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }
    let _ = terminal::disable_raw_mode();
    #[cfg(windows)]
    console::restore_modes();
    let mut stdout = io::stdout();
    if stdout.is_terminal() {
        let _ = stdout.write_all(TERMINAL_RESET);
        let _ = stdout.flush();
    }
}

/// Windows consoles need VT sequences switched on explicitly: input so that
/// arrow and function keys arrive as escape sequences for the PTY, output so
/// that the shell's sequences are interpreted rather than printed.
#[cfg(windows)]
mod console {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use crossterm_winapi::{ConsoleMode, Handle};

    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;
    const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;

    static SAVED: AtomicBool = AtomicBool::new(false);
    static SAVED_INPUT: AtomicU32 = AtomicU32::new(0);
    static SAVED_OUTPUT: AtomicU32 = AtomicU32::new(0);

    fn input() -> std::io::Result<ConsoleMode> {
        Ok(ConsoleMode::from(Handle::current_in_handle()?))
    }

    fn output() -> std::io::Result<ConsoleMode> {
        Ok(ConsoleMode::from(Handle::current_out_handle()?))
    }

    pub fn save_modes() {
        let modes = input()
            .and_then(|c| c.mode())
            .and_then(|i| Ok((i, output()?.mode()?)));
        if let Ok((input_mode, output_mode)) = modes {
            SAVED_INPUT.store(input_mode, Ordering::SeqCst);
            SAVED_OUTPUT.store(output_mode, Ordering::SeqCst);
            SAVED.store(true, Ordering::SeqCst);
        }
    }

    pub fn enable_virtual_terminal() {
        if let Ok(console) = input() {
            if let Ok(mode) = console.mode() {
                let _ = console.set_mode(mode | ENABLE_VIRTUAL_TERMINAL_INPUT);
            }
        }
        if let Ok(console) = output() {
            if let Ok(mode) = console.mode() {
                let _ = console.set_mode(
                    mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN,
                );
            }
        }
    }

    pub fn restore_modes() {
        if !SAVED.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Ok(console) = input() {
            let _ = console.set_mode(SAVED_INPUT.load(Ordering::SeqCst));
        }
        if let Ok(console) = output() {
            let _ = console.set_mode(SAVED_OUTPUT.load(Ordering::SeqCst));
        }
    }
}

fn terminal_size() -> PtySize {
    let (cols, rows) = match terminal::size() {
        Ok((cols, rows)) if cols > 0 && rows > 0 => (cols, rows),
        _ => (80, 24),
    };
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn sync_size(master: &SharedMaster) {
    if let Ok(master) = master.lock() {
        let _ = master.resize(terminal_size());
    }
}

// ---------------------------------------------------------------------------
// Stream pumps
// ---------------------------------------------------------------------------

/// PTY -> display, plus a best-effort copy to the tap. Returns at EOF.
#[cfg(test)]
fn pump_output(
    pty: impl Read,
    display: impl Write,
    tap: &SyncSender<Vec<u8>>,
    dropped: &AtomicU64,
) {
    pump_output_while(
        pty,
        display,
        Some(tap.clone()),
        dropped,
        &AtomicBool::new(true),
    );
}

fn pump_output_while(
    mut pty: impl Read,
    mut display: impl Write,
    mut tap: Option<SyncSender<Vec<u8>>>,
    dropped: &AtomicU64,
    active: &AtomicBool,
) {
    let mut buf = [0u8; READ_CHUNK];
    loop {
        let n = match pty.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break, // EIO on Linux once the shell has gone
        };
        let chunk = &buf[..n];
        // Display first and unconditionally; a closed stdout must not stop
        // the shell from being drained.
        let _ = display.write_all(chunk).and_then(|()| display.flush());
        if !active.load(Ordering::Acquire) {
            // Once the session has closed past DRAIN_GRACE, drop the tap
            // sender so stray background-job bytes never reach the sink.
            tap = None;
            continue;
        }
        if let Some(sender) = &tap {
            if let Err(TrySendError::Full(_)) = sender.try_send(chunk.to_vec()) {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// User input -> PTY, verbatim. Returns when the input reaches EOF.
fn pump_input(mut input: impl Read, pty: &mut dyn Write) {
    let mut buf = [0u8; READ_CHUNK];
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if pty.write_all(&buf[..n]).and_then(|()| pty.flush()).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// After the input has ended (a pipe ran dry, or the terminal went away),
/// tells the shell so by typing the terminal EOF character until it exits.
///
/// One EOF is not enough: a shell with line editing (bash, zsh) only treats
/// Ctrl-D as end-of-input while it is waiting at an empty prompt, so an EOF
/// sent during startup or while a command runs is lost.
fn signal_end_of_input(pty: &mut dyn Write, session_over: &AtomicBool) {
    const CLEAR_LINE_THEN_EOF: &[u8] = b"\x15\x04";
    const EOF: &[u8] = b"\x04";
    const RETRY: Duration = Duration::from_millis(250);

    if !cfg!(unix) {
        return; // dropping the writer closes the ConPTY input pipe
    }
    let mut bytes = EOF;
    while !session_over.load(Ordering::Relaxed) {
        if pty.write_all(bytes).and_then(|()| pty.flush()).is_err() {
            break;
        }
        bytes = CLEAR_LINE_THEN_EOF;
        thread::sleep(RETRY);
    }
}

/// Runs the C filter off the display path and hands clean lines to `sink`.
fn spawn_tap_worker(chunks: Receiver<Vec<u8>>, mut sink: LineSink) -> JoinHandle<TapStats> {
    thread::spawn(move || {
        let mut filter = TapFilter::new();
        for chunk in chunks {
            for line in filter.feed(&chunk) {
                sink(&line);
            }
        }
        if let Some(line) = filter.flush() {
            sink(&line);
        }
        filter.stats()
    })
}

// ---------------------------------------------------------------------------
// Resize and termination signals
// ---------------------------------------------------------------------------

/// Background watcher that keeps the PTY the same size as the real terminal
/// and, on Unix, turns `SIGTERM` / `SIGHUP` into an orderly shutdown.
struct Watcher {
    #[cfg(unix)]
    handle: signal_hook::iterator::Handle,
    #[cfg(not(unix))]
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Watcher {
    #[cfg(unix)]
    fn start(
        master: SharedMaster,
        mut killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
    ) -> Result<Self> {
        use signal_hook::consts::{SIGHUP, SIGTERM, SIGWINCH};
        use signal_hook::iterator::Signals;

        let mut signals =
            Signals::new([SIGWINCH, SIGTERM, SIGHUP]).context("cannot install signal handlers")?;
        let handle = signals.handle();
        let thread = thread::spawn(move || {
            for signal in signals.forever() {
                if signal == SIGWINCH {
                    sync_size(&master);
                } else {
                    // Ending the shell ends the session through the normal
                    // path, so the terminal is restored.
                    let _ = killer.kill();
                }
            }
        });
        Ok(Self {
            handle,
            thread: Some(thread),
        })
    }

    /// Windows has no `SIGWINCH`: poll the console size every 250 ms.
    #[cfg(not(unix))]
    fn start(
        master: SharedMaster,
        _killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut last = terminal::size().ok();
            while !stopped.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(250));
                let now = terminal::size().ok();
                if now != last {
                    last = now;
                    sync_size(&master);
                }
            }
        });
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        #[cfg(unix)]
        self.handle.close();
        #[cfg(not(unix))]
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Runs the shell described by `spec` until it exits. Blocks the caller.
pub fn run_session(spec: &SessionSpec, sink: LineSink) -> Result<SessionOutcome> {
    let pair = native_pty_system()
        .openpty(terminal_size())
        .context("cannot open a pseudo-terminal")?;

    let mut command = CommandBuilder::new(&spec.program);
    command.args(&spec.args);
    command.cwd(&spec.cwd);
    // $TERM and $COLORTERM are inherited; only fill in a missing $TERM.
    if std::env::var_os("TERM").is_none_or(|term| term.is_empty()) {
        command.env("TERM", "xterm-256color");
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }

    let mut child = pair.slave.spawn_command(command).with_context(|| {
        format!(
            "cannot start the shell '{}'",
            crate::evidence::sanitize(&spec.program, 200)
        )
    })?;
    drop(pair.slave); // only the shell keeps the slave side open

    let io_setup = pair
        .master
        .try_clone_reader()
        .and_then(|reader| Ok((reader, pair.master.take_writer()?)));
    let (reader, writer) = match io_setup {
        Ok(streams) => streams,
        Err(error) => {
            let _ = child.kill();
            return Err(error.context("cannot attach to the pseudo-terminal"));
        }
    };
    let master: SharedMaster = Arc::new(Mutex::new(pair.master));

    let guard = match TerminalGuard::enter() {
        Ok(guard) => guard,
        Err(error) => {
            let _ = child.kill();
            return Err(error);
        }
    };
    // The window may have changed size between openpty and raw mode.
    sync_size(&master);
    let watcher = Watcher::start(Arc::clone(&master), child.clone_killer());

    let (tap_tx, tap_rx) = mpsc::sync_channel::<Vec<u8>>(TAP_QUEUE);
    let tap_worker = spawn_tap_worker(tap_rx, sink);
    let dropped = Arc::new(AtomicU64::new(0));
    let (drained_tx, drained_rx) = mpsc::channel::<()>();
    let output_dropped = Arc::clone(&dropped);
    let display_open = Arc::new(AtomicBool::new(true));
    let pump_display_open = Arc::clone(&display_open);
    struct GatedStdout(Arc<AtomicBool>);
    impl Write for GatedStdout {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.0.load(Ordering::Acquire) {
                return Ok(buf.len());
            }
            io::stdout().write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            if !self.0.load(Ordering::Acquire) {
                return Ok(());
            }
            io::stdout().flush()
        }
    }
    thread::spawn(move || {
        pump_output_while(
            reader,
            GatedStdout(Arc::clone(&pump_display_open)),
            Some(tap_tx),
            &output_dropped,
            &pump_display_open,
        );
        let _ = drained_tx.send(());
    });
    // Blocks in `read` on stdin; if the session ends first, the thread ends
    // with the process.
    let session_over = Arc::new(AtomicBool::new(false));
    let input_over = Arc::clone(&session_over);
    let mut writer = writer;
    thread::spawn(move || {
        pump_input(io::stdin().lock(), &mut *writer);
        signal_end_of_input(&mut *writer, &input_over);
    });

    let status = child.wait();
    session_over.store(true, Ordering::Relaxed);

    // The shell is gone. Give the output pump a moment to reach EOF; a
    // background job that still holds the PTY must not keep the session open.
    let drained = drained_rx.recv_timeout(DRAIN_GRACE).is_ok();
    display_open.store(false, Ordering::Release);
    drop(watcher);
    drop(guard);

    let tap = if drained {
        tap_worker.join().unwrap_or_default()
    } else {
        TapStats::default()
    };
    let status = status.context("cannot wait for the shell")?;
    Ok(SessionOutcome {
        exit_code: status.exit_code(),
        tap,
        tap_chunks_dropped: dropped.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn collecting_sink() -> (LineSink, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink_lines = Arc::clone(&lines);
        let sink: LineSink = Box::new(move |line| sink_lines.lock().unwrap().push(line.to_owned()));
        (sink, lines)
    }

    #[test]
    fn shell_resolution_order() {
        assert_eq!(
            resolve_shell(Some("/opt/fish"), Some("/bin/zsh")),
            "/opt/fish"
        );
        assert_eq!(
            resolve_shell(Some("  "), Some("")),
            resolve_shell(None, None)
        );
        // Control characters (NUL, LF, ESC) in configured or env shells are rejected.
        assert_eq!(
            resolve_shell(Some("/bin/zsh\0bad"), Some("/bin/bash\x1b[2J")),
            resolve_shell(None, None)
        );
        #[cfg(unix)]
        assert_eq!(resolve_shell(None, Some("/bin/zsh")), "/bin/zsh");
        #[cfg(target_os = "linux")]
        assert_eq!(resolve_shell(None, None), "/bin/bash");
        #[cfg(target_os = "macos")]
        assert_eq!(resolve_shell(None, None), "/bin/zsh");
        #[cfg(windows)]
        assert_eq!(resolve_shell(None, Some("/bin/zsh")), "powershell.exe");
    }

    #[test]
    fn reset_sequence_matches_the_spec() {
        assert_eq!(
            TERMINAL_RESET,
            b"\x1b[?1049l\x1b[?1000l\x1b[?2004l\x1b[?25h"
        );
    }

    #[test]
    fn display_bytes_are_untouched_and_tap_gets_clean_lines() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"\x1b[1;32mgreen\x1b[0m\r\n");
        raw.extend_from_slice(b"\x1b[?1049h\x00\xff vim screen \x1b[?1049l");
        raw.extend_from_slice("caf\u{e9} 10%\r100%\r\n".as_bytes());
        raw.extend_from_slice(&vec![b'x'; 3 * READ_CHUNK]);
        raw.extend_from_slice(b"\r\n");

        let (tx, rx) = mpsc::sync_channel(TAP_QUEUE);
        let (sink, lines) = collecting_sink();
        let worker = spawn_tap_worker(rx, sink);
        let dropped = AtomicU64::new(0);
        let mut display = Vec::new();
        pump_output(Cursor::new(raw.clone()), &mut display, &tx, &dropped);
        drop(tx);
        let stats = worker.join().unwrap();

        assert_eq!(display, raw, "display path must be byte-for-byte");
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        let lines = lines.lock().unwrap();
        assert_eq!(lines[0], "green");
        assert_eq!(lines[1], "100%");
        assert_eq!(lines.len(), 3);
        assert_eq!(stats.lines_emitted, 3);
    }

    #[test]
    fn a_stalled_tap_never_blocks_the_display() {
        let raw = vec![b'y'; 10 * READ_CHUNK];
        // Capacity 2 and nobody receiving: the tap is completely stalled.
        let (tx, rx) = mpsc::sync_channel(2);
        let dropped = AtomicU64::new(0);
        let mut display = Vec::new();
        pump_output(Cursor::new(raw.clone()), &mut display, &tx, &dropped);

        assert_eq!(display, raw);
        assert_eq!(dropped.load(Ordering::Relaxed), 8);
        assert_eq!(rx.try_iter().count(), 2);
    }

    #[test]
    fn a_closed_tap_or_display_does_not_stop_draining() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        struct Counting(Cursor<Vec<u8>>, Arc<AtomicU64>);
        impl Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = self.0.read(buf)?;
                self.1.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            }
        }

        let read = Arc::new(AtomicU64::new(0));
        let source = Counting(Cursor::new(vec![b'z'; 5 * READ_CHUNK]), Arc::clone(&read));
        let (tx, rx) = mpsc::sync_channel(1);
        drop(rx);
        let dropped = AtomicU64::new(0);
        pump_output(source, Broken, &tx, &dropped);
        assert_eq!(read.load(Ordering::Relaxed), 5 * READ_CHUNK as u64);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn input_is_forwarded_verbatim() {
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let typed = b"ls -la\r\x1b[A\x03\x04\xe2\x9c\x93".to_vec();
        let received = Arc::new(Mutex::new(Vec::new()));
        let mut pty = Shared(Arc::clone(&received));
        pump_input(Cursor::new(typed.clone()), &mut pty);
        assert_eq!(*received.lock().unwrap(), typed);

        // At end of input the EOF character is repeated until the session
        // is over.
        received.lock().unwrap().clear();
        let over = Arc::new(AtomicBool::new(false));
        let stopper = Arc::clone(&over);
        let seen = Arc::clone(&received);
        let watcher = thread::spawn(move || {
            while seen.lock().unwrap().len() < 4 {
                thread::sleep(Duration::from_millis(20));
            }
            stopper.store(true, Ordering::Relaxed);
        });
        signal_end_of_input(&mut pty, &over);
        watcher.join().unwrap();
        #[cfg(unix)]
        assert!(received.lock().unwrap().starts_with(b"\x04\x15\x04"));
    }

    #[test]
    fn post_session_output_is_drained_without_feeding_tap() {
        let (tx, rx) = mpsc::sync_channel(TAP_QUEUE);
        let (sink, lines) = collecting_sink();
        let worker = spawn_tap_worker(rx, sink);
        let dropped = AtomicU64::new(0);
        let active = AtomicBool::new(false);
        let mut display = Vec::new();
        pump_output_while(
            Cursor::new(b"stray background line\r\n".to_vec()),
            &mut display,
            Some(tx),
            &dropped,
            &active,
        );
        let stats = worker.join().unwrap();
        assert_eq!(stats.lines_emitted, 0);
        assert!(lines.lock().unwrap().is_empty());
    }
}
