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
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use ratatui::crossterm::terminal;

use crate::tap::{TapFilter, TapStats};

/// Written to `stdout` when the session ends or panics: stop mouse
/// tracking, stop bracketed paste, show the cursor.
pub const TERMINAL_RESET: &[u8] = b"\x1b[?1000l\x1b[?2004l\x1b[?25h";
/// Leaves the alternate screen; written before [`TERMINAL_RESET`] only when
/// the session left it on. On the normal screen, xterm-like terminals take
/// it as "move the cursor back to where the last full-screen program
/// started", and what follows would be drawn over older lines.
pub const LEAVE_ALT_SCREEN: &[u8] = b"\x1b[?1049l";

const READ_CHUNK: usize = 4096;
/// Chunks the tap may queue before new ones are dropped (about 1 MiB).
const TAP_QUEUE: usize = 256;
/// How long to keep draining output after the shell has exited.
const DRAIN_GRACE: Duration = Duration::from_millis(500);
/// Once the shell has exited, how long the tap and the resize watcher get
/// to finish before they are left behind.
const THREAD_GRACE: Duration = Duration::from_secs(1);
/// After a signal that ends the session, how long the shell gets to end on
/// the hang-up it is sent before it is killed.
#[cfg(unix)]
const KILL_GRACE: Duration = Duration::from_secs(2);

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
/// Whether the session's output left the terminal on the alternate screen.
static ALT_SCREEN: AtomicBool = AtomicBool::new(false);
static PANIC_HOOK: Once = Once::new();
/// The thread that runs the session and owns the terminal.
static SESSION_THREAD: std::sync::OnceLock<thread::ThreadId> = std::sync::OnceLock::new();
/// The name of the threads the PTY host starts for the session.
const PTY_THREAD: &str = "meow-pty";

/// Whether a panic on the current thread ends the session, so the terminal
/// must be given back: on the session's own thread or one of the PTY host's.
/// A fault in a background task (the coordinator's, contained by its
/// runtime) leaves the session running, and taking raw mode away from it
/// would garble the screen and let the next Ctrl-C kill meow unsaved.
fn panic_ends_the_session() -> bool {
    let current = thread::current();
    SESSION_THREAD.get() == Some(&current.id()) || current.name() == Some(PTY_THREAD)
}

/// `thread::spawn` for the PTY host's own threads: named, so that a panic on
/// one of them still gives the terminal back.
fn spawn_pty<F, T>(work: F) -> thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .name(PTY_THREAD.to_owned())
        .spawn(work)
        .expect("cannot start a thread")
}

/// Restores standard cooked flags on `ios` if canonical mode, echo, or signal
/// generation were left disabled (e.g., after a prior process died from `kill -9`).
/// Returns `true` if `ios` was modified; leaves already-cooked terminals intact.
#[cfg(unix)]
fn ensure_cooked_termios(ios: &mut libc::termios) -> bool {
    let required_lflag = libc::ICANON | libc::ECHO | libc::ISIG;
    if (ios.c_lflag & required_lflag) == required_lflag {
        return false;
    }
    ios.c_iflag |= libc::BRKINT | libc::ICRNL | libc::IXON;
    ios.c_oflag |= libc::OPOST | libc::ONLCR;
    ios.c_lflag |=
        libc::ICANON | libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ISIG | libc::IEXTEN;
    true
}

/// Ensures the controlling terminal is in cooked mode on Unix before crossterm
/// snapshots "original" settings and after exiting raw mode.
pub fn ensure_cooked_terminal() {
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, RawFd};

        fn fix_fd(fd: RawFd) {
            // SAFETY: `termios` is plain C data filled by `tcgetattr`.
            let mut ios: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(fd, &mut ios) } != 0 {
                return;
            }
            if ensure_cooked_termios(&mut ios) {
                // SAFETY: `ios` came from `tcgetattr` on `fd` with valid cooked flags set.
                unsafe {
                    libc::tcsetattr(fd, libc::TCSANOW, &ios);
                }
            }
        }

        if let Ok(tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        {
            fix_fd(tty.as_raw_fd());
        } else if io::stdin().is_terminal() {
            fix_fd(io::stdin().as_raw_fd());
        }
    }
}

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
        let _ = SESSION_THREAD.set(thread::current().id());
        PANIC_HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                if panic_ends_the_session() {
                    restore_terminal();
                }
                previous(info);
            }));
        });
        ensure_cooked_terminal();
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
    ensure_cooked_terminal();
    #[cfg(windows)]
    console::restore_modes();
    let mut stdout = io::stdout();
    if stdout.is_terminal() {
        let _ = stdout.write_all(&reset_sequence(ALT_SCREEN.swap(false, Ordering::SeqCst)));
        let _ = stdout.flush();
    }
}

fn reset_sequence(alt_screen: bool) -> Vec<u8> {
    let leave = if alt_screen { LEAVE_ALT_SCREEN } else { b"" };
    [leave, TERMINAL_RESET].concat()
}

/// Follows whether the display is on the alternate screen, from the private
/// modes that full-screen programs set and reset (1049, 1047 and 47) and the
/// full reset (`ESC c`) that `reset` sends, which goes back to the normal one.
#[derive(Default)]
struct AltScreen {
    /// The end of what was seen: a sequence may be split across writes.
    seen: Vec<u8>,
}

impl AltScreen {
    const LONGEST: usize = b"\x1b[?1049h".len();

    /// Returns which screen `bytes` leave the display on, if they switch.
    fn feed(&mut self, bytes: &[u8]) -> Option<bool> {
        self.seen.extend_from_slice(bytes);
        let seen = &self.seen;
        // The last switch wins. One kept from the previous call is found
        // again only when nothing came after it, and then changes nothing.
        let last = (0..seen.len())
            .rev()
            .filter(|&at| seen[at] == 0x1b)
            .find_map(|at| Self::switch(&seen[at..]));
        let keep_from = seen.len().saturating_sub(Self::LONGEST - 1);
        self.seen.drain(..keep_from);
        last
    }

    fn switch(sequence: &[u8]) -> Option<bool> {
        if sequence.starts_with(b"\x1bc") {
            return Some(false);
        }
        let mode = sequence.strip_prefix(b"\x1b[?")?;
        let rest = [&b"1049"[..], b"1047", b"47"]
            .iter()
            .find_map(|number| mode.strip_prefix(*number))?;
        match rest.first()? {
            b'h' => Some(true),
            b'l' => Some(false),
            _ => None,
        }
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
/// Ends when every sender is gone, or at the first chunk (an empty one
/// wakes it) after `open` goes false.
fn spawn_tap_worker(
    chunks: Receiver<Vec<u8>>,
    open: Arc<AtomicBool>,
    mut sink: LineSink,
) -> JoinHandle<TapStats> {
    spawn_pty(move || {
        let mut filter = TapFilter::new();
        while let Ok(chunk) = chunks.recv() {
            let last = !open.load(Ordering::Acquire);
            // The session is over, though a background job may still hold
            // the PTY and the pump its sender: what is queued is all.
            let queued: Vec<Vec<u8>> = if last {
                chunks.try_iter().collect()
            } else {
                Vec::new()
            };
            for chunk in std::iter::once(chunk).chain(queued) {
                for line in filter.feed(&chunk) {
                    sink(&line);
                }
            }
            if last {
                break;
            }
        }
        if let Some(line) = filter.flush() {
            sink(&line);
        }
        filter.stats()
    })
}

/// Joins `thread` if it ends within `limit`, and otherwise leaves it
/// running: leaving the session must not wait on a stuck thread.
fn join_within<T>(thread: JoinHandle<T>, limit: Duration) -> Option<T> {
    let deadline = Instant::now() + limit;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(5));
    }
    thread.join().ok()
}

// ---------------------------------------------------------------------------
// Resize and termination signals
// ---------------------------------------------------------------------------

/// Background watcher that keeps the PTY the same size as the real terminal
/// and turns what ends meow from outside into an orderly shutdown: on Unix
/// `SIGTERM`, `SIGHUP`, `SIGINT` and `SIGQUIT`; on Windows a closed console
/// window, a logoff or a shutdown (see `close`).
struct Watcher {
    #[cfg(unix)]
    handle: signal_hook::iterator::Handle,
    #[cfg(not(unix))]
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Watcher {
    /// `shell` is the shell's process ID, and `over` is set once the shell
    /// has been waited for (after which that ID may belong to another).
    #[cfg(unix)]
    fn start(
        master: SharedMaster,
        mut killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
        shell: Option<u32>,
        over: Arc<AtomicBool>,
    ) -> Result<Self> {
        use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGWINCH};
        use signal_hook::iterator::Signals;

        // `SIGINT` and `SIGQUIT` come from `kill`, or from Ctrl-C and
        // Ctrl-\ where the terminal is not in raw mode (output to a pipe).
        // In raw mode those keys are bytes for the shell.
        let mut signals = Signals::new([SIGWINCH, SIGTERM, SIGHUP, SIGINT, SIGQUIT])
            .context("cannot install signal handlers")?;
        let handle = signals.handle();
        let thread = spawn_pty(move || {
            let mut shell = shell.and_then(|pid| libc::pid_t::try_from(pid).ok());
            for signal in signals.forever() {
                if signal == SIGWINCH {
                    sync_size(&master);
                    continue;
                }
                // Waited for: the session is ending already, and the
                // shell's ID may be another's.
                if over.load(Ordering::SeqCst) {
                    continue;
                }
                // Ending the shell ends the session through the normal
                // path, so the terminal is restored.
                let _ = killer.kill();
                // A shell stuck in its own exit (on a locked history file,
                // say) ignores the hang-up: it is killed if still there.
                if let Some(pid) = shell.take() {
                    let over = Arc::clone(&over);
                    spawn_pty(move || {
                        thread::sleep(KILL_GRACE);
                        if !over.load(Ordering::SeqCst) {
                            // SAFETY: a signal to the shell, which has not
                            // been waited for, so the ID is still its own.
                            unsafe { libc::kill(pid, libc::SIGKILL) };
                        }
                    });
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
        killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
        _shell: Option<u32>,
        _over: Arc<AtomicBool>,
    ) -> Result<Self> {
        #[cfg(windows)]
        close::watch(killer);
        #[cfg(not(windows))]
        drop(killer);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = spawn_pty(move || {
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
        #[cfg(windows)]
        close::shell_over();
        if let Some(thread) = self.thread.take() {
            let _ = join_within(thread, THREAD_GRACE);
        }
        // signal-hook's handler stays installed, so SIGTERM, SIGHUP, SIGINT
        // and SIGQUIT are ignored from here on (and on Windows the console
        // handler waits). That is wanted: the coordinator's cleanup, which
        // stops running scans, is bounded and must not be cut short.
    }
}

/// meow has done all it does as a session ends. On Windows a console
/// window that is being closed waits for this, up to 4.5 s.
pub fn cleaned_up() {
    #[cfg(windows)]
    close::cleaned_up();
}

/// Closing the console window, logging off or shutting down ends the
/// session as `SIGHUP` does on Unix: the shell is ended and meow's own
/// cleanup runs. Windows ends the process once the handler returns, or
/// about 5 s after the event, so the handler waits for the cleanup.
/// Ctrl-C and Ctrl-Break keep what Windows does with them.
#[cfg(windows)]
mod close {
    use std::sync::{Condvar, Mutex, MutexGuard, Once, PoisonError};
    use std::time::{Duration, Instant};

    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };

    type Killer = Box<dyn portable_pty::ChildKiller + Send + Sync>;

    /// The longest the handler waits for the cleanup: less than the about
    /// 5 s Windows gives it.
    pub const WAIT: Duration = Duration::from_millis(4500);

    /// The shell of the session, while it runs.
    static SHELL: Mutex<Option<Killer>> = Mutex::new(None);
    /// Whether meow has cleaned up after the session.
    static DONE: Mutex<bool> = Mutex::new(false);
    static DONE_SAID: Condvar = Condvar::new();
    static INSTALL: Once = Once::new();

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether console `event` ends the session.
    pub fn ends_session(event: u32) -> bool {
        matches!(
            event,
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
        )
    }

    /// The session's shell runs: the handler is installed (once; it stays,
    /// as signal handlers do on Unix) and ends it on a close.
    pub fn watch(shell: Killer) {
        *lock(&DONE) = false;
        *lock(&SHELL) = Some(shell);
        INSTALL.call_once(|| {
            // SAFETY: `handler` is a function that lives as long as the
            // process.
            unsafe { SetConsoleCtrlHandler(Some(handler), TRUE) };
        });
    }

    /// The shell has ended: nothing is left to end on a close.
    pub fn shell_over() {
        lock(&SHELL).take();
    }

    pub fn cleaned_up() {
        *lock(&DONE) = true;
        DONE_SAID.notify_all();
    }

    /// Called by Windows on a thread of its own. Returning FALSE passes the
    /// event on to the next handler: for Ctrl-C and Ctrl-Break, Windows'
    /// own, which ends the process.
    unsafe extern "system" fn handler(event: u32) -> BOOL {
        if !ends_session(event) {
            return FALSE;
        }
        end_and_wait(WAIT);
        TRUE
    }

    /// Ends the shell, if it still runs, and waits up to `limit` for the
    /// cleanup. Returns whether it was done in time.
    pub fn end_and_wait(limit: Duration) -> bool {
        if let Some(mut shell) = lock(&SHELL).take() {
            let _ = shell.kill();
        }
        let deadline = Instant::now() + limit;
        let mut done = lock(&DONE);
        while !*done {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            done = DONE_SAID
                .wait_timeout(done, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};

        /// A shell that counts how often it was ended.
        #[derive(Debug, Clone)]
        struct Shell(Arc<AtomicUsize>);

        impl portable_pty::ChildKiller for Shell {
            fn kill(&mut self) -> std::io::Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
                Box::new(self.clone())
            }
        }

        /// The only test of this module's state, which is the process's.
        #[test]
        fn closing_the_console_ends_the_shell_and_waits_for_the_cleanup() {
            for event in [CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT] {
                assert!(ends_session(event), "{event}");
            }
            for event in [CTRL_C_EVENT, CTRL_BREAK_EVENT, 3, 4, 7] {
                assert!(!ends_session(event), "{event}");
            }

            let ended = Arc::new(AtomicUsize::new(0));
            watch(Box::new(Shell(Arc::clone(&ended))));
            // Ctrl-C and Ctrl-Break are passed on, and end nothing.
            // SAFETY: the handler is a plain function.
            unsafe {
                assert_eq!(handler(CTRL_C_EVENT), FALSE);
                assert_eq!(handler(CTRL_BREAK_EVENT), FALSE);
            }
            assert_eq!(ended.load(Ordering::SeqCst), 0);

            // A cleanup that never comes is waited for no longer than said.
            let started = Instant::now();
            assert!(!end_and_wait(Duration::from_millis(100)));
            assert!(started.elapsed() >= Duration::from_millis(100));
            assert!(started.elapsed() < Duration::from_secs(2));
            assert_eq!(ended.load(Ordering::SeqCst), 1);

            // The window closes as the session runs: the shell is ended,
            // and the handler returns once meow has cleaned up.
            watch(Box::new(Shell(Arc::clone(&ended))));
            let cleanup = std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                cleaned_up();
            });
            let started = Instant::now();
            // SAFETY: as above.
            assert_eq!(unsafe { handler(CTRL_CLOSE_EVENT) }, TRUE);
            assert!(started.elapsed() >= Duration::from_millis(200));
            assert!(started.elapsed() < WAIT);
            assert_eq!(ended.load(Ordering::SeqCst), 2);
            cleanup.join().unwrap();

            // Once the shell is over, a close ends nothing more and, the
            // cleanup done, returns at once.
            watch(Box::new(Shell(Arc::clone(&ended))));
            shell_over();
            cleaned_up();
            // SAFETY: as above.
            assert_eq!(unsafe { handler(CTRL_SHUTDOWN_EVENT) }, TRUE);
            assert_eq!(ended.load(Ordering::SeqCst), 2);
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Resolves `program` to an absolute executable path without consulting empty
/// or relative `PATH` entries or the current working directory.
fn resolve_shell_executable(program: &str) -> Result<PathBuf> {
    #[cfg(windows)]
    if program.eq_ignore_ascii_case("powershell.exe") || program.eq_ignore_ascii_case("powershell")
    {
        if let Some(ps) = crate::tools::windows_powershell_exe() {
            return Ok(ps);
        }
    }
    crate::tools::find_program(program).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot find executable shell '{}'",
            crate::evidence::sanitize(program, 200)
        )
    })
}

/// Where the session's input comes from and its output goes.
struct Terminal {
    input: Box<dyn Read + Send>,
    output: Box<dyn Write + Send>,
    /// The user's own terminal: raw mode, resizes and termination signals.
    real: bool,
}

/// The display: shut once the session is over, and watched for the
/// alternate screen.
struct Display {
    open: Arc<AtomicBool>,
    output: Box<dyn Write + Send>,
    alt_screen: AltScreen,
}

impl Write for Display {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.open.load(Ordering::Acquire) {
            return Ok(buf.len());
        }
        let written = self.output.write(buf)?;
        if let Some(on) = self.alt_screen.feed(&buf[..written]) {
            ALT_SCREEN.store(on, Ordering::SeqCst);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.open.load(Ordering::Acquire) {
            return Ok(());
        }
        self.output.flush()
    }
}

/// Runs the shell described by `spec` until it exits. Blocks the caller.
pub fn run_session(spec: &SessionSpec, sink: LineSink) -> Result<SessionOutcome> {
    let terminal = Terminal {
        input: Box::new(io::stdin()),
        output: Box::new(io::stdout()),
        real: true,
    };
    host_session(spec, sink, terminal)
}

/// [`run_session`] on any input and output. Once the shell has exited this
/// returns within about [`DRAIN_GRACE`] plus [`THREAD_GRACE`], whatever
/// still holds the PTY, and gives the terminal back first.
fn host_session(spec: &SessionSpec, sink: LineSink, terminal: Terminal) -> Result<SessionOutcome> {
    let executable = resolve_shell_executable(&spec.program)?;
    let pair = native_pty_system()
        .openpty(terminal_size())
        .context("cannot open a pseudo-terminal")?;

    let mut command = CommandBuilder::new(&executable);
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
    let session_over = Arc::new(AtomicBool::new(false));

    let (guard, watcher) = if terminal.real {
        let guard = match TerminalGuard::enter() {
            Ok(guard) => guard,
            Err(error) => {
                let _ = child.kill();
                return Err(error);
            }
        };
        // The window may have changed size between openpty and raw mode.
        sync_size(&master);
        let watcher = Watcher::start(
            Arc::clone(&master),
            child.clone_killer(),
            child.process_id(),
            Arc::clone(&session_over),
        )
        .ok();
        (guard, watcher)
    } else {
        (None, None)
    };

    let display_open = Arc::new(AtomicBool::new(true));
    let (tap_tx, tap_rx) = mpsc::sync_channel::<Vec<u8>>(TAP_QUEUE);
    // Kept to wake the tap once the session is over.
    let tap_wake = tap_tx.clone();
    let tap_worker = spawn_tap_worker(tap_rx, Arc::clone(&display_open), sink);
    let dropped = Arc::new(AtomicU64::new(0));
    let (drained_tx, drained_rx) = mpsc::channel::<()>();
    let output_dropped = Arc::clone(&dropped);
    let display = Display {
        open: Arc::clone(&display_open),
        output: terminal.output,
        alt_screen: AltScreen::default(),
    };
    let pump_display_open = Arc::clone(&display_open);
    spawn_pty(move || {
        pump_output_while(
            reader,
            display,
            Some(tap_tx),
            &output_dropped,
            &pump_display_open,
        );
        let _ = drained_tx.send(());
    });
    // Blocks in `read` on stdin; if the session ends first, the thread ends
    // with the process.
    let input_over = Arc::clone(&session_over);
    let mut writer = writer;
    let input = terminal.input;
    spawn_pty(move || {
        pump_input(input, &mut *writer);
        signal_end_of_input(&mut *writer, &input_over);
    });

    let status = child.wait();
    session_over.store(true, Ordering::SeqCst);

    // The shell is gone. Give the output pump a moment to reach EOF; a
    // background job that still holds the PTY must not keep the session open.
    let _ = drained_rx.recv_timeout(DRAIN_GRACE);
    display_open.store(false, Ordering::Release);
    // The terminal goes back to the user before anything below may wait.
    drop(guard);
    // What the tap has queued is all it gets now.
    let _ = tap_wake.try_send(Vec::new());
    drop(tap_wake);
    drop(watcher);
    drop(master);
    let tap = join_within(tap_worker, THREAD_GRACE).unwrap_or_default();
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

    #[test]
    fn a_fault_in_a_background_thread_leaves_the_terminal_to_the_session() {
        // A thread of the coordinator's runtime.
        let other = thread::Builder::new()
            .name("meow-coordinator".into())
            .spawn(panic_ends_the_session)
            .unwrap()
            .join()
            .unwrap();
        assert!(!other);
        // The PTY host's own threads, and the session's thread, do end it.
        assert!(spawn_pty(panic_ends_the_session).join().unwrap());
        let _ = SESSION_THREAD.set(thread::current().id());
        if SESSION_THREAD.get() == Some(&thread::current().id()) {
            assert!(panic_ends_the_session());
        }
    }
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
    fn shell_executable_resolution_rejects_relative_and_missing_programs() {
        assert!(resolve_shell_executable("./bash").is_err());
        assert!(resolve_shell_executable("../bash").is_err());
        assert!(resolve_shell_executable("definitely-not-a-real-shell-binary-xyz").is_err());
        #[cfg(unix)]
        assert_eq!(
            resolve_shell_executable("/bin/sh").unwrap(),
            PathBuf::from("/bin/sh")
        );
    }

    #[test]
    fn reset_sequence_matches_the_spec() {
        assert_eq!(
            reset_sequence(true),
            b"\x1b[?1049l\x1b[?1000l\x1b[?2004l\x1b[?25h"
        );
        // Not on the alternate screen: no 1049l, which would move the
        // cursor back over older output.
        assert_eq!(reset_sequence(false), b"\x1b[?1000l\x1b[?2004l\x1b[?25h");
    }

    #[test]
    fn the_alternate_screen_is_followed_across_writes() {
        let mut alt = AltScreen::default();
        assert_eq!(alt.feed(b"plain text\r\n\x1b[1;32mgreen\x1b[0m"), None);
        assert_eq!(alt.feed(b"\x1b[?1049h\x1b[22;0;0t less"), Some(true));
        assert_eq!(alt.feed(b"page two"), None);
        assert_eq!(alt.feed(b"\x1b[?1049l$ "), Some(false));
        // The last switch in a write wins.
        assert_eq!(alt.feed(b"\x1b[?1047h vim \x1b[?1047l"), Some(false));
        assert_eq!(alt.feed(b"\x1b7\x1b[?47h"), Some(true));
        // A sequence split across writes, at every point.
        let sequence = b"\x1b[?1049l";
        for split in 1..sequence.len() {
            let mut alt = AltScreen::default();
            assert_eq!(alt.feed(b"\x1b[?1049h"), Some(true));
            assert_eq!(alt.feed(&sequence[..split]), None, "{split}");
            assert_eq!(alt.feed(&sequence[split..]), Some(false), "{split}");
        }
        // `reset` after a full-screen program was killed: the full reset
        // goes back to the normal screen, even when split.
        let mut alt = AltScreen::default();
        assert_eq!(alt.feed(b"\x1b[?1049h"), Some(true));
        assert_eq!(alt.feed(b"\x1bc\x1b]104\x07"), Some(false));
        assert_eq!(alt.feed(b"\x1b[?1049h\x1b"), Some(true));
        assert_eq!(alt.feed(b"c$ "), Some(false));
        // Other modes, and incomplete or non-private ones, are not switches.
        let mut alt = AltScreen::default();
        for other in [
            &b"\x1b[?1000h"[..],
            b"\x1b[?2004l",
            b"\x1b[1049h",
            b"\x1b[?470h",
            b"\x1b[?104",
            b"\x1b[c",
            b"\x1b[0c",
        ] {
            assert_eq!(alt.feed(other), None, "{other:?}");
        }
    }

    #[test]
    fn the_tap_ends_with_the_session_even_if_the_pty_stays_open() {
        let (tx, rx) = mpsc::sync_channel(TAP_QUEUE);
        let open = Arc::new(AtomicBool::new(true));
        let (sink, lines) = collecting_sink();
        let worker = spawn_tap_worker(rx, Arc::clone(&open), sink);
        tx.send(b"last line\r\n".to_vec()).unwrap();
        tx.send(b"no newline".to_vec()).unwrap();
        // `tx` stays alive, as the pump's sender does while a background
        // job holds the PTY.
        open.store(false, Ordering::Release);
        tx.send(Vec::new()).unwrap();
        let stats =
            join_within(worker, Duration::from_secs(3)).expect("the tap thread never ended");
        assert_eq!(*lines.lock().unwrap(), ["last line", "no newline"]);
        assert_eq!(stats.lines_emitted, 2);
        drop(tx);
    }

    #[test]
    fn a_stuck_thread_is_left_behind() {
        let (release, wait) = mpsc::channel::<()>();
        let stuck = thread::spawn(move || {
            let _ = wait.recv();
        });
        let started = Instant::now();
        assert!(join_within(stuck, Duration::from_millis(100)).is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(release);
        assert_eq!(
            join_within(thread::spawn(|| 7), Duration::from_secs(3)),
            Some(7)
        );
    }

    /// After the session, a late hang-up must not kill meow while the
    /// coordinator is still stopping the scans it started.
    #[cfg(unix)]
    #[test]
    fn hang_ups_stay_caught_after_the_session() {
        #[derive(Debug)]
        struct NoShell;
        impl portable_pty::ChildKiller for NoShell {
            fn kill(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
                Box::new(NoShell)
            }
        }
        let pair = native_pty_system().openpty(PtySize::default()).unwrap();
        let master: SharedMaster = Arc::new(Mutex::new(pair.master));
        let over = Arc::new(AtomicBool::new(true));
        drop(Watcher::start(master, Box::new(NoShell), None, over).unwrap());
        for signal in [libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: reads the current action only.
            let action = unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut action), 0);
                action
            };
            assert_ne!(action.sa_sigaction, libc::SIG_DFL, "{signal}");
        }
    }

    /// The shell has exited but a background job still holds the PTY: the
    /// session ends anyway, and its tap lets go of the sink (which holds the
    /// coordinator's last sender) instead of waiting for the job.
    #[cfg(unix)]
    #[test]
    fn a_job_holding_the_pty_does_not_hold_up_the_end_of_the_session() {
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
        struct Dropped(mpsc::Sender<()>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let spec = SessionSpec {
            program: "/bin/sh".to_owned(),
            // The job ignores the hang-up the shell's exit sends, and keeps
            // the PTY open for 5 s without writing to it.
            args: vec![
                "-c".to_owned(),
                "trap '' HUP; sleep 5 & echo \"job $! started\"; exit 7".to_owned(),
            ],
            cwd: std::env::temp_dir(),
            env: Vec::new(),
        };
        let (dropped_tx, dropped_rx) = mpsc::channel();
        let held = Dropped(dropped_tx);
        let sink: LineSink = Box::new(move |_line| {
            std::hint::black_box(&held);
        });
        let shown = Arc::new(Mutex::new(Vec::new()));
        let terminal = Terminal {
            input: Box::new(io::empty()),
            output: Box::new(Shared(Arc::clone(&shown))),
            real: false,
        };

        let started = Instant::now();
        let outcome = host_session(&spec, sink, terminal).unwrap();
        let took = started.elapsed();
        let gone = dropped_rx.recv_timeout(Duration::from_millis(500));

        let shown = String::from_utf8_lossy(&shown.lock().unwrap()).into_owned();
        let job = shown
            .split("job ")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .and_then(|pid| pid.parse::<libc::pid_t>().ok());
        if let Some(pid) = job {
            // SAFETY: ends the test's own background job.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        assert_eq!(outcome.exit_code, 7, "{shown:?}");
        assert!(took < DRAIN_GRACE + THREAD_GRACE, "{took:?}");
        assert!(gone.is_ok(), "the tap still holds the sink: {shown:?}");
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
        let worker = spawn_tap_worker(rx, Arc::new(AtomicBool::new(true)), sink);
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

        received.lock().unwrap().clear();
        // At end of input the EOF character is repeated until the session
        // is over.
        #[cfg(unix)]
        {
            let over = Arc::new(AtomicBool::new(false));
            let stopper = Arc::clone(&over);
            let seen = Arc::clone(&received);
            let watcher = spawn_pty(move || {
                while seen.lock().unwrap().len() < 4 {
                    thread::sleep(Duration::from_millis(20));
                }
                stopper.store(true, Ordering::Relaxed);
            });
            signal_end_of_input(&mut pty, &over);
            watcher.join().unwrap();
            assert!(received.lock().unwrap().starts_with(b"\x04\x15\x04"));
        }
        // On Windows nothing is typed: closing the writer ends ConPTY input.
        #[cfg(not(unix))]
        {
            signal_end_of_input(&mut pty, &AtomicBool::new(false));
            assert!(received.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn post_session_output_is_drained_without_feeding_tap() {
        let (tx, rx) = mpsc::sync_channel(TAP_QUEUE);
        let (sink, lines) = collecting_sink();
        let worker = spawn_tap_worker(rx, Arc::new(AtomicBool::new(true)), sink);
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

    #[cfg(unix)]
    #[test]
    fn ensure_cooked_termios_repairs_raw_mode_and_leaves_cooked_mode_intact() {
        // SAFETY: `termios` is plain C data zeroed and mutated by `cfmakeraw`.
        let mut raw: libc::termios = unsafe { std::mem::zeroed() };
        raw.c_iflag = libc::ICRNL | libc::IXON;
        raw.c_oflag = libc::OPOST | libc::ONLCR;
        raw.c_lflag = libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN;
        assert!(!ensure_cooked_termios(&mut raw));

        unsafe { libc::cfmakeraw(&mut raw) };
        assert_eq!(raw.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG), 0);
        assert!(ensure_cooked_termios(&mut raw));
        assert_eq!(
            raw.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG),
            libc::ICANON | libc::ECHO | libc::ISIG
        );
        assert_ne!(raw.c_iflag & libc::ICRNL, 0);
        assert_ne!(raw.c_oflag & libc::OPOST, 0);
        assert!(!ensure_cooked_termios(&mut raw));
    }
}
