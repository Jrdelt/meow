//! A one-line answer on the terminal that starts filled in and is edited in
//! place: arrows, Backspace, Delete, Home/End and Ctrl-A/E/U/W; Enter
//! accepts, Esc or Ctrl-C cancels.
//!
//! On Unix the terminal is put in raw mode with termios and the bytes of
//! stdin are read here. crossterm's event reader is never used: the process
//! that asks goes on to host the session's PTY, and that reader must not
//! have been started in it. Without raw mode (Windows, or a terminal that
//! refuses it) a plain question is asked instead.

use std::io::{self, BufRead, Write};

const ESC: u8 = 0x1b;
/// An escape sequence longer than this is not one a key sends.
const MAX_SEQUENCE: usize = 32;

/// How a question ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Enter: the text as it stands.
    Accept(String),
    /// Esc, Ctrl-C, or Ctrl-D on an empty line.
    Cancel,
}

/// The edited text and its cursor. Bytes go in, a finished answer comes
/// out; nothing here touches the terminal.
#[derive(Debug, Clone, Default)]
pub struct Editor {
    text: Vec<char>,
    /// Position in `text`, in characters.
    cursor: usize,
    /// Bytes of an escape sequence or a character not complete yet.
    pending: Vec<u8>,
}

impl Editor {
    /// Starts with `initial`, the cursor at its end.
    pub fn new(initial: &str) -> Self {
        let text: Vec<char> = initial.chars().collect();
        Self {
            cursor: text.len(),
            text,
            pending: Vec::new(),
        }
    }

    pub fn text(&self) -> String {
        self.text.iter().collect()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// True while part of a key is waiting for the rest.
    pub fn is_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Takes bytes as the terminal sends them; a key may be split across
    /// calls. Returns the outcome once a key ends the question; later bytes
    /// are not used.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<Outcome> {
        for &byte in bytes {
            if let Some(outcome) = self.push(byte) {
                return Some(outcome);
            }
        }
        None
    }

    /// No more bytes came for a moment: an Esc on its own was the Esc key,
    /// anything else unfinished is dropped.
    pub fn idle(&mut self) -> Option<Outcome> {
        let lone_esc = self.pending == [ESC];
        self.pending.clear();
        lone_esc.then_some(Outcome::Cancel)
    }

    fn push(&mut self, byte: u8) -> Option<Outcome> {
        if self.pending.is_empty() {
            return match byte {
                ESC => {
                    self.pending.push(byte);
                    None
                }
                0x80.. => {
                    self.pending.push(byte);
                    self.utf8()
                }
                _ => self.control_or_char(byte),
            };
        }
        if self.pending[0] == ESC {
            self.pending.push(byte);
            return self.escape();
        }
        if byte & 0xc0 != 0x80 {
            // A character cut short: drop it and start again with this byte.
            self.pending.clear();
            return self.push(byte);
        }
        self.pending.push(byte);
        self.utf8()
    }

    fn utf8(&mut self) -> Option<Outcome> {
        let need = match self.pending[0] {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => {
                self.pending.clear();
                return None;
            }
        };
        if self.pending.len() < need {
            return None;
        }
        if let Ok(text) = std::str::from_utf8(&self.pending) {
            let chars: Vec<char> = text.chars().collect();
            for ch in chars {
                self.insert(ch);
            }
        }
        self.pending.clear();
        None
    }

    fn control_or_char(&mut self, byte: u8) -> Option<Outcome> {
        match byte {
            b'\r' | b'\n' => return Some(Outcome::Accept(self.text())),
            0x03 => return Some(Outcome::Cancel),
            0x04 if self.text.is_empty() => return Some(Outcome::Cancel),
            0x04 => self.delete(),
            0x7f | 0x08 => self.backspace(),
            0x01 => self.cursor = 0,
            0x05 => self.cursor = self.text.len(),
            0x02 => self.cursor = self.cursor.saturating_sub(1),
            0x06 => self.cursor = (self.cursor + 1).min(self.text.len()),
            0x15 => {
                self.text.drain(..self.cursor);
                self.cursor = 0;
            }
            0x0b => {
                self.text.truncate(self.cursor);
            }
            0x17 => self.rub_out_word(),
            0x20..=0x7e => self.insert(char::from(byte)),
            _ => {}
        }
        None
    }

    /// `pending` starts with Esc. Arrows, Home, End and Delete are used;
    /// every other sequence is read to its end and ignored.
    fn escape(&mut self) -> Option<Outcome> {
        let seq = &self.pending[1..];
        let done = match seq {
            [] => return None,
            [ESC, ..] => {
                // Esc pressed twice.
                self.pending.clear();
                return Some(Outcome::Cancel);
            }
            [b'['] | [b'O'] => return None,
            [b'O', key] => Some((Vec::new(), *key)),
            [b'[', rest @ ..] => match rest.last() {
                Some(&last) if (0x40..=0x7e).contains(&last) => {
                    Some((rest[..rest.len() - 1].to_vec(), last))
                }
                _ if self.pending.len() > MAX_SEQUENCE => {
                    self.pending.clear();
                    return None;
                }
                _ => return None,
            },
            // Alt and a key: not used.
            _ => None,
        };
        self.pending.clear();
        if let Some((params, key)) = done {
            self.key(&params, key);
        }
        None
    }

    fn key(&mut self, params: &[u8], key: u8) {
        // Modifiers come after a `;` (Ctrl-Left is `1;5D`).
        let first = params.split(|b| *b == b';').next().unwrap_or_default();
        match (key, first) {
            (b'D', _) => self.cursor = self.cursor.saturating_sub(1),
            (b'C', _) => self.cursor = (self.cursor + 1).min(self.text.len()),
            (b'H', _) | (b'~', b"1" | b"7") => self.cursor = 0,
            (b'F', _) | (b'~', b"4" | b"8") => self.cursor = self.text.len(),
            (b'~', b"3") => self.delete(),
            _ => {}
        }
    }

    fn insert(&mut self, ch: char) {
        self.text.insert(self.cursor, ch);
        self.cursor += 1;
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.text.remove(self.cursor);
        }
    }

    fn delete(&mut self) {
        if self.cursor < self.text.len() {
            self.text.remove(self.cursor);
        }
    }

    /// Ctrl-W: back over separators, then back to the previous one, so
    /// `/a/bc` becomes `/a/`.
    fn rub_out_word(&mut self) {
        let separator = |ch: char| matches!(ch, '/' | '\\' | ' ');
        let mut start = self.cursor;
        while start > 0 && separator(self.text[start - 1]) {
            start -= 1;
        }
        while start > 0 && !separator(self.text[start - 1]) {
            start -= 1;
        }
        self.text.drain(start..self.cursor);
        self.cursor = start;
    }

    /// The line to draw: back to its start, `prompt`, as much of the text as
    /// fits in `columns` around the cursor, the rest of the line cleared,
    /// and the cursor put back in place. Widths are terminal columns (a CJK
    /// character or an emoji takes two). Control characters show as `?`.
    pub fn render(&self, prompt: &str, columns: usize) -> String {
        let room = columns.saturating_sub(text_width(prompt) + 1).max(8);
        let shown: Vec<char> = self
            .text
            .iter()
            .map(|&ch| if ch.is_control() { '?' } else { ch })
            .collect();
        let widths: Vec<usize> = shown.iter().map(|&ch| char_width(ch)).collect();
        // What is before the cursor, and the cell it stands on, must fit.
        let mut start = 0;
        let mut used: usize = widths[..self.cursor].iter().sum();
        while used + 1 > room && start < self.cursor {
            used -= widths[start];
            start += 1;
        }
        let mut end = self.cursor;
        while end < shown.len() && used + widths[end] <= room {
            used += widths[end];
            end += 1;
        }
        let text: String = shown[start..end].iter().collect();
        let mut line = format!("\r{prompt}{text}\x1b[K");
        let back: usize = widths[self.cursor..end].iter().sum();
        if back > 0 {
            line.push_str(&format!("\x1b[{back}D"));
        }
        line
    }
}

/// Columns `text` takes on the terminal.
fn text_width(text: &str) -> usize {
    ratatui::text::Span::raw(text).width()
}

/// Columns one character takes on the terminal.
fn char_width(ch: char) -> usize {
    let mut buf = [0u8; 4];
    text_width(ch.encode_utf8(&mut buf))
}

/// Asks for one line on the terminal, starting from `initial`. `label` is
/// shown before it (`"    Folder"`). `None` when the user cancels or input
/// ends.
pub fn ask(label: &str, initial: &str) -> io::Result<Option<String>> {
    #[cfg(unix)]
    if let Some(raw) = unix::RawMode::enter() {
        return unix::edit(&raw, &format!("{label}: "), initial);
    }
    plain(label, initial)
}

/// `Folder [<initial>]: `: Enter keeps `initial`, typed text replaces it.
fn plain(label: &str, initial: &str) -> io::Result<Option<String>> {
    let shown = crate::evidence::sanitize(initial, 1024);
    let mut out = io::stdout();
    write!(out, "{label} [{shown}]: ")?;
    out.flush()?;
    let mut answer = String::new();
    if io::stdin().lock().read_line(&mut answer)? == 0 {
        writeln!(out)?;
        return Ok(None);
    }
    let answer = answer.trim();
    Ok(Some(if answer.is_empty() {
        initial.to_owned()
    } else {
        answer.to_owned()
    }))
}

#[cfg(unix)]
mod unix {
    use std::cell::UnsafeCell;
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{Editor, Outcome};

    /// How long to wait for the rest of an escape sequence before taking a
    /// lone Esc as the key.
    const ESC_WAIT_MS: i32 = 80;

    /// Signals that end meow by default. While the question waits, the
    /// terminal is put back before one of them ends it.
    const ENDING: [libc::c_int; 4] = [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT, libc::SIGINT];

    /// The terminal and its settings from before raw mode, for the signal
    /// handler.
    struct Saved(UnsafeCell<Option<(libc::c_int, libc::termios)>>);

    // SAFETY: written only while `ARMED` is false, before the handler is
    // installed; the handler reads it only while `ARMED` is true.
    unsafe impl Sync for Saved {}

    static SAVED: Saved = Saved(UnsafeCell::new(None));
    static ARMED: AtomicBool = AtomicBool::new(false);

    /// Puts the saved settings back on the terminal. All it calls is safe
    /// in a signal handler.
    pub(super) fn put_back_saved() {
        if ARMED.load(Ordering::SeqCst) {
            // SAFETY: `SAVED` is not written while `ARMED` is set.
            if let Some((fd, termios)) = unsafe { &*SAVED.0.get() } {
                // SAFETY: restores settings `tcgetattr` returned.
                unsafe { libc::tcsetattr(*fd, libc::TCSANOW, termios) };
            }
        }
    }

    extern "C" fn put_back_and_end(signal: libc::c_int) {
        put_back_saved();
        // SAFETY: both are safe in a signal handler. The signal is held
        // until this returns, and then ends meow as it would have.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
    }

    /// Raw mode on a terminal; the saved settings come back on drop, which
    /// also runs when a panic unwinds (the release profile unwinds), and
    /// before a signal ends meow.
    pub(super) struct RawMode {
        fd: libc::c_int,
        saved: libc::termios,
        /// What the ending signals did before, put back on drop.
        previous: Vec<(libc::c_int, libc::sigaction)>,
    }

    impl RawMode {
        pub(super) fn enter() -> Option<Self> {
            Self::enter_on(libc::STDIN_FILENO)
        }

        pub(super) fn enter_on(fd: libc::c_int) -> Option<Self> {
            // One question at a time.
            if ARMED.load(Ordering::SeqCst) {
                return None;
            }
            // SAFETY: `termios` is plain C data that `tcgetattr` fills.
            let mut saved: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: `fd` is open for the whole process; `saved` is valid.
            if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
                return None;
            }
            // SAFETY: not armed, so no handler reads it now.
            unsafe { *SAVED.0.get() = Some((fd, saved)) };
            ARMED.store(true, Ordering::SeqCst);
            let mut mode = Self {
                fd,
                saved,
                previous: Vec::new(),
            };
            mode.catch_ending_signals();
            let mut raw = saved;
            raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
            raw.c_iflag &= !(libc::IXON
                | libc::ICRNL
                | libc::INLCR
                | libc::IGNCR
                | libc::ISTRIP
                | libc::BRKINT);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            // SAFETY: `raw` is a copy of valid settings with flags cleared.
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
                return None;
            }
            Some(mode)
        }

        /// Installs the handler for each ending signal that still does what
        /// it does by default; one ignored or handled elsewhere is left be.
        fn catch_ending_signals(&mut self) {
            for signal in ENDING {
                // SAFETY: `sigaction` is plain C data; the calls only read
                // `action` and fill `old`.
                unsafe {
                    let mut old: libc::sigaction = std::mem::zeroed();
                    if libc::sigaction(signal, std::ptr::null(), &mut old) != 0
                        || old.sa_sigaction != libc::SIG_DFL
                    {
                        continue;
                    }
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction =
                        put_back_and_end as extern "C" fn(libc::c_int) as libc::sighandler_t;
                    libc::sigemptyset(&mut action.sa_mask);
                    if libc::sigaction(signal, &action, &mut old) == 0 {
                        self.previous.push((signal, old));
                    }
                }
            }
        }
    }

    impl Drop for RawMode {
        fn drop(&mut self) {
            // SAFETY: restores the settings `tcgetattr` returned, then what
            // each signal did before.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
                for (signal, old) in &self.previous {
                    libc::sigaction(*signal, old, std::ptr::null_mut());
                }
            }
            ARMED.store(false, Ordering::SeqCst);
        }
    }

    fn columns() -> usize {
        ratatui::crossterm::terminal::size()
            .map(|(cols, _)| usize::from(cols))
            .ok()
            .filter(|cols| *cols > 0)
            .unwrap_or(80)
    }

    /// Waits up to `timeout_ms` (-1: no limit) for input. `Ok(false)` on
    /// time out; an interrupted wait (a resize) counts as input to redraw.
    fn wait(timeout_ms: i32) -> io::Result<bool> {
        let mut poll = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid `pollfd`.
        match unsafe { libc::poll(&mut poll, 1, timeout_ms) } {
            0 => Ok(false),
            n if n > 0 => Ok(true),
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    Ok(true)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Reads what is there: `Ok(None)` at the end of input, `Ok(Some(0))`
    /// when a signal cut the read short.
    fn read(buf: &mut [u8]) -> io::Result<Option<usize>> {
        // SAFETY: `buf` is valid for `buf.len()` bytes.
        let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len()) };
        match usize::try_from(n) {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(n)),
            Err(_) => {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => Ok(Some(0)),
                    _ => Err(error),
                }
            }
        }
    }

    pub(super) fn edit(_raw: &RawMode, prompt: &str, initial: &str) -> io::Result<Option<String>> {
        let mut editor = Editor::new(initial);
        let mut out = io::stdout();
        let mut buf = [0u8; 256];
        let outcome = loop {
            write!(out, "{}", editor.render(prompt, columns()))?;
            out.flush()?;
            let timeout = if editor.is_pending() { ESC_WAIT_MS } else { -1 };
            if !wait(timeout)? {
                match editor.idle() {
                    Some(outcome) => break outcome,
                    None => continue,
                }
            }
            match read(&mut buf)? {
                None => break Outcome::Cancel,
                Some(n) => {
                    if let Some(outcome) = editor.feed(&buf[..n]) {
                        break outcome;
                    }
                }
            }
        };
        write!(out, "{}\r\n", editor.render(prompt, columns()))?;
        out.flush()?;
        Ok(match outcome {
            Outcome::Accept(text) => Some(text),
            Outcome::Cancel => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(initial: &str, keys: &[u8]) -> (Editor, Option<Outcome>) {
        let mut editor = Editor::new(initial);
        let outcome = editor.feed(keys);
        (editor, outcome)
    }

    #[test]
    fn starts_filled_in_with_the_cursor_at_the_end() {
        let editor = Editor::new("/Users/j/Desktop");
        assert_eq!(editor.text(), "/Users/j/Desktop");
        assert_eq!(editor.cursor(), 16);
        assert!(!editor.is_pending());
    }

    #[test]
    fn enter_accepts_and_typing_inserts_at_the_cursor() {
        let (_, outcome) = typed("/a", b"\r");
        assert_eq!(outcome, Some(Outcome::Accept("/a".into())));
        let (_, outcome) = typed("/a", b"/b\n");
        assert_eq!(outcome, Some(Outcome::Accept("/a/b".into())));
        // Left twice, then type: the text goes in the middle.
        let (editor, outcome) = typed("/ab", b"\x1b[D\x1b[Dx");
        assert_eq!(
            (editor.text(), editor.cursor(), outcome),
            ("/xab".into(), 2, None)
        );
        // Bytes after Enter are not used.
        let (editor, outcome) = typed("", b"a\rb");
        assert_eq!(outcome, Some(Outcome::Accept("a".into())));
        assert_eq!(editor.text(), "a");
    }

    #[test]
    fn utf8_is_one_character_even_when_split_across_reads() {
        let mut editor = Editor::new("/caf");
        let bytes = "é/日本🐱".as_bytes();
        for byte in bytes {
            assert_eq!(editor.feed(&[*byte]), None);
        }
        assert_eq!(editor.text(), "/café/日本🐱");
        assert_eq!(editor.cursor(), 9);
        editor.feed(b"\x7f\x7f");
        assert_eq!(editor.text(), "/café/日");
        // A cut-short character is dropped, the next byte still counts.
        editor.feed(&[0xe6, 0x97, b'x']);
        assert_eq!(editor.text(), "/café/日x");
        // A stray continuation byte or an invalid lead byte is ignored.
        editor.feed(&[0x97, 0xff, b'y']);
        assert_eq!(editor.text(), "/café/日xy");
    }

    #[test]
    fn arrows_home_and_end_move_within_the_text() {
        let mut editor = Editor::new("abc");
        for (keys, cursor) in [
            (&b"\x1b[D"[..], 2),
            (b"\x1bOD", 1),
            (b"\x1b[D\x1b[D\x1b[D", 0),
            (b"\x1b[C", 1),
            (b"\x1bOC", 2),
            (b"\x1b[C\x1b[C\x1b[C", 3),
            (b"\x1b[H", 0),
            (b"\x1b[F", 3),
            (b"\x1b[1~", 0),
            (b"\x1b[4~", 3),
            (b"\x1b[7~", 0),
            (b"\x1b[8~", 3),
            (b"\x1bOH", 0),
            (b"\x1bOF", 3),
            (b"\x01", 0),
            (b"\x05", 3),
            (b"\x02", 2),
            (b"\x06", 3),
            (b"\x1b[1;5D", 2),
            // Up and down change nothing.
            (b"\x1b[A\x1b[B", 2),
        ] {
            assert_eq!(editor.feed(keys), None, "{keys:?}");
            assert_eq!(editor.cursor(), cursor, "{keys:?}");
        }
        assert_eq!(editor.text(), "abc");
    }

    #[test]
    fn backspace_and_delete_stop_at_the_edges() {
        let mut editor = Editor::new("ab");
        editor.feed(b"\x1b[3~");
        assert_eq!(
            (editor.text(), editor.cursor()),
            ("ab".into(), 2),
            "delete at the end"
        );
        editor.feed(b"\x7f");
        assert_eq!(editor.text(), "a");
        editor.feed(b"\x08\x7f\x7f");
        assert_eq!((editor.text(), editor.cursor()), (String::new(), 0));
        let mut editor = Editor::new("abc");
        editor.feed(b"\x01\x7f");
        assert_eq!(
            (editor.text(), editor.cursor()),
            ("abc".into(), 0),
            "backspace at the start"
        );
        editor.feed(b"\x1b[3~");
        assert_eq!((editor.text(), editor.cursor()), ("bc".into(), 0));
        // Ctrl-D deletes under the cursor while there is text.
        assert_eq!(editor.feed(b"\x04"), None);
        assert_eq!(editor.text(), "c");
    }

    #[test]
    fn ctrl_u_k_and_w_clear_parts_of_the_line() {
        let (editor, _) = typed("/Users/j/Desktop", b"\x17");
        assert_eq!(editor.text(), "/Users/j/");
        let (editor, _) = typed("/Users/j/Desktop", b"\x17\x17");
        assert_eq!(editor.text(), "/Users/");
        let (editor, _) = typed("my folder", b"\x17");
        assert_eq!(editor.text(), "my ");
        let (editor, _) = typed("", b"\x17");
        assert_eq!(editor.text(), "");
        // Ctrl-U clears up to the cursor, Ctrl-K from it.
        let (editor, _) = typed("/a/b/c", b"\x1b[D\x1b[D\x15");
        assert_eq!((editor.text(), editor.cursor()), ("/c".into(), 0));
        let (editor, _) = typed("/a/b/c", b"\x1b[D\x1b[D\x0b");
        assert_eq!((editor.text(), editor.cursor()), ("/a/b".into(), 4));
    }

    #[test]
    fn esc_ctrl_c_and_ctrl_d_on_an_empty_line_cancel() {
        assert_eq!(typed("/a", b"\x03").1, Some(Outcome::Cancel));
        assert_eq!(typed("", b"\x04").1, Some(Outcome::Cancel));
        assert_eq!(typed("/a", b"\x15\x04").1, Some(Outcome::Cancel));
        assert_eq!(typed("/a", b"\x1b\x1b").1, Some(Outcome::Cancel));
        // A lone Esc waits: it may be the start of a key's sequence.
        let mut editor = Editor::new("/a");
        assert_eq!(editor.feed(b"\x1b"), None);
        assert!(editor.is_pending());
        assert_eq!(editor.idle(), Some(Outcome::Cancel));
        // Nothing pending: waiting changes nothing.
        let mut editor = Editor::new("/a");
        assert_eq!(editor.idle(), None);
    }

    #[test]
    fn escape_sequences_split_across_reads_are_keys_not_text() {
        let mut editor = Editor::new("abc");
        for chunk in [&b"\x1b"[..], b"[", b"D"] {
            assert_eq!(editor.feed(chunk), None);
        }
        assert_eq!((editor.text(), editor.cursor()), ("abc".into(), 2));
        for chunk in [&b"\x1b["[..], b"3", b"~"] {
            assert_eq!(editor.feed(chunk), None);
        }
        assert_eq!((editor.text(), editor.cursor()), ("ab".into(), 2));
        assert!(!editor.is_pending());
        // A pasted block's markers are dropped; its text goes in.
        editor.feed(b"\x1b[200~/x\x1b[201~");
        assert_eq!(editor.text(), "ab/x");
        // Alt and a key, and unknown sequences, change nothing.
        editor.feed(b"\x1bb\x1b[99X\x1b[15~");
        assert_eq!(editor.text(), "ab/x");
        // Tabs and other control bytes are not typed in.
        editor.feed(b"\t\x00\x07");
        assert_eq!(editor.text(), "ab/x");
        // A runaway sequence is given up, typing works again after it.
        editor.feed(b"\x1b[");
        editor.feed(&[b'1'; 40]);
        editor.feed(b"z");
        assert!(editor.text().ends_with('z'), "{}", editor.text());
    }

    #[test]
    fn render_keeps_the_cursor_in_view_on_a_narrow_terminal() {
        let editor = Editor::new("/a/b");
        assert_eq!(editor.render("Folder: ", 80), "\rFolder: /a/b\x1b[K");
        let mut editor = Editor::new("/a/b");
        editor.feed(b"\x1b[D\x1b[D");
        assert_eq!(editor.render("Folder: ", 80), "\rFolder: /a/b\x1b[K\x1b[2D");
        // 20 columns leave 11 for the text: the end of a long path shows.
        let editor = Editor::new("/0123456789abcdef");
        let line = editor.render("Folder: ", 20);
        assert_eq!(line, "\rFolder: 6789abcdef\x1b[K");
        let mut editor = Editor::new("/0123456789abcdef");
        editor.feed(b"\x01");
        assert_eq!(
            editor.render("Folder: ", 20),
            "\rFolder: /0123456789\x1b[K\x1b[11D"
        );
        // Control characters never reach the terminal.
        let editor = Editor::new("/a\x1b]0;x\x07");
        assert!(!editor.render("F: ", 80).contains('\x07'));
    }

    #[test]
    fn render_counts_wide_characters_as_two_columns() {
        // Left once from the end: the cursor goes back over 本, two columns.
        let mut editor = Editor::new("/日本");
        editor.feed(b"\x1b[D");
        assert_eq!(
            editor.render("Folder: ", 80),
            "\rFolder: /日本\x1b[K\x1b[2D"
        );
        // 20 columns leave 11 for the text: five wide characters and the
        // cursor fit, never more, so the line does not wrap.
        let editor = Editor::new("/日本語日本語日本語");
        assert_eq!(editor.render("Folder: ", 20), "\rFolder: 本語日本語\x1b[K");
        let mut editor = Editor::new("/日本語日本語日本語");
        editor.feed(b"\x01");
        let line = editor.render("Folder: ", 20);
        assert_eq!(line, "\rFolder: /日本語日本\x1b[K\x1b[11D");
        // An emoji, and a mark that joins the character before it.
        let mut editor = Editor::new("/🐱e\u{301}x");
        editor.feed(b"\x1b[D\x1b[D\x1b[D");
        assert_eq!(editor.render("F: ", 80), "\rF: /🐱e\u{301}x\x1b[K\x1b[2D");
    }

    /// A terminal of its own for the test: the far end of a new PTY.
    #[cfg(unix)]
    fn test_terminal() -> (libc::c_int, libc::c_int) {
        // SAFETY: plain calls on descriptors this test opens and owns.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "{}", io::Error::last_os_error());
            assert_eq!(libc::grantpt(master), 0);
            assert_eq!(libc::unlockpt(master), 0);
            let name = std::ffi::CStr::from_ptr(libc::ptsname(master)).to_owned();
            let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            assert!(slave >= 0, "{}", io::Error::last_os_error());
            (master, slave)
        }
    }

    /// The terminal's local modes, without PENDIN and FLUSHO: those are
    /// state the kernel keeps, not settings. macOS (like every BSD) sets
    /// PENDIN by itself when a terminal goes back to line mode, so pending
    /// input is typed again.
    #[cfg(unix)]
    fn local_flags(fd: libc::c_int) -> libc::tcflag_t {
        // SAFETY: `termios` is plain C data that `tcgetattr` fills.
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(fd, &mut termios), 0);
            termios.c_lflag & !(libc::PENDIN | libc::FLUSHO)
        }
    }

    #[cfg(unix)]
    fn handler_of(signal: libc::c_int) -> libc::sighandler_t {
        // SAFETY: only reads the current action.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut action), 0);
            action.sa_sigaction
        }
    }

    #[cfg(unix)]
    #[test]
    fn raw_mode_comes_back_off_on_drop_and_before_a_signal_ends_meow() {
        let (master, slave) = test_terminal();
        let cooked = local_flags(slave);
        assert_ne!(cooked & libc::ICANON, 0);
        let before = handler_of(libc::SIGTERM);

        let raw = unix::RawMode::enter_on(slave).unwrap();
        assert_eq!(
            local_flags(slave) & (libc::ICANON | libc::ECHO | libc::ISIG),
            0
        );
        assert!(unix::RawMode::enter_on(slave).is_none(), "one at a time");
        if before == libc::SIG_DFL {
            assert_ne!(handler_of(libc::SIGTERM), libc::SIG_DFL);
        }
        // What the handler does first when SIGTERM, SIGHUP, SIGQUIT or
        // SIGINT comes: the terminal as it was.
        unix::put_back_saved();
        assert_eq!(local_flags(slave), cooked);

        drop(raw);
        assert_eq!(local_flags(slave), cooked);
        assert_eq!(handler_of(libc::SIGTERM), before);
        // Disarmed: nothing is put back any more.
        unix::put_back_saved();
        // SAFETY: closes the descriptors `test_terminal` opened.
        unsafe {
            libc::close(slave);
            libc::close(master);
        }
    }
}
