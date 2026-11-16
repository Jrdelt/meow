//! Safe wrapper around the C ECMA-48 tap filter (`src/c/tap_filter.c`).
//!
//! The filter turns raw PTY bytes into clean text lines for analysis. It is a
//! read-only tap: the PTY host writes raw bytes straight to `stdout` and hands
//! copies of each chunk to a [`TapFilter`] on a worker thread.

/// Counters kept by the filter since creation.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TapStats {
    pub lines_emitted: u64,
    /// Lines dropped as binary / non-UTF-8.
    pub dropped_binary: u64,
    /// Password / passphrase prompts suppressed.
    pub dropped_secret: u64,
    /// Lines lost because the output buffer was full (never happens through
    /// this wrapper, which always sizes the buffer for the worst case).
    pub dropped_nospace: u64,
}

mod ffi {
    use super::TapStats;

    /// Opaque `tap_state_t`; only ever handled behind a pointer.
    #[repr(C)]
    pub struct TapState {
        _opaque: [u8; 0],
    }

    extern "C" {
        pub fn tap_state_size() -> usize;
        pub fn tap_state_align() -> usize;
        pub fn tap_line_max() -> usize;
        pub fn tap_init(st: *mut TapState);
        pub fn tap_feed(
            st: *mut TapState,
            input: *const u8,
            in_len: usize,
            out: *mut u8,
            out_cap: usize,
        ) -> usize;
        pub fn tap_flush(st: *mut TapState, out: *mut u8, out_cap: usize) -> usize;
        pub fn tap_get_stats(st: *const TapState, out: *mut TapStats);
        pub fn tap_in_alt_screen(st: *const TapState) -> i32;
    }
}

/// Stateful stream filter. Feed it PTY chunks of any size, split anywhere.
pub struct TapFilter {
    /// Storage for the C `tap_state_t`, sized by the C side at runtime so the
    /// struct layout is never duplicated in Rust. `u64` gives 8-byte alignment.
    state: Box<[u64]>,
    out: Vec<u8>,
    line_max: usize,
}

impl TapFilter {
    pub fn new() -> Self {
        // SAFETY: these functions take no arguments and only return constants.
        let (size, align, line_max) = unsafe {
            (
                ffi::tap_state_size(),
                ffi::tap_state_align(),
                ffi::tap_line_max(),
            )
        };
        assert!(
            align <= std::mem::align_of::<u64>(),
            "tap_state_t needs {align}-byte alignment"
        );
        let words = size.div_ceil(std::mem::size_of::<u64>());
        let mut filter = Self {
            state: vec![0u64; words].into_boxed_slice(),
            out: Vec::new(),
            line_max,
        };
        // SAFETY: `state` is at least `tap_state_size()` bytes, suitably
        // aligned, and exclusively borrowed.
        unsafe { ffi::tap_init(filter.state_mut()) };
        filter
    }

    fn state_ptr(&self) -> *const ffi::TapState {
        self.state.as_ptr().cast()
    }

    fn state_mut(&mut self) -> *mut ffi::TapState {
        self.state.as_mut_ptr().cast()
    }

    /// Feeds one chunk and returns the clean lines it completed.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        // Every emitted line ends at an input '\n' (at most `line_max + 1`
        // bytes each), and each ConPTY `CSI <n> C` (`'C'` final byte) can
        // expand into up to 256 spaces. Bound by the tighter of the two so
        // `dropped_nospace` remains impossible without over-allocating.
        let newlines = chunk.iter().filter(|&&b| b == b'\n').count();
        let cuf_extra = chunk
            .iter()
            .filter(|&&b| b == b'C')
            .count()
            .saturating_mul(256);
        let line_cap = self.line_max.saturating_add(1);
        let by_expansion = chunk
            .len()
            .saturating_add(cuf_extra)
            .saturating_add(line_cap);
        let by_newlines = newlines.saturating_mul(line_cap);
        let needed = by_expansion.min(by_newlines).max(1);
        self.out.resize(needed, 0);
        let state = self.state_mut();
        // SAFETY: `state` was initialised by `tap_init`; `chunk` and `out`
        // are valid for the lengths passed and do not overlap.
        let written = unsafe {
            ffi::tap_feed(
                state,
                chunk.as_ptr(),
                chunk.len(),
                self.out.as_mut_ptr(),
                self.out.len(),
            )
        };
        split_lines(&self.out[..written])
    }

    /// Emits the buffered partial line, if any. Call at end of stream.
    pub fn flush(&mut self) -> Option<String> {
        self.out.resize(self.line_max + 1, 0);
        let state = self.state_mut();
        // SAFETY: as in `feed`.
        let written = unsafe { ffi::tap_flush(state, self.out.as_mut_ptr(), self.out.len()) };
        split_lines(&self.out[..written]).pop()
    }

    pub fn stats(&self) -> TapStats {
        let mut stats = TapStats::default();
        // SAFETY: both pointers are valid; `TapStats` mirrors `tap_stats_t`.
        unsafe { ffi::tap_get_stats(self.state_ptr(), &mut stats) };
        stats
    }

    /// True while a full-screen application (vim, less, htop) owns the
    /// alternate screen and scraping is paused.
    pub fn in_alt_screen(&self) -> bool {
        // SAFETY: the state pointer is valid and initialised.
        unsafe { ffi::tap_in_alt_screen(self.state_ptr()) != 0 }
    }
}

impl Default for TapFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn split_lines(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(chunks: &[&[u8]]) -> Vec<String> {
        let mut filter = TapFilter::new();
        let mut lines = Vec::new();
        for chunk in chunks {
            lines.extend(filter.feed(chunk));
        }
        lines
    }

    fn feed_bytewise(input: &[u8]) -> Vec<String> {
        let mut filter = TapFilter::new();
        let mut lines = Vec::new();
        for byte in input {
            lines.extend(filter.feed(std::slice::from_ref(byte)));
        }
        lines
    }

    #[test]
    fn state_storage_matches_c_layout() {
        let filter = TapFilter::new();
        let size = unsafe { ffi::tap_state_size() };
        assert!(filter.state.len() * 8 >= size);
        assert!(size > filter.line_max);
        assert_eq!(filter.line_max, 4096);
        assert_eq!(std::mem::size_of::<TapStats>(), 32);
    }

    #[test]
    fn plain_crlf_lines() {
        let lines = feed_all(&[b"alpha\r\nbeta\r\n\r\ngamma\n"]);
        assert_eq!(lines, ["alpha", "beta", "gamma"]);
    }

    #[test]
    fn sgr_colors_are_stripped() {
        let lines = feed_all(&[b"\x1b[1;31mred\x1b[0m and \x1b[38;5;82mgreen\x1b[m\r\n"]);
        assert_eq!(lines, ["red and green"]);
    }

    #[test]
    fn csi_split_across_chunks() {
        let lines = feed_all(&[b"ab\x1b", b"[3", b"8;5;", b"196mcd\x1b[", b"0m\r", b"\n"]);
        assert_eq!(lines, ["abcd"]);
    }

    #[test]
    fn bytewise_feed_matches_single_chunk() {
        let input: &[u8] = b"\x1b]0;user@box: ~\x07\x1b[?2004h$ ls\r\n\
            \x1b[01;34mdir\x1b[0m  caf\xc3\xa9.txt  \xe2\x9c\x93\r\n\
            10%\r55%\r100%\r\n\x1b(B\x1b[?1049hTUI\r\njunk\x1b[?1049l\
            done \xf0\x9f\x90\xb1\r\n";
        let whole = feed_all(&[input]);
        assert_eq!(whole, ["$ ls", "dir  café.txt  ✓", "100%", "done 🐱"]);
        assert_eq!(feed_bytewise(input), whole);
    }

    #[test]
    fn utf8_split_at_every_boundary() {
        let input = "héllo ✓ 🐱 end\n".as_bytes();
        for cut in 0..=input.len() {
            let (a, b) = input.split_at(cut);
            assert_eq!(feed_all(&[a, b]), ["héllo ✓ 🐱 end"], "cut at {cut}");
        }
    }

    #[test]
    fn bare_cr_rewinds_spinner_lines() {
        let lines = feed_all(&[b"start\r\n 10%\r 50%\r", b"100%\r\nnext\r\n"]);
        assert_eq!(lines, ["start", "100%", "next"]);
    }

    #[test]
    fn cr_split_from_lf_is_still_a_newline() {
        assert_eq!(feed_all(&[b"one\r", b"\ntwo\r\r\n"]), ["one", "two"]);
    }

    #[test]
    fn cr_then_erase_sequence_then_text_rewinds() {
        let lines = feed_all(&[
            b"Compiling a\r\x1b[KCompiling b\r\x1b[KFinished\r\n",
            b"Cleared\r\x1b[K\r\n",
        ]);
        assert_eq!(lines, ["Finished"]);
    }

    #[test]
    fn erase_line_and_column_one_rewind() {
        let lines = feed_all(&[b"spin |\x1b[2K\x1b[1Gspin /\x1b[2K\x1b[Gdone\n"]);
        assert_eq!(lines, ["done"]);
    }

    #[test]
    fn backspace_removes_whole_characters() {
        let lines = feed_all(&["ab✓\x08\x08c\n|\x08/\x08-\n".as_bytes()]);
        assert_eq!(lines, ["ac", "-"]);
    }

    #[test]
    fn alternate_screen_pauses_scraping() {
        let mut filter = TapFilter::new();
        assert_eq!(filter.feed(b"before\r\n$ vim x\r\n"), ["before", "$ vim x"]);
        assert!(filter.feed(b"\x1b[?10").is_empty());
        assert!(!filter.in_alt_screen());
        assert!(filter
            .feed(b"49h~\r\n~ \x1b[7mINSERT\x1b[0m\r\n")
            .is_empty());
        assert!(filter.in_alt_screen());
        assert!(filter
            .feed(b"[sudo] password for x: \r\nmore\r\n")
            .is_empty());
        assert!(filter.feed(b"tail\x1b[?1049").is_empty());
        assert_eq!(filter.feed(b"lafter\r\n"), ["after"]);
        assert!(!filter.in_alt_screen());
        assert_eq!(filter.stats().lines_emitted, 3);
        assert_eq!(filter.stats().dropped_secret, 0);
    }

    #[test]
    fn alternate_screen_legacy_modes_and_combined_params() {
        let mut filter = TapFilter::new();
        filter.feed(b"\x1b[?47h");
        assert!(filter.in_alt_screen());
        filter.feed(b"\x1b[?47l");
        assert!(!filter.in_alt_screen());
        filter.feed(b"\x1b[?1;1049h");
        assert!(filter.in_alt_screen());
        // Non-private CSI 1049 l is not DECRST and must not leave.
        filter.feed(b"\x1b[1049l");
        assert!(filter.in_alt_screen());
        // RIS (ESC c) returns to the main screen.
        filter.feed(b"\x1bc");
        assert!(!filter.in_alt_screen());
    }

    #[test]
    fn osc_and_dcs_strings_are_dropped() {
        let lines = feed_all(&[
            b"\x1b]0;window title\x07a",
            b"\x1b]8;;http://x/\x1b",
            b"\\link\x1b]8;;\x1b\\",
            b"\x1bPq#0;2;0;0;0\x1b\\b\r\n",
        ]);
        assert_eq!(lines, ["alinkb"]);
    }

    #[test]
    fn charset_and_two_byte_escapes_are_dropped() {
        assert_eq!(feed_all(&[b"\x1b(Bx\x1b=y\x1b7z\x1b8\n"]), ["xyz"]);
    }

    #[test]
    fn password_prompts_are_suppressed() {
        let mut filter = TapFilter::new();
        let lines = filter.feed(
            b"[sudo] password for bob: \r\n\
              [sudo] password for bob: secret123\r\n\
              Password for 'https://git.corp.local': token123\r\n\
              bob@10.0.0.5's Password:\r\n\
              Password: hunter2\r\n\
              Enter API key: sk-secret\r\n\
              Bearer token:\r\n\
              Token: ghp_secret\r\n\
              Enter passphrase for key '/home/bob/.ssh/id_ed25519': \r\n\
              Enter PEM pass phrase:\r\n\
              password policy: enabled\r\n\
              ok\r\n",
        );
        assert_eq!(lines, ["password policy: enabled", "ok"]);
        assert_eq!(filter.stats().dropped_secret, 10);
    }

    #[test]
    fn conpty_cursor_forward_preserves_word_spacing() {
        let lines = feed_all(&[b"80/tcp\x1b[3Copen\x1b[Cnginx\x1b[1C1.24.0\r\n"]);
        assert_eq!(lines, ["80/tcp   open nginx 1.24.0"]);
    }

    #[test]
    fn binary_bursts_are_dropped() {
        let mut filter = TapFilter::new();
        let mut input = b"text\n".to_vec();
        input.extend_from_slice(&[0x7f, b'E', b'L', b'F', 0x00, 0x01, 0xff, 0xfe, 0x80, 0x02]);
        input.extend_from_slice(b"\nclean\n");
        let mut wrap = vec![0x00; 256];
        wrap.extend_from_slice(b"after256nuls\n");
        input.extend_from_slice(&wrap);
        assert_eq!(filter.feed(&input), ["text", "clean"]);
        assert_eq!(filter.stats().dropped_binary, 2);
    }

    #[test]
    fn stray_invalid_bytes_are_removed_from_text() {
        // Lone 0xff, overlong 0xc0 0xaf, and a truncated 3-byte sequence.
        assert_eq!(feed_all(&[b"a\xffb\n"]), ["ab"]);
        assert_eq!(feed_all(&[b"a\xe2\x9cb\n"]), ["ab"]);
        assert_eq!(feed_all(&[b"\xed\xa0\x80ok\n"]), ["ok"]);
    }

    #[test]
    fn long_lines_truncate_on_a_character_boundary() {
        let mut input = vec![b'a'; 4095];
        input.extend_from_slice("éééé tail\n".as_bytes());
        input.extend_from_slice(b"short\n");
        let lines = feed_all(&[&input]);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), 4095);
        assert!(lines[0].bytes().all(|b| b == b'a'));
        assert_eq!(lines[1], "short");
    }

    #[test]
    fn flush_emits_the_partial_line() {
        let mut filter = TapFilter::new();
        assert_eq!(filter.feed(b"done\r\n$ partial"), ["done"]);
        assert_eq!(filter.flush().as_deref(), Some("$ partial"));
        assert_eq!(filter.flush(), None);
    }

    #[test]
    fn unterminated_osc_does_not_swallow_the_stream() {
        let mut filter = TapFilter::new();
        filter.feed(b"\x1b]0;never closed");
        filter.feed(&vec![b'x'; 70_000]);
        // Past TAP_STRING_MAX the string is abandoned and text flows again.
        let lines = filter.feed(b"\nvisible\n");
        assert_eq!(lines.last().map(String::as_str), Some("visible"));
    }

    #[test]
    fn multi_colon_and_indented_secret_prompts_redact_echoed_secrets() {
        let mut filter = TapFilter::new();
        let lines = filter.feed(
            b"bob@fe80::1's password: hunter2\r\n\
              https://bob@git.corp.local:8443's password: s3cr3t\r\n\
              [12:34:56] Enter API key: sk-live-secret\r\n\
              mysql [127.0.0.1:3306] Enter password: dbsecret\r\n\
                Password: indented-secret\r\n\
              \tToken: ghp_indented\r\n\
              Client secret: oauth-secret\r\n\
              token count: 42\r\n\
              80/tcp open http\r\n",
        );
        assert_eq!(lines, ["token count: 42", "80/tcp open http"]);
        assert_eq!(filter.stats().dropped_secret, 7);
    }

    #[test]
    fn incomplete_csi_across_newline_and_truncated_backspaces_stay_contained() {
        let mut filter = TapFilter::new();
        let lines = filter.feed(b"first\x1b[?1049\nhost\n\x1b[31\n80/tcp open http\n");
        assert!(!filter.in_alt_screen());
        assert_eq!(lines, ["first", "host", "80/tcp open http"]);

        let mut overlong = vec![b'x'; 4096];
        overlong.extend_from_slice(b"overflow\x08\x08\x08\n");
        let truncated = filter.feed(&overlong);
        assert_eq!(truncated.len(), 1);
        assert_eq!(truncated[0].len(), 4096);
    }

    #[test]
    fn dense_conpty_cuf_burst_never_drops_for_nospace() {
        let mut filter = TapFilter::new();
        let burst = b"\x1b[256Cx\n".repeat(25);
        let lines = filter.feed(&burst);
        assert_eq!(lines.len(), 25);
        assert_eq!(filter.stats().dropped_nospace, 0);
    }
}
