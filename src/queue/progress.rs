//! How far a running tool is, read from the file it is still writing.
//!
//! nmap is told to write a `taskprogress` element every few seconds; only
//! the end of its file is read for it. katana and feroxbuster write one
//! result per line, and the new lines are counted. The file is unfinished
//! and part of it is what a scanned server sent, so nothing here trusts it:
//! reads are bounded, numbers are clamped and text is cleaned.

use std::io::{Read, Seek, SeekFrom};

use super::*;

/// What a tool's output file is, for telling how far the tool is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    /// nmap's XML, with a `taskprogress` element every few seconds.
    NmapXml,
    /// One result per line (katana, feroxbuster).
    JsonLines,
    /// Nothing that says how far the tool is.
    Other,
}

/// How much of the end of nmap's file is looked at.
const TAIL_BYTES: u64 = 8 * 1024;
/// The longest element that is read.
const MAX_ELEMENT_BYTES: usize = 1024;
/// The most new bytes whose lines are counted in one look.
const COUNT_BYTES: u64 = 256 * 1024;

/// The last complete `<name .../>` in `text`: where it starts and the text
/// of its attributes. One that is cut off, too long or not closed before
/// the next element begins is passed over.
fn last_element<'a>(text: &'a str, name: &str) -> Option<(usize, &'a str)> {
    let open = format!("<{name}");
    let mut end = text.len();
    while let Some(at) = text[..end].rfind(&open) {
        end = at;
        let rest = &text[at + open.len()..];
        if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let window = &rest.as_bytes()[..rest.len().min(MAX_ELEMENT_BYTES)];
        let Some(close) = window.windows(2).position(|pair| pair == b"/>") else {
            continue;
        };
        // `close` is where an ASCII character starts, so the cut is clean.
        let attributes = &rest[..close];
        if !attributes.contains('<') {
            return Some((at, attributes));
        }
    }
    None
}

/// The value of attribute `name` in the text between an element's name and
/// its end.
fn attribute<'a>(attributes: &'a str, name: &str) -> Option<&'a str> {
    let mut rest = attributes;
    loop {
        let (key, after) = rest.trim_start().split_once('=')?;
        let quote = after.chars().next().filter(|c| matches!(c, '"' | '\''))?;
        let (value, tail) = after[1..].split_once(quote)?;
        if key.trim_end() == name {
            return Some(value);
        }
        rest = tail;
    }
}

/// `12.34` -> 12, and nothing for what is not a plain number.
fn whole_percent(text: &str) -> Option<u8> {
    let whole = text.split('.').next()?;
    if whole.is_empty() || whole.len() > 3 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    whole.parse::<u16>().ok().map(|n| n.min(100) as u8)
}

fn whole_seconds(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 12 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// What the end of nmap's unfinished XML says about the scan it is on: the
/// last complete `taskprogress` (percent, seconds left, the scan's name),
/// or only the name once a `taskbegin` after it started the next scan.
pub(super) fn nmap_progress(tail: &[u8]) -> Option<Progress> {
    let text = String::from_utf8_lossy(tail);
    let named = |attributes: &str| attribute(attributes, "task").map(unescape);
    let last = last_element(&text, "taskprogress");
    let begun = last_element(&text, "taskbegin");
    let progress = match (last, begun) {
        (Some((at, attributes)), begun) if begun.is_none_or(|(next, _)| next < at) => Progress {
            percent: attribute(attributes, "percent").and_then(whole_percent),
            eta_s: attribute(attributes, "remaining").and_then(whole_seconds),
            note: named(attributes),
            ..Progress::default()
        },
        (_, Some((_, attributes))) => Progress {
            note: named(attributes),
            ..Progress::default()
        },
        _ => return None,
    }
    .checked();
    (progress != Progress::default()).then_some(progress)
}

/// Counts the results in a JSON Lines file as it grows.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct LineCounter {
    /// How much of the file has been counted.
    offset: u64,
    lines: u64,
    /// The line being read has something on it.
    in_line: bool,
}

impl LineCounter {
    /// Takes the next piece of the file. A line counts once it has ended;
    /// an empty one is not a result.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            match byte {
                b'\n' => {
                    self.lines += u64::from(self.in_line);
                    self.in_line = false;
                }
                byte if byte.is_ascii_whitespace() => {}
                _ => self.in_line = true,
            }
        }
        self.offset += bytes.len() as u64;
    }

    pub fn lines(&self) -> u64 {
        self.lines
    }
}

/// At most `len` bytes of the regular file at `path`, from `from` on.
fn read_piece(path: &Path, from: u64, len: u64) -> Option<Vec<u8>> {
    let (mut file, _) = parsers::open_regular_file(path).ok()?;
    file.seek(SeekFrom::Start(from)).ok()?;
    let mut piece = Vec::new();
    file.take(len).read_to_end(&mut piece).ok()?;
    Some(piece)
}

/// Follows one tool's output file while the tool runs.
#[derive(Debug)]
pub(super) struct OutputWatch {
    kind: OutputKind,
    /// The size the file had at the last look.
    size: u64,
    lines: LineCounter,
    last: Option<Progress>,
}

impl OutputWatch {
    pub fn new(kind: OutputKind) -> Self {
        Self {
            kind,
            size: 0,
            lines: LineCounter::default(),
            last: None,
        }
    }

    /// Looks at the file, now `size` bytes long, and returns what it says
    /// if that is news. The work is bounded whatever the file holds: the
    /// end of it for nmap, the next piece of it for lines.
    pub fn look(&mut self, path: &Path, size: u64) -> Option<Progress> {
        let now = match self.kind {
            OutputKind::Other => return None,
            OutputKind::NmapXml => {
                if size == self.size {
                    return None;
                }
                self.size = size;
                let tail = read_piece(path, size.saturating_sub(TAIL_BYTES), TAIL_BYTES)?;
                nmap_progress(&tail)?
            }
            OutputKind::JsonLines => {
                if size < self.lines.offset {
                    // The tool started its file over.
                    self.lines = LineCounter::default();
                }
                if size == self.lines.offset {
                    return None;
                }
                let new = (size - self.lines.offset).min(COUNT_BYTES);
                let piece = read_piece(path, self.lines.offset, new)?;
                self.lines.feed(&piece);
                Progress {
                    done: Some(self.lines.lines()),
                    ..Progress::default()
                }
            }
        };
        if self.last.as_ref() == Some(&now) {
            return None;
        }
        self.last = Some(now.clone());
        Some(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS --stats-every 5s -oX out.xml 192.0.2.5" start="1700000000">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
<taskbegin task="SYN Stealth Scan" time="1700000001"/>
<taskprogress task="SYN Stealth Scan" time="1700000006" percent="12.34" remaining="56" etc="1700000062"/>
<taskprogress task="SYN Stealth Scan" time="1700000011" percent="48.90" remaining="21" etc="1700000032"/>
"#;

    fn progress(percent: Option<u8>, eta_s: Option<u64>, note: &str) -> Progress {
        Progress {
            percent,
            eta_s,
            note: (!note.is_empty()).then(|| note.to_owned()),
            ..Progress::default()
        }
    }

    #[test]
    fn the_last_complete_taskprogress_is_what_nmap_is_doing() {
        assert_eq!(
            nmap_progress(RUNNING.as_bytes()),
            Some(progress(Some(48), Some(21), "SYN Stealth Scan"))
        );
        // Whole numbers, single quotes, attributes in any order, entities.
        let other = "<taskprogress remaining='7' percent='100' task='Service scan &amp; more'/>";
        assert_eq!(
            nmap_progress(other.as_bytes()),
            Some(progress(Some(100), Some(7), "Service scan & more"))
        );
        // The next scan began: its name, and no number of the one before.
        let next = format!("{RUNNING}<taskend task=\"SYN Stealth Scan\" time=\"1700000030\"/>\n<taskbegin task=\"Service scan\" time=\"1700000030\"/>\n");
        assert_eq!(
            nmap_progress(next.as_bytes()),
            Some(progress(None, None, "Service scan"))
        );
        // And its first report takes over again.
        let later = format!(
            "{next}<taskprogress task=\"Service scan\" time=\"1\" percent=\"3.00\" remaining=\"90\"/>\n"
        );
        assert_eq!(
            nmap_progress(later.as_bytes()),
            Some(progress(Some(3), Some(90), "Service scan"))
        );
        // Nothing to say before the first task, or in other XML.
        for silent in [
            "",
            "<nmaprun>",
            "<host><status state=\"up\"/></host>",
            "taskprogress percent=\"50\"",
        ] {
            assert_eq!(nmap_progress(silent.as_bytes()), None, "{silent:?}");
        }
    }

    #[test]
    fn an_element_still_being_written_is_passed_over() {
        // Cut at every length: never a panic, and never a number from an
        // element that is not all there.
        let complete = [
            None,
            Some(progress(None, None, "SYN Stealth Scan")),
            Some(progress(Some(12), Some(56), "SYN Stealth Scan")),
            Some(progress(Some(48), Some(21), "SYN Stealth Scan")),
        ];
        let mut seen = Vec::new();
        for cut in 0..=RUNNING.len() {
            let now = nmap_progress(&RUNNING.as_bytes()[..cut]);
            assert!(complete.contains(&now), "cut at {cut}: {now:?}");
            if seen.last() != Some(&now) {
                seen.push(now);
            }
        }
        assert_eq!(seen, complete);

        // The file is read from somewhere in its middle, even inside a
        // character: what is whole after that still counts.
        let middle = format!("é{RUNNING}");
        assert_eq!(
            nmap_progress(&middle.as_bytes()[1..]),
            Some(progress(Some(48), Some(21), "SYN Stealth Scan"))
        );
        let cut_front = &RUNNING.as_bytes()[RUNNING.find("gress task").unwrap()..];
        assert_eq!(
            nmap_progress(cut_front),
            Some(progress(Some(48), Some(21), "SYN Stealth Scan"))
        );
    }

    #[test]
    fn hostile_progress_is_clamped_cleaned_or_left_out() {
        let of =
            |attributes: &str| nmap_progress(format!("<taskprogress {attributes}/>").as_bytes());
        // Numbers out of range are clamped; a week is the longest wait.
        assert_eq!(
            of("task=\"x\" percent=\"250.9\" remaining=\"999999999999\""),
            Some(progress(Some(100), Some(7 * 24 * 3600), "x"))
        );
        // What is not a plain number is no number.
        for bad in [
            "-5", "+5", "1e3", "NaN", "", " 5", "5 ", "0x10", "٤٢", ".5", "5,5",
        ] {
            assert_eq!(
                of(&format!("task=\"x\" percent=\"{bad}\" remaining=\"{bad}\"")),
                Some(progress(None, None, "x")),
                "{bad:?}"
            );
        }
        assert_eq!(whole_percent("1234"), None);
        assert_eq!(whole_seconds("1234"), Some(1234));
        assert_eq!(whole_seconds("1234567890123"), None);

        // A name with terminal control sequences and hidden characters
        // comes out as plain text, at most 80 bytes of it.
        let name = format!("\u{1b}[31mSYN\u{202e} Scan\u{7}{}", "A".repeat(500));
        let shown = of(&format!("task=\"{name}\" percent=\"5\""))
            .unwrap()
            .note
            .unwrap();
        assert!(shown.starts_with("[31mSYN Scan"), "{shown:?}");
        assert_eq!(shown.len(), PROGRESS_NOTE_MAX);
        assert!(!shown.contains(|c: char| c.is_control()));
        // An entity cannot bring a control character back in.
        let escaped = of("task=\"a&#27;[2Jb&amp;#27;\" percent=\"5\"")
            .unwrap()
            .note
            .unwrap();
        assert_eq!(escaped, "a&#27;[2Jb&#27;");

        // No end, no attributes, a quote that never closes, another
        // element inside: nothing is made up.
        for broken in [
            "<taskprogress percent=\"50\"",
            "<taskprogress/>",
            "<taskprogress />",
            "<taskprogress percent=\"50 />",
            "<taskprogress percent=50 task=x />",
            "<taskprogress task=\"x\" <host/> percent=\"50\"/>",
            "<taskprogressx percent=\"50\" task=\"x\"/>",
            "< taskprogress percent=\"50\" task=\"x\"/>",
        ] {
            let now = nmap_progress(broken.as_bytes());
            assert!(
                now.as_ref().is_none_or(|p| p.percent.is_none()),
                "{broken:?}: {now:?}"
            );
        }
        // One that is whole before a broken one is still found.
        let mixed = "<taskprogress task=\"a\" percent=\"7\"/><taskprogress task=\"b\" percent=\"9";
        assert_eq!(
            nmap_progress(mixed.as_bytes()),
            Some(progress(Some(7), None, "a"))
        );
    }

    #[test]
    fn a_huge_element_or_file_costs_no_more_than_a_small_one() {
        // An element longer than any nmap writes is not read to its end.
        let long = format!(
            "<taskprogress task=\"{}\" percent=\"50\"/>",
            "A".repeat(MAX_ELEMENT_BYTES)
        );
        assert_eq!(nmap_progress(long.as_bytes()), None);
        // Megabytes of `<taskprogress` without an end, then a real one.
        let mut flood = "<taskprogress ".repeat(4096);
        flood.push_str("<taskprogress task=\"real\" percent=\"61.5\" remaining=\"3\"/>\n");
        assert_eq!(
            nmap_progress(flood.as_bytes()),
            Some(progress(Some(61), Some(3), "real"))
        );

        // From a file, only the end is read: 64 MB of holes before it
        // take no longer, and what lies before the end is not seen.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.xml");
        let mut file = std::fs::File::create(&path).unwrap();
        use std::io::Write;
        file.write_all(b"<taskprogress task=\"early\" percent=\"99\" remaining=\"1\"/>\n")
            .unwrap();
        file.seek(SeekFrom::Start(64 * 1024 * 1024)).unwrap();
        file.write_all(&vec![b' '; TAIL_BYTES as usize]).unwrap();
        drop(file);
        let size = std::fs::metadata(&path).unwrap().len();
        let mut watch = OutputWatch::new(OutputKind::NmapXml);
        let started = std::time::Instant::now();
        assert_eq!(watch.look(&path, size), None);
        assert!(started.elapsed() < Duration::from_secs(2));

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(RUNNING.as_bytes()).unwrap();
        drop(file);
        let size = std::fs::metadata(&path).unwrap().len();
        assert_eq!(
            watch.look(&path, size),
            Some(progress(Some(48), Some(21), "SYN Stealth Scan"))
        );
        // Unchanged: nothing is read and nothing is news.
        assert_eq!(watch.look(&path, size), None);
        // Something that is not a file is not read.
        assert_eq!(
            OutputWatch::new(OutputKind::NmapXml).look(dir.path(), 4096),
            None
        );
        assert_eq!(OutputWatch::new(OutputKind::Other).look(&path, size), None);
    }

    #[test]
    fn result_lines_are_counted_as_the_file_grows() {
        let mut counter = LineCounter::default();
        let pieces: [&[u8]; 4] = [
            b"{\"url\":\"a\"}\n{\"url\":",
            b"\"b\"}\n\n   \n\r\n{\"url\":\"c\"}\r\n{",
            b"}",
            b"\n",
        ];
        // The second line has not ended; empty lines are not results.
        for (piece, lines) in pieces.iter().zip([1, 3, 3, 4]) {
            counter.feed(piece);
            assert_eq!(counter.lines(), lines);
        }
        let fed: usize = pieces.iter().map(|piece| piece.len()).sum();
        assert_eq!(counter.offset, fed as u64);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.jsonl");
        let size = |path: &Path| std::fs::metadata(path).unwrap().len();
        let done = |lines: u64| {
            Some(Progress {
                done: Some(lines),
                ..Progress::default()
            })
        };
        let mut watch = OutputWatch::new(OutputKind::JsonLines);
        std::fs::write(&path, "").unwrap();
        assert_eq!(watch.look(&path, 0), None);
        std::fs::write(&path, "{\"url\":\"a\"}\n{\"url\":\"b\"}\n{\"ur").unwrap();
        assert_eq!(watch.look(&path, size(&path)), done(2));
        assert_eq!(watch.look(&path, size(&path)), None);
        // Only what is new is read: the first lines are not counted again.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"l\":\"c\"}\n").unwrap();
        assert_eq!(watch.look(&path, size(&path)), done(3));

        // A burst larger than one look takes is caught up with over the
        // next looks, each of them bounded.
        let line = format!("{{\"url\":\"{}\"}}\n", "x".repeat(1000));
        let burst = line.repeat(600);
        assert!(burst.len() as u64 > 2 * COUNT_BYTES);
        let before = size(&path);
        file.write_all(burst.as_bytes()).unwrap();
        drop(file);
        let total = size(&path);
        let first = watch.look(&path, total).unwrap().done.unwrap();
        assert!(first > 3 && first < 603, "{first}");
        assert_eq!(watch.lines.offset, before + COUNT_BYTES);
        let mut last = first;
        while let Some(more) = watch.look(&path, total) {
            last = more.done.unwrap();
        }
        assert_eq!(last, 603);

        // The tool started the file over: so does the count.
        std::fs::write(&path, "{\"url\":\"z\"}\n").unwrap();
        assert_eq!(watch.look(&path, size(&path)), done(1));
    }
}
