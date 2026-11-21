//! Parsers that turn tool output into [`Observation`]s at zero AI cost.

pub mod diff;
pub mod jsonl;
pub mod nmap;
pub mod text;

use std::fmt;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::evidence::Source;
use crate::graph::Observation;

/// Largest file `meow add` (and a recon stage) will ingest.
pub const INGEST_CAP: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    NmapXml,
    Jsonl,
    GitDiff,
    Log,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::NmapXml => "Nmap XML",
            Format::Jsonl => "JSON Lines",
            Format::GitDiff => "git diff",
            Format::Log => "text log",
        })
    }
}

#[derive(Debug)]
pub struct Parsed {
    pub format: Format,
    pub observations: Vec<Observation>,
    /// Lines that held nothing usable (JSONL only).
    pub skipped: usize,
}

/// Guesses the format from the content, not the file name.
pub fn detect(text: &str) -> Format {
    let head: String = text.chars().take(2048).collect();
    let trimmed = head.trim_start();
    if trimmed.starts_with("<?xml")
        || trimmed.starts_with("<!DOCTYPE nmaprun")
        || head.contains("<nmaprun")
    {
        return Format::NmapXml;
    }
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if first.len() <= 64 * 1024
        && first.trim_start().starts_with('{')
        && serde_json::from_str::<serde::de::IgnoredAny>(first).is_ok()
    {
        return Format::Jsonl;
    }
    let diff_marks = text
        .lines()
        .take(200)
        .filter(|l| {
            l.starts_with("diff --git ")
                || l.starts_with("--- ")
                || l.starts_with("+++ ")
                || l.starts_with("@@ ")
        })
        .count();
    if first.starts_with("diff --git ") || diff_marks >= 2 {
        return Format::GitDiff;
    }
    Format::Log
}

pub fn parse_text(text: &str) -> Result<Parsed> {
    let format = detect(text);
    let (observations, skipped) = match format {
        // An imported file is not this session's scan: its names are claims.
        Format::NmapXml => (nmap::parse(text, false)?, 0),
        Format::Jsonl => jsonl::parse(text),
        Format::GitDiff => (diff::parse(text), 0),
        Format::Log => (text::TextParser::parse(Source::LogRegex, text), 0),
    };
    Ok(Parsed {
        format,
        observations,
        skipped,
    })
}

fn bytes_to_string_lossy(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|err| String::from_utf8_lossy(&err.into_bytes()).into_owned())
}

/// Opens `path` for reading if it is a regular file and no link: the file
/// and its size.
pub(crate) fn open_regular_file(path: &Path) -> Result<(std::fs::File, u64)> {
    crate::workspace::refuse_file_symlink(path)?;
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("cannot open {}", path.display()))?
    };
    #[cfg(not(unix))]
    let file = {
        let pre =
            std::fs::metadata(path).with_context(|| format!("cannot open {}", path.display()))?;
        if !pre.is_file() {
            bail!("{} is not a regular file", path.display());
        }
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?
    };
    let meta = file
        .metadata()
        .with_context(|| format!("cannot inspect {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok((file, meta.len()))
}

/// Reads at most [`INGEST_CAP`] bytes of `path` as (lossy) UTF-8, refusing
/// files that exceed the cap before or during the read.
pub fn read_capped(path: &Path) -> Result<String> {
    let (file, size) = open_regular_file(path)?;
    if size > INGEST_CAP {
        bail!(
            "{} is {} MB; the ingestion limit is {} MB",
            path.display(),
            size / (1024 * 1024),
            INGEST_CAP / (1024 * 1024)
        );
    }
    let mut bytes = Vec::new();
    file.take(INGEST_CAP + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() as u64 > INGEST_CAP {
        bail!(
            "{} grew past the {} MB ingestion limit while being read",
            path.display(),
            INGEST_CAP / (1024 * 1024)
        );
    }
    Ok(bytes_to_string_lossy(bytes))
}

pub fn parse_file(path: &Path) -> Result<Parsed> {
    let text = read_capped(path)?;
    parse_text(&text).with_context(|| format!("cannot parse {}", path.display()))
}

/// Reads up to [`INGEST_CAP`] bytes of a line-oriented tool output file as
/// (lossy) UTF-8, trimming an incomplete trailing line when the file exceeded
/// the cap.
pub fn read_prefix_capped(path: &Path) -> Result<String> {
    let (file, size) = open_regular_file(path)?;
    let mut bytes = Vec::new();
    file.take(INGEST_CAP + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let truncated = size > INGEST_CAP || bytes.len() as u64 > INGEST_CAP;
    if bytes.len() as u64 > INGEST_CAP {
        bytes.truncate(INGEST_CAP as usize);
    }
    if truncated {
        if let Some(last_nl) = bytes.iter().rposition(|&b| b == b'\n') {
            bytes.truncate(last_nl + 1);
        } else {
            bytes.clear();
        }
    }
    Ok(bytes_to_string_lossy(bytes))
}

/// Parses up to [`INGEST_CAP`] bytes of a line-oriented tool output file,
/// trimming an incomplete trailing line when the file exceeded the cap.
pub fn parse_file_prefix(path: &Path) -> Result<Parsed> {
    let text = read_prefix_capped(path)?;
    parse_text(&text).with_context(|| format!("cannot parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_are_detected_from_content() {
        assert_eq!(detect(nmap::SAMPLE), Format::NmapXml);
        assert_eq!(
            detect("\n  <nmaprun scanner=\"nmap\"></nmaprun>"),
            Format::NmapXml
        );
        assert_eq!(
            detect("{\"type\":\"response\",\"url\":\"http://x/\"}\n{}"),
            Format::Jsonl
        );
        assert_eq!(
            detect("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"),
            Format::GitDiff
        );
        assert_eq!(
            detect("--- a\n+++ b\n@@ -1 +1 @@\n-a\n+b\n"),
            Format::GitDiff
        );
        assert_eq!(
            detect("Nmap scan report for 10.0.0.5\n22/tcp open ssh\n"),
            Format::Log
        );
        assert_eq!(detect("{ not json\n"), Format::Log);
        assert_eq!(detect(""), Format::Log);
    }

    #[test]
    fn an_imported_scan_never_moves_a_name_or_takes_over_a_host_worked_on() {
        use crate::evidence::{Confidence, EvidenceRecord};
        use crate::graph::{Advisory, Graph, Observation};
        let mut graph = Graph::default();
        // The session's own scan named 192.0.2.10.
        let own = r#"<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="portal.example" type="user"/></hostnames></host></nmaprun>"#;
        graph.apply_all(nmap::parse(own, true).unwrap());
        // A name seen in the terminal, with the operator's note and a CVE.
        graph.apply(Observation::Note {
            address: Some("intranet.example".into()),
            text: "admin panel creds rotated, keep watching".into(),
            record: EvidenceRecord::observed(Source::ManualNote, Confidence::Medium, "note"),
        });
        graph.add_advisory(
            "intranet.example",
            Advisory {
                id: "CVE-2021-23017".into(),
                title: "t".into(),
                severity: None,
                cvss: None,
                kev: false,
                matched: "keywordSearch=nginx 1.18.0".into(),
                port: None,
                references: vec![],
                fixed_in: None,
                last_affected: None,
                record: EvidenceRecord::observed(Source::NvdApi, Confidence::Medium, "{}"),
            },
        );
        // A name nobody worked on yet.
        graph.apply(Observation::Hostname {
            address: "www.example".into(),
            hostname: "www.example".into(),
            record: EvidenceRecord::observed(Source::PtyRegex, Confidence::Medium, "www"),
        });
        let before = graph.hosts["intranet.example"].clone();

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hostile.xml");
        std::fs::write(
            &file,
            r#"<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="198.51.100.66" addrtype="ipv4"/><hostnames><hostname name="intranet.example" type="user"/></hostnames></host>
<host><status state="up"/><address addr="198.51.100.67" addrtype="ipv4"/><hostnames><hostname name="portal.example" type="user"/></hostnames></host>
<host><status state="up"/><address addr="198.51.100.68" addrtype="ipv4"/><hostnames><hostname name="www.example" type="user"/></hostnames></host>
</nmaprun>"#,
        )
        .unwrap();
        graph.apply_all(parse_file(&file).unwrap().observations);

        assert_eq!(graph.hosts["intranet.example"], before, "not taken over");
        assert!(graph.hosts["198.51.100.66"].hostnames.is_empty());
        assert!(graph.hosts["198.51.100.66"].advisories.is_empty());
        assert!(graph.hosts["192.0.2.10"]
            .hostnames
            .contains("portal.example"));
        assert!(graph.hosts["198.51.100.67"].hostnames.is_empty());
        // A name nobody owns or worked on still joins its address.
        assert!(!graph.hosts.contains_key("www.example"));
        assert!(graph.hosts["198.51.100.68"]
            .hostnames
            .contains("www.example"));
    }

    #[test]
    fn files_are_parsed_by_detected_format() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("scan.txt"); // the extension is irrelevant
        std::fs::write(&file, nmap::SAMPLE).unwrap();
        let parsed = parse_file(&file).unwrap();
        assert_eq!(parsed.format, Format::NmapXml);
        assert!(parsed.observations.len() > 5);

        std::fs::write(
            &file,
            b"Discovered open port 80/tcp on 10.0.0.5\n\xff\xfe binary\n",
        )
        .unwrap();
        let parsed = parse_file(&file).unwrap();
        assert_eq!((parsed.format, parsed.observations.len()), (Format::Log, 1));

        std::fs::write(&file, "<?xml version=\"1.0\"?><nmaprun><host>").unwrap();
        assert!(format!("{:#}", parse_file(&file).unwrap_err()).contains("scan.txt"));
        assert!(parse_file(&dir.path().join("missing")).is_err());
        assert!(read_capped(dir.path()).is_err());
        assert!(read_prefix_capped(dir.path()).is_err());

        #[cfg(unix)]
        {
            let link = dir.path().join("link.txt");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(parse_file(&link).is_err());
            assert!(crate::graph::Graph::load(&link).is_err());

            let fifo = dir.path().join("pipe.fifo");
            let c_fifo = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            if unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) } == 0 {
                assert!(parse_file(&fifo).is_err());
                assert!(crate::graph::Graph::load(&fifo).is_err());
            }
        }
    }
}
