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
    if first.trim_start().starts_with('{')
        && serde_json::from_str::<serde_json::Value>(first).is_ok()
    {
        return Format::Jsonl;
    }
    let diff_marks = text
        .lines()
        .take(200)
        .filter(|l| l.starts_with("diff --git ") || l.starts_with("@@ ") || l.starts_with("+++ "))
        .count();
    if first.starts_with("diff --git ") || diff_marks >= 2 {
        return Format::GitDiff;
    }
    Format::Log
}

pub fn parse_text(text: &str) -> Result<Parsed> {
    let format = detect(text);
    let (observations, skipped) = match format {
        Format::NmapXml => (nmap::parse(text)?, 0),
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

/// Reads at most [`INGEST_CAP`] bytes of `path` as (lossy) UTF-8.
pub fn read_capped(path: &Path) -> Result<String> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    if size > INGEST_CAP {
        bail!(
            "{} is {} MB; the ingestion limit is {} MB",
            path.display(),
            size / (1024 * 1024),
            INGEST_CAP / (1024 * 1024)
        );
    }
    let mut bytes = Vec::new();
    file.take(INGEST_CAP)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn parse_file(path: &Path) -> Result<Parsed> {
    let text = read_capped(path)?;
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
    }
}
