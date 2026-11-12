//! The mandatory five-field evidence schema.
//!
//! Every parsed fact, advisory or note carries an [`EvidenceRecord`]. Raw
//! observations are never promoted straight to confirmed findings: the only
//! way to `Confirmed` is through `UnverifiedHypothesis`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::timeutil::now_rfc3339;

/// Longest raw snippet kept per record.
pub const EVIDENCE_MAX: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    PtyRegex,
    NmapXml,
    HttpHeader,
    TlsSan,
    KatanaJsonl,
    FeroxJson,
    NvdApi,
    OsvApi,
    CisaKev,
    ManualNote,
    /// Lines of an imported log file (`meow add`).
    LogRegex,
    /// `+` / `-` blocks of an imported `git diff` (`meow add`).
    GitDiff,
    /// Local OS network tables read by the passive observer.
    LocalNet,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::PtyRegex => "pty_regex",
            Source::NmapXml => "nmap_xml",
            Source::HttpHeader => "http_header",
            Source::TlsSan => "tls_san",
            Source::KatanaJsonl => "katana_jsonl",
            Source::FeroxJson => "ferox_json",
            Source::NvdApi => "nvd_api",
            Source::OsvApi => "osv_api",
            Source::CisaKev => "cisa_kev",
            Source::ManualNote => "manual_note",
            Source::LogRegex => "log_regex",
            Source::GitDiff => "git_diff",
            Source::LocalNet => "local_net",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationStatus {
    Observed,
    UnverifiedHypothesis,
    Confirmed,
    FalsePositive,
}

impl VerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            VerificationStatus::Observed => "Observed",
            VerificationStatus::UnverifiedHypothesis => "UnverifiedHypothesis",
            VerificationStatus::Confirmed => "Confirmed",
            VerificationStatus::FalsePositive => "FalsePositive",
        }
    }

    /// `Observed -> UnverifiedHypothesis -> Confirmed | FalsePositive`.
    /// A verdict can be reopened (back to `UnverifiedHypothesis`), but
    /// `Observed` can never jump straight to a verdict.
    pub fn can_become(self, next: VerificationStatus) -> bool {
        use VerificationStatus::*;
        matches!(
            (self, next),
            (Observed, UnverifiedHypothesis)
                | (UnverifiedHypothesis, Confirmed | FalsePositive)
                | (Confirmed | FalsePositive, UnverifiedHypothesis)
        )
    }
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: VerificationStatus,
    pub to: VerificationStatus,
}

impl fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot change verification status from {} to {}",
            self.from, self.to
        )
    }
}

impl std::error::Error for IllegalTransition {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub source: Source,
    /// RFC 3339, UTC.
    pub timestamp_utc: String,
    pub confidence: Confidence,
    /// Exact raw snippet, XML/JSON attribute or diff block.
    pub evidence: String,
    pub verification_status: VerificationStatus,
}

impl EvidenceRecord {
    fn new(
        source: Source,
        confidence: Confidence,
        evidence: &str,
        status: VerificationStatus,
    ) -> Self {
        Self {
            source,
            timestamp_utc: now_rfc3339(),
            confidence,
            evidence: sanitize(evidence, EVIDENCE_MAX),
            verification_status: status,
        }
    }

    /// A raw observation.
    pub fn observed(source: Source, confidence: Confidence, evidence: &str) -> Self {
        Self::new(source, confidence, evidence, VerificationStatus::Observed)
    }

    /// A possible issue derived from observations (for example a CVE match).
    pub fn hypothesis(source: Source, confidence: Confidence, evidence: &str) -> Self {
        Self::new(
            source,
            confidence,
            evidence,
            VerificationStatus::UnverifiedHypothesis,
        )
    }

    /// An observation whose evidence keeps its line breaks.
    pub fn observed_block(source: Source, confidence: Confidence, evidence: &str) -> Self {
        Self {
            evidence: sanitize_block(evidence, EVIDENCE_MAX),
            ..Self::observed(source, confidence, "")
        }
    }

    pub fn transition(&mut self, to: VerificationStatus) -> Result<(), IllegalTransition> {
        if !self.verification_status.can_become(to) {
            return Err(IllegalTransition {
                from: self.verification_status,
                to,
            });
        }
        self.verification_status = to;
        Ok(())
    }
}

/// Like [`sanitize`], but keeps line breaks: for multi-line evidence such as
/// a `git diff` block.
pub fn sanitize_block(text: &str, max: usize) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let line = sanitize(line, max);
        if out.len() + line.len() + 1 > max {
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&line);
    }
    out
}

/// Makes scraped text safe to store, print in a terminal and embed in a
/// prompt: control characters (including ESC) are removed, newlines and tabs
/// become spaces, and the result is capped at `max` bytes on a character
/// boundary.
pub fn sanitize(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max));
    let mut last_space = false;
    for ch in text.chars() {
        let ch = match ch {
            '\n' | '\r' | '\t' => ' ',
            c if c.is_control() => continue,
            // Bidirectional overrides and zero-width characters can hide text.
            '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}' => continue,
            c => c,
        };
        if ch == ' ' && last_space {
            continue;
        }
        if out.len() + ch.len_utf8() > max {
            break;
        }
        last_space = ch == ' ';
        out.push(ch);
    }
    out.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeutil::parse_rfc3339;
    use VerificationStatus::*;

    #[test]
    fn record_serializes_to_exactly_five_fields() {
        let record =
            EvidenceRecord::observed(Source::NmapXml, Confidence::High, "<port portid=\"22\"/>");
        let json = serde_json::to_value(&record).unwrap();
        let object = json.as_object().unwrap();
        let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "confidence",
                "evidence",
                "source",
                "timestamp_utc",
                "verification_status"
            ]
        );
        assert_eq!(json["source"], "nmap_xml");
        assert_eq!(json["confidence"], "High");
        assert_eq!(json["verification_status"], "Observed");
        assert!(parse_rfc3339(json["timestamp_utc"].as_str().unwrap()).is_some());
        assert_eq!(
            serde_json::from_value::<EvidenceRecord>(json).unwrap(),
            record
        );
    }

    #[test]
    fn every_source_has_its_wire_name() {
        for source in [
            Source::PtyRegex,
            Source::NmapXml,
            Source::HttpHeader,
            Source::TlsSan,
            Source::KatanaJsonl,
            Source::FeroxJson,
            Source::NvdApi,
            Source::OsvApi,
            Source::CisaKev,
            Source::ManualNote,
            Source::LogRegex,
            Source::GitDiff,
            Source::LocalNet,
        ] {
            let wire = serde_json::to_string(&source).unwrap();
            assert_eq!(wire, format!("\"{}\"", source.as_str()));
        }
    }

    #[test]
    fn observed_can_never_jump_to_a_verdict() {
        let mut record =
            EvidenceRecord::observed(Source::HttpHeader, Confidence::Medium, "Server: nginx");
        for verdict in [Confirmed, FalsePositive] {
            let error = record.transition(verdict).unwrap_err();
            assert_eq!(error.from, Observed);
            assert_eq!(record.verification_status, Observed);
        }
        record.transition(UnverifiedHypothesis).unwrap();
        record.transition(Confirmed).unwrap();
        assert_eq!(record.verification_status, Confirmed);
    }

    #[test]
    fn transition_table_is_exact() {
        let all = [Observed, UnverifiedHypothesis, Confirmed, FalsePositive];
        let allowed = [
            (Observed, UnverifiedHypothesis),
            (UnverifiedHypothesis, Confirmed),
            (UnverifiedHypothesis, FalsePositive),
            (Confirmed, UnverifiedHypothesis),
            (FalsePositive, UnverifiedHypothesis),
        ];
        for from in all {
            for to in all {
                assert_eq!(
                    from.can_become(to),
                    allowed.contains(&(from, to)),
                    "{from} -> {to}"
                );
            }
        }
    }

    #[test]
    fn evidence_is_sanitized_and_capped() {
        let hostile = "Server: nginx\x1b[2J\x1b]0;pwn\x07\r\nX-Evil:\t\u{202e}txt.exe\0  end";
        let record = EvidenceRecord::observed(Source::HttpHeader, Confidence::Low, hostile);
        assert_eq!(
            record.evidence,
            "Server: nginx[2J]0;pwn X-Evil: txt.exe end"
        );
        assert!(!record.evidence.chars().any(char::is_control));

        let long = "é".repeat(EVIDENCE_MAX);
        let capped = sanitize(&long, EVIDENCE_MAX);
        assert_eq!(capped.len(), EVIDENCE_MAX);
        assert!(capped.chars().all(|c| c == 'é'));
    }
}
