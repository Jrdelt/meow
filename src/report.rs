//! `meow report`: compiles the workspace into `REPORT.md`.
//!
//! No AI and no network are involved: the report is assembled from
//! `graph.json`, `state.db`, `replay.sh` and `chats/*.md`. The CVEs found
//! on each host are listed by the software and version they were found
//! from.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::cve;
use crate::db::Db;
use crate::evidence::{inert_markdown, Source};
use crate::graph::{Advisory, DnsSecurity, Fact, Graph, Host, HttpInfo};
use crate::mode::Mode;
use crate::queue::{self, TaskRow};
use crate::timeutil::now_rfc3339;
use crate::topology::{only_mentioned, Topology};
use crate::vault::{ExposedSecret, Vault};
use crate::workspace::{write_private_atomic, Workspace};

const MAX_REPLAY_LINES: usize = 600;
const MAX_PATHS_PER_PORT: usize = 80;
const MAX_FACTS_PER_HOST: usize = 80;
const MAX_ENDPOINTS_PER_PORT: usize = 40;
const MAX_SCRIPTS_PER_PORT: usize = 20;
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

/// [`md`] for text that starts a list item: a value such as `- x`, `+ x`
/// or `1. x` would otherwise open a list of its own inside the item, and
/// leading spaces could turn it into a code block.
fn md_item(text: &str) -> String {
    let escaped = md(text);
    let escaped = escaped.trim_start();
    let bytes = escaped.as_bytes();
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    // `1.` opens a list only before a space or the end: `10.0.0.1` does not.
    let marker_ends = matches!(bytes.get(digits + 1), None | Some(b' '));
    match bytes.get(digits) {
        Some(b'-' | b'+') if digits == 0 => format!("\\{escaped}"),
        Some(b'.' | b')') if digits > 0 && marker_ends => {
            format!("{}\\{}", &escaped[..digits], &escaped[digits..])
        }
        _ => escaped.to_owned(),
    }
}

/// Whether `text` is a vault placeholder (`<<SEC_03>>`). The graph keeps
/// nothing else for a key, but a hand-edited `graph.json` could: then the
/// text may be the key itself, and it is not printed.
fn is_placeholder(text: &str) -> bool {
    text.strip_prefix("<<SEC_")
        .and_then(|rest| rest.strip_suffix(">>"))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
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

/// Writes `line` with a heading in it nested below the chat's section, also
/// one that is moved in, or sits in a quote or a list item (`- # Hosts`,
/// `> 1. ## Fix`, a nested item's next line). Lines of code get the same
/// marks, fenced or indented: a dialect without that kind of code block
/// reads them as text, and a `# Secrets to rotate` there would be a
/// section of the report.
fn push_nested_heading(out: &mut String, line: &str) {
    let text_at = crate::evidence::nested_text_start(line);
    if line.as_bytes().get(text_at) == Some(&b'#') {
        out.push_str(&line[..text_at]);
        out.push_str("###");
        out.push_str(&line[text_at..]);
    } else {
        out.push_str(line);
    }
}

/// Writes a chat file into the report: its own headings one level down, and
/// nothing in it live (see [`inert_markdown`]). A code block the text left
/// open is closed, so that it cannot take the rest of the report with it.
/// A code block starts at the left edge of its quote, never inside a list
/// item: a line indented less than the item would end the item and the
/// block with it, unseen here.
fn render_chat_markdown(out: &mut String, text: &str) {
    // The open fence: its character, length, quote depth and indent.
    let mut open_fence: Option<(u8, usize, usize, usize)> = None;
    for line in inert_markdown(text).lines() {
        let (qdepth, qprefix, rest) = split_blockquote_prefix(line);
        if let Some((open, length, fence_qdepth, indent)) = open_fence {
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
                if qdepth == fence_qdepth {
                    // Moved left as far as its fence was.
                    let spaces = rest.bytes().take(indent).take_while(|&b| b == b' ').count();
                    let content = &rest[spaces..];
                    out.push_str(qprefix);
                    if is_fence_closing(content, open, length) {
                        open_fence = None;
                        out.push_str(content);
                    } else {
                        push_nested_heading(out, content);
                    }
                } else {
                    push_nested_heading(out, line);
                }
                out.push('\n');
                continue;
            }
        }
        if let Some((marker, len, normalized_fence)) = fence_opening(rest) {
            let indent = rest.len() - rest.trim_start_matches(' ').len();
            open_fence = Some((marker, len, qdepth, indent));
            for _ in 0..qdepth {
                out.push_str("> ");
            }
            out.push_str(normalized_fence.trim_start_matches(' '));
            out.push('\n');
            continue;
        }
        push_nested_heading(out, &neutralize_unmatched_inline_backticks(line));
        out.push('\n');
    }
    if let Some((marker, length, fence_qdepth, _)) = open_fence {
        for _ in 0..fence_qdepth {
            out.push_str("> ");
        }
        out.extend(std::iter::repeat_n(marker as char, length));
        out.push('\n');
    }
}

/// The release that fixes one CVE: `1.20.1`, `newer than 1.19.9`, or `-`.
fn fixed_cell(advisory: &Advisory) -> String {
    match (&advisory.fixed_in, &advisory.last_affected) {
        (Some(fixed), _) => md(fixed),
        (None, Some(last)) => format!("newer than {}", md(last)),
        (None, None) => "-".to_owned(),
    }
}

/// One host's CVEs, by the software and version they were found from.
fn render_cves(out: &mut String, host: &Host) {
    let _ = writeln!(out, "### {}\n", md(&host.label()));
    for group in cve::by_software(host) {
        let _ = writeln!(out, "#### {}\n", md(&group.heading()));
        // One of meow's own sentences, not scanned text: its commands stay
        // code spans.
        if let Some(note) = cve::backport_note_for(host, group.port.as_deref()) {
            let _ = writeln!(out, "{note}.\n");
        }
        out.push_str(
            "| CVE | Severity | Known exploited | Fixed in | Summary |\n|---|---|---|---|---|\n",
        );
        for advisory in &group.cves {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                md_cell(&advisory.id),
                md_cell(&cve::severity_label(advisory)),
                if advisory.kev { "yes" } else { "-" },
                fixed_cell(advisory),
                md_cell(&advisory.title)
            );
        }
        out.push('\n');
    }
}

fn fact_line(fact: &Fact) -> String {
    format!(
        "- {} _({}, {:?}, {})_",
        md(&fact.claim),
        fact.record.source.as_str(),
        fact.record.confidence,
        md(&fact.record.timestamp_utc)
    )
}

/// [`md`] for a table cell, with `-` for nothing so that no cell is blank.
fn md_cell(text: &str) -> String {
    let escaped = md(text);
    if escaped.trim().is_empty() {
        "-".to_owned()
    } else {
        escaped
    }
}

/// A stack entry the web fingerprint marked as outdated, split into the
/// software and why it is a concern: `jQuery 1.12.4 (older than 3.5.0: ...)`.
fn outdated(tech: &str) -> Option<(&str, &str)> {
    if !tech.contains("(older than") && !tech.contains("end of life") {
        return None;
    }
    Some(match tech.find(" (") {
        Some(at) => {
            let why = &tech[at + 2..];
            (&tech[..at], why.strip_suffix(')').unwrap_or(why))
        }
        None => (tech, ""),
    })
}

/// What the web fingerprint and the site's own scripts showed on one port:
/// the software stack, the security-header grade, cookies, exposed keys,
/// the endpoints the scripts name and the scripts themselves. `port` is
/// already escaped. A port with none of these gets nothing, not an empty
/// heading.
fn render_web_details(out: &mut String, port: &str, http: &HttpInfo) {
    if !http.tech.is_empty() {
        let _ = writeln!(out, "Software stack on {port}:\n");
        out.push_str("| Software | Note |\n|---|---|\n");
        for tech in &http.tech {
            let (name, note) = match outdated(tech) {
                Some((name, "")) => (md_cell(name), "outdated".to_owned()),
                Some((name, why)) => (md_cell(name), format!("outdated: {}", md(why))),
                None => (md_cell(tech), "-".to_owned()),
            };
            let _ = writeln!(out, "| {name} | {note} |");
        }
        out.push('\n');
    }
    if http.header_grade.is_some() || !http.header_notes.is_empty() {
        match &http.header_grade {
            Some(grade) => {
                let _ = writeln!(out, "Security headers on {port}: grade {}.\n", md(grade));
            }
            None => {
                let _ = writeln!(out, "Security headers on {port}:\n");
            }
        }
        for note in &http.header_notes {
            let _ = writeln!(out, "- {}", md_item(note));
        }
        if !http.header_notes.is_empty() {
            out.push('\n');
        }
    }
    if !http.cookies.is_empty() {
        let _ = writeln!(
            out,
            "Cookies set on {port} (names and flags only; values are never kept):\n"
        );
        out.push_str("| Cookie | Flags | Issues |\n|---|---|---|\n");
        for cookie in &http.cookies {
            let issues: Vec<String> = cookie.issues.iter().map(|issue| md(issue)).collect();
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                md_cell(&cookie.name),
                md_cell(&cookie.flags),
                if issues.is_empty() {
                    "none".to_owned()
                } else {
                    issues.join("; ")
                }
            );
        }
        out.push('\n');
    }
    if !http.js_secrets.is_empty() {
        // The rotation list is "Secrets to rotate", from the vault; here is
        // only where each key was found, under the same placeholder.
        let _ = writeln!(
            out,
            "Keys exposed in the scripts on {port}. The keys stay in the vault, never in this \
             report; each is listed under Secrets to rotate by the same placeholder.\n"
        );
        out.push_str("| Kind | File | Placeholder | Hint |\n|---|---|---|---|\n");
        for secret in &http.js_secrets {
            let token = if is_placeholder(&secret.token) {
                code_cell(&secret.token)
            } else {
                "withheld".to_owned()
            };
            let _ = writeln!(
                out,
                "| {} | {} | {token} | {} |",
                md_cell(&secret.kind),
                md_cell(&secret.file),
                md_cell(&secret.preview)
            );
        }
        out.push('\n');
    }
    for (label, list, max) in [
        (
            "Endpoints named in the scripts",
            &http.js_endpoints,
            MAX_ENDPOINTS_PER_PORT,
        ),
        (
            "Script files of the site",
            &http.scripts,
            MAX_SCRIPTS_PER_PORT,
        ),
    ] {
        if list.is_empty() {
            continue;
        }
        let _ = writeln!(out, "{label} on {port} ({}):\n", list.len());
        for item in list.iter().take(max) {
            let _ = writeln!(out, "- {}", md_item(item));
        }
        if list.len() > max {
            let _ = writeln!(out, "- +{} more", list.len() - max);
        }
        out.push('\n');
    }
}

/// How well the domain a host was found under protects its mail and DNS,
/// from the `mail-dns` stage.
fn render_dns(out: &mut String, dns: &DnsSecurity) {
    let grade = match dns.grade.trim() {
        "" | "?" => "not graded".to_owned(),
        grade => format!("grade {}", md(grade)),
    };
    if dns.domain.trim().is_empty() {
        let _ = writeln!(out, "DNS & Mail: {grade}.\n");
    } else {
        let _ = writeln!(out, "DNS & Mail for {}: {grade}.\n", md(&dns.domain));
    }
    if !dns.checks.is_empty() {
        out.push_str("| Check | Status | Value | Advice |\n|---|---|---|---|\n");
        for check in &dns.checks {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                md_cell(&check.name),
                md_cell(&check.status),
                md_cell(&check.value),
                md_cell(&check.advice)
            );
        }
        out.push('\n');
    }
    if !dns.services.is_empty() {
        out.push_str(
            "Services published in DNS:\n\n| Record | Target | Meaning |\n|---|---|---|\n",
        );
        for service in &dns.services {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                md_cell(&service.record),
                md_cell(&service.target),
                md_cell(&service.meaning)
            );
        }
        out.push('\n');
    }
    // Its lookups failed: the check in the table says so.
    let unchecked = dns.checks.iter().any(|check| check.name == "Wildcard");
    if dns.wildcard.is_empty() && !unchecked {
        out.push_str("Wildcard DNS: none.\n\n");
    } else if !dns.wildcard.is_empty() {
        let addresses: Vec<String> = dns.wildcard.iter().map(|a| md(a)).collect();
        let _ = writeln!(
            out,
            "Wildcard DNS: made-up names under the domain resolve to {}.\n",
            addresses.join(", ")
        );
    }
    if !dns.subdomains.is_empty() {
        out.push_str(
            "Names from the certificate logs, looked up:\n\n\
             | Name | Status | Addresses |\n|---|---|---|\n",
        );
        for sub in &dns.subdomains {
            let status = match sub.status.as_str() {
                "resolves" => "resolves".to_owned(),
                "wildcard" => "wildcard only (may not exist)".to_owned(),
                "gone" => "no record".to_owned(),
                "unknown" => "lookup failed".to_owned(),
                other => md_cell(other),
            };
            let addresses: Vec<String> = sub.addresses.iter().map(|a| md(a)).collect();
            let _ = writeln!(
                out,
                "| {} | {status} | {} |",
                md_cell(&sub.name),
                if addresses.is_empty() {
                    "-".to_owned()
                } else {
                    addresses.join(", ")
                }
            );
        }
        out.push('\n');
    }
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
    for port in host.ports.values() {
        if let Some(http) = &port.http {
            render_web_details(out, &md(&port.key()), http);
        }
    }
    if let Some(dns) = &host.dns_security {
        render_dns(out, dns);
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
        out.push_str("Observations:\n\n");
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
    let kev = graph
        .hosts
        .values()
        .flat_map(|host| &host.advisories)
        .filter(|advisory| advisory.kev)
        .count();
    let mut out = String::new();

    let _ = writeln!(out, "# Audit report: {}\n", md(&inputs.session));
    let _ = writeln!(
        out,
        "Generated {} by meow {} from local workspace files (no AI, no network). Mode: {}.\n",
        md(&inputs.generated_utc),
        env!("CARGO_PKG_VERSION"),
        inputs.mode
    );
    // The hosts on the map: not the names only printed somewhere.
    let (mentioned, seen): (Vec<&Host>, Vec<&Host>) =
        graph.hosts.values().partition(|host| only_mentioned(host));
    let _ = writeln!(
        out,
        "| Hosts | CVEs | Known exploited | Secrets to rotate |\n\
         |---|---|---|---|\n| {} | {} | {kev} | {} |\n",
        seen.len(),
        graph.advisory_count(),
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

    // What to do, before the lists of what was found: one update per
    // piece of software usually fixes every CVE found from it.
    let fixes: Vec<(&Host, cve::FixItem)> = graph
        .hosts
        .values()
        .flat_map(|host| cve::fix_plan(host).into_iter().map(move |fix| (host, fix)))
        .collect();
    if !fixes.is_empty() {
        out.push_str("## What to update\n\n");
        out.push_str(
            "One line per piece of software. CVEs are found by version number: a system that \
             takes security updates from its vendor may already have the fix under the same \
             version number.\n\n",
        );
        for (host, fix) in &fixes {
            let _ = writeln!(
                out,
                "- {}: {} ({})",
                md(&host.label()),
                md(&fix.action),
                fix.counts()
            );
        }
        out.push('\n');
    }

    out.push_str("## CVEs\n\n");
    // The host with the most urgent CVE first.
    let mut affected: Vec<(&Host, &Advisory)> = graph
        .hosts
        .values()
        .filter_map(|host| {
            let worst = host
                .advisories
                .iter()
                .min_by(|a, b| cve::cmp_urgency(a, b))?;
            Some((host, worst))
        })
        .collect();
    if affected.is_empty() {
        out.push_str("None found.\n\n");
    }
    affected.sort_by(|a, b| cve::cmp_urgency(a.1, b.1).then(a.0.address.cmp(&b.0.address)));
    for (host, _) in affected {
        render_cves(&mut out, host);
    }

    out.push_str("## Hosts\n\n");
    if seen.is_empty() {
        out.push_str("No hosts recorded.\n\n");
    }
    if !mentioned.is_empty() {
        let names: Vec<String> = mentioned.iter().map(|host| md(&host.label())).collect();
        let _ = writeln!(
            out,
            "Only mentioned, not looked at: {}.\n",
            names.join(", ")
        );
    }
    for host in &seen {
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
                    md(crate::queue::status_word(&stage.status)),
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

/// Renders a single-host engagement report containing that host's CVEs,
/// what was seen on it, operator notes, the keys found in its scripts, and
/// AI remediation chat (`chats/<address>.md`).
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
    // The vault does not say where a secret was seen, so only the keys found
    // in this host's own scripts are listed to rotate here. Each keeps the
    // web stage's hint, not the vault's: the vault shows the first characters
    // of every value, and the web stage shows a password-like one only by
    // its length. This report is the one the map offers for download.
    let found_here: Vec<_> = host
        .ports
        .values()
        .filter_map(|port| port.http.as_ref())
        .flat_map(|http| &http.js_secrets)
        .collect();
    let secrets = inputs
        .secrets
        .iter()
        .filter_map(|secret| {
            let found = found_here.iter().find(|js| js.token == secret.token)?;
            Some(ExposedSecret {
                preview: found.preview.clone(),
                ..secret.clone()
            })
        })
        .collect();
    let filtered = Inputs {
        session: format!("{} ({})", inputs.session, host.label()),
        mode: inputs.mode,
        generated_utc: inputs.generated_utc.clone(),
        graph: sub_graph,
        tasks,
        secrets,
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
    let mut tasks = queue::tasks(&db.lock().unwrap_or_else(|p| p.into_inner()), 200)?;
    // A session that was killed left its stages running or waiting; with
    // no session open they are over, and the next one marks them so.
    if !crate::ipc::is_live(&workspace.dir) {
        queue::show_ended(&mut tasks);
    }
    let vault = Vault::open(Arc::clone(&db))?;
    let secrets = vault.exposed_secrets();
    let mut graph = Graph::load(&workspace.graph_path())?;
    graph.hide_script_keys(&vault);
    let (replay, chats) = read_chats_and_replay(&workspace.dir);
    Ok(Inputs {
        session: workspace.name.clone(),
        mode: workspace.profile.mode,
        generated_utc: now_rfc3339(),
        graph,
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
            record: EvidenceRecord::observed(Source::NvdApi, Confidence::Medium, "{\"id\":\"x\"}"),
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
        graph.add_advisory(
            "10.10.10.5",
            Advisory {
                fixed_in: Some("1.20.1".into()),
                ..advisory("CVE-2021-23017", 7.7, true)
            },
        );
        graph.add_advisory("10.10.10.5", advisory("CVE-2019-0001", 9.8, false));
        graph.add_advisory(
            "10.10.10.5",
            Advisory {
                severity: Some("MEDIUM".into()),
                last_affected: Some("1.19.9".into()),
                ..advisory("CVE-2018-0002", 5.0, false)
            },
        );
        graph.add_advisory(
            "10.10.10.9",
            Advisory {
                severity: Some("MEDIUM".into()),
                ..advisory("CVE-2020-0003", 6.0, false)
            },
        );

        let stage = |stage, status: &str, detail: &str| StageRow {
            stage,
            status: status.into(),
            detail: detail.into(),
            started_utc: None,
            finished_utc: None,
            progress: None,
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
    fn cves_are_listed_by_software_and_version() {
        let text = render(&inputs());
        let section = |title: &str| -> &str {
            let start = text
                .find(&format!("## {title}\n"))
                .unwrap_or_else(|| panic!("no section {title}"));
            let rest = &text[start + 3..];
            let end = rest.find("\n## ").map_or(rest.len(), |i| i + 1);
            &rest[..end]
        };
        let cves = section("CVEs");
        // Known exploited first, then by score; the fix for the whole group
        // in its heading, each CVE's own in its row.
        let expected = [
            "### 10.10.10.5\n",
            "#### nginx 1.18.0 \u{b7} 443/tcp \u{b7} fixed in 1.20.1\n",
            "| CVE | Severity | Known exploited | Fixed in | Summary |",
            "| CVE-2021-23017 | High 7.7 | yes | 1.20.1 | CVE-2021-23017 summary with \
             &lt;b&gt;markup&lt;/b&gt; \\| pipe |",
            "| CVE-2019-0001 | High 9.8 | - | - | ",
            "| CVE-2018-0002 | Medium 5.0 | - | newer than 1.19.9 | ",
            "### 10.10.10.9\n",
            "#### nginx 1.18.0 \u{b7} 443/tcp\n",
            "| CVE-2020-0003 | Medium 6.0 | - | - | ",
        ];
        let mut from = 0;
        for line in expected {
            match cves[from..].find(line) {
                Some(at) => from += at + line.len(),
                None => panic!("missing or out of order: {line:?}\n{cves}"),
            }
        }
        for gone in [
            "hypothes",
            "Hypothes",
            "verif",
            "Verif",
            "onfirmed",
            "alse positive",
            "Checklist",
            "research ready",
            "Evidence",
        ] {
            assert!(!text.contains(gone), "{gone} in:\n{text}");
        }
        assert!(text.contains("| Hosts | CVEs | Known exploited | Secrets to rotate |"));
        assert!(text.contains("| 2 | 4 | 1 | 1 |"));
        assert!(
            section("What to update").contains(
                "- 10.10.10.5: Update nginx 1.18.0 to 1.20.1 or later, or close 443/tcp if \
                 the service is not needed. (3 CVEs, 1 known exploited)"
            ),
            "{text}"
        );
        assert_tables_keep_their_columns(&text);
    }

    #[test]
    fn a_workspace_from_meow_0_2_2_still_renders() {
        // Version 0.2.2 marked CVEs confirmed or false positive. Both are
        // listed as the CVEs they are, and nothing speaks of a verdict.
        // Its distribution note asked to verify before confirming; it is
        // in today's words, once per software, and gone from the titles.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("graph.json");
        let old_note = "Debian banner detected: Debian backports security fixes without bumping \
                        the upstream version; verify installed package revision locally \
                        (`dpkg -l` / `apt-cache policy`) before confirming";
        let cut_title = "Username enumeration [Debian banner detected: Debian backports security \
                         fixes without bumping the upstream version; verify installed package \
                         revision locally (`dpkg -l` / `apt-cache policy`) before";
        let cve = |id: &str, kev: bool, status: &str| {
            serde_json::json!({
                "id": id,
                "title": if id == "CVE-2018-15473" {
                    cut_title.to_owned()
                } else {
                    format!("about {id} [{old_note}]")
                },
                "severity": "HIGH",
                "cvss": 7.5,
                "kev": kev,
                "matched": "cpeName=cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
                "port": "22/tcp",
                "references": [],
                "fixed_in": "7.6",
                "source": "nvd_api",
                "timestamp_utc": "2026-11-12T00:00:00Z",
                "confidence": "Medium",
                "evidence": "{}",
                "verification_status": status
            })
        };
        let old = serde_json::json!({
            "version": 2,
            "updated_utc": "2026-11-12T00:00:00Z",
            "hosts": {
                "198.51.100.7": {
                    "address": "198.51.100.7",
                    "ports": {
                        "22/tcp": {
                            "number": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "product": "OpenSSH",
                            "version": "7.4",
                            "extra_info": "Debian 10+deb9u7",
                            "facts": [{
                                "claim": "22/tcp open ssh OpenSSH 7.4",
                                "source": "nmap_xml",
                                "timestamp_utc": "2026-11-12T00:00:00Z",
                                "confidence": "High",
                                "evidence": "<port/>",
                                "verification_status": "Observed"
                            }, {
                                "claim": format!("Distro backporting note: {old_note}"),
                                "source": "nmap_xml",
                                "timestamp_utc": "2026-11-12T00:00:00Z",
                                "confidence": "High",
                                "evidence": "OpenSSH 7.4 Debian 10+deb9u7",
                                "verification_status": "Observed"
                            }]
                        }
                    },
                    "advisories": [
                        cve("CVE-2018-15473", false, "FalsePositive"),
                        cve("CVE-2023-38408", true, "Confirmed"),
                        cve("CVE-2017-15906", false, "UnverifiedHypothesis")
                    ]
                }
            }
        });
        std::fs::write(&file, serde_json::to_vec(&old).unwrap()).unwrap();
        let data = Inputs {
            graph: Graph::load(&file).unwrap(),
            secrets: Vec::new(),
            ..inputs()
        };
        for text in [
            render(&data),
            render_host_report(&data, "198.51.100.7").unwrap(),
        ] {
            let at = text
                .find("#### OpenSSH 7.4 \u{b7} 22/tcp \u{b7} fixed in 7.6")
                .unwrap_or_else(|| panic!("{text}"));
            let rows = &text[at..];
            let order: Vec<usize> = ["CVE-2023-38408", "CVE-2017-15906", "CVE-2018-15473"]
                .iter()
                .map(|id| rows.find(&format!("| {id} | High 7.5 |")).unwrap())
                .collect();
            assert!(order.windows(2).all(|w| w[0] < w[1]), "{rows}");
            assert!(rows.contains("| CVE-2023-38408 | High 7.5 | yes | 7.6 |"));
            for gone in [
                "onfirmed",
                "alse positive",
                "hypothes",
                "Verification",
                "verify installed",
                "banner detected",
            ] {
                assert!(!text.contains(gone), "{gone} in:\n{text}");
            }
            assert!(text.contains("| 1 | 3 | 1 | 0 |"), "{text}");
            assert!(
                rows.contains("| CVE-2018-15473 | High 7.5 | - | 7.6 | Username enumeration |"),
                "{rows}"
            );
            assert!(rows.contains("| about CVE-2023-38408 |"), "{rows}");
            // Under the software heading, once for its three CVEs.
            let group = &rows[..rows[1..].find("\n#").map_or(rows.len(), |end| end + 1)];
            let note = "Debian backports security fixes without changing the upstream version";
            assert_eq!(group.matches(note).count(), 1, "{group}");
        }
        let full = render(&data);
        assert!(
            full.contains("- Distro backporting note: Debian backports security fixes"),
            "{full}"
        );
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
            "## CVEs",
            "### 10.10.10.5",
            "#### nginx 1.18.0 \u{b7} 443/tcp \u{b7} fixed in 1.20.1",
            "### 10.10.10.9",
            "#### nginx 1.18.0 \u{b7} 443/tcp",
            "## Hosts",
            "### 10.10.10.5",
            "| 443/tcp | open | ssl/http | nginx | 1.18.0 |",
            "Paths on 443/tcp:",
            "- `/admin/`",
            "- `/admin/login.php` (200)",
            "Observations:",
            "_(nmap_xml, High, 2026-",
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
        // Found from software no open port runs: the port it names is shown.
        let hostile = &mut custom.graph.hosts.get_mut("10.10.10.5").unwrap().advisories[1];
        hostile.port = Some("443/tcp | <img src=x>".into());
        hostile.matched = "cpeName=cpe:2.3:a:example:widget:2.0:*:*:*:*:*:*:*".into();
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
        assert!(rendered.contains("#### widget 2.0 \u{b7} 443/tcp \\| &lt;img src=x&gt;\n"));
        // No tag opens anywhere, in or out of code: what counts as code
        // differs between Markdown dialects.
        assert!(rendered.contains("#### Heading &lt;script>alert(1)&lt;/script>"));
        assert!(rendered.contains("> Quote with &lt;b>html&lt;/b> and `&lt;raw>` span"));
        assert!(rendered.contains("```sh\n#### shell comment stays a comment\n"));
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
            // A CVE whose title starts like a list item and opens a code
            // block.
            host.advisories[0].title = "- Status: fixed ``` swallow the rest".into();
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
        // what follows the CVE is still there, outside any block.
        assert!(
            rendered.contains("| - Status: fixed \\`\\`\\` swallow the rest |"),
            "{rendered}"
        );
        assert!(rendered.contains("\n## Hosts\n"));
        assert!(
            rendered.contains("| `<<SEC_01>>` | `a\\|b... (9 chars)` |"),
            "{rendered}"
        );
    }

    /// Every table keeps the columns of its header row: no cell text added
    /// a border or took one away.
    fn assert_tables_keep_their_columns(text: &str) {
        let borders = |line: &str| {
            line.replace("\\\\", "")
                .replace("\\|", "")
                .matches('|')
                .count()
        };
        let lines: Vec<&str> = text.lines().collect();
        let mut columns = None;
        for (at, line) in lines.iter().enumerate() {
            if !line.starts_with('|') {
                columns = None;
                continue;
            }
            match columns {
                None => {
                    assert!(
                        lines
                            .get(at + 1)
                            .is_some_and(|next| next.starts_with("|---")),
                        "a table row without a header: {line}\n{text}"
                    );
                    columns = Some(borders(line));
                }
                Some(count) => assert_eq!(borders(line), count, "{line}\n{text}"),
            }
        }
    }

    /// The section of one host under "Hosts" in a report: from its heading
    /// to the next.
    fn host_section<'a>(text: &'a str, heading: &str) -> &'a str {
        let hosts = text.find("\n## Hosts\n").expect("a Hosts section");
        let start = hosts
            + text[hosts..]
                .find(&format!("{heading}\n"))
                .unwrap_or_else(|| panic!("no {heading}"));
        let rest = &text[start + heading.len()..];
        let end = ["\n### ", "\n## "]
            .iter()
            .filter_map(|next| rest.find(next))
            .min()
            .unwrap_or(rest.len());
        &rest[..end]
    }

    /// The fields the web fingerprint, the site's scripts and the mail-dns
    /// stage fill in, on 10.10.10.5.
    fn with_web_and_dns_details() -> Inputs {
        use crate::graph::{CookieCheck, DnsCheck, DnsService, JsSecret, SubdomainCheck};
        let mut data = inputs();
        // Built here: no key-shaped text in the source.
        let hint = format!("{}{}\u{2026} (20 chars)", "AK", "IA");
        let host = data.graph.hosts.get_mut("10.10.10.5").unwrap();
        let http = host
            .ports
            .get_mut("443/tcp")
            .unwrap()
            .http
            .as_mut()
            .unwrap();
        http.tech = vec![
            "nginx 1.18.0".into(),
            "jQuery 1.12.4 (older than 3.5.0: known XSS issues (CVE-2020-11022, CVE-2020-11023))"
                .into(),
            "AngularJS 1.8.2 (AngularJS 1.x reached end of life in 2021: no more security fixes)"
                .into(),
        ];
        http.header_grade = Some("D".into());
        http.header_notes = vec![
            "missing Content-Security-Policy, X-Frame-Options".into(),
            "Strict-Transport-Security max-age is under six months".into(),
        ];
        http.cookies = vec![
            CookieCheck {
                name: "PHPSESSID".into(),
                flags: "HttpOnly".into(),
                issues: vec![
                    "no Secure flag: it is also sent over plain HTTP".into(),
                    "no SameSite: browsers default to Lax".into(),
                ],
            },
            CookieCheck {
                name: "lang".into(),
                flags: "Secure HttpOnly SameSite=Lax".into(),
                issues: vec![],
            },
        ];
        http.scripts = vec!["/static/app.js".into(), "/static/vendor.js".into()];
        http.js_endpoints = (0..50).map(|i| format!("/api/v1/item{i}")).collect();
        http.js_endpoints[1] = "https://api.partner.example/v2/orders".into();
        http.js_secrets = vec![JsSecret {
            kind: "AWS access key ID".into(),
            token: "<<SEC_02>>".into(),
            preview: hint.clone(),
            file: "/static/app.js".into(),
        }];
        host.dns_security = Some(DnsSecurity {
            domain: "example.test".into(),
            grade: "C".into(),
            checks: vec![
                DnsCheck {
                    name: "SPF".into(),
                    status: "ok".into(),
                    value: "v=spf1 -all".into(),
                    advice: String::new(),
                },
                DnsCheck {
                    name: "DMARC".into(),
                    status: "warn".into(),
                    value: "p=none".into(),
                    advice: "move to p=quarantine once the reports look clean".into(),
                },
            ],
            services: vec![DnsService {
                record: "_ldap._tcp.example.test".into(),
                target: "dc01.corp.example.test:389".into(),
                meaning: "LDAP directory (often Active Directory domain controllers)".into(),
            }],
            wildcard: vec!["203.0.113.50".into()],
            subdomains: vec![
                SubdomainCheck {
                    name: "www.example.test".into(),
                    status: "resolves".into(),
                    addresses: vec!["203.0.113.10".into()],
                },
                SubdomainCheck {
                    name: "old.example.test".into(),
                    status: "wildcard".into(),
                    addresses: vec!["203.0.113.50".into()],
                },
                SubdomainCheck {
                    name: "gone.example.test".into(),
                    status: "gone".into(),
                    addresses: vec![],
                },
            ],
        });
        data.secrets.push(ExposedSecret {
            token: "<<SEC_02>>".into(),
            preview: format!("{}{}... (20 chars)", "AK", "IA"),
            first_seen_utc: "2026-11-12T09:10:00Z".into(),
        });
        data
    }

    #[test]
    fn web_and_dns_details_have_their_own_sections() {
        let data = with_web_and_dns_details();
        let hint = format!("{}{}\u{2026} (20 chars)", "AK", "IA");
        let expected_host = [
            "| 443/tcp | open | ssl/http | nginx | 1.18.0 |",
            "Paths on 443/tcp:",
            "Software stack on 443/tcp:\n\n| Software | Note |\n|---|---|\n",
            "| nginx 1.18.0 | - |",
            "| jQuery 1.12.4 | outdated: older than 3.5.0: known XSS issues \
             (CVE-2020-11022, CVE-2020-11023) |",
            "| AngularJS 1.8.2 | outdated: AngularJS 1.x reached end of life in 2021: \
             no more security fixes |",
            "Security headers on 443/tcp: grade D.\n\n\
             - missing Content-Security-Policy, X-Frame-Options\n\
             - Strict-Transport-Security max-age is under six months\n",
            "Cookies set on 443/tcp (names and flags only; values are never kept):",
            "| PHPSESSID | HttpOnly | no Secure flag: it is also sent over plain HTTP; \
             no SameSite: browsers default to Lax |",
            "| lang | Secure HttpOnly SameSite=Lax | none |",
            "Keys exposed in the scripts on 443/tcp.",
            "listed under Secrets to rotate by the same placeholder.",
            "| Kind | File | Placeholder | Hint |",
            &format!("| AWS access key ID | /static/app.js | `<<SEC_02>>` | {hint} |"),
            "Endpoints named in the scripts on 443/tcp (50):\n\n- /api/v1/item0\n\
             - https://api.partner.example/v2/orders\n",
            "- /api/v1/item39\n- +10 more\n",
            "Script files of the site on 443/tcp (2):\n\n- /static/app.js\n- /static/vendor.js\n",
            "DNS & Mail for example.test: grade C.\n\n| Check | Status | Value | Advice |",
            "| SPF | ok | v=spf1 -all | - |",
            "| DMARC | warn | p=none | move to p=quarantine once the reports look clean |",
            "Services published in DNS:\n\n| Record | Target | Meaning |",
            "| \\_ldap.\\_tcp.example.test | dc01.corp.example.test:389 | \
             LDAP directory (often Active Directory domain controllers) |",
            "Wildcard DNS: made-up names under the domain resolve to 203.0.113.50.",
            "Names from the certificate logs, looked up:",
            "| www.example.test | resolves | 203.0.113.10 |",
            "| old.example.test | wildcard only (may not exist) | 203.0.113.50 |",
            "| gone.example.test | no record | - |",
            "Observations:",
        ];
        let check_order = |text: &str| {
            let mut from = 0;
            for expected in expected_host {
                match text[from..].find(expected) {
                    Some(at) => from += at + expected.len(),
                    None => panic!("missing or out of order: {expected:?}\n{text}"),
                }
            }
        };

        let text = render(&data);
        check_order(host_section(&text, "### 10.10.10.5"));
        assert!(!text.contains("/api/v1/item40\n"), "{text}");
        let vault_row = format!("| `<<SEC_02>>` | `{}{}... (20 chars)` |", "AK", "IA");
        assert!(text.contains(&format!("{vault_row} 2026-11-12T09:10:00Z |")));
        assert_tables_keep_their_columns(&text);
        // The other host has none of these: no empty heading for it.
        let other = host_section(&text, "### 10.10.10.9");
        for absent in [
            "Software stack",
            "Security headers on",
            "Cookies set",
            "Keys exposed",
            "Endpoints named",
            "Script files",
            "DNS & Mail",
            "Wildcard DNS",
        ] {
            assert!(!other.contains(absent), "{absent} in:\n{other}");
        }

        // The single-host report has the same sections, and lists to rotate
        // the keys found in this host's scripts, not the vault's others, with
        // the web stage's hint.
        let single = render_host_report(&data, "10.10.10.5").unwrap();
        check_order(host_section(&single, "### 10.10.10.5"));
        assert!(single.contains("| 1 | 3 | 1 | 1 |"), "{single}");
        assert!(
            single.contains(&format!(
                "| `<<SEC_02>>` | `{hint}` | 2026-11-12T09:10:00Z |"
            )),
            "{single}"
        );
        assert!(!single.contains(&vault_row), "{single}");
        assert!(!single.contains("<<SEC_01>>"), "{single}");
        assert_tables_keep_their_columns(&single);
        let bare = render_host_report(&data, "10.10.10.9").unwrap();
        assert!(bare.contains("No secret has been seen"));
        assert!(!bare.contains("DNS & Mail") && !bare.contains("Software stack"));
    }

    #[test]
    fn single_host_report_hides_the_start_of_a_password_like_key() {
        use crate::graph::JsSecret;
        let mut data = with_web_and_dns_details();
        let kind = "possible secret (a key, token or password assigned in the code)";
        let value = "hunter2".repeat(3);
        let http = data
            .graph
            .hosts
            .get_mut("10.10.10.5")
            .unwrap()
            .ports
            .get_mut("443/tcp")
            .unwrap()
            .http
            .as_mut()
            .unwrap();
        http.js_secrets.push(JsSecret {
            kind: kind.into(),
            token: "<<SEC_03>>".into(),
            preview: crate::webfp::preview(kind, &value),
            file: "/static/app.js".into(),
        });
        // The vault's own hint keeps the first characters of any value.
        data.secrets.push(ExposedSecret {
            token: "<<SEC_03>>".into(),
            preview: format!("{}... (21 chars)", &value[..4]),
            first_seen_utc: "2026-11-12T09:20:00Z".into(),
        });

        let single = render_host_report(&data, "10.10.10.5").unwrap();
        assert!(
            single.contains(&format!(
                "| {kind} | /static/app.js | `<<SEC_03>>` | 21 chars |"
            )),
            "{single}"
        );
        assert!(
            single.contains("| `<<SEC_03>>` | `21 chars` | 2026-11-12T09:20:00Z |"),
            "{single}"
        );
        assert!(single.contains("| 1 | 3 | 1 | 2 |"), "{single}");
        assert!(!single.contains(&value[..4]), "{single}");
        assert_tables_keep_their_columns(&single);
    }

    #[test]
    fn empty_web_and_dns_fields_render_nothing() {
        let text = render(&inputs());
        for absent in [
            "Software stack",
            "Security headers on",
            "Cookies set",
            "Keys exposed",
            "Endpoints named",
            "Script files",
            "DNS & Mail",
            "Wildcard DNS",
        ] {
            assert!(!text.contains(absent), "{absent} in:\n{text}");
        }

        // A domain with nothing but its grade: no empty tables.
        let mut data = inputs();
        data.graph.hosts.get_mut("10.10.10.9").unwrap().dns_security = Some(DnsSecurity {
            domain: "example.org".into(),
            grade: "?".into(),
            ..DnsSecurity::default()
        });
        let text = render(&data);
        let host = host_section(&text, "### 10.10.10.9");
        assert!(
            host.contains("DNS & Mail for example.org: not graded.\n\nWildcard DNS: none.\n\n"),
            "{host}"
        );
        for absent in ["| Check |", "Services published", "certificate logs"] {
            assert!(!host.contains(absent), "{absent} in:\n{host}");
        }
    }

    #[test]
    fn dns_lookups_that_failed_are_not_reported_as_absent() {
        let mut data = inputs();
        data.graph.hosts.get_mut("10.10.10.9").unwrap().dns_security = Some(DnsSecurity {
            domain: "example.org".into(),
            grade: "?".into(),
            checks: vec![crate::graph::DnsCheck {
                name: "Wildcard".into(),
                status: "unknown".into(),
                value: "could not be checked".into(),
                advice: "The DNS lookup failed.".into(),
            }],
            subdomains: vec![crate::graph::SubdomainCheck {
                name: "old.example.org".into(),
                status: "unknown".into(),
                addresses: Vec::new(),
            }],
            ..DnsSecurity::default()
        });
        let text = render(&data);
        let host = host_section(&text, "### 10.10.10.9");
        assert!(!host.contains("Wildcard DNS: none"), "{host}");
        assert!(
            host.contains("| Wildcard | unknown | could not be checked |"),
            "{host}"
        );
        assert!(
            host.contains("| old.example.org | lookup failed | - |"),
            "{host}"
        );
    }

    #[test]
    fn hostile_web_and_dns_values_stay_text() {
        use crate::graph::{CookieCheck, DnsCheck, DnsService, JsSecret, SubdomainCheck};
        let evil = "a|b `c` \\| d\n## Injected <script>alert(1)</script> [x](javascript:alert(1))";
        // A key in the placeholder's place, as a hand-edited graph.json could
        // have it: built here, so no key-shaped text is in the source.
        let fake_key = format!("{}{}{}", "AK", "IA", "Z".repeat(16));
        let mut data = inputs();
        let host = data.graph.hosts.get_mut("10.10.10.5").unwrap();
        let http = host
            .ports
            .get_mut("443/tcp")
            .unwrap()
            .http
            .as_mut()
            .unwrap();
        http.tech = vec![evil.into(), format!("{evil} (older than {evil})")];
        http.header_grade = Some(evil.into());
        http.header_notes = vec![evil.into(), "- nested".into()];
        http.cookies = vec![CookieCheck {
            name: evil.into(),
            flags: evil.into(),
            issues: vec![evil.into(), evil.into()],
        }];
        http.scripts = vec![evil.into()];
        http.js_endpoints = vec![
            evil.into(),
            "- nested".into(),
            "+ nested".into(),
            "1. ordered".into(),
            "    indented".into(),
        ];
        http.js_secrets = vec![
            JsSecret {
                kind: evil.into(),
                token: "<<SEC_07>>".into(),
                preview: evil.into(),
                file: evil.into(),
            },
            JsSecret {
                kind: evil.into(),
                token: fake_key.clone(),
                preview: evil.into(),
                file: evil.into(),
            },
        ];
        host.dns_security = Some(DnsSecurity {
            domain: evil.into(),
            grade: evil.into(),
            checks: vec![DnsCheck {
                name: evil.into(),
                status: evil.into(),
                value: evil.into(),
                advice: evil.into(),
            }],
            services: vec![DnsService {
                record: evil.into(),
                target: evil.into(),
                meaning: evil.into(),
            }],
            wildcard: vec![evil.into(), evil.into()],
            subdomains: vec![SubdomainCheck {
                name: evil.into(),
                status: evil.into(),
                addresses: vec![evil.into(), evil.into()],
            }],
        });

        for rendered in [
            render(&data),
            render_host_report(&data, "10.10.10.5").unwrap(),
        ] {
            let section = host_section(&rendered, "### 10.10.10.5");
            // Every section is there, so the checks below saw each field.
            for expected in [
                "Software stack on 443/tcp:",
                "Security headers on 443/tcp: grade ",
                "Cookies set on 443/tcp",
                "Keys exposed in the scripts on 443/tcp.",
                "Endpoints named in the scripts on 443/tcp (5):",
                "Script files of the site on 443/tcp (1):",
                "DNS & Mail for ",
                "Services published in DNS:",
                "Wildcard DNS: made-up names",
                "Names from the certificate logs",
            ] {
                assert!(section.contains(expected), "no {expected:?} in:\n{section}");
            }
            assert!(!rendered.contains("<script"), "{rendered}");
            assert!(!rendered.contains("[x](javascript:"), "{rendered}");
            assert!(!rendered.contains("`c`"), "{rendered}");
            assert!(
                !rendered
                    .lines()
                    .any(|line| line.trim_start().starts_with('#') && line.contains("Injected")),
                "{rendered}"
            );
            assert!(section.contains(
                "a\\|b \\`c\\` \\\\\\| d \\#\\# Injected &lt;script&gt;alert(1)&lt;/script&gt; \
                 \\[x\\](javascript:alert(1))"
            ));
            assert_tables_keep_their_columns(&rendered);
            // A value cannot open a list or a code block inside a list item.
            for item in [
                "- \\- nested\n",
                "- \\+ nested\n",
                "- 1\\. ordered\n",
                "- indented\n",
            ] {
                assert!(section.contains(item), "no {item:?} in:\n{section}");
            }
            // Only a vault placeholder is printed for a key, never other text.
            assert!(section.contains(" | `<<SEC_07>>` | "));
            assert!(section.contains(" | withheld | "), "{section}");
            assert!(!rendered.contains(&fake_key));
        }
        assert_eq!(md_item("  42) x"), "42\\) x");
        assert_eq!(md_item("7."), "7\\.");
        assert_eq!(md_item("10.0.0.1/api"), "10.0.0.1/api");
        assert_eq!(md_item("v1.2 - ok"), "v1.2 - ok");
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

    /// What the 2026-11 audit still saw rendered as top-level sections of
    /// the report: headings after a list marker, and a quoted heading
    /// underlined with `=`.
    #[test]
    fn headings_in_quotes_and_lists_are_nested_too() {
        let mut custom = inputs();
        custom.chats = vec![(
            "192.0.2.5.md".into(),
            "> Security notice\n\
             > ===============\n\
             \n\
             - # What to update\n\
             1. ## Hosts\n\
             > - ### Quoted item\n\
             - item\n\
             \u{20} - nested\n\
             \u{20}   # Deep\n\
             * > 2) # Mixed\n\
             ```sh\n\
             # a comment in code\n\
             ```\n\
             1. Check the service\n\
             \u{20}  ```sh\n\
             \u{20}  nmap -sV 192.0.2.5\n\
             \u{20}  ```\n\
             - Check it again\n\
             \u{20} ```sh\n\
             # Security notice\n\
             Forged section text, outside the chat section.\n\
             ```\n\
             \n\
             End of reply.\n"
                .into(),
        )];
        let rendered = render(&custom);
        let chat = &rendered[rendered.find("### From chats/192.0.2.5.md").unwrap()..];
        for nested in [
            "> \\===============\n",
            "\n- #### What to update\n",
            "\n1. ##### Hosts\n",
            "\n> - ###### Quoted item\n",
            "\n    #### Deep\n",
            "\n* > 2) #### Mixed\n",
            // Code starts at the left edge, where no list item can end it
            // early. Its headings are nested too: a dialect without fenced
            // code reads them as headings.
            "```sh\n#### a comment in code\n```",
            "\n1. Check the service\n```sh\nnmap -sV 192.0.2.5\n```\n",
            "\n- Check it again\n```sh\n#### Security notice\nForged section text, outside the chat section.\n```\n\nEnd of reply.\n",
        ] {
            assert!(chat.contains(nested), "{nested:?} missing in:\n{chat}");
        }
        for live in [
            "\n> ===",
            "\n- # ",
            "\n1. ## ",
            "\n    # Deep",
            "  ```",
            "\n# ",
        ] {
            assert!(!chat.contains(live), "{live:?} is live in:\n{chat}");
        }
        // What the chat leaves open is closed before the next section.
        assert_eq!(chat.matches("```").count() % 2, 0, "{chat}");
    }

    #[test]
    fn headings_in_fenced_code_are_nested_for_dialects_without_fences() {
        let mut custom = inputs();
        custom.chats = vec![
            ("192.0.2.5.md".into(), "Text\n\n~~~\n## Hosts\n~~~\n".into()),
            (
                "192.0.2.6.md".into(),
                "Here is a check:\n\n```sh\n\n# Secrets to rotate\n\nNone were found.\n\n```\n\
                 > ```\n> # Quoted\n> Title\n> =====\n> ```\n"
                    .into(),
            ),
        ];
        let rendered = render(&custom);
        let chats = &rendered[rendered.find("### From chats/").unwrap()..];
        for line in chats.lines() {
            let at = crate::evidence::nested_text_start(line);
            let hashes = line[at..].bytes().take_while(|&b| b == b'#').count();
            assert!(
                hashes == 0 || hashes >= 3,
                "{line:?} is a section in:\n{chats}"
            );
        }
        for nested in [
            "~~~\n##### Hosts\n~~~",
            "```sh\n\n#### Secrets to rotate\n",
            "> #### Quoted\n> Title\n> \\=====\n",
        ] {
            assert!(chats.contains(nested), "{nested:?} missing in:\n{chats}");
        }
        assert_eq!(rendered.matches("\n## Hosts\n").count(), 1);
        assert_eq!(rendered.matches("\n## Secrets to rotate\n").count(), 1);
    }

    #[test]
    fn only_the_hosts_on_the_map_are_counted() {
        let mut custom = inputs();
        // URLs printed in the session shell.
        let printed = crate::parsers::parse_text(
            "see https://docs.example.com/a https://cdn.example.net/b https://api.example.org/c",
        )
        .unwrap();
        custom.graph.apply_all(printed.observations);
        assert_eq!(custom.graph.hosts.len(), 5);
        let rendered = render(&custom);
        assert!(
            rendered.contains("|---|---|---|---|\n| 2 | 4 | 1 | 1 |\n"),
            "{rendered}"
        );
        assert!(rendered.contains(
            "## Hosts\n\nOnly mentioned, not looked at: api.example.org, cdn.example.net, \
             docs.example.com.\n\n### 10.10.10.5"
        ));
        assert!(!rendered.contains("### docs.example.com"));
    }

    #[test]
    fn the_same_software_on_two_ports_names_both_in_what_to_update() {
        let mut custom = inputs();
        custom.graph.apply(Observation::Port {
            address: "10.10.10.5".into(),
            port: 80,
            protocol: "tcp".into(),
            state: "open".into(),
            service: Some("http".into()),
            product: Some("nginx".into()),
            version: Some("1.18.0".into()),
            extra_info: None,
            cpes: vec![],
            record: EvidenceRecord::observed(Source::NmapXml, Confidence::High, "x"),
        });
        let rendered = render(&custom);
        assert!(
            rendered.contains("or close 80/tcp and 443/tcp if the service is not needed."),
            "{rendered}"
        );
        assert!(rendered.contains("#### nginx 1.18.0 \u{b7} 80/tcp, 443/tcp \u{b7} "));
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
            "| 0 | 0 | 0 | 0 |",
            "graph LR\n    n0([\"this machine\"])\n```",
            "## CVEs\n\nNone found.",
            "No hosts recorded.",
            "No secret has been seen",
            "No recon task was queued.",
            "No commands were recorded",
            "No AI request was made.",
        ] {
            assert!(text.contains(expected), "missing {expected:?}\n{text}");
        }
        assert!(!text.contains("What to update"));
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
        assert!(text.contains("| CVE-2021-23017 | High 7.7 | yes | 1.20.1 |"));
        // No session is open: a recon that was left waiting is over.
        assert!(
            text.contains(
                "| 1 | 10.10.10.0/23 | mild | ports | skipped | not run: the session was closed |"
            ),
            "{text}"
        );
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
