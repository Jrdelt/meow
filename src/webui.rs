//! The browser map (`meow map`): one HTML page plus its script, style sheet,
//! device icons and the vendored Cytoscape.js, all embedded in the binary so
//! the map works offline.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const PAGE: &str = include_str!("../assets/map.html");
const SCRIPT: &str = include_str!("../assets/map.js");
const STYLE: &str = include_str!("../assets/map.css");
const CYTOSCAPE: &str = include_str!("../assets/cytoscape.min.js");

/// One drawing per `topology::Role`, served as `icon-<role>.svg`. A switch
/// is drawn like a network segment: both are the box everything plugs into.
const ICONS: &[(&str, &str)] = &[
    ("internet", include_str!("../assets/icons/internet.svg")),
    ("you", include_str!("../assets/icons/you.svg")),
    ("segment", include_str!("../assets/icons/segment.svg")),
    ("switch", include_str!("../assets/icons/segment.svg")),
    ("router", include_str!("../assets/icons/router.svg")),
    ("firewall", include_str!("../assets/icons/firewall.svg")),
    ("server", include_str!("../assets/icons/server.svg")),
    ("client", include_str!("../assets/icons/client.svg")),
    // Not a role: the map picks it from a device's open ports.
    ("printer", include_str!("../assets/icons/printer.svg")),
];

fn with_type(content_type: &'static str, body: String) -> Response {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
        body,
    )
        .into_response()
}

fn with_static(content_type: &'static str, body: &'static str) -> Response {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
        body,
    )
        .into_response()
}

fn valid_session_secret(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn escape_html_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// The map page. The session token is written into the asset URLs so the
/// browser can fetch them; `page_key` is a second secret that only ever
/// travels from the session to its page so a program that takes over the
/// port after the session has ended cannot feed the open tab.
pub fn page(token: &str, page_key: &str) -> Response {
    if !valid_session_secret(token) || !valid_session_secret(page_key) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    with_type(
        "text/html; charset=utf-8",
        PAGE.replace("{{TOKEN}}", token)
            .replace("{{PAGE}}", page_key),
    )
}

/// What a reload of the map gets before it has shown its token again: no
/// secret in it. Its script reads the token the page kept in the tab's own
/// storage (separate for each port) and loads the map with it.
const RELOAD_PAGE: &str = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>meow map</title><script src=\"/reload.js\"></script></head>\
<body style=\"background:#0b0c0e;color:#e7e9ec;font:14px monospace;padding:24px\">\
<p id=\"why\">Opening the map\u{2026}</p></body></html>\n";

const RELOAD_SCRIPT: &str = "(function () {\n\
  var token = '';\n\
  try { token = sessionStorage.getItem('meow-map-token') || ''; } catch (_) {}\n\
  if (/^[0-9a-f]{64}$/.test(token)) {\n\
    location.replace('/?token=' + token);\n\
    return;\n\
  }\n\
  document.addEventListener('DOMContentLoaded', function () {\n\
    document.getElementById('why').textContent =\n\
      'This map link has no session any more: run `meow map` in the session again.';\n\
  });\n\
})();\n";

pub fn reload_page() -> Response {
    with_type("text/html; charset=utf-8", RELOAD_PAGE.to_owned())
}

pub fn reload_script() -> Response {
    with_static("text/javascript; charset=utf-8", RELOAD_SCRIPT)
}

pub fn asset(name: &str) -> Response {
    match name {
        "map.js" => with_static("text/javascript; charset=utf-8", SCRIPT),
        "map.css" => with_static("text/css; charset=utf-8", STYLE),
        "cytoscape.min.js" => with_static("text/javascript; charset=utf-8", CYTOSCAPE),
        _ => {
            let role = name
                .strip_prefix("icon-")
                .and_then(|rest| rest.strip_suffix(".svg"));
            match ICONS.iter().find(|(known, _)| Some(*known) == role) {
                Some((_, svg)) => with_static("image/svg+xml", svg),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }
}

/// Headers added to every response of the loopback server: no framing, no
/// caching of token-bearing pages, no referrer, a content policy that
/// allows scripts only from the coordinator itself, and nothing loaded by
/// a page of another origin (which would learn that meow runs, and where).
pub fn security_headers(response: &mut Response, port: u16) {
    let policy = format!(
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
         connect-src 'self' ws://127.0.0.1:{port} ws://localhost:{port}; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&policy) {
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
}

/// `http://127.0.0.1:<port>/?token=<token>`
pub fn map_url(port: u16, token: &str) -> String {
    format!("http://127.0.0.1:{port}/?token={token}")
}

/// The page `meow map` hands to the desktop's opener, in the workspace's
/// `tmp` folder.
pub const OPENER_FILE: &str = "map.html";

fn validate_bootstrap_url(url: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(url).map_err(|_| anyhow::anyhow!("invalid map URL"))?;
    let loopback = matches!(parsed.scheme(), "http" | "https")
        && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost"))
        && parsed.port().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
        && !url
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | ';' | '\\' | ' '));
    if !loopback {
        anyhow::bail!("map bootstrap URL must target loopback HTTP(S)");
    }
    Ok(())
}

/// A page that sends the browser on to `url`. The opener is given this
/// file's path, never the URL: a program's arguments can be read by every
/// user on the machine for as long as it runs, and the URL carries the
/// session token. The file is as private as `runtime.json` beside it.
pub fn opener_page(url: &str) -> String {
    if validate_bootstrap_url(url).is_err() {
        return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
                <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\">\
                <title>meow map</title></head>\
                <body><p>Refused invalid map address.</p></body></html>\n"
            .to_owned();
    }
    let safe = escape_html_attr(url);
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>meow map</title>\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n\
         <meta http-equiv=\"refresh\" content=\"0;url={safe}\"></head>\n\
         <body><p>Opening the meow map. If nothing happens, \
         <a href=\"{safe}\" rel=\"noreferrer\">open it here</a>.</p></body></html>\n"
    )
}

/// Writes a `0600` local redirect file (`map.html`) in `tmp_dir` so the
/// browser opener's command line (`ps aux` / `/proc/<pid>/cmdline`) never
/// contains the session bearer token.
pub fn write_bootstrap(tmp_dir: &std::path::Path, url: &str) -> anyhow::Result<std::path::PathBuf> {
    validate_bootstrap_url(url)?;
    let path = tmp_dir.join(OPENER_FILE);
    let html = opener_page(url);
    crate::workspace::write_private_atomic(&path, html.as_bytes())?;
    Ok(path)
}

#[cfg(windows)]
fn windows_rundll32() -> std::path::PathBuf {
    use std::path::{Component, PathBuf, Prefix};
    let trusted = std::env::var_os("SystemRoot")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|path| {
            let mut comps = path.components();
            matches!(comps.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
                && matches!(comps.next(), Some(Component::RootDir))
                && comps.all(|c| matches!(c, Component::Normal(_)))
        })
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    trusted.join("System32").join("rundll32.exe")
}

fn validate_browser_target(target: &str) -> bool {
    if target.is_empty() || target.starts_with('-') || target.chars().any(char::is_control) {
        return false;
    }
    if validate_bootstrap_url(target).is_ok() {
        return true;
    }
    // Reject Windows UNC/SMB paths (`\\server\share\...`) on every platform.
    if target.starts_with(r"\\") {
        return false;
    }
    let path = std::path::Path::new(target);
    if !path.is_absolute() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        if !matches!(
            path.components().next(),
            Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_))
        ) {
            return false;
        }
    }
    let is_html = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("html") || ext.eq_ignore_ascii_case("htm"));
    is_html && std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

/// Opens `url` (a validated loopback URL, or the absolute path of a private
/// `.html` opener page) in the default browser. Returns false if the target
/// is unsafe or no opener could be started (headless machine, SSH session).
pub fn open_in_browser(url: &str) -> bool {
    use std::process::{Command, Stdio};
    if !validate_browser_target(url) {
        return false;
    }
    let mut command = if cfg!(target_os = "macos") {
        let Some(prog) = crate::tools::find_program("open") else {
            return false;
        };
        let mut command = Command::new(prog);
        command.arg(url);
        command
    } else if cfg!(windows) {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let sys32 = windows_rundll32();
            if !sys32.is_file() {
                return false;
            }
            let mut command = Command::new(sys32);
            command.creation_flags(0x08000000);
            command.args(["url.dll,FileProtocolHandler", url]);
            command
        }
        #[cfg(not(windows))]
        {
            return false;
        }
    } else {
        let Some(prog) = crate::tools::find_program("xdg-open") else {
            return false;
        };
        let mut command = Command::new(prog);
        command.arg(url);
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page and the HUD say the same of a stage: the page's words for
    /// each status are the queue's, and the recons of a session that went
    /// away are shown with the very words the session stores for them.
    #[test]
    fn the_page_words_a_stage_as_the_queue_and_the_hud_do() {
        use crate::queue::{
            status_word, CLOSED_DETAIL, LIGHT_DETAIL, NOT_RUN, NOT_RUN_CLOSED, NOT_RUN_ENDED,
        };
        for status in [
            "pending",
            "running",
            "done",
            "skipped",
            "failed",
            "interrupted",
        ] {
            let pair = format!("{status}: '{}'", status_word(status));
            assert!(SCRIPT.contains(&pair), "the page has no {pair}");
        }
        assert!(SCRIPT.contains(&format!(
            "var CLOSED_DETAIL = '{CLOSED_DETAIL}', NOT_RUN_DETAIL = '{NOT_RUN_CLOSED}';"
        )));
        // A stage the end of its session left out is told by how its
        // reason starts, whichever way the session ended.
        assert!(SCRIPT.contains(&format!("/^{NOT_RUN}/.test(stage.detail)")));
        for detail in [NOT_RUN_CLOSED, NOT_RUN_ENDED] {
            assert!(detail.starts_with(NOT_RUN), "{detail}");
        }
        // The reason it tells apart is found in what the session says.
        assert!(SCRIPT.contains("/light mode/i") && LIGHT_DETAIL.contains("light mode"));
        assert!(!CLOSED_DETAIL.contains("light mode"));
        for detail in [CLOSED_DETAIL, LIGHT_DETAIL] {
            assert!(detail.starts_with("stopped: "), "{detail}");
        }
        // Nothing on the page says a recon goes on in a later session.
        assert!(!SCRIPT.to_lowercase().contains("resum"));
    }

    #[test]
    fn page_references_its_assets_with_the_token() {
        let token = "ab".repeat(32);
        let page_key = "cd".repeat(32);
        assert!(
            !PAGE.contains("<script>"),
            "inline scripts would need a weaker content policy"
        );
        assert_eq!(PAGE.matches("{{TOKEN}}").count(), 3);
        assert_eq!(PAGE.matches("{{PAGE}}").count(), 1);
        assert!(SCRIPT.contains("message.key !== pageKey"));
        assert_eq!(page(&token, &page_key).status(), StatusCode::OK);
        assert_eq!(
            page("bad\"><script>", &page_key).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let filled = PAGE.replace("{{TOKEN}}", &token);
        for asset in ["map.css", "cytoscape.min.js", "map.js"] {
            assert!(
                filled.contains(&format!("/assets/{asset}?token={token}")),
                "{asset}"
            );
        }
        assert_eq!(
            map_url(8765, &token),
            format!("http://127.0.0.1:8765/?token={token}")
        );
        // The opener's page leads there and nowhere else.
        let opener = opener_page(&map_url(8765, &token));
        assert_eq!(
            opener
                .matches(&format!("http://127.0.0.1:8765/?token={token}"))
                .count(),
            2
        );
        assert!(!opener.contains("<script"));
        // Tokens with '-' and '_' (accepted by RuntimeInfo::read) also work.
        let dash_url = map_url(8765, "tok_en-1234");
        assert!(opener_page(&dash_url).contains("http://127.0.0.1:8765/?token=tok_en-1234"));

        let tmp = tempfile::tempdir().unwrap();
        let boot = write_bootstrap(tmp.path(), &map_url(8765, &token)).unwrap();
        assert_eq!(boot.file_name().and_then(|n| n.to_str()), Some(OPENER_FILE));
        assert!(!boot.to_string_lossy().contains(&token));
        let html = std::fs::read_to_string(&boot).unwrap();
        assert!(html.contains(&format!("http://127.0.0.1:8765/?token={token}")));
        assert!(validate_browser_target(&boot.to_string_lossy()));
    }

    #[test]
    fn opener_page_and_browser_target_refuse_hostile_inputs_in_release() {
        for hostile in [
            "javascript:alert(1)",
            "https://evil.example/?token=abc",
            "http://127.0.0.1:8765/?token=abc\"><script>alert(1)</script>",
            "http://127.0.0.1:8765/?token=abc;url=https://evil.example",
            "http://user@127.0.0.1:8765/?token=abc",
        ] {
            let rendered = opener_page(hostile);
            assert!(!rendered.contains("http-equiv=\"refresh\""), "{hostile}");
            assert!(!rendered.contains("evil.example"), "{hostile}");
            assert!(!rendered.contains("<script"), "{hostile}");
            assert!(!validate_browser_target(hostile), "{hostile}");
        }

        let tmp = tempfile::tempdir().unwrap();
        let sh = tmp.path().join("exploit.sh");
        std::fs::write(&sh, "#!/bin/sh\n").unwrap();
        assert!(!validate_browser_target(&sh.to_string_lossy()));
        assert!(!validate_browser_target("-option"));
        assert!(!validate_browser_target(r"\\evil.example\share\map.html"));
        assert!(!validate_browser_target("relative/map.html"));

        #[cfg(unix)]
        {
            let real = tmp.path().join("real.html");
            std::fs::write(&real, "<!doctype html>").unwrap();
            let link = tmp.path().join("link.html");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(validate_browser_target(&real.to_string_lossy()));
            assert!(!validate_browser_target(&link.to_string_lossy()));
        }
    }

    #[test]
    fn scraped_text_is_never_inserted_as_html() {
        for forbidden in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
        ] {
            assert!(!SCRIPT.contains(forbidden), "map.js uses {forbidden}");
        }
        assert!(SCRIPT.contains("textContent"));
    }

    #[test]
    fn vendored_cytoscape_is_present_with_its_license() {
        assert!(CYTOSCAPE.len() > 300_000);
        assert!(CYTOSCAPE.starts_with("/**\n * Copyright (c) 2016-"));
        let license = include_str!("../assets/cytoscape.LICENSE");
        assert!(license.contains("Permission is hereby granted, free of charge"));
    }

    #[test]
    fn every_role_has_a_self_contained_icon() {
        use crate::topology::Role;
        for role in [
            Role::Internet,
            Role::You,
            Role::Segment,
            Role::Router,
            Role::Firewall,
            Role::Switch,
            Role::Server,
            Role::Client,
        ] {
            let name = serde_json::to_value(role).unwrap();
            let name = name.as_str().unwrap();
            let response = asset(&format!("icon-{name}.svg"));
            assert_eq!(response.status(), StatusCode::OK, "{name}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "image/svg+xml");
            // The map script draws the same roles.
            assert!(SCRIPT.contains(&format!("'{name}'")), "map.js lacks {name}");
        }
        for (name, svg) in ICONS {
            assert!(svg.starts_with("<svg xmlns="), "{name}");
            // Nothing is fetched from anywhere and nothing can run.
            for forbidden in ["http://", "https://", "<script", "<image", "onload"] {
                let rest = svg.replace("http://www.w3.org/2000/svg", "");
                assert!(!rest.contains(forbidden), "{name} contains {forbidden}");
            }
        }
        assert_eq!(asset("icon-.svg").status(), StatusCode::NOT_FOUND);
        assert_eq!(asset("icon-nope.svg").status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn unknown_assets_are_not_served() {
        assert_eq!(asset("map.js").status(), StatusCode::OK);
        assert_eq!(asset("../Cargo.toml").status(), StatusCode::NOT_FOUND);
        assert_eq!(asset("map.html").status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn ai_triage_panel_renders_full_width_below_cards() {
        let notices_end = PAGE
            .find("id=\"notices\"")
            .expect("notices list inside #cards");
        let cards_close = PAGE[notices_end..]
            .find("</div>")
            .map(|offset| notices_end + offset)
            .expect("closing </div> for #cards");
        let ai_card = PAGE.find("id=\"card-ai\"").expect("#card-ai section");
        let main_close = PAGE.find("</main>").expect("closing </main>");
        assert!(
            ai_card > cards_close && ai_card < main_close,
            "#card-ai must appear after #cards and inside <main>"
        );
        assert!(STYLE.contains("#card-ai"));
        assert!(STYLE.contains(".ai-prose"));
        assert!(SCRIPT.contains("function renderAiMarkdown("));
        assert!(SCRIPT.contains("function renderAiPanel("));
    }

    /// Runs the map's renderer of AI replies under Node, with a small
    /// stand-in for the page, on replies written to stall it: 200 KB each
    /// (a reply's limit), formatted in full, then the cap on what is. No
    /// reply makes many more elements than it has characters.
    const RENDER_CHECK: &str = r#"'use strict';
const src = require('fs').readFileSync(process.argv[2], 'utf8');
const start = src.indexOf('  function codeSpanCloser(');
const end = src.indexOf('  function renderAiPanel(');
if (start < 0 || end < start) { throw new Error('renderer not found'); }
let made = 0;
function node(tag) {
  made += 1;
  return { tag, children: [], appendChild(child) { this.children.push(child); return child; } };
}
const document = { createElement: node, createTextNode: (text) => { made += 1; return { text }; } };
function el(tag, className, text) {
  const n = node(tag);
  if (text !== undefined && text !== null) { n.textContent = String(text); }
  return n;
}
const [markdown, triage] = new Function('document', 'el',
  src.slice(start, end) + '\nreturn [renderAiMarkdown, renderTriage];')(document, el);
const N = 200000;
const fill = (unit) => unit.repeat(Math.floor(N / unit.length));
let failed = false;
function time(name, render, text) {
  const root = node('div');
  made = 0;
  const t = Date.now();
  render(root, text);
  const ms = Date.now() - t;
  console.log(`${name}: ${ms} ms, ${made} elements`);
  failed = failed || ms > 1500 || made > text.length + 10000;
  return root;
}
let backticks = '';
for (let run = 1; backticks.length < N; run += 1) { backticks = '`'.repeat(run) + 'a' + backticks; }
const table = (head) => '|'.repeat(head) + '\n|---\n' + '|\n'.repeat((N - head) / 2);
const formatted = {
  'heading of spaces': '# a' + ' '.repeat(N - 4) + 'b',
  'heading closed by spaced #s': '# a' + fill(' #'),
  'brackets': fill('[]'),
  'paragraph of short bracket lines': fill('[] [] [] [] []\n'),
  'quote of bracket lines': fill('> [] [] [] []\n'),
  'list of bracket items': fill('- [] [] [] []\n'),
  'links never closed': fill('[a]('),
  'links closed once at the end': fill('[a](http://x ') + ')',
  'code spans never closed': backticks,
  'wide table header over one-pipe rows': table(1000),
  'table header of half the reply': table(N / 2),
};
for (const [name, text] of Object.entries(formatted)) { time(name, markdown, text); }
// Past the cap the rest is one plain text node, whatever it holds.
const capped = { 'capped brackets': fill('[]'), 'capped backticks': backticks, 'capped table': table(1000) };
for (const [name, text] of Object.entries(capped)) {
  const root = time(name, triage, text);
  const rest = root.children[root.children.length - 1];
  if (!(rest.tag === 'pre' && rest.textContent.length > N / 2 && text.endsWith(rest.textContent))) {
    console.log(`${name}: the rest is not one plain text node`);
    failed = true;
  }
}
// A table still reads as one: short rows get the header's empty cells, and
// a row of more cells than allowed keeps the rest in its last one.
const wide = Array.from({ length: 40 }, (_, n) => `c${n}`).join(' | ');
const small = node('div');
markdown(small, '| a | b | c |\n|---|---|---|\n| 1 |\n| ' + wide + ' |');
const rows = small.children[0].children[1].children;
const cells = rows.map((row) => row.children.length);
const last = rows[1].children[31].children.map((text) => text.text).join('');
if (cells.join() !== '3,32' || last !== 'c31 | ' + wide.split(' | ').slice(32).join(' | ')) {
  console.log(`table cells ${cells}, last ${last}`);
  failed = true;
}
process.exit(failed ? 1 : 0);
"#;

    #[test]
    fn ai_replies_written_to_stall_the_map_render_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let (check, script) = (dir.path().join("check.js"), dir.path().join("map.js"));
        std::fs::write(&check, RENDER_CHECK).unwrap();
        std::fs::write(&script, SCRIPT).unwrap();
        let Ok(output) = std::process::Command::new("node")
            .arg(&check)
            .arg(&script)
            .output()
        else {
            eprintln!("Node is not installed: the map's reply renderer was not timed");
            return;
        };
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Runs the map's `reconStill` under Node on the recons a session sent
    /// last and prints them as it leaves them.
    const STILL_CHECK: &str = r#"'use strict';
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
function grab(from, to) {
  const start = src.indexOf(from), end = src.indexOf(to, start);
  if (start < 0 || end < start) { throw new Error('not found: ' + from); }
  return src.slice(start, end);
}
const code = grab('  var CLOSED_DETAIL = ', '  function reconRank(') +
  grab('  function reconStill() {', '  function paintRow(');
const state = { tasks: JSON.parse(fs.readFileSync(process.argv[3], 'utf8')) };
const byId = () => ({ classList: { add() {} } });
new Function('state', 'byId', 'renderRecon', 'reconTick',
  code + '\nreconStill();')(state, byId, () => {}, () => {});
console.log(JSON.stringify(state.tasks));
"#;

    /// When the session goes, an open map shows its recons in the words the
    /// session stores for them, as the HUD does for a session that is gone:
    /// a stage that had started (running, or stopped by light mode) is cut
    /// short, and only one that never started is "not run".
    #[test]
    fn the_map_ends_a_gone_sessions_recons_as_the_hud_does() {
        use crate::queue::{show_ended, TaskRow, CLOSED_DETAIL, LIGHT_DETAIL, NOT_RUN_CLOSED};
        let (start, end) = ("2026-11-21T21:46:40Z", "2026-11-21T21:46:45Z");
        let tasks = serde_json::json!([
            { "id": 1, "target": "192.0.2.1", "mode": "mild", "extra_flags": [],
              "created_utc": start, "stages": [
                { "stage": "trace", "status": "skipped",
                  "detail": "turned off in config.toml (recon.skip)" },
                { "stage": "ports", "status": "interrupted", "detail": LIGHT_DETAIL,
                  "started_utc": start, "finished_utc": end },
                { "stage": "udp", "status": "interrupted", "detail": LIGHT_DETAIL },
                { "stage": "services", "status": "pending", "detail": "",
                  "started_utc": start, "finished_utc": end },
                { "stage": "headers", "status": "pending", "detail": "" } ] },
            { "id": 2, "target": "198.51.100.7", "mode": "mild", "extra_flags": [],
              "created_utc": start, "stages": [
                { "stage": "dns", "status": "done", "detail": "2 records",
                  "started_utc": start, "finished_utc": end },
                { "stage": "ports", "status": "running", "detail": "", "started_utc": start,
                  "progress": { "percent": 42, "note": "SYN Stealth Scan" } },
                { "stage": "services", "status": "pending", "detail": "" } ] }
        ]);
        let mut hud: Vec<TaskRow> = serde_json::from_value(tasks.clone()).unwrap();
        show_ended(&mut hud);
        let words = |stages: &serde_json::Value| -> Vec<(String, String, String)> {
            stages
                .as_array()
                .unwrap()
                .iter()
                .map(|stage| {
                    let field = |name: &str| stage[name].as_str().unwrap_or("").to_owned();
                    (field("stage"), field("status"), field("detail"))
                })
                .collect()
        };
        let hud = serde_json::to_value(&hud).unwrap();
        let light = &words(&hud[0]["stages"]);
        assert_eq!(
            light[1],
            ("ports".into(), "interrupted".into(), CLOSED_DETAIL.into())
        );
        assert_eq!(
            light[2],
            ("udp".into(), "skipped".into(), NOT_RUN_CLOSED.into())
        );
        assert_eq!(light[3].2, CLOSED_DETAIL);
        assert_eq!(light[4].2, NOT_RUN_CLOSED);

        let dir = tempfile::tempdir().unwrap();
        let (check, script, sent) = (
            dir.path().join("check.js"),
            dir.path().join("map.js"),
            dir.path().join("tasks.json"),
        );
        std::fs::write(&check, STILL_CHECK).unwrap();
        std::fs::write(&script, SCRIPT).unwrap();
        std::fs::write(&sent, tasks.to_string()).unwrap();
        let Ok(output) = std::process::Command::new("node")
            .args([&check, &script, &sent])
            .output()
        else {
            eprintln!("Node is not installed: the map's end of a session was not checked");
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let map: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        for task in 0..2 {
            assert_eq!(words(&map[task]["stages"]), words(&hud[task]["stages"]));
            // The times a stage ran are kept, and nothing is still counting.
            for (shown, stored) in map[task]["stages"]
                .as_array()
                .unwrap()
                .iter()
                .zip(hud[task]["stages"].as_array().unwrap())
            {
                assert_eq!(shown["started_utc"], stored["started_utc"]);
                assert_eq!(shown["finished_utc"], stored["finished_utc"]);
                assert!(shown.get("progress").is_none());
            }
        }
    }
}
