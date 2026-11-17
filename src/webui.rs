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
/// caching of token-bearing pages, no referrer, and a content policy that
/// allows scripts only from the coordinator itself.
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
}
