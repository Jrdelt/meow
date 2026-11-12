//! The browser map (`meow map`): one HTML page plus its script, style sheet
//! and the vendored Cytoscape.js, all embedded in the binary so the map
//! works offline.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const PAGE: &str = include_str!("../assets/map.html");
const SCRIPT: &str = include_str!("../assets/map.js");
const STYLE: &str = include_str!("../assets/map.css");
const CYTOSCAPE: &str = include_str!("../assets/cytoscape.min.js");

fn with_type(content_type: &'static str, body: String) -> Response {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
        body,
    )
        .into_response()
}

/// The map page. The session token is written into the asset URLs so the
/// browser can fetch them; it is 64 hex characters, so no escaping applies.
pub fn page(token: &str) -> Response {
    debug_assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    with_type("text/html; charset=utf-8", PAGE.replace("{{TOKEN}}", token))
}

pub fn asset(name: &str) -> Response {
    match name {
        "map.js" => with_type("text/javascript; charset=utf-8", SCRIPT.to_owned()),
        "map.css" => with_type("text/css; charset=utf-8", STYLE.to_owned()),
        "cytoscape.min.js" => with_type("text/javascript; charset=utf-8", CYTOSCAPE.to_owned()),
        _ => StatusCode::NOT_FOUND.into_response(),
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

/// Opens `url` in the default browser. Returns false if no opener could be
/// started (headless machine, SSH session).
pub fn open_in_browser(url: &str) -> bool {
    use std::process::{Command, Stdio};
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("open");
        command.arg(url);
        command
    } else if cfg!(windows) {
        // rundll32 takes the URL as one argument, unlike `cmd /c start`.
        let mut command = Command::new("rundll32");
        command.args(["url.dll,FileProtocolHandler", url]);
        command
    } else {
        let mut command = Command::new("xdg-open");
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
        assert!(
            !PAGE.contains("<script>"),
            "inline scripts would need a weaker content policy"
        );
        assert_eq!(PAGE.matches("{{TOKEN}}").count(), 3);
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
    fn unknown_assets_are_not_served() {
        assert_eq!(asset("map.js").status(), StatusCode::OK);
        assert_eq!(asset("../Cargo.toml").status(), StatusCode::NOT_FOUND);
        assert_eq!(asset("map.html").status(), StatusCode::NOT_FOUND);
    }
}
