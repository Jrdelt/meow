//! Web fingerprinting: what a site is built with, how its cookies and
//! security headers are set, and what its JavaScript files give away.
//!
//! Everything here reads text meow already fetched (a page's headers and
//! HTML, a script's source); nothing here touches the network. The `headers`
//! stage calls [`fingerprint`] on the page it fetches, and the `js` stage
//! calls [`extract_endpoints`] and [`find_secrets`] on the site's own
//! scripts. A key found is handed to the vault by the caller and only its
//! placeholder is kept.

use std::sync::LazyLock;

use regex::Regex;

use crate::graph::CookieCheck;

/// What the `headers` stage learns from one page.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Fingerprint {
    pub tech: Vec<String>,
    pub cookies: Vec<CookieCheck>,
    pub header_grade: String,
    pub header_notes: Vec<String>,
    /// Paths of the site's own scripts on this port.
    pub scripts: Vec<String>,
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> impl Iterator<Item = &'a str> {
    let name = name.to_ascii_lowercase();
    headers
        .iter()
        .filter(move |(k, _)| k.eq_ignore_ascii_case(&name))
        .map(|(_, v)| v.trim())
}

fn push(list: &mut Vec<String>, item: impl Into<String>) {
    let item = item.into();
    // "nginx" is dropped when "nginx 1.18.0" is already there, and replaced
    // when it comes after.
    let base = item.split_whitespace().next().unwrap_or("").to_owned();
    if let Some(pos) = list
        .iter()
        .position(|t| t.split_whitespace().next() == Some(&base))
    {
        if item.len() > list[pos].len() {
            list[pos] = item;
        }
        return;
    }
    list.push(item);
}

/// `nginx/1.18.0` -> `nginx 1.18.0`; `Apache/2.4.7 (Ubuntu)` -> `Apache httpd 2.4.7`.
fn product(token: &str) -> Option<String> {
    let (name, version) = match token.split_once('/') {
        Some((n, v)) => (
            n.trim(),
            Some(
                v.trim()
                    .trim_end_matches(|c: char| !c.is_ascii_alphanumeric()),
            ),
        ),
        None => (token.trim(), None),
    };
    let known = match name.to_ascii_lowercase().as_str() {
        "nginx" => "nginx",
        "apache" => "Apache httpd",
        "microsoft-iis" => "IIS",
        "openresty" => "OpenResty",
        "litespeed" => "LiteSpeed",
        "caddy" => "Caddy",
        "envoy" => "Envoy",
        "gunicorn" => "Gunicorn",
        "uvicorn" => "Uvicorn",
        "werkzeug" => "Werkzeug (Flask)",
        "python" => "Python",
        "php" => "PHP",
        "kestrel" => "ASP.NET Core (Kestrel)",
        "jetty" => "Jetty",
        "tomcat" | "apache-coyote" => "Apache Tomcat",
        "express" => "Express (Node.js)",
        "next.js" => "Next.js",
        "asp.net" => "ASP.NET",
        "cloudflare" => "Cloudflare",
        "akamaighost" => "Akamai",
        "varnish" => "Varnish",
        "lighttpd" => "lighttpd",
        "tengine" => "Tengine",
        "cowboy" => "Cowboy (Erlang/Elixir)",
        "phusion_passenger" => "Phusion Passenger",
        "servlet" => "Java Servlet",
        "plesklin" | "pleskwin" => "Plesk",
        _ => return None,
    };
    Some(
        match version.filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit())) {
            Some(v) => format!("{known} {v}"),
            None => known.to_owned(),
        },
    )
}

/// Cookie names that say which framework set them.
const COOKIE_TECH: &[(&str, &str)] = &[
    ("phpsessid", "PHP"),
    ("jsessionid", "Java"),
    ("asp.net_sessionid", "ASP.NET"),
    (".aspnetcore.", "ASP.NET Core"),
    ("aspxauth", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("csrftoken", "Django"),
    ("connect.sid", "Express (Node.js)"),
    ("ci_session", "CodeIgniter"),
    ("wordpress_", "WordPress"),
    ("wp-settings", "WordPress"),
    ("cfid", "ColdFusion"),
    ("cftoken", "ColdFusion"),
    ("__cf_bm", "Cloudflare"),
    ("cf_clearance", "Cloudflare"),
    ("awsalb", "AWS load balancer"),
    ("bigipserver", "F5 BIG-IP"),
    ("incap_ses", "Imperva"),
    ("visid_incap", "Imperva"),
    ("arraffinity", "Azure App Service"),
    ("_shopify", "Shopify"),
    ("prestashop-", "PrestaShop"),
    ("mage-", "Magento"),
    ("_gitlab_session", "GitLab"),
    ("grafana_session", "Grafana"),
    ("jenkins", "Jenkins"),
];

/// Signs in a page's HTML.
const HTML_TECH: &[(&str, &str)] = &[
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/_next/static", "Next.js"),
    ("__next_data__", "Next.js"),
    ("/_nuxt/", "Nuxt.js"),
    ("window.__nuxt__", "Nuxt.js"),
    ("data-reactroot", "React"),
    ("data-v-app", "Vue.js"),
    ("drupal.settings", "Drupal"),
    ("/sites/default/files", "Drupal"),
    ("/media/jui/", "Joomla"),
    ("cdn.shopify.com", "Shopify"),
    ("static.wixstatic.com", "Wix"),
    ("static1.squarespace.com", "Squarespace"),
    (
        "name=\"csrf-param\" content=\"authenticity_token\"",
        "Ruby on Rails",
    ),
    ("__viewstate", "ASP.NET Web Forms"),
    ("__sveltekit", "SvelteKit"),
    ("__remixcontext", "Remix"),
    ("___gatsby", "Gatsby"),
    ("googletagmanager.com", "Google Tag Manager"),
    ("/static/js/main.", "Create React App"),
    ("ghost-", "Ghost"),
    ("/typo3", "TYPO3"),
];

static GENERATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"'<>]{1,80})["']"#)
        .unwrap()
});
static NG_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"ng-version="(\d+\.\d+(?:\.\d+)?)""#).unwrap());
static SCRIPT_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']([^"'<>\s]{1,300})["']"#).unwrap()
});
/// `jquery-3.6.0.min.js`, `jquery.min.js?ver=3.6.0`, `/libs/jquery/3.6.0/`, `jquery@3.6.0`.
static LIBRARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(jquery-ui|jquery|bootstrap|angular|react-dom|react|vue|lodash|moment|underscore|backbone|ember|d3|three|alpinejs|alpine|axios|handlebars|knockout|dojo|prototype|mootools|swiper|select2|datatables|chart)(?:\.js)?(?:[-.@/]|\.min\.js\?ver=|\.js\?ver=)v?(\d+\.\d+(?:\.\d+)?)",
    )
    .unwrap()
});

fn library_name(lower: &str) -> &'static str {
    match lower {
        "jquery" => "jQuery",
        "jquery-ui" => "jQuery UI",
        "bootstrap" => "Bootstrap",
        "angular" => "AngularJS",
        "react" | "react-dom" => "React",
        "vue" => "Vue.js",
        "lodash" => "Lodash",
        "moment" => "Moment.js",
        "underscore" => "Underscore.js",
        "backbone" => "Backbone.js",
        "ember" => "Ember.js",
        "d3" => "D3.js",
        "three" => "three.js",
        "alpine" | "alpinejs" => "Alpine.js",
        "axios" => "Axios",
        "handlebars" => "Handlebars",
        "knockout" => "Knockout",
        "dojo" => "Dojo",
        "prototype" => "Prototype",
        "mootools" => "MooTools",
        "swiper" => "Swiper",
        "select2" => "Select2",
        "datatables" => "DataTables",
        "chart" => "Chart.js",
        _ => "",
    }
}

fn version_below(version: &str, limit: &[u32]) -> bool {
    let parts: Vec<u32> = version.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    for (index, bound) in limit.iter().enumerate() {
        let have = parts.get(index).copied().unwrap_or(0);
        if have != *bound {
            return have < *bound;
        }
    }
    false
}

/// Why a library version is a concern, if it is.
pub fn outdated(library: &str, version: &str) -> Option<&'static str> {
    match library {
        "jQuery" if version_below(version, &[3, 5, 0]) => {
            Some("older than 3.5.0: known XSS issues (CVE-2020-11022, CVE-2020-11023)")
        }
        "jQuery UI" if version_below(version, &[1, 13, 2]) => {
            Some("older than 1.13.2: known XSS issues")
        }
        "Bootstrap" if version.starts_with("3.") && version_below(version, &[3, 4, 1]) => {
            Some("older than 3.4.1: known XSS issues")
        }
        "Bootstrap" if version.starts_with("4.") && version_below(version, &[4, 3, 1]) => {
            Some("older than 4.3.1: known XSS issues")
        }
        "AngularJS" if version.starts_with("1.") => {
            Some("AngularJS 1.x reached end of life in 2021: no more security fixes")
        }
        "Lodash" if version_below(version, &[4, 17, 21]) => {
            Some("older than 4.17.21: prototype pollution and ReDoS issues")
        }
        "Moment.js" if version_below(version, &[2, 29, 4]) => {
            Some("older than 2.29.4: ReDoS and path traversal issues")
        }
        _ => None,
    }
}

/// Paths of `<script src>` files on the page's own site (relative, or
/// absolute on `host`), and every library named in a script's file name.
pub fn scripts_and_libraries(body: &str, host: &str) -> (Vec<String>, Vec<String>) {
    let mut own = Vec::new();
    let mut libraries = Vec::new();
    for found in SCRIPT_SRC.captures_iter(body).take(200) {
        let src = found[1].trim();
        if let Some(lib) = LIBRARY.captures(src) {
            let name = library_name(&lib[1].to_ascii_lowercase());
            if !name.is_empty() {
                let version = &lib[2];
                push(
                    &mut libraries,
                    match outdated(name, version) {
                        Some(why) => format!("{name} {version} ({why})"),
                        None => format!("{name} {version}"),
                    },
                );
            }
        }
        if let Some(path) = same_site_path(src, host) {
            if !own.contains(&path) && own.len() < 40 {
                own.push(path);
            }
        }
    }
    (own, libraries)
}

/// `src` as a path on `host`, or `None` when it is on another site.
fn same_site_path(src: &str, host: &str) -> Option<String> {
    if src.starts_with("data:") || src.starts_with("javascript:") {
        return None;
    }
    if let Some(rest) = src.strip_prefix("//") {
        return same_site_path(&format!("https://{rest}"), host);
    }
    if src.starts_with("http://") || src.starts_with("https://") {
        let url = url::Url::parse(src).ok()?;
        if !url.host_str()?.eq_ignore_ascii_case(host) {
            return None;
        }
        return Some(url.path().to_owned());
    }
    let path = src.split(['?', '#']).next()?;
    if path.is_empty() {
        return None;
    }
    Some(if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{}", path.trim_start_matches("./"))
    })
}

/// The software stack from a page's headers, cookies and HTML.
pub fn detect_stack(headers: &[(String, String)], body: &str) -> Vec<String> {
    let mut tech = Vec::new();
    for server in header(headers, "server") {
        for token in server.split_whitespace() {
            let token = token.trim_matches(|c: char| c == '(' || c == ')');
            if let Some(name) = product(token) {
                push(&mut tech, name);
            }
        }
    }
    for powered in header(headers, "x-powered-by") {
        for token in powered.split([',', ';']) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            push(
                &mut tech,
                product(token).unwrap_or_else(|| token.chars().take(40).collect()),
            );
        }
    }
    for version in header(headers, "x-aspnet-version") {
        push(&mut tech, format!("ASP.NET {version}"));
    }
    for version in header(headers, "x-aspnetmvc-version") {
        push(&mut tech, format!("ASP.NET MVC {version}"));
    }
    for generator in header(headers, "x-generator") {
        push(&mut tech, generator.chars().take(60).collect::<String>());
    }
    let has = |name: &str| header(headers, name).next().is_some();
    for (name, what) in [
        ("x-drupal-cache", "Drupal"),
        ("x-drupal-dynamic-cache", "Drupal"),
        ("x-shopify-stage", "Shopify"),
        ("x-wix-request-id", "Wix"),
        ("x-vercel-id", "Vercel"),
        ("x-amz-cf-id", "Amazon CloudFront"),
        ("fly-request-id", "Fly.io"),
        ("x-github-request-id", "GitHub Pages"),
        ("x-nf-request-id", "Netlify"),
        ("x-varnish", "Varnish"),
        ("x-litespeed-cache", "LiteSpeed"),
        ("x-turbo-charged-by", "LiteSpeed"),
        ("x-magento-cache-debug", "Magento"),
        ("x-jenkins", "Jenkins"),
    ] {
        if has(name) {
            push(&mut tech, what);
        }
    }
    for cookie in header(headers, "set-cookie") {
        let name = cookie
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if let Some((_, what)) = COOKIE_TECH
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix))
        {
            push(&mut tech, *what);
        } else if name.starts_with('_') && name.ends_with("_session") && name.len() > 9 {
            push(&mut tech, "Ruby on Rails");
        }
    }
    if let Some(generator) = GENERATOR.captures(body) {
        push(&mut tech, generator[1].trim().to_owned());
    }
    if let Some(ng) = NG_VERSION.captures(body) {
        push(&mut tech, format!("Angular {}", &ng[1]));
    }
    let lower = body.to_ascii_lowercase();
    for (sign, what) in HTML_TECH {
        if lower.contains(sign) {
            push(&mut tech, *what);
        }
    }
    tech.truncate(24);
    tech
}

fn sounds_like_session(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["sess", "sid", "token", "auth", "jwt", "login", "remember"]
        .iter()
        .any(|word| lower.contains(word))
}

/// The flags of every cookie the page set, and what is wrong with them.
pub fn cookie_checks(headers: &[(String, String)], https: bool) -> Vec<CookieCheck> {
    let mut out = Vec::new();
    for cookie in header(headers, "set-cookie").take(24) {
        let mut parts = cookie.split(';');
        let name = parts
            .next()
            .and_then(|pair| pair.split('=').next())
            .unwrap_or("")
            .trim()
            .to_owned();
        if name.is_empty() {
            continue;
        }
        let (mut secure, mut http_only, mut same_site) = (false, false, None::<String>);
        for attribute in parts {
            let attribute = attribute.trim();
            let lower = attribute.to_ascii_lowercase();
            if lower == "secure" {
                secure = true;
            } else if lower == "httponly" {
                http_only = true;
            } else if let Some(value) = lower.strip_prefix("samesite=") {
                same_site = Some(value.trim().to_owned());
            }
        }
        let mut flags = Vec::new();
        if secure {
            flags.push("Secure".to_owned());
        }
        if http_only {
            flags.push("HttpOnly".to_owned());
        }
        if let Some(value) = &same_site {
            flags.push(format!("SameSite={value}"));
        }
        let mut issues = Vec::new();
        if !secure {
            issues.push(if https {
                "no Secure flag: it is also sent over plain HTTP".to_owned()
            } else {
                "set over plain HTTP: readable on the network".to_owned()
            });
        }
        if !http_only && sounds_like_session(&name) {
            issues.push("no HttpOnly: page scripts (and XSS) can read it".to_owned());
        }
        match same_site.as_deref() {
            None => issues.push("no SameSite: browsers default to Lax".to_owned()),
            Some("none") if !secure => {
                issues.push("SameSite=None without Secure: browsers reject it".to_owned())
            }
            _ => {}
        }
        out.push(CookieCheck {
            name: name.chars().take(64).collect(),
            flags: if flags.is_empty() {
                "none".to_owned()
            } else {
                flags.join(" ")
            },
            issues,
        });
    }
    out
}

/// A to F for the security headers, with what to fix and what the headers
/// give away.
pub fn grade_headers(headers: &[(String, String)], https: bool) -> (String, Vec<String>) {
    let get = |name: &str| header(headers, name).next().map(str::to_owned);
    let csp = get("content-security-policy");
    let mut missing = Vec::new();
    let mut notes = Vec::new();
    if https {
        match get("strict-transport-security") {
            None => missing.push("Strict-Transport-Security"),
            Some(hsts) => {
                let age = hsts
                    .to_ascii_lowercase()
                    .split(';')
                    .find_map(|p| {
                        p.trim()
                            .strip_prefix("max-age=")
                            .and_then(|v| v.trim().parse::<u64>().ok())
                    })
                    .unwrap_or(0);
                if age < 15_552_000 {
                    notes.push(format!(
                        "HSTS max-age is {age} s: under the 180 days browsers expect"
                    ));
                }
            }
        }
    }
    match &csp {
        None => missing.push("Content-Security-Policy"),
        Some(policy) => {
            let lower = policy.to_ascii_lowercase();
            for (word, why) in [
                (
                    "'unsafe-inline'",
                    "CSP allows 'unsafe-inline': inline scripts (and XSS) still run",
                ),
                ("'unsafe-eval'", "CSP allows 'unsafe-eval'"),
            ] {
                if lower.contains(word) {
                    notes.push(why.to_owned());
                }
            }
        }
    }
    let frames_by_csp = csp
        .as_deref()
        .is_some_and(|p| p.to_ascii_lowercase().contains("frame-ancestors"));
    if get("x-frame-options").is_none() && !frames_by_csp {
        missing.push("X-Frame-Options (or CSP frame-ancestors)");
    }
    if !get("x-content-type-options").is_some_and(|v| v.eq_ignore_ascii_case("nosniff")) {
        missing.push("X-Content-Type-Options: nosniff");
    }
    if get("referrer-policy").is_none() {
        missing.push("Referrer-Policy");
    }
    if get("permissions-policy").is_none() {
        missing.push("Permissions-Policy");
    }
    if !missing.is_empty() {
        notes.insert(0, format!("missing {}", missing.join(", ")));
    }
    if let Some(server) = get("server").filter(|s| s.chars().any(|c| c.is_ascii_digit())) {
        notes.push(format!("Server header gives the version away: {server}"));
    }
    if let Some(powered) = get("x-powered-by") {
        notes.push(format!("X-Powered-By gives the stack away: {powered}"));
    }
    let grade = match missing.len() {
        0 if notes.iter().any(|n| n.starts_with("CSP allows")) => "B",
        0 => "A",
        1 => "B",
        2 => "C",
        3 => "D",
        4 => "E",
        _ => "F",
    };
    (grade.to_owned(), notes)
}

/// Everything the `headers` stage learns from one page on `host`.
pub fn fingerprint(
    headers: &[(String, String)],
    body: &str,
    host: &str,
    https: bool,
) -> Fingerprint {
    let mut tech = detect_stack(headers, body);
    let (scripts, libraries) = scripts_and_libraries(body, host);
    for library in libraries {
        push(&mut tech, library);
    }
    tech.truncate(24);
    let (header_grade, header_notes) = grade_headers(headers, https);
    Fingerprint {
        tech,
        cookies: cookie_checks(headers, https),
        header_grade,
        header_notes,
        scripts,
    }
}

// ---------------------------------------------------------------------------
// JavaScript files
// ---------------------------------------------------------------------------

/// Quoted paths that look like an API: `"/api/v1/users"`, `'/graphql'`.
static API_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"["'`](/(?:[A-Za-z0-9_\-.~{}:%]+/)*?(?:api|apis|graphql|rest|v[0-9]{1,2}|auth|oauth2?|admin|internal|private|users?|accounts?|login|logout|token|upload|webhooks?|ws|rpc)(?:[/?][A-Za-z0-9_\-./{}:%?=&~]*)?)["'`]"#,
    )
    .unwrap()
});
static ABSOLUTE_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:https?|wss?)://[A-Za-z0-9.\-]{3,253}(?::\d{1,5})?(?:/[A-Za-z0-9_\-./{}:%?=&~]*)?"#)
        .unwrap()
});
/// Hosts that appear in nearly every bundle and say nothing about the site.
const NOISE_HOSTS: &[&str] = &[
    "www.w3.org",
    "w3.org",
    "schema.org",
    "reactjs.org",
    "react.dev",
    "fb.me",
    "github.com",
    "developer.mozilla.org",
    "mozilla.org",
    "jquery.com",
    "jquery.org",
    "example.com",
    "localhost",
    "vuejs.org",
    "angular.io",
    "getbootstrap.com",
    "momentjs.com",
    "lodash.com",
    "npms.io",
    "nodejs.org",
    "polyfill.io",
    "underscorejs.org",
    "json-schema.org",
    "tc39.es",
    "ecma-international.org",
    "goo.gl",
    "bit.ly",
];
const STATIC_FILES: &[&str] = &[
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".webp", ".mp4", ".webm",
];

/// An endpoint as it is kept: without its fragment and without the values
/// of its query, which can hold a key or a token (`?key=...`,
/// `?access_token=...`). The parameter names stay: `/api/x?key&page`.
pub fn endpoint_without_values(endpoint: &str) -> String {
    let endpoint = endpoint.split('#').next().unwrap_or("");
    let Some((base, query)) = endpoint.split_once('?') else {
        return endpoint.to_owned();
    };
    let mut names: Vec<&str> = Vec::new();
    for pair in query.split(['&', ';']) {
        let name = pair.split('=').next().unwrap_or("");
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    if names.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", names.join("&"))
    }
}

/// Whether `text` holds a key [`find_secrets`] knows. A Slack webhook URL
/// is a key whole.
pub fn holds_key(text: &str) -> bool {
    KEYS.iter().any(|key| key.pattern.is_match(text))
}

/// `endpoint` as it is kept: without query values (see
/// [`endpoint_without_values`]), and with each of `keys`, a key's value and
/// its vault placeholder, as the placeholder. Nothing else in it is masked:
/// an id in a path is no key. `None` for an endpoint that holds a key
/// [`find_secrets`] knows (a Slack webhook URL), or that is a key alone.
pub fn kept_endpoint(endpoint: &str, keys: &[(String, String)]) -> Option<String> {
    let mut kept = endpoint_without_values(endpoint);
    if kept.is_empty() || holds_key(&kept) {
        return None;
    }
    let mut rest = kept.clone();
    for (value, token) in keys.iter().filter(|(value, _)| !value.is_empty()) {
        kept = kept.replace(value.as_str(), token);
        rest = rest.replace(value.as_str(), "");
    }
    rest.chars().any(char::is_alphanumeric).then_some(kept)
}

/// API paths and URLs named in a script: same-site paths first, then other
/// sites' URLs (third-party APIs and internal hosts), at most `max`. Each
/// without its query values (see [`endpoint_without_values`]); one that
/// holds a key is left out, since [`find_secrets`] reports the key.
pub fn extract_endpoints(source: &str, max: usize) -> Vec<String> {
    let mut paths = Vec::new();
    for found in API_PATH.captures_iter(source) {
        let raw = &found[1];
        let bare = raw
            .split(['?', '#'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if raw.len() < 3 || raw.len() > 200 || raw.contains("//") {
            continue;
        }
        if STATIC_FILES.iter().any(|ext| bare.ends_with(ext)) {
            continue;
        }
        let path = endpoint_without_values(raw);
        if holds_key(&path) {
            continue;
        }
        if !paths.contains(&path) {
            paths.push(path);
        }
        if paths.len() >= max {
            return paths;
        }
    }
    for found in ABSOLUTE_URL.find_iter(source) {
        let url = found.as_str().trim_end_matches(['.', ',', ')']).to_owned();
        let Ok(parsed) = url::Url::parse(&url) else {
            continue;
        };
        let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
            continue;
        };
        if NOISE_HOSTS
            .iter()
            .any(|n| host == *n || host.ends_with(&format!(".{n}")))
        {
            continue;
        }
        let bare = parsed.path().to_ascii_lowercase();
        if STATIC_FILES.iter().any(|ext| bare.ends_with(ext)) {
            continue;
        }
        if url.len() > 200 {
            continue;
        }
        let url = endpoint_without_values(&url);
        if !holds_key(&url) && !paths.contains(&url) {
            paths.push(url);
        }
        if paths.len() >= max {
            break;
        }
    }
    paths
}

/// A kind of key and how to recognise it.
struct KeyPattern {
    kind: &'static str,
    pattern: LazyLock<Regex>,
}

macro_rules! key {
    ($kind:expr, $re:expr) => {
        KeyPattern {
            kind: $kind,
            pattern: LazyLock::new(|| Regex::new($re).unwrap()),
        }
    };
}

static KEYS: [KeyPattern; 13] = [
    key!("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    key!(
        "Google API key (often a browser key: check its restrictions)",
        r"\bAIza[0-9A-Za-z_\-]{35}\b"
    ),
    key!(
        "GitHub token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"
    ),
    key!("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
    key!(
        "Slack webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"
    ),
    key!(
        "Stripe secret key",
        r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,99}\b"
    ),
    key!(
        "private key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    ),
    key!(
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    ),
    key!(
        "SendGrid API key",
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"
    ),
    key!("Twilio API key", r"\bSK[0-9a-f]{32}\b"),
    key!("Mailgun API key", r"\bkey-[0-9a-zA-Z]{32}\b"),
    key!("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    key!(
        "possible secret (a key, token or password assigned in the code)",
        r#"(?i)\b(?:api[_-]?key|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/=.]{16,128})["']"#
    ),
];

/// Keys in a script, as (kind, the key). The caller puts each key in the
/// vault at once and keeps only its placeholder.
pub fn find_secrets(source: &str) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for key in &KEYS {
        for found in key.pattern.captures_iter(source).take(8) {
            // The generic pattern's key is its first group; the others are
            // the whole match.
            let value = found
                .get(1)
                .unwrap_or_else(|| found.get(0).expect("a match"))
                .as_str()
                .to_owned();
            // Placeholder text in examples and docs is not a key.
            let lower = value.to_ascii_lowercase();
            if [
                "example",
                "xxxxxxxx",
                "your_",
                "your-",
                "<",
                "changeme",
                "placeholder",
            ]
            .iter()
            .any(|w| lower.contains(w))
            {
                continue;
            }
            if !out.iter().any(|(_, v)| *v == value) {
                out.push((key.kind, value));
            }
            if out.len() >= 32 {
                return out;
            }
        }
    }
    out
}

/// A hint at a key that does not give it away: its first four characters
/// (which name the kind: `AKIA`, `ghp_`, `sk_l`) and its length. A
/// password-like value shows only its length.
pub fn preview(kind: &str, value: &str) -> String {
    let length = value.chars().count();
    if kind.starts_with("possible secret") {
        return format!("{length} chars");
    }
    let head: String = value.chars().take(4).collect();
    format!("{head}\u{2026} ({length} chars)")
}

/// The site's own script files on one port: the page's `<script src>`
/// paths, then `.js` files the crawl found, at most `max`.
pub fn script_paths(port: &crate::graph::Port, max: usize) -> Vec<String> {
    fn walk(node: &crate::graph::PathNode, prefix: &str, out: &mut Vec<String>, max: usize) {
        for (name, child) in &node.children {
            if out.len() >= max {
                return;
            }
            let path = format!("{prefix}/{name}");
            let bare = name
                .split(['?', '#'])
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if (bare.ends_with(".js") || bare.ends_with(".mjs")) && !out.contains(&path) {
                out.push(path.clone());
            }
            walk(child, &path, out, max);
        }
    }
    let mut out: Vec<String> = port
        .http
        .as_ref()
        .map(|http| http.scripts.iter().take(max).cloned().collect())
        .unwrap_or_default();
    walk(&port.paths, "", &mut out, max);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn the_stack_is_read_from_headers_cookies_html_and_script_names() {
        let headers = h(&[
            ("Server", "nginx/1.18.0 (Ubuntu)"),
            ("X-Powered-By", "PHP/7.4.3"),
            ("Set-Cookie", "PHPSESSID=abc; path=/"),
            ("Set-Cookie", "_myapp_session=xyz; HttpOnly"),
            ("X-Vercel-Id", "iad1::abc"),
        ]);
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2">
            <link href="/wp-content/themes/x/style.css">
            <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.4.1"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script>
            <script src="/static/app.4f2a.js"></script>
            <script src="https://shop.example.test/js/cart.js?v=2"></script>
            <script src="https://cdn.other.test/lib.js"></script>
            </head><body ng-version="15.2.0"></body></html>"#;
        let print = fingerprint(&headers, body, "shop.example.test", true);
        let has = |name: &str| print.tech.iter().any(|t| t.starts_with(name));
        assert!(has("nginx 1.18.0"), "{:?}", print.tech);
        assert!(
            has("PHP 7.4.3") && has("Ruby on Rails") && has("Vercel"),
            "{:?}",
            print.tech
        );
        assert!(
            has("WordPress 6.4.2") && has("Angular 15.2.0"),
            "{:?}",
            print.tech
        );
        // One entry per product: the versioned one wins.
        assert_eq!(
            print
                .tech
                .iter()
                .filter(|t| t.starts_with("WordPress"))
                .count(),
            1
        );
        let jquery = print
            .tech
            .iter()
            .find(|t| t.starts_with("jQuery"))
            .expect("jQuery");
        assert!(
            jquery.contains("3.4.1") && jquery.contains("XSS"),
            "{jquery}"
        );
        assert!(print
            .tech
            .iter()
            .any(|t| t.starts_with("AngularJS 1.8.2") && t.contains("end of life")));
        // Only the site's own scripts are kept, as paths.
        assert_eq!(
            print.scripts,
            [
                "/wp-includes/js/jquery/jquery.min.js",
                "/static/app.4f2a.js",
                "/js/cart.js"
            ]
        );
    }

    #[test]
    fn cookie_flags_are_checked_and_values_never_kept() {
        let headers = h(&[
            ("Set-Cookie", "session_id=SECRETVALUE; Path=/"),
            ("Set-Cookie", "theme=dark; Secure; SameSite=Lax"),
            (
                "Set-Cookie",
                "auth=T0KEN; Secure; HttpOnly; SameSite=Strict",
            ),
            ("Set-Cookie", "track=1; SameSite=None"),
        ]);
        let cookies = cookie_checks(&headers, true);
        assert_eq!(cookies.len(), 4);
        let session = &cookies[0];
        assert_eq!(session.flags, "none");
        assert!(session.issues.iter().any(|i| i.contains("Secure")));
        assert!(session.issues.iter().any(|i| i.contains("HttpOnly")));
        assert!(session.issues.iter().any(|i| i.contains("SameSite")));
        assert!(cookies[1].issues.is_empty(), "{:?}", cookies[1]);
        assert_eq!(cookies[2].flags, "Secure HttpOnly SameSite=strict");
        assert!(cookies[2].issues.is_empty());
        assert!(cookies[3]
            .issues
            .iter()
            .any(|i| i.contains("SameSite=None without Secure")));
        let text = format!("{cookies:?}");
        assert!(
            !text.contains("SECRETVALUE") && !text.contains("T0KEN"),
            "{text}"
        );
        assert!(
            cookie_checks(&h(&[("Set-Cookie", "a=1")]), false)[0].issues[0].contains("plain HTTP")
        );
    }

    #[test]
    fn security_headers_are_graded_a_to_f() {
        let all = h(&[
            (
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            ),
            (
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "camera=()"),
        ]);
        assert_eq!(grade_headers(&all, true).0, "A");
        let mut inline = all.clone();
        inline[1].1 = "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'".to_owned();
        let (grade, notes) = grade_headers(&inline, true);
        assert_eq!(grade, "B");
        assert!(notes.iter().any(|n| n.contains("unsafe-inline")));
        let (grade, notes) = grade_headers(&h(&[("Server", "Apache/2.4.7")]), true);
        assert_eq!(grade, "F");
        assert!(
            notes[0].starts_with("missing Strict-Transport-Security"),
            "{notes:?}"
        );
        assert!(notes.iter().any(|n| n.contains("Apache/2.4.7")));
        // On plain HTTP there is no HSTS to ask for.
        let (grade, _) = grade_headers(&all[1..], false);
        assert_eq!(grade, "A");
        let short = h(&[("Strict-Transport-Security", "max-age=300")]);
        assert!(grade_headers(&short, true)
            .1
            .iter()
            .any(|n| n.contains("max-age is 300")));
    }

    #[test]
    fn endpoints_and_keys_are_found_in_scripts() {
        // Fake keys, put together here so no key-shaped text sits in the
        // source for a secret scanner to trip over.
        let aws = format!("{}{}", "AKIA", "IOSFODNN7EXAMPL3");
        let google = format!("{}{}", "AIza", "SyD-1234567890abcdefghijklmnopqrstu");
        let stripe = format!("{}_{}_{}", "sk", "live", "0123456789abcdefghijklmn");
        let sample = format!("{}{}", "AKIA", "EXAMPLEEXAMPLE12");
        let source = format!(
            r#"
            fetch("/api/v1/users/" + id); axios.post('/graphql', q);
            const ws = "wss://realtime.shop.example.test/socket";
            const pay = "https://api.payments.test/v2/charges";
            const img = "/static/logo.png"; const doc = "https://www.w3.org/2000/svg";
            const aws = "{aws}";
            const google = "{google}";
            var config = {{ apiKey: "{stripe}", password: "hunter2hunter2hunter2" }};
            const sample = "{sample}";
        "#
        );
        let source = source.as_str();
        let endpoints = extract_endpoints(source, 50);
        assert!(
            endpoints.contains(&"/api/v1/users/".to_owned()),
            "{endpoints:?}"
        );
        assert!(endpoints.contains(&"/graphql".to_owned()));
        assert!(endpoints.contains(&"wss://realtime.shop.example.test/socket".to_owned()));
        assert!(endpoints.contains(&"https://api.payments.test/v2/charges".to_owned()));
        assert!(
            !endpoints
                .iter()
                .any(|e| e.contains("logo.png") || e.contains("w3.org")),
            "{endpoints:?}"
        );

        let secrets = find_secrets(source);
        let kinds: Vec<&str> = secrets.iter().map(|(k, _)| *k).collect();
        assert!(kinds.contains(&"AWS access key ID"), "{kinds:?}");
        assert!(kinds.iter().any(|k| k.starts_with("Google API key")));
        assert!(kinds.contains(&"Stripe secret key"));
        assert!(secrets
            .iter()
            .any(|(k, v)| k.starts_with("possible secret") && v == "hunter2hunter2hunter2"));
        // Example keys in docs are not reported.
        assert!(
            !secrets.iter().any(|(_, v)| v.contains("EXAMPLE")),
            "{secrets:?}"
        );
        assert_eq!(
            preview("AWS access key ID", &aws),
            "AKIA\u{2026} (20 chars)"
        );
        assert_eq!(
            preview("possible secret (x)", "hunter2hunter2hunter2"),
            "21 chars"
        );
    }

    #[test]
    fn endpoints_keep_their_parameter_names_but_never_a_value_or_a_key() {
        // Built here, so that no key-shaped text stands in the source.
        let google = format!("{}{}", "AIza", "SyD-1234567890abcdefghijklmnopqrstu");
        let hook = format!(
            "https://hooks.slack.com/services/{}/{}/{}",
            "T0123456", "B0123456", "abcdefghijklmnopqrstuvwx"
        );
        let token = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
        let source = format!(
            r#"const maps = "https://maps.googleapis.com/maps/api/js?key={google}&v=3";
            const hook = "{hook}";
            fetch("/api/v1/orders?access_token={token}&page=2&page=3");
            fetch("/api/v1/orders?access_token={token}2");
            fetch("/api/v1/search?q");"#
        );
        let endpoints = extract_endpoints(&source, 60);
        assert_eq!(
            endpoints,
            [
                "/api/v1/orders?access_token&page",
                "/api/v1/orders?access_token",
                "/api/v1/search?q",
                "https://maps.googleapis.com/maps/api/js?key&v",
            ]
        );
        for endpoint in &endpoints {
            assert!(!holds_key(endpoint), "{endpoint}");
        }
        assert!(holds_key(&hook) && holds_key(&google));
        assert_eq!(
            endpoint_without_values("/login#access_token=abc&state=x"),
            "/login"
        );
        assert_eq!(endpoint_without_values("/api/x?=1&&a=1;b"), "/api/x?a&b");
        assert_eq!(endpoint_without_values("/api/x?"), "/api/x");
        assert_eq!(endpoint_without_values("/api/x"), "/api/x");
    }

    #[test]
    fn a_kept_endpoint_hides_the_keys_given_and_nothing_else() {
        let keys = [("Zq3vLm8pRt5wXy2nBc7k".to_owned(), "<<SEC_04>>".to_owned())];
        assert_eq!(
            kept_endpoint("/api/v1/reports/Zq3vLm8pRt5wXy2nBc7k/latest?x=1", &keys).as_deref(),
            Some("/api/v1/reports/<<SEC_04>>/latest?x")
        );
        // Ids are no keys.
        for id in [
            "/api/v2/projects/5f8d0d55b54764421b7156c5/members",
            "https://api.example.com/v1/orders/550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert_eq!(kept_endpoint(id, &keys).as_deref(), Some(id));
        }
        // A key alone, or one find_secrets knows: left out.
        assert_eq!(kept_endpoint("/Zq3vLm8pRt5wXy2nBc7k", &keys), None);
        let hook = format!(
            "https://hooks.slack.com/services/{}/{}/{}",
            "T0123456", "B0123456", "abcdefghijklmnopqrstuvwx"
        );
        assert_eq!(kept_endpoint(&hook, &[]), None);
        assert_eq!(kept_endpoint("?", &[]), None);
    }

    #[test]
    fn library_versions_are_compared_by_number() {
        assert!(outdated("jQuery", "1.12.4").is_some());
        assert!(outdated("jQuery", "3.4.1").is_some());
        assert!(outdated("jQuery", "3.5.0").is_none());
        assert!(outdated("jQuery", "3.10.0").is_none());
        assert!(outdated("Bootstrap", "4.6.2").is_none());
        assert!(outdated("Bootstrap", "3.3.7").is_some());
        assert!(outdated("React", "16.0.0").is_none());
    }
}
