//! Passive OSINT and lightweight `mild`-mode service verification tasks.
//!
//! Every probe in this module is either strictly passive (DNS, DoH, Team
//! Cymru ASN, RDAP, Certificate Transparency `crt.sh`, local ARP/NDP cache)
//! or single-connection and non-intrusive (HTTP `GET /`, `/robots.txt`,
//! `/.well-known/security.txt`, `/favicon.ico`, TLS handshake inspection,
//! and RFC 4253 `SSH_MSG_KEXINIT` algorithm parsing with zero authentication
//! attempts).
//!
//! Network calls time out within 5–10 seconds and degrade gracefully so rate
//! limits or offline environments mark a stage `skipped` or emit a notice
//! without failing the recon pipeline.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::endpoint::{HostAddr, Target};
use crate::evidence::{sanitize, Confidence, EvidenceRecord, Source};
use crate::geoip::GeoDb;
use crate::graph::{HttpInfo, Observation};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_HTTP_BYTES: usize = 256 * 1024;
const MAX_FAVICON_BYTES: usize = 512 * 1024;
const MAX_CRTSH_BYTES: usize = 4 * 1024 * 1024;
const MAX_SUBDOMAINS: usize = 50;
const MAX_SSH_PACKET_BYTES: usize = 64 * 1024;

/// Required HTTP security response headers checked by the `headers` stage.
pub const REQUIRED_SECURITY_HEADERS: &[&str] = &[
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
];

// ---------------------------------------------------------------------------
// Bounded HTTP helpers
// ---------------------------------------------------------------------------

pub(crate) fn build_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT.min(timeout))
        .read_timeout(timeout)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("meow-osint/0.1")
        .build()
        .context("cannot create OSINT HTTP client")
}

fn configure_osint_command(cmd: &mut tokio::process::Command) {
    cmd.env_clear();
    if let Some(raw_path) = std::env::var_os("PATH") {
        let safe_dirs = std::env::split_paths(&raw_path)
            .filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute());
        if let Ok(joined) = std::env::join_paths(safe_dirs) {
            cmd.env("PATH", joined);
        }
    }
    cmd.env("LC_ALL", "C").env("LANG", "C");
    #[cfg(windows)]
    {
        let sys_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("SYSTEMROOT"))
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
        cmd.env("SystemRoot", sys_root);
    }
    #[cfg(unix)]
    cmd.process_group(0);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
}

#[cfg(unix)]
struct OsintGroupGuard(Option<u32>);

#[cfg(unix)]
impl Drop for OsintGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0.filter(|&p| p > 1 && p <= i32::MAX as u32) {
            // SAFETY: negative pid signals the dedicated process group started with process_group(0).
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
    }
}

async fn wait_bounded_stdout(
    mut child: tokio::process::Child,
    max_bytes: usize,
    timeout: Duration,
) -> Option<String> {
    #[cfg(unix)]
    let _group = OsintGroupGuard(child.id());
    let mut stdout = child.stdout.take()?;
    let fut = async move {
        let mut buf = Vec::with_capacity(max_bytes.min(8192));
        let mut limited = (&mut stdout).take(max_bytes as u64);
        let _ = limited.read_to_end(&mut buf).await;
        let _ = child.kill().await;
        let _ = child.wait().await;
        String::from_utf8_lossy(&buf).into_owned()
    };
    tokio::time::timeout(timeout, fut).await.ok()
}

async fn read_bytes_bounded(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            bail!("response content-length ({len}) exceeds {max_bytes} byte cap");
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("failed reading HTTP body")? {
        if out.len() + chunk.len() > max_bytes {
            bail!("response body exceeds {max_bytes} byte cap");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn read_bytes_prefix(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("failed reading HTTP body")? {
        if out.len() + chunk.len() > max_bytes {
            out.extend_from_slice(&chunk[..max_bytes.saturating_sub(out.len())]);
            break;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// True when `ip` is safe to accept as a DNS resolution result for `domain`.
/// Blocks unspecified, broadcast, multicast, link-local / cloud metadata IMDS
/// (`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, `100.100.100.200`), and loopback addresses unless `domain` is
/// explicitly `localhost`, while still permitting RFC 1918 / RFC 4193 lab hosts.
pub fn is_allowed_resolved_ip_for_name(domain: &str, ip: IpAddr) -> bool {
    let is_localhost = domain
        .trim()
        .trim_end_matches('.')
        .eq_ignore_ascii_case("localhost");
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            // Alibaba Cloud's metadata service sits outside link-local.
            if v4.is_unspecified()
                || v4.octets()[0] == 0
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.octets() == [100, 100, 100, 200]
            {
                return false;
            }
            if v4.is_loopback() && !is_localhost {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // AWS's metadata service over IPv6 is fd00:ec2::254.
            if v6.is_unspecified()
                || v6.is_multicast()
                || (segs[0] & 0xffc0) == 0xfe80
                || segs == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
            {
                return false;
            }
            if v6.is_loopback() && !is_localhost {
                return false;
            }
            true
        }
    }
}

/// True when `ip` is loopback, private (RFC 1918 / RFC 4193), link-local,
/// multicast, CGNAT, benchmarking, or documentation space that external
/// internet registries (Team Cymru / RDAP) do not index as public routable
/// autonomous systems.
pub fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)) // 198.18.0.0/15
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segs[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (segs[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (segs[0] == 0x2001 && segs[1] == 0x0db8) // 2001:db8::/32 doc
        }
    }
}

mod asn;
mod dns;
mod ssh;
mod subdomains;
mod tls;
mod trace;
mod web;

pub use asn::*;
pub use dns::*;
pub use ssh::*;
pub use subdomains::*;
pub use tls::*;
pub use trace::*;
pub use web::*;

// ---------------------------------------------------------------------------
// 9. Distro Backport Detection Helper for `cves` & `ai`
// ---------------------------------------------------------------------------

/// Detects whether a host or service banner indicates Linux distribution
/// packaging (Ubuntu, Debian, RHEL, CentOS, Fedora, SUSE, Alpine, Amazon Linux)
/// where upstream version strings commonly carry backported security patches.
pub fn distro_backport_note(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("ubuntu") {
        Some("Ubuntu backports security fixes without changing the upstream version: the installed package (`dpkg -l`) may already have the fix")
    } else if lower.contains("debian") || lower.contains("+deb") {
        Some("Debian backports security fixes without changing the upstream version: the installed package (`dpkg -l`) may already have the fix")
    } else if lower.contains("redhat")
        || lower.contains("rhel")
        || lower.contains("centos")
        || lower.contains(".el7")
        || lower.contains(".el8")
        || lower.contains(".el9")
    {
        Some("Enterprise Linux backports security fixes without changing the upstream version: the installed package (`rpm -q --changelog`) may already have the fix")
    } else if lower.contains("amzn") || lower.contains("amazon") {
        Some("Amazon Linux backports security fixes: the installed package (`rpm -q`) may already have the fix")
    } else if lower.contains("suse") || lower.contains("sles") {
        Some("SUSE backports security fixes: the installed package (`rpm -q`) may already have the fix")
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests;
