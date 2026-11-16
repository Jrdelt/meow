### What's New in `meow` v0.2.0

- **Expanded 14-Stage `recon <target>` OSINT & Triage Pipeline (`mild` mode):**
  - Passive & non-intrusive stages run automatically alongside port/service discovery: `lan` (passive ARP/NDP neighbour sweep), `dns` (DoH/UDP `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, and reverse `PTR`), `asn` (Team Cymru DNS + RDAP + offline `GeoDb` fallback), `subdomains` (`crt.sh` Certificate Transparency), `trace` (traceroute hop & RTT latency parser), `ports`, `services`, `headers` (`GET /`, `/robots.txt`, `/.well-known/security.txt`, MurmurHash3 `/favicon.ico` framework fingerprinting), `waf-cdn` (Cloudflare, Akamai, CloudFront, Fastly, AWS WAF detection before `dirs`), `tls-audit` (TLS 1.0–1.3, weak ciphers, X.509 SANs & validity), `ssh-audit` (RFC 4253 `SSH_MSG_KEXINIT` algorithm audit), `cves` (OSV.dev + NVD CPE/CVE hypothesis matcher with distro backport awareness), `crawl`, and `dirs`.
- **Rich OPSEC & Transit Topology Map:**
  - Vertical OPSEC pipeline: `You` -> `Gateway` -> `WAN Egress · <IP> (<ISP>)` (or dashed cyan `VPN Exit` tunnel) -> `Internet (<N> hops · <X> ms)` (click to expand intermediate traceroute hops with per-hop RTT & GeoIP labels) -> optional `WAF / CDN` shield node -> compound `ASN / Cloud Provider` box grouping sibling hosts -> rich target labels (`<hostname> (<ip>)`, compact ports, city, and verification status badge).
  - **Associated Hosts** panel & `Host Info` grouping discovered names into **Domains** (registrable apex domains) and **Hosts** (subdomains/FQDNs).
- **One-Click Engagement Report Export:**
  - Export per-host or full-workspace Markdown reports (`/api/report/<address>` and `/api/report`) or Print/PDF directly from the WebUI, combining Host Info, Open Ports, Web & TLS posture, confirmed/hypothesis Advisories, Evidence facts, operator notes, and AI remediation transcripts.
- **Security Hardening & Cross-Platform Audit:**
  - Comprehensive security audit across Unix, macOS, and Windows (ConPTY & Job Objects, path/ACL/SID validation, bounded XML/JSON/DNS/HTTP parsers, zero-trust Privacy Vault masking, and strict CSP/DOM sanitization).

---

### Installation

Download the file for your computer below.

**Mac:** `meow-<version>-macos-arm64.pkg` (Apple Silicon: M1 and newer) or
`meow-<version>-macos-x86_64.pkg` (Intel). Double-click it; because it is not
signed with a paid Apple Developer certificate, macOS blocks it the first time.
On macOS 15 (Sequoia) and newer, open **System Settings → Privacy & Security**,
scroll down, and click **Open Anyway** (on macOS 14 and earlier, Control-click
the `.pkg` and choose **Open → Open**). `meow` is installed to
`/usr/local/bin/meow`.

**Linux / Kali:** `meow-<version>-linux-x86_64.tar.gz` (or `-linux-arm64`):

    sha256sum -c meow-*-linux-*.tar.gz.sha256
    tar -xzf meow-*-linux-*.tar.gz
    sudo install -m 0755 meow /usr/local/bin/meow

**Windows:** `meow-<version>-windows-x86_64.zip` (x64, or runs under emulation
on ARM64): verify against `.sha256` with `Get-FileHash`, unzip it, and place
`meow.exe` in a folder on your `PATH`.

Then run `meow`. On first run, the interactive Cat Setup wizard configures your
mode and privacy preferences and `meow tools` offers to install the optional
scanners (`nmap`, `katana`, `feroxbuster`), wordlist, and offline DB-IP Lite
location database. Later, `meow update` downloads, SHA-256 verifies, and
installs newer releases automatically.
