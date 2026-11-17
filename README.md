# meow

```text
  /\_/\
 ( ^w^ )  meow — local security triage shell, topology mapper & grounded audit workspace
  > ^ <
```

`meow` wraps your normal interactive shell (`zsh`, `bash`, `fish`, or `pwsh`), passively observes authorized reconnaissance and command output, grounds discovered services against public vulnerability feeds, maps your OPSEC transit path and target topology on a live local canvas, and compiles a verified Markdown or printable PDF audit report.

Everything stays on your machine in a private workspace (`~/.meow/workspaces/<name>/` or `./.meow/`). When you ask a cloud AI model for triage notes, `meow` masks IP addresses, hostnames, domains, emails, MAC addresses, and credentials into placeholders (`<<HOST_01>>`, `<<DOM_01>>`, `<<SEC_01>>`) before any text leaves your machine, and restores the real values locally when the reply returns.

> **Authorized use only.** Use `meow` only on systems and networks you own or have explicit written permission to test. `meow` inventories services, configurations, and public advisories to help operators patch and verify systems; it never generates exploits or attacks.

---

## Install

### Option 1 — Homebrew (macOS & Linux)

```sh
brew tap Jrdelt/meow https://github.com/Jrdelt/meow.git
brew trust Jrdelt/meow   # Homebrew 7+
brew install meow
```

Homebrew installs `meow` along with `nmap`, `katana`, `feroxbuster`, and the SecLists `common.txt` wordlist. To install the optional offline IP location database afterwards, run:

```sh
meow tools
```

To upgrade a Homebrew installation later, run `meow update` (which automatically delegates to `brew update && brew upgrade`), or run:

```sh
brew update && brew upgrade meow
```

To track the latest `main` branch instead of tagged releases, install with `--HEAD` (`brew install --HEAD meow`, or `brew uninstall meow && brew install --HEAD meow` if switching from a release install), after which `meow update` runs `brew upgrade --fetch-HEAD meow`.

### Option 2 — macOS `.pkg` installer

Download the `.pkg` installer for your Mac (`meow-<version>-macos-arm64.pkg` for Apple Silicon or `meow-<version>-macos-x86_64.pkg` for Intel) from the [latest GitHub Release](https://github.com/Jrdelt/meow/releases/latest) and open it, or install from the terminal:

```sh
sudo installer -pkg meow-0.2.1-macos-arm64.pkg -target /
```

Then run `meow tools` once in your terminal to install any missing companion scanners (`nmap`, `katana`, `feroxbuster`), the web wordlist, and the offline location database.

### Option 3 — Build from source with the installer (macOS & Linux)

```sh
git clone https://github.com/Jrdelt/meow.git && cd meow && ./install.sh
```

The installer builds `meow` from the clone it is part of (installing Rust through `rustup` if needed) and sets up `nmap`, `katana`, `feroxbuster`, the SecLists `common.txt` wordlist (`~/.meow/wordlists/common.txt`), and the DB-IP Lite offline location database (`~/.meow/geo/`).

Installer flags (when running `./install.sh` from a git clone):

- `./install.sh --no-tools` — install `meow` without installing `nmap`, `katana`, `feroxbuster`, or the wordlist
- `./install.sh --no-geo` — skip downloading the offline location database
- `./install.sh --yes` — non-interactive mode (do not prompt)

### Option 4 — Windows (PowerShell)

Download `meow-<version>-windows-x86_64.zip` from the [latest GitHub Release](https://github.com/Jrdelt/meow/releases/latest), or run `install.ps1` from a PowerShell window:

```powershell
git clone https://github.com/Jrdelt/meow.git
cd meow
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

---

## First-Time Setup

Run `meow` with no arguments (or `meow setup`) in an interactive terminal to open the **Cat Setup GUI**:

```sh
meow
```

The 5-step setup wizard walks you through:

1. **Welcome & Overview** — how sessions, masking, and local workspaces work.
2. **Cloud AI Provider** — choose **OpenRouter**, **Anthropic (Claude API)**, or **Local-Only (Offline)**, paste your API key (kept hidden), and pick triage/research models.
3. **Local AI Server** — configure an optional local server (`Ollama` on `http://127.0.0.1:11434/v1` or `LM Studio` on `http://127.0.0.1:1234/v1`) for completely offline `[L]` local triage.
4. **CVE Feeds & Offline GeoIP** — toggle public vulnerability lookups (NVD, OSV.dev, CISA KEV), optionally add an NVD API key for higher rate limits, and enable offline IP geolocation.
5. **Companion Tools Check** — verify `nmap`, `katana`, `feroxbuster`, the SecLists wordlist, and the DB-IP City Lite database, and optionally launch your first workspace immediately.

You can re-open this wizard any time with `meow setup` (or pass `meow setup --plain` for a line-by-line text menu).

---

## Quick Start

### 1. Open a session

```sh
meow acme
```

This opens your normal shell inside the `acme` workspace (`~/.meow/workspaces/acme/`). Your prompt is prefixed with `(meow:acme:light)` (reflecting the active workspace and mode) so you always know a session is active, and `meow` prints the localhost URL for the live topology map.

To keep the workspace in `./.meow/` inside the current folder instead:

```sh
meow acme --local
```

Type `exit` (or press `Ctrl-D`) at any time to close the session shell and save the workspace.

### 2. Run commands or queue background recon

Anything you run in the session shell (`nmap`, `ping`, `curl`, `ssh`, `dig`, `git diff`) is observed passively. When a command discovers a host, open port, service banner, HTTP path, or configuration diff, `meow` records it in the workspace graph and looks up matching advisories in the background.

For an automated inventory of an authorized target, switch to `mild` (or `aggressive`) mode and run `meow recon`:

```sh
meow mode mild
meow recon scanme.nmap.org
```

Or pass custom `nmap` flags after `--`:

```sh
meow recon 192.168.1.0/24 -- -p 22,80,443,8080
```

### 3. Open the live topology map or HUD

From inside the session (or from another terminal window):

```sh
meow map          # opens the live topology map in your browser
meow hud          # opens the terminal TUI companion panel
```

### 4. Generate the audit report

When you are ready to export your findings:

```sh
meow report
```

This writes `REPORT.md` inside the workspace directory (`~/.meow/workspaces/<name>/REPORT.md` or `./.meow/REPORT.md`). You can also export the full workspace report or a single-host report directly from the browser map using **Export report (.md)** or **Print / PDF**.

---

## Command Reference

| Command | Description |
| :--- | :--- |
| `meow` | Launch the first-time Cat Setup GUI, or list saved workspaces |
| `meow <name>` | Open or resume the saved workspace `~/.meow/workspaces/<name>/` |
| `meow <name> --local` | Open or resume a workspace in `./.meow/` of the current directory |
| `meow list` (`meow ls`) | List all saved workspaces in `~/.meow/workspaces/` |
| `meow delete <name>` (`meow rm`) | Delete a saved workspace (`--local` for `./.meow/`, `-y` to skip confirmation) |
| `meow mode <light\|mild\|aggressive>` | Switch the discovery rate/load profile of the session |
| `meow recon <target> [-- <nmap_flags>...]` | Queue the 17-stage OSINT & service inventory for a host, domain, IP, or CIDR |
| `meow map [--no-open]` | Open the live topology map in your browser (or print the URL with `--no-open`) |
| `meow hud` | Attach the terminal TUI companion panel (`Tab` panels, `a` AI view, `m` machine view, `1`/`2`/`3` mode) |
| `meow add <file> [--no-cve]` | Import an Nmap XML, katana/feroxbuster JSONL, log, or `git diff` file |
| `meow report` | Compile the workspace into `REPORT.md` |
| `meow setup` | Open the interactive Cat Setup GUI (or pass flags for scriptable setup) |
| `meow tools [--yes]` | Check companion tools, wordlist, and location database, and install any missing ones |
| `meow update [--check]` | Upgrade `meow` (via Homebrew, SHA-256 verified GitHub Release, or source checkout) and refresh tools |

> **Targeting a workspace from another terminal:** Helper commands (`mode`, `recon`, `map`, `hud`, `add`, `report`) automatically detect the active session when run inside a `meow` shell. From a separate terminal window, add `--session <name>` (or `--local`).

---

## Modes (`light`, `mild`, `aggressive`)

Every session runs in one of three modes:

| Mode | Passive shell observation | `meow recon` | Tool pacing |
| :--- | :--- | :--- | :--- |
| `light` *(default)* | Enabled | Disabled (refused) | Passive only — zero outbound background scan packets |
| `mild` | Enabled | Enabled | Rate-limited active discovery (`nmap -T3 --top-ports 1000`, `katana` depth 2, `feroxbuster` 20 req/s) |
| `aggressive` | Enabled | Enabled | Full active discovery (`nmap -T4 -p- -O`, `katana` depth 4, `feroxbuster --auto-tune`) |

Switch modes at any time with:

```sh
meow mode light
meow mode mild
meow mode aggressive
```

---

## What `meow recon` Does (17 Stages)

`meow recon <target>` runs one stage at a time in the background so you can keep using your shell. Follow progress in `meow hud` or on the live browser map.

1. **`lan`** — Reads your local ARP/NDP neighbour cache and routing table to identify your local gateway and LAN neighbours without sending broadcast traffic.
2. **`dns`** — Resolves `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT` (SPF/DMARC/verification), and reverse `PTR` records through your own resolvers first, with DNS-over-HTTPS as a fallback only for public names. Internal names (`.local`, `.corp`, `.internal`, ...) and the reverse names of private addresses never go to a public resolver, and a reverse record never takes a name another host has.
3. **`asn`** — Queries Team Cymru DNS and RDAP to identify the target's Autonomous System Number (ASN), BGP prefix, cloud/ISP organization, and country, plus offline GeoIP city coordinates.
4. **`subdomains`** — Queries Certificate Transparency logs (`crt.sh`) for public domain targets to discover associated hostnames and subdomains passively; an internal name, or one that resolves to a private address, is not sent.
5. **`mail-dns`** — For domain targets, grades mail and DNS protection A–F: SPF (its `-all`/`~all` ending and the 10-lookup limit), DMARC (policy, coverage, reports), DKIM (24 common selectors, key length), CAA (which certificate authorities may issue) and DNSSEC (DS at the parent, DNSKEY in the zone), and names the mail provider. It lists services the domain publishes in SRV records and well-known names (`_ldap`, `_kerberos`, `_gc`, `_sip`, `_autodiscover`, `autodiscover`, `lyncdiscover`, `enterpriseenrollment`), which often reveal Active Directory or Microsoft 365, and checks for wildcard DNS: two made-up names are looked up, and each certificate-log name is marked as resolving, answering only through the wildcard (so it may not exist), or gone. Only DNS questions are asked, the same way as `dns`; nothing is sent to the target's servers. Results appear in the host's **DNS & Mail** tab on the map.
6. **`trace`** — Runs a bounded traceroute (`traceroute`, `tracepath`, or `tracert`) to map intermediate network hops and round-trip latency between your gateway and the target.
7. **`ports`** — Runs `nmap` to discover open TCP ports on the target.
8. **`udp`** — Aggressive mode only, and only as root (UDP scanning sends raw packets and is slow): runs `nmap -sU -sV` on a named list of security-relevant UDP services (DNS 53, DHCP 67, TFTP 69, Kerberos 88, RPC 111, NTP 123, NetBIOS 137, SNMP 161, CLDAP 389, IKE 500/4500, syslog 514, RIP 520, IPMI 623, OpenVPN 1194, SQL Server Browser 1434, SSDP 1900, NFS 2049, SIP 5060, mDNS 5353, CoAP 5683, memcached 11211, WireGuard 51820). Each service that answers gets a note on what it means (for example SNMP's clear-text community strings, IPMI's pre-login password hashes). In mild mode, or without root, it is skipped with the command to run yourself.
9. **`services`** — Runs `nmap -sV` strictly on the open ports found in `ports` to fingerprint service banners, versions, and CPEs.
10. **`headers`** — Inspects HTTP/HTTPS endpoints for server headers, security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`), HTML `<title>`, `/robots.txt`, `/.well-known/security.txt`, and `/favicon.ico` framework hashes. It also fingerprints the software stack from response headers, cookie names, the HTML (generator tag, CMS and framework signs) and script file names (flagging outdated libraries such as jQuery before 3.5.0 or AngularJS 1.x), checks each cookie's `Secure`, `HttpOnly` and `SameSite` flags (never keeping its value), and grades the security headers A–F (HSTS, CSP, frame protection, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, and what `Server`/`X-Powered-By` give away).
11. **`waf-cdn`** — Detects edge WAF/CDN providers (Cloudflare, AWS CloudFront, Akamai, Fastly, Imperva, Sucuri, Azure Front Door, Google Cloud CDN) from HTTP headers and CNAME chains.
12. **`tls-audit`** — Inspects TLS certificates (Subject, Issuer, validity dates, Subject Alternative Names) and checks supported TLS protocol versions (`TLSv1.0`–`TLSv1.3`), flagging deprecated protocols or expiring certificates.
13. **`ssh-audit`** — Performs a zero-authentication RFC 4253 `SSH_MSG_KEXINIT` handshake on open SSH ports to inventory key-exchange, host-key, cipher, and MAC algorithms and flag weak cryptography (`ssh-rsa`, `ssh-dss`, `diffie-hellman-group1-sha1`, CBC/RC4 ciphers, MD5/SHA-1 MACs).
14. **`cves`** — Grounds discovered product/version CPEs against OSV.dev, NVD, and the CISA Known Exploited Vulnerabilities (KEV) catalog, noting when Linux distribution banners (Ubuntu, Debian, RHEL) indicate backported security patches.
15. **`crawl`** — Crawls discovered HTTP/HTTPS services with `katana` to inventory linked endpoints.
16. **`js`** — Reads the site's own JavaScript files (from the page's script tags and the crawl; up to 15 in mild mode, 40 in aggressive, never another site's) and pulls out API paths and URLs they name, and exposed keys (AWS, Google, GitHub, Slack, Stripe, SendGrid, Twilio, Mailgun, npm, JWTs, private keys, and keys or passwords assigned in the code). A key goes straight into the Privacy Vault: the map, the evidence and the report show only its placeholder (`<<SEC_03>>`), its kind and a short hint, and the report lists it under secrets to rotate.
17. **`dirs`** — Runs `feroxbuster` with the SecLists `common.txt` wordlist against discovered web services to find unlinked directories and files.

If an external tool (`nmap`, `katana`, `feroxbuster`, `traceroute`, `openssl`) is not installed, `meow` marks that stage `skipped` with a clear reason and continues the remaining stages.

---

## Live Topology Map & Report Export

Run `meow map` to open the local topology view in your browser (`127.0.0.1:<port>`, protected by a per-session token).

The drawing fills the whole card, which fills the window. Your rough location (a small satellite map) floats over its top-right corner: fold it into a pill with **−**, and it folds itself when it would hide a device. **Expand** fills the entire browser window with the map and the side panel; press **Esc** to go back.

- **Vertical OPSEC & transit path** — Traces your traffic from **You (Operator)** → **Local Gateway** → **WAN Egress / VPN Exit** (highlighting whether a VPN tunnel such as `utun`/`wg`/`tun` is active or direct ISP egress is exposed) → **Internet** (click to expand hop-by-hop traceroute latency; click a hop for its city, region and country from the offline location database, its network/ASN, address type, reverse DNS and the latency it adds) → **WAF / CDN Edge** → **ASN / Cloud Provider** compound group → **Target Hosts**.
- **Host tabs** — Click a host and its details open under the map in tabs: **Overview** (Server Status and an *At a Glance* summary that links to each tab), **Ports**, **Web & TLS**, **Advisories**, **Evidence**, and **Notes & AI**. Counts on the tabs show open ports, open advisories (red when one is confirmed or known exploited) and facts. The tab you pick stays open across live updates and when you switch hosts; arrow keys move between tabs and `1`–`6` open one directly. Print / PDF includes every tab.
- **Host inspector & Associated Hosts** — Click any host node to see its **Server Status** (up or not as the scans last saw it, how long ago, and a **Check now** button that makes one connection to each of up to six of its known open ports, in mild and aggressive mode only), its ports (one line each: port, open/closed/filtered, service and version), HTTP security headers, TLS certificate details, SSH algorithm inventories, discovered web paths, traceroute hops, and CVE hypotheses. Subdomains and TLS SANs discovered via passive OSINT appear in the **Associated Hosts** drawer with a one-click **Queue Recon** button.
- **Hypothesis verification** — Every CVE match starts as an **Unverified Hypothesis** with a verification checklist. Confirming or dismissing a hypothesis updates both the map badge and `REPORT.md`.
- **AI Triage (`[L]` Local / `[C]` Cloud / `[R]` Research)** — Ask a local or cloud AI model to prioritize findings for the selected host. A triage answer comes in two panels side by side: **Red Team** (authorized penetration test: attack-surface priorities, non-destructive verification steps, evidence to collect; never exploit code) and **Blue Team** (SOC defense: hardening and patches, a detection rule, monitoring and response). All private addresses, names, and secrets are masked into placeholders (`<<HOST_01>>`, `<<DOM_01>>`, `<<SEC_01>>`) before any text leaves your machine.
- **One-click Report Export** — Use **Export report (.md)** or **Print / PDF** in the side panel for the full workspace report, or inside any host drawer for a single-host report.

---

## Configuring AI & Settings (`meow setup`)

Run `meow setup` with no flags to use the interactive **Cat Setup GUI**, or configure settings from the command line:

```sh
# Show current AI & tool configuration
meow setup --show

# Test connectivity to your configured local server and cloud API key
meow setup --check

# Store an OpenRouter or Claude API key safely via standard input (never saved in shell history)
meow setup --provider openrouter --api-key-stdin
meow setup --provider claude --api-key-stdin

# Configure a local OpenAI-compatible model server (Ollama or LM Studio)
meow setup --local-url http://localhost:11434/v1 --local-model qwen2.5-coder:14b

# Remove a stored cloud API key (or choose Local-Only in `meow setup` to lock cloud AI off)
meow setup --forget-key
```

### Configuration files

All user configuration lives in `~/.meow/` (or `$MEOW_HOME` if set) with owner-only (`0600`) permissions:

- **`~/.meow/ai.toml`** — AI provider, model names, local server URL, `disable_cloud` lock, and API key (managed by `meow setup`).
- **`~/.meow/config.toml`** — Default mode, scanner paths, wordlist path, NVD API key, and offline location database settings. Created automatically on first run with commented defaults:

```toml
default_mode = "light"

[recon]
stage_timeout_secs = 1800
output_cap_mb = 50
nmap = "nmap"
katana = "katana"
feroxbuster = "feroxbuster"
# wordlist_path = "/usr/share/seclists/Discovery/Web-Content/common.txt"

[cve]
enabled = true
# nvd_api_key = "..."   # optional NVD API key for higher rate limits

[location]
enabled = true
map = true
# database = ""         # empty uses ~/.meow/geo/
```

---

## Troubleshooting

### `meow update` says `<path> is not a meow git checkout` or `/private/tmp/... is a temporary build folder`

- **If you installed with Homebrew (`brew install meow`):** Newer builds of `meow update` detect Homebrew automatically and run `brew update && brew upgrade` (or `brew upgrade --fetch-HEAD` for `--HEAD` installs). If an older binary prints the temporary build folder message, upgrade through Homebrew directly:
  ```sh
  brew update && brew upgrade meow
  ```
  To switch from a tagged release to the latest `main` branch:
  ```sh
  brew uninstall meow && brew install --HEAD meow
  ```
  If `brew upgrade meow` says `Error: jrdelt/meow/meow not installed`, install it first with `brew install meow`.
- **If you installed from a git clone and deleted or moved that folder:** pass `--source <path-to-meow-clone>` (or set `MEOW_SOURCE=<path-to-meow-clone>`) to update from the moved checkout, or install a release download (`.pkg`, `.tar.gz`, `.zip`): a meow installed from a release updates itself from GitHub Releases, SHA-256 verified.

### macOS says the `.pkg` installer "cannot be opened because it is from an unidentified developer"

On macOS 15 (Sequoia) and newer, open **System Settings → Privacy & Security**, scroll down, and click **Open Anyway** (on macOS 14 and earlier, Control-click the `.pkg` in Finder and choose **Open**), or install directly from Terminal:

```sh
sudo installer -pkg meow-0.2.1-macos-arm64.pkg -target /
```

### `meow recon` says it is refused in `light` mode

`light` mode is strictly passive so no active background packets are sent. Switch the session to `mild` (or `aggressive`) mode before queuing recon:

```sh
meow mode mild
meow recon <target>
```

### Missing `nmap`, `katana`, `feroxbuster`, wordlist, or location database

Run `meow tools` at any time to check which companion tools and data files are installed and automatically install any missing ones:

```sh
meow tools
```

### `meow map` does not open a browser tab (or you are on SSH / headless Linux)

Print the map URL directly to the terminal and open it by hand (or forward the localhost port over SSH):

```sh
meow map --no-open
```

### `Nested meow sessions are disabled (active: <name>)`

You are already inside an active `meow` shell. Run helper commands (`meow recon`, `meow map`, `meow hud`, `meow report`) directly, or type `exit` first if you want to switch to a different workspace.

### Cloud or local AI requests fail

Run the built-in connectivity check to see which endpoint or key needs attention:

```sh
meow setup --check
```

- For **OpenRouter** (`sk-or-...`) or **Claude API** (`sk-ant-...`), run `meow setup` to re-enter your key or switch providers.
- For **Ollama** (`http://127.0.0.1:11434`) or **LM Studio** (`http://127.0.0.1:1234`), verify the local server is running and has at least one model pulled (`ollama list`).

### Removing `meow`

- **Homebrew:** `brew uninstall meow && brew untap Jrdelt/meow`
- **Installer / Binary:** Remove `~/.cargo/bin/meow` (or `/usr/local/bin/meow`) and, if you want to remove all saved workspaces and keys, remove `~/.meow`.

---

## Security & License

See [SECURITY.md](SECURITY.md) for how to report a security vulnerability privately. Released under the [MIT License](LICENSE).
