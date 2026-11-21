# meow

```text
  /\_/\
 ( ^w^ )  meow — local security triage shell, topology mapper & grounded audit workspace
  > ^ <
```

`meow` wraps your normal interactive shell (`zsh`, `bash`, `fish`, or `pwsh`), passively observes authorized reconnaissance and command output, grounds discovered services against public vulnerability feeds, maps your OPSEC transit path and target topology on a live local canvas, and compiles a Markdown or printable PDF audit report.

Everything stays on your machine in a private session folder (`./meow/<name>/` in the folder you run `meow` from, unless you pick another). When you ask a cloud AI model for triage notes, `meow` masks IP addresses, hostnames, domains, emails, MAC addresses, and credentials into placeholders (`<<HOST_01>>`, `<<DOM_01>>`, `<<SEC_01>>`) before any text leaves your machine. In the reply, only the host's own address and names are put back.

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
sudo installer -pkg meow-0.2.4-macos-arm64.pkg -target /
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

Run `meow` with no arguments (or `meow setup`) in a terminal to open the full-screen setup:

```sh
meow
```

Five steps, one question each. The defaults work, and `?` explains the step you are on:

1. **Mode** — what `meow recon` may send by default: `light` (0 packets to hosts), `mild` (slow, rate-limited scans) or `aggressive` (fast scans; labs and authorized hosts only).
2. **Local AI** — a model server on this machine: LM Studio, Ollama, llama.cpp, or your own URL. $0; host data stays on this machine.
3. **Cloud AI** — Off, **Claude API**, or **OpenRouter / other**, with its key (hidden, kept in `ai.toml`, sent only to that service) and models. Private data is masked first; daily cap $1.00 and 20 calls by default.
4. **Lookups & tools** — CVE lookups (software versions to NVD, OSV.dev, CISA KEV), an optional NVD key, your public IP to ipinfo.io, the satellite map (the rough area to EOX); and which of `nmap`, `katana`, `feroxbuster`, the wordlist and the GeoIP database are installed. No lookup carries a scanned host's address or name.
5. **Save** — review, test the connections, save to `~/.meow` (files only you can read), and optionally open your first session.

`meow setup` opens it again; `meow setup --plain` is a line menu for the AI setup.

---

## Quick Start

### 1. Open a session

```sh
meow acme
```

A new session asks where to save it. Press Enter to keep the folder you are in, or edit the path first:

```text
[?] Save session 'acme' in:
    Folder: /Users/j/Desktop
    -> /Users/j/Desktop/meow/acme
```

Sessions saved in the same folder share one `meow/` folder there (`meow/acme/`, `meow/beta/`). It is private, and the `.gitignore` files in it keep it out of git; a running session puts them back if a pull changes them, and warns if git tracks files there. If a pull or an unpacked archive replaces files in it, meow says so, drops that session's shell history and asks before resuming its scans. `meow acme` reopens the same session from any folder.

Then your normal shell opens inside the session. Your prompt is prefixed with `(meow:acme:light)` (reflecting the active session and mode) so you always know a session is active, and `meow` prints the localhost URL for the live topology map.

- `meow acme --local` saves in `./meow/acme/` here without asking.
- `meow acme --home` saves in `~/.meow/workspaces/acme/` without asking. Sessions made there (and old `./.meow/` ones) by earlier versions keep working.

Type `exit` (or press `Ctrl-D`) at any time to close the session shell and save the workspace.

Each workspace keeps its own shell history: `history`, the up arrow and `Ctrl-R` show only its commands. A shell started inside the session (or `exec zsh`) whose startup file sets `HISTFILE` uses that file instead.

### 2. Run commands or queue background recon

Anything you run in the session shell (`nmap`, `ping`, `curl`, `ssh`, `dig`, `git diff`) is observed passively. When a command discovers a host, open port, service banner, HTTP path, or configuration diff, `meow` records it in the workspace graph and looks up matching advisories in the background.
Lookups for hosts and ports known only from terminal text or `meow add` wait behind those for what `meow recon` finds and stop at 256 per session; a notice says when.

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

This writes `REPORT.md` inside the session folder (for example `./meow/acme/REPORT.md`). You can also export the full workspace report or a single-host report directly from the browser map using **Export report (.md)** or **Print / PDF**.

---

## Command Reference

| Command | Description |
| :--- | :--- |
| `meow` | Launch the first-time Cat Setup GUI, or list your sessions |
| `meow <name>` | Open the session `<name>` from any folder; a new one asks where to save it (`./meow/<name>/` by default) |
| `meow <name> --local` | Save or open it in `./meow/<name>/` of this folder without asking |
| `meow <name> --home` | Save or open it in `~/.meow/workspaces/<name>/` without asking |
| `meow list` (`meow ls`) | List every session and where it lives |
| `meow delete <name>` (`meow rm`) | Delete a session (`--local` for the one in this folder, `-y` to skip confirmation) |
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

`meow recon <target>` runs these one at a time in the background (mild and aggressive mode). Follow along in `meow hud` or on the map.

| # | Stage | What it finds |
|---|---|---|
| 1 | `lan` | Gateway and LAN neighbours from your ARP/NDP cache and routes (sends nothing) |
| 2 | `dns` | A, AAAA, CNAME, MX, NS, TXT and PTR records |
| 3 | `asn` | ASN, BGP prefix, provider and country |
| 4 | `subdomains` | Subdomains from Certificate Transparency logs (`crt.sh`) |
| 5 | `mail-dns` | A–F grade for SPF, DMARC, DKIM, CAA and DNSSEC; published services (AD, Microsoft 365); wildcard DNS |
| 6 | `trace` | Route hops and latency |
| 7 | `ports` | Open TCP ports (`nmap`) |
| 8 | `udp` | Key UDP services such as SNMP, IPMI, NTP and DNS (aggressive mode, as root) |
| 9 | `services` | Service versions and CPEs on the open ports (`nmap -sV`) |
| 10 | `headers` | Web stack, cookie flags, security-header grade, title, `robots.txt`, `security.txt` |
| 11 | `waf-cdn` | WAF or CDN in front of the site |
| 12 | `tls-audit` | Certificate details and TLS versions |
| 13 | `ssh-audit` | SSH algorithms, weak ones flagged |
| 14 | `cves` | Known vulnerabilities for the versions found (OSV, NVD, CISA KEV) |
| 15 | `crawl` | Linked pages (`katana`) |
| 16 | `js` | API endpoints and exposed keys in the site's own scripts |
| 17 | `dirs` | Unlinked files and folders (`feroxbuster`) |

Good to know:

- A missing tool skips its stage with the reason; the rest still run. `meow tools` installs them.
- DNS questions go to your own resolvers. DNS-over-HTTPS is used only when they give no answer; it and `crt.sh` only get public names, never internal ones or private addresses. The target's address is the one your system gives (`/etc/hosts` included), as for `nmap`.
- `mail-dns` only asks DNS questions; nothing is sent to the target's servers.
- `js` reads only the target site's scripts (15 in mild, 40 in aggressive). A key it finds goes straight into the Privacy Vault: you only ever see a placeholder like `<<SEC_03>>`, and the report lists it to rotate. Endpoints keep their parameter names, never the values.
- Cookie values are never stored. `dirs` skips sites behind a WAF in mild mode.

---

## Live Topology Map & Report Export

`meow map` opens the map in your browser (`127.0.0.1`, protected by a per-session token).

- **Path** — You → gateway → WAN or VPN exit → Internet (click for each hop's location, network and latency) → WAF/CDN → provider → target hosts.
- **Location** — a small satellite map floats top right; **−** folds it. **Expand** fills the window; **Esc** goes back.
- **Host tabs** — Overview, Ports, Web & TLS, DNS & Mail, CVEs, and Notes & AI. Use ←/→ or `1`–`6`. Hover a row for details.
- **Check now** — one connection to each of a host's known open ports, to see if it is up (mild and aggressive mode).
- **CVEs** — found by software version and listed per software, known exploited first, with the release that fixes them.
- **AI triage** — `[L]` local, `[C]` cloud, `[R]` research. Answers come as a **Red Team** plan (authorized testing, no exploit code) and a **Blue Team** plan (defense). Private addresses, names and secrets are masked before anything leaves your machine. Answers get back only the host's own address and names, and not on a line that names another host; anything else stays a placeholder (the report lists secrets to rotate).
- **Export** — **Export report (.md)** or **Print / PDF**, for the whole workspace or one host.

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

# Remove a stored cloud API key (or choose Off under Cloud AI in `meow setup` to lock cloud AI off)
meow setup --forget-key
```

### Configuration files

All user configuration lives in `~/.meow/` (or `$MEOW_HOME` if set) with owner-only (`0600`) permissions:

- **`~/.meow/ai.toml`** — AI provider, model names, local server URL, `disable_cloud` lock, and API key (managed by `meow setup`). If the file cannot be read, cloud AI stays off until it is fixed. A key goes only to the service it was set for, also one in `config.toml`.
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
# skip = ["udp", "js"]   # stages to leave out

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

### `meow update` refuses a `.git/config` setting or a submodule

meow only runs git in a checkout that looks like a plain clone: its `.git/config` holds only what `git clone` writes (plus `user.name`, `user.email`, `pull.rebase`, `pull.ff`, `gc.auto`), its `.git` has no `commondir`, and it has no submodules. Remove what the message names, or clone meow again.

### macOS says the `.pkg` installer "cannot be opened because it is from an unidentified developer"

On macOS 15 (Sequoia) and newer, open **System Settings → Privacy & Security**, scroll down, and click **Open Anyway** (on macOS 14 and earlier, Control-click the `.pkg` in Finder and choose **Open**), or install directly from Terminal:

```sh
sudo installer -pkg meow-0.2.4-macos-arm64.pkg -target /
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

### The `udp` stage is skipped

It runs only in aggressive mode and as root, because UDP scanning sends raw packets and is slow. To run it yourself and add the result:

```sh
sudo nmap -sU -sV -p U:53,67,69,88,111,123,137,161,389,500,514,520,623,1194,1434,1900,2049,4500,5060,5353,5683,11211,51820 <target> -oX udp.xml
meow add udp.xml
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
- A server on this machine gets unmasked text and API keys only when meow can see it is yours. Another user's server, or one meow cannot check (on Windows a system or service process, which does not tell whose it is, or a port opened by a process that has since exited; `lsof` failing on macOS), gets masked text and no key.

### Removing `meow`

- **Homebrew:** `brew uninstall meow && brew untap Jrdelt/meow`
- **Installer / Binary:** Remove `~/.cargo/bin/meow` (or `/usr/local/bin/meow`). To remove your settings, keys and sessions too, delete `~/.meow` and any `meow/` session folders (`meow list` shows where they are).

---

## Security & License

See [SECURITY.md](SECURITY.md) for how to report a security vulnerability privately. Released under the [MIT License](LICENSE).
