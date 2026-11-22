# meow

```text
  /\_/\
 ( ^w^ )  meow — local security triage shell, topology mapper & grounded audit workspace
  > ^ <
```

`meow` wraps your normal shell (`zsh`, `bash`, `fish` or PowerShell) and watches what your commands print. It records hosts, ports, services, web paths and config diffs, and looks up known CVEs for the versions it finds. It draws your route out and the target network on a live local map, and writes a Markdown or printable PDF report.

Everything stays on your machine, in a private session folder. Before any text goes to a cloud AI, meow replaces private values with placeholders such as `<<HOST_01>>`, `<<DOM_01>>` and `<<SEC_01>>`.

> **Authorized use only.** Use meow only on systems you own or have written permission to test. meow lists services, settings and public advisories so you can patch and verify. It never writes exploits or attacks.

---

## Install

### Homebrew (macOS and Linux)

```sh
brew tap Jrdelt/meow https://github.com/Jrdelt/meow.git
brew trust Jrdelt/meow   # Homebrew 7+
brew install meow
```

This also installs `nmap`, `katana`, `feroxbuster` and the SecLists `common.txt` wordlist. Run `meow tools` once to add the offline location database.

To follow the `main` branch instead of releases, use `brew install --HEAD meow` (from a release install: `brew uninstall meow && brew install --HEAD meow`).

### Release downloads

Get the file for your system from the [latest release](https://github.com/Jrdelt/meow/releases/latest). Each has a `.sha256` file.

- **macOS:** `meow-<version>-macos-arm64.pkg` (Apple Silicon) or `meow-<version>-macos-x86_64.pkg` (Intel). It installs `/usr/local/bin/meow`. macOS blocks it the first time: see [Troubleshooting](#macos-blocks-the-pkg-installer).
  ```sh
  sudo installer -pkg meow-0.2.6-macos-arm64.pkg -target /
  ```
- **Linux:** `meow-<version>-linux-x86_64.tar.gz` (or `-linux-arm64`).
  ```sh
  sha256sum -c meow-0.2.6-linux-x86_64.tar.gz.sha256
  tar -xzf meow-0.2.6-linux-x86_64.tar.gz
  sudo install -m 0755 meow /usr/local/bin/meow
  ```
- **Windows:** `meow-<version>-windows-x86_64.zip` (x64, or ARM64 under emulation). Check it with `Get-FileHash`, unzip it, and put `meow.exe` in a folder on your `PATH`.

Then run `meow tools` to add the scanners, the wordlist and the location database.

### Build from source (macOS and Linux)

```sh
git clone https://github.com/Jrdelt/meow.git && cd meow && ./install.sh
```

`install.sh` builds the clone it is in and installs `~/.cargo/bin/meow`. First it installs what is missing: a C compiler, Rust 1.89 or newer (through `rustup`), `nmap`, `katana`, `feroxbuster`, a wordlist (`~/.meow/wordlists/common.txt`) and the DB-IP Lite location database (`~/.meow/geo/`, kept for 30 days). It is safe to run again. Piping it into `sh` is not supported.

| Flag | Effect |
| :--- | :--- |
| `--yes` | Do not ask |
| `--dry-run` | Only show what it would do |
| `--no-tools` | Leave out the scanners and the wordlist |
| `--no-geo` | Leave out the location database |
| `--tools-only` | Do not build meow; install the scanners, the wordlist and the location database |

### Build from source (Windows)

```powershell
git clone https://github.com/Jrdelt/meow.git
cd meow
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

`install.ps1` takes `-Yes`, `-DryRun`, `-NoTools`, `-NoGeo` and `-ToolsOnly`. It installs tools with `winget` or `scoop`; with `winget` it also adds the Visual Studio C++ Build Tools. It stops if this folder, or one above it, has a `.cargo`, `.cargo\config`, `.cargo\config.toml`, `rust-toolchain` or `rust-toolchain.toml` that another account can change, because cargo would use it.

### Updating

`meow update` upgrades meow itself; `meow tools` checks the scanners and data files. `meow update --check` only shows what is new.

| Installed from | `meow update` |
| :--- | :--- |
| `.pkg`, `.tar.gz`, `.zip` | Downloads the newest release for this system, checks its SHA-256 and replaces the meow program. Nothing else. Pre-releases are skipped unless this meow is one. |
| Homebrew | Runs `brew update`, then `brew upgrade meow` (`brew upgrade --fetch-HEAD meow` for a `--HEAD` install). This also upgrades outdated `nmap`, `katana` and `feroxbuster`. |
| `install.sh` | Pulls the latest code into the folder meow was built from and runs its `install.sh --yes`, which rebuilds meow and adds missing tools and the location database. |
| `install.ps1` | Pulls the latest code, then asks you to close meow and run `install.ps1 -Yes`. |

Updates from a source folder:

- Only fast-forward pulls. Nothing is pulled while the folder has local changes.
- `--source <dir>` or `MEOW_SOURCE=<dir>` names another clone. The remote must be an `https://` or ssh address; a local folder works only with `--source`.
- git never asks for a password. A private https remote needs a credential helper in your own git config, or ssh.
- On macOS and Linux the build runs in `~/.meow/build`, private and kept, so later updates rebuild only what changed. It can reach several hundred MB; deleting it only costs a full rebuild. Old `meow-build-XXXXXX` folders of yours in the temp folder are removed.
- Open sessions keep the old version until you reopen them.

---

## First-Time Setup

Run `meow` (or `meow setup`) in a terminal. On a new machine, a bare `meow` opens the full-screen setup: five steps, one question each. The defaults work, and `?` explains the step.

| Step | What you choose |
| :--- | :--- |
| 1 Mode | What `meow recon` may send by default: `light` (0 packets to hosts), `mild` (slow, rate-limited scans) or `aggressive` (fast scans; labs and authorized hosts only) |
| 2 Local AI | A model server on this machine: LM Studio, Ollama, llama.cpp or your own URL. $0; host data stays here |
| 3 Cloud AI | Off, **Claude API**, or **OpenRouter / other**, with its key and models. The key is hidden, kept in `ai.toml` and sent only to that service. Private data is masked first. Cap: $1.00 and 20 calls a day, all sessions together |
| 4 Lookups & tools | CVE lookups (versions to NVD, OSV.dev, CISA KEV), an optional NVD key, your public IP to ipinfo.io, the satellite map (rough area to EOX), and which tools are installed. No lookup carries a scanned host's address or name |
| 5 Save | Review, test the connections, save to `~/.meow` (files only you can read), and open your first session if you like |

On a key row (Cloud AI key, NVD key), typing goes into the key. A box opened this way takes only a key of 16 or more characters. For a shorter key, or to remove one, press `Enter` on the row first.

`meow setup --plain` (or `TERM=dumb`) shows a line menu for the AI setup: `1` local AI server, `2` Claude key, `3` OpenRouter or other key, `4` remove key, `5` test, `6` cloud AI off (local AI only), `q` done.

---

## Quick Start

### 1. Open a session

```sh
meow acme
```

A new session asks where to save it. Press Enter to keep the folder you are in, or edit the path:

```text
[?] Save session 'acme' in:
    Folder: /Users/you/projects/audit
    -> /Users/you/projects/audit/meow/acme
```

Your shell then opens inside the session, and meow says where it is saved. `exit` (or `Ctrl-D`) closes it; `meow acme` opens it again from any folder.

- `meow acme --local` saves in `./meow/acme/` here without asking.
- `meow acme --home` saves in `~/.meow/workspaces/acme/` without asking.

meow does not change your prompt. To show the session in it, use `$MEOW_SESSION` and `$MEOW_MODE` (bash, zsh and PowerShell keep `$MEOW_MODE` current).

Each session has its own shell history: `history`, the up arrow and `Ctrl-R` show only its commands. A shell started inside it (or `exec zsh`) whose startup file sets `HISTFILE` uses that file instead. fish keeps a history list for the session, but gets no hooks, so `replay.sh` stays empty.

### 2. Run commands or queue recon

meow watches what you run (`nmap`, `ping`, `curl`, `ssh`, `dig`, `git diff`). When the output shows a host, open port, banner, HTTP path or config diff, meow records it and looks up CVEs in the background. Lookups for what only terminal text or `meow add` showed wait behind those for `meow recon`. They stop at 256 new questions per session, and a notice says when.

For an automated inventory of an authorized target, switch to `mild` (or `aggressive`) and queue a recon. Extra `nmap` flags go after `--`:

```sh
meow mode mild
meow recon example.com
meow recon 192.0.2.0/24 -- -p 22,80,443,8080
```

### 3. Watch it live

From the session or another terminal:

```sh
meow map    # live map in your browser
meow hud    # the same in this terminal; ? lists its keys
```

### 4. Write the report

```sh
meow report
```

This writes `REPORT.md` in the session folder (for example `./meow/acme/REPORT.md`). It is not masked: review it before you share it. The map also exports it: **Download .md**, **Host report .md** or **Print / PDF**.

---

## Command Reference

| Command | What it does |
| :--- | :--- |
| `meow` | First-time setup on a new machine; otherwise list your sessions |
| `meow <name>` | Open session `<name>` from any folder. A new one asks where to save it (`./meow/<name>/` by default) |
| `meow <name> --local` | Save or open it in `./meow/<name>/` here, without asking |
| `meow <name> --home` | Save or open it in `~/.meow/workspaces/<name>/`, without asking |
| `meow list` (`ls`, `status`) | List your sessions, where they are, and which are running |
| `meow delete <name>` (`rm`) | Delete a session (`--local`: the one here; `-y`: do not ask) |
| `meow mode <light\|mild\|aggressive>` | Switch the session's mode |
| `meow recon <target> [-- <nmap flags>]` | Queue the 17-stage inventory of a host, domain, IP or CIDR range. `--install-tools` installs a missing scanner or wordlist without asking |
| `meow map [--no-open]` | Open the live map, or only print its URL |
| `meow hud` | Watch the session in this terminal |
| `meow add <file> [--no-cve]` | Import an Nmap XML, katana or feroxbuster JSONL, log or `git diff` file; `--no-cve` skips CVE lookups |
| `meow report` | Write `REPORT.md` |
| `meow setup` | Change the setup ([flags](#meow-setup-flags)) |
| `meow tools [--yes]` | Check the scanners, wordlist and location database; install what is missing |
| `meow update [--check] [--source <dir>]` | Upgrade meow itself ([Updating](#updating)) |

- Inside a session, `mode`, `recon`, `map`, `hud`, `add` and `report` find it by themselves. From another terminal, add `--session <name>`, or `--local` for the one session in `./meow/` here.
- `meow recon` and `meow map` need a running session. `meow hud` opens a closed one read-only.
- Sessions do not nest: `meow` and `meow <name>` are refused inside one.

---

## Session Folders

New sessions go in `./meow/<name>/` of the folder you pick. Sessions in the same folder share its `meow/` folder (`meow/acme/`, `meow/beta/`).

- The folders are private (`0700`; on Windows, an access list for you alone). meow never follows a link there.
- `./meow/` and each session have a `.gitignore` that keeps them out of git. In a repository of yours, meow also adds `./meow` to `.git/info/exclude`.
- meow warns when the folder looks synced to a cloud service (Dropbox, OneDrive, Google Drive, iCloud): scan data would be uploaded.
- Sessions of older versions keep working: `~/.meow/workspaces/<name>/` and the old `./.meow/`. `meow list` shows an old `./.meow/` only from its own folder.

### Folders meow refuses

On macOS and Linux, meow refuses a folder that another user owns or can write to. It also refuses one inside a folder they can change; a sticky folder like `/tmp` is fine. It checks again whenever a session there is opened, used or deleted. The message names the reason and the fix:

| Reason (for the folder or one above it) | Fix |
| :--- | :--- |
| other users can write to it | Make that folder yours alone |
| a group shared with other users can write to it | Make that folder yours alone |
| a group can write to it, and meow cannot read its access list (NFS, FUSE) | Remove group write from the folder |
| meow cannot read who may write to it (an SMB share) | Move that folder to a disk of this computer |
| meow cannot read who may write to it (an unreadable access list) | Check the folder's access list |

- The share reasons (SMB, NFS, FUSE) apply on Linux.
- On macOS, group write for a shared group such as `staff` counts even beside an ACL like "everyone deny delete". Folders older versions accepted, for example after `chmod 775 ~`, may now be refused.
- A path that is not valid UTF-8 is refused.
- On Windows, meow does not read the folders' access lists: use `--home` there.

### In a git folder

- meow checks the session files at open and every 2 s. It asks git again only when git's index has changed.
- git runs only on the repository at the top of the work tree. It reaches no remote, ignores the repository's `core.sshCommand` and credential helpers, and never asks for a password. Opening a session in a cloned or unpacked repository runs none of its programs.
- git gets 3 s per check. Past that, it is stopped and meow says once: `git did not answer in 3 s: session files not checked`.
- A `.gitignore` of meow's that a pull changed is put back, and meow says so.
- If git tracks session files, meow names up to 3: `git tracks session files (...)`. Fix it with `git rm -r --cached meow`. A `.gitignore` of yours that lets them in gets a warning too.
- Linked work trees, submodules, and `.git` folders that are shared or another user's get only the `.gitignore` files: no git check, no warning.

### Files changed outside meow

meow records the session files when a session ends and compares them at the next open.

- If a `git pull`, a checkout or an unpacked archive replaced them between sessions, meow says `Files changed outside meow: shell history and last folder not used` and drops those two.
- The same follows a `git pull` during the session. meow notices one when:
  - git tracks files that meow reads back;
  - a `.gitignore` had to be put back; or
  - git did not answer after its index changed.

  While git tracks those files, every session ends this way.
- A file copied or unpacked over the shell history while the session runs is not noticed.
- A scan queued in session files never runs: a session runs only what you queue in it.
- After an end meow did not see (`kill -9`, a crash, power loss), it says `meow did not end cleanly last time`. It keeps the history, unless git or a replaced file says otherwise.

### Sessions from elsewhere, moved folders

- A session that came with a cloned, unpacked or copied folder opens only after you accept it. meow first says what it carries. It opens in your default mode, without its shell history, start folder and queued scans, and never under the name of one of yours.
- Move or rename a project folder, and `meow <name>` finds the session again: `Session moved from <old path>`. This works when the old folder is gone and the files are unchanged. History and start folder stay. Until then, helpers ask you to run `meow <name>` first.
- With no session running, `meow add` and `meow report` hold `helper.lock` while they write. `meow <name>` waits up to 5 s for them; `meow delete` and another `add` or `report` are refused.

---

## Modes (`light`, `mild`, `aggressive`)

| Mode | Shell watching | `meow recon` | Scans |
| :--- | :--- | :--- | :--- |
| `light` (default) | On | Refused | None: 0 packets to hosts |
| `mild` | On | On | `nmap -sS -T3 --top-ports 1000`, `katana` depth 2, `feroxbuster` 20 requests/s |
| `aggressive` | On | On | `nmap -sS -T4 -p- -O`, `katana` depth 4, `feroxbuster --auto-tune` |

Switch any time: `meow mode light`, `meow mode mild`, `meow mode aggressive`.

- Light mode cannot stop a command you type. In bash and zsh it warns before `nmap -T4`, `-T5` or `-A`, `masscan` or `--min-rate`.
- Without root (administrator on Windows), nmap uses a connect scan instead of a SYN scan and skips OS detection.
- Flags after `--` must be safe nmap flags, 32 at most. File outputs and target files are refused.
- Scripts run only by category (`default`, `safe`, `vuln`, `discovery`, `version`) or by name (`ssl-cert`, `http-server-header`, `http-title`, `ssh-hostkey`, `banner`). Scripts in the intrusive, brute, dos, exploit, external, fuzzer, malware and broadcast categories never run.
- For anything else, run nmap yourself and `meow add` its XML.

---

## What `meow recon` Does (17 Stages)

`meow recon <target>` runs these one at a time in the background (mild and aggressive mode).

| # | Stage | What it finds |
|---|---|---|
| 1 | `lan` | Gateway and LAN neighbours from your ARP/NDP cache and routes (sends nothing) |
| 2 | `dns` | A, AAAA, CNAME, MX, NS, TXT and PTR records |
| 3 | `asn` | ASN, BGP prefix, provider and country |
| 4 | `subdomains` | Subdomains from Certificate Transparency logs (`crt.sh`) |
| 5 | `mail-dns` | A–F grade for SPF, DMARC, DKIM, CAA and DNSSEC; published services (AD, Microsoft 365); wildcard DNS |
| 6 | `ports` | Open TCP ports (`nmap`) |
| 7 | `trace` | Route hops and latency to the address `ports` scanned |
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

### Progress and stopping

- The HUD and the map show each stage as done, running, waiting, skipped, failed or stopped, with nmap's own percent and time left. `7/17` means 7 stages are over.
- A missing tool skips its stage with the reason; the rest still run. `skip` in `config.toml` turns stages off.
- If the port scan fails, every later stage except `trace` is skipped.
- A tool run stops after `stage_timeout_secs` (1800) or when its output passes `output_cap_mb` (50).
- `meow mode light` pauses a recon; `mild` or `aggressive` continues it in the same session.
- Ending the session stops the running stage and every program it started. Finished stages are kept; stages not started are shown as `not run`. The next start says `Recon <target> cut short at <stage>`. Nothing restarts by itself: run `meow recon <target>` to scan again.
- The session ends this way on `exit`, a closed terminal, `kill` (TERM, HUP, INT or QUIT), and `Ctrl-C` when meow's output goes to a pipe or file. On Windows, also on a closed console window, log-off or shutdown; meow then takes at most 4.5 s.
- If meow is killed outright (`kill -9`, a crash), a helper process stops the scans: `meow-guard` on Linux, `meow __guard` on macOS. If it dies too, the next `meow`, `meow list` or session start does. On Windows the scans end with meow's process.
- A program a scanner starts in a session or process group of its own (`setsid`, `sudo` with its own terminal) is not stopped.

### Scan targets and route

- nmap scans a domain at the address the `dns` stage picked: the first IPv4 address, or the first IPv6 address with `-- -6`. The route, DNS facts, **DNS & Mail** tab and crt.sh summary go on that host. Without a `dns` result, nmap gets the name.
- `-Pn`, `-P*`, `-n`, `-R`, `--system-dns`, `-4` and `-6` apply to every nmap scan, whether given after `--` or in a mode's `nmap_ports`. With both `-4` and `-6`, the last counts.
- If nothing answers nmap's up check, `ports` and `udp` say so and suggest `-- -Pn`.
- `trace` runs `traceroute -n -q 1 -w 1 -m 15`, then `tracepath -n -m 15` (Windows: `tracert -d -h 15 -w 500`), for 50 s at most. It records only hops the tool printed. With no hops, or no tool, it is skipped.

### DNS and privacy

- DNS questions go to your own resolvers:
  - Linux and BSD: the servers in `/etc/resolv.conf`.
  - macOS: the resolver `scutil --dns` lists for the name's domain (VPN, Tailscale, `/etc/resolver/*`), else the default one.
  - Windows: the servers of the NRPT rule for the name, else the network adapters' servers.
- Up to 3 servers are asked. `.local` names never go to a DNS server.
- DNS-over-HTTPS (Cloudflare or Google) is used only for public names, and only when your resolvers give no answer. It is never used for split-DNS names or an internal target.
- `crt.sh` and DNS-over-HTTPS never get internal names or non-public addresses: private, loopback, documentation, `0.0.0.0/8`, `240.0.0.0/4`, `3fff::/20`.
- The target's address is the one your system gives (`/etc/hosts` included), as for `nmap`.
- For an internal target, "no such record" counts only from the DNS server for the name's domain, or a default one that gives the target's own address. Otherwise meow says `this machine's DNS server does not know <name>`.
- `mail-dns` only asks DNS questions, through your resolvers. The domain's own DNS servers see them all, including two made-up names (16 random hex digits) for the wildcard check.
- A DNS check with no definite answer shows `could not be checked` and is left out of the grade. The grade is `?` unless SPF, DMARC and one more check were done.

### Web stages

- `js` reads only the site's own scripts (15 in mild, 40 in aggressive). A key it finds goes straight into the Privacy Vault: you see only a placeholder like `<<SEC_03>>`, and the report lists it to rotate. Endpoints keep parameter names, never values.
- Cookie values are never stored. `dirs` skips sites behind a WAF or CDN in mild mode.

### CVE lookups

- Each host gets at most 64 lookups, each question once. The software on its open ports comes first. Libraries guessed from script names come last: at most 8 per port, and only from files the server served.
- A rescan that names a port's software again replaces its old version. The old version's CVEs go at the next full lookup.
- A TLS retest replaces the TLS versions and weak ciphers only when every handshake answered. Otherwise new findings are added.

---

## Live Map, HUD and Report

### Map

`meow map` opens the map in your browser, on `127.0.0.1`, with the session's token.

- **Drawing:** you, your router, your public address or VPN, and the Internet. Click the Internet for each hop's place, network and latency. Then come the hosts, by network and provider. Each host shows its address, open ports and CVEs; a red glow is a CVE that is known exploited, critical or high. The legend lists only what is drawn.
- **Large networks:** at most 24 devices under the router and 12 in `No route`; the rest are counted (`+N more in Hosts`). The Hosts card lists all.
- **Routes:** a route whose target did not answer ends at the last hop that did, with no route time.
- **Location:** a small satellite map floats top right. **−** folds it; it folds by itself over a device. **Expand** fills the window; **Esc** goes back. On screens up to 900 px wide, tapping a device leaves Expand and scrolls to its card.
- **This machine:** only what could be read: system, interfaces with their gateway, listening ports. Routes, neighbours and all interfaces fold away below.
- **Host tabs:** Overview, Ports, Web & TLS, DNS & Mail, CVEs, Notes & AI. Use `←`/`→` or `1`–`6`; hover a row for details.
- **Check now:** tests whether the host is up, in mild and aggressive mode. It makes one connection to each of up to 6 known open ports (else 443, 80 and 22), 3 s each.
- **CVEs:** one line per update, hosts with known exploited CVEs first, for example `Update nginx 1.18.0 to 1.20.1 or later, or close 80/tcp and 443/tcp if the service is not needed.` Each line unfolds into its CVEs.
- **Notes:** 2000 bytes at most. The box counts bytes and turns red when over, and the session refuses more: `the note is too long: N bytes, 2000 at most`. The note stays in the box until the session keeps it.
- **AI:** **Local AI**, **Cloud AI** and **Research**, with today's cloud spend (all sessions) and the daily cap. Answers come as a **Red team** plan (authorized testing, no exploit code) and a **Blue team** plan (defense). Saved notes are listed under the host and in the report.
- **Report:** **Download .md** or **Print / PDF** for the session; **Host report .md** on a host's card.

| Badge | Meaning |
| :--- | :--- |
| `live` | The session answered with its own key |
| `reconnecting…` | The connection dropped; the page retries. Recon progress stays as it was |
| `session closed` | Reconnecting failed; running recons show as stopped |
| `session ended` | Something else answers on the port (wrong key, or nothing in 10 s); the page stops retrying |

Until the session proves who it is, the page sends nothing and shows nothing it receives. A tab reloaded after its session ended says: `This map link has no session any more: run meow map in the session again.`

### HUD

`meow hud` shows hosts, what to update, CVEs, recon progress and notices. With no session running it opens the files read-only. It needs at least 60x12.

| Key | Action |
| :--- | :--- |
| `↑` `↓` `j` `k` | Move |
| `Tab` `←` `→` | Hosts or CVEs |
| `PgUp` `PgDn` | Scroll the host, AI or machine panel |
| `L` / `C` / `R` | Ask local AI / cloud AI (masked, daily cap) / CVE research (versions only, daily cap) |
| `a` | Show or hide the AI answer |
| `m` | Show or hide all of this machine |
| `n` | Note on the host |
| `1` `2` `3` | Mode: light, mild, aggressive |
| `q` `Esc` | Quit |

### Report

`REPORT.md` has: Topology (Mermaid), What to update, CVEs, Hosts, Secrets to rotate, Background tasks, Command trail (`replay.sh`) and AI triage notes.

- Fix lines name every open port that runs the old version.
- Only hosts on the map are counted. Names only printed in the shell or a log, or only in the certificate logs, share one line: `Only mentioned, not scanned: ...`.

---

## AI and Settings

### AI tiers

| Key | Tier | What it sends |
| :--- | :--- | :--- |
| `L` | Local AI | The host's evidence, unmasked, to a model server on this machine ($0) |
| `C` | Cloud AI | Masked evidence, to the Claude API or OpenRouter. Without a key, or past the daily cap, local AI answers |
| `R` | Research | Cloud AI that also searches the web for each CVE. Only software versions and advisory IDs, masked |

A model server on this machine gets unmasked text and API keys only when meow sees it is yours:

- Linux: a server run by you, root or a system account (user ID below 1000) counts as yours; another login user's does not.
- macOS: only a server meow sees running as you.
- All others get masked text and no key: another user's server, one on another machine, or one meow cannot check (on Windows a system or service process, or a port whose process has exited; on macOS when `lsof` fails).

### What is masked

- Before anything goes to a cloud AI, meow replaces IP addresses, host names, domains, email user names, MAC addresses, file paths, user names and secrets with placeholders. A value always gets the same placeholder.
- In the reply, only the triaged host's own address and names are filled back, and only in prose. They stay placeholders in code, command-like lines, lines naming another host, and names built on a placeholder. Such replies end with `_Placeholders stay in code, commands and lines naming other hosts._`
- Secrets always stay placeholders; the report lists them to rotate.
- Your notes go to a cloud AI only with `cloud_notes = true`.

### Daily cloud cap

- `max_daily_usd` ($1.00) and `max_daily_calls` (20) are one budget for all your sessions, per local calendar day, kept in `~/.meow/ai-usage`.
- A call is counted at its highest cost before it is sent, then at its real cost. The HUD and map may briefly show the higher figure.
- If one call could cost more than is left: `one call could cost up to $X; $Y left today (raise max_daily_usd)`. Research with Fable, Mythos or an unknown Claude model (about $1.36 a call) does not fit the default cap.
- If `~/.meow/ai-usage` cannot be read, cloud AI is off: `C` answers locally and `R` is off.

### `meow setup` flags

| Flag | Effect |
| :--- | :--- |
| `--show` | Show the AI setup (never the key) |
| `--check` | Test the local AI server and the cloud AI key |
| `--plain` | Line menu |
| `--local-url <url>`, `--local-model <name>` | Local AI server and model (`""`: the server's choice) |
| `--provider claude\|openrouter` | Cloud AI service |
| `--cloud-url <url>` | Address of another cloud AI service |
| `--cloud-model <name>`, `--research-model <name>` | Cloud triage and research models |
| `--fallback-models <a,b>` | Claude API: models asked when one declines (`""`: the API chooses) |
| `--api-key-stdin` | Read the key from standard input, so it stays out of shell history |
| `--forget-key` | Remove the stored key |
| `--cloud-off` | Cloud AI off (local AI only); removes the stored key |

```sh
meow setup --provider openrouter --api-key-stdin
meow setup --provider claude --api-key-stdin
meow setup --local-url http://localhost:11434/v1 --local-model qwen2.5-coder:14b
meow setup --cloud-off
```

- Without `--provider` or `--cloud-url`, an `sk-ant-` key picks the Claude API and an `sk-or-` key OpenRouter. To keep a gateway, name it in the same command.
- A key for the other known service is refused (`key refused: it is for api.anthropic.com, not openrouter.ai`). A server on this machine takes any key. Setup prints `Key saved for <host>`, never the key.
- A key goes only to the service it was set for, also one in `config.toml`. An exported key wins over `ai.toml`: `from $OPENROUTER_API_KEY · ai.toml key not used`.
- `--cloud-off` saves `disable_cloud = true` in `ai.toml`. It holds even with `OPENROUTER_API_KEY` or `ANTHROPIC_API_KEY` exported. It cannot be combined with `--provider`, `--cloud-url` or `--api-key-stdin`; a later one of those turns the cloud on again.

### Files in `~/.meow`

All settings live in `~/.meow/` (or `$MEOW_HOME`): files `0600`, folders `0700`.

| Path | Holds |
| :--- | :--- |
| `config.toml` | Global settings, made on first run with comments |
| `ai.toml` | Your AI setup and key (`meow setup`); overrides `[ai]` in `config.toml`. Unreadable: cloud AI off until fixed |
| `ai-usage`, `ai-usage.lock` | Today's cloud use, all sessions |
| `local-workspaces`, `session-files/` | Where your project-folder sessions are, and their files at the last end |
| `run/` | One file per running scan tool, to stop leftovers |
| `build/` | Build folder of source updates |
| `geo/`, `wordlists/` | Location database; extra wordlists (any `.txt`) |
| `workspaces/` | Sessions saved with `--home` |

Environment: `MEOW_HOME` (another folder for all of this), `MEOW_SOURCE` (the clone `meow update` uses), `OPENROUTER_API_KEY` and `ANTHROPIC_API_KEY`. A session shell has `MEOW_SESSION`, `MEOW_MODE` and `MEOW_WORKSPACE`.

### `config.toml`

Unknown keys are ignored.

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `default_mode` | `"light"` | Mode of new sessions |
| `shell` | not set | Shell to start; else `$SHELL` on macOS and Linux, else zsh, bash or PowerShell |
| `[location] enabled` | `true` | With the map open, estimate this machine's place from its public address: once, then when the network changes; never while a VPN carries all traffic |
| `[location] url` | `"https://ipinfo.io/json"` | Service asked (`https://` only) |
| `[location] map` | `true` | Satellite map; fetches at most six pictures from EOX, which tells EOX the rough area |
| `[location] tiles` | EOX Sentinel-2 cloudless | Another picture source |
| `[location] database` | `""` (`~/.meow/geo/`) | Offline database for selected hosts; never looked up online |
| `[cve] enabled` | `true` | CVE lookups; only software names and versions are sent |
| `[cve] nvd_api_key` | not set | NVD pacing 0.7 s instead of 6.5 s |
| `[recon] stage_timeout_secs` | `1800` | Seconds per tool run |
| `[recon] output_cap_mb` | `50` | Output per tool run |
| `[recon] nmap`, `katana`, `feroxbuster` | the program names | Program names or paths |
| `[recon] wordlist_path` | not set | Wordlist for `dirs`; else SecLists and dirb paths, then `~/.meow/wordlists/` |
| `[recon] skip` | `[]` | Stages to leave out, e.g. `["udp", "js"]` |
| `[recon.mild]`, `[recon.aggressive]` | built in | `nmap_ports`, `nmap_services`, `katana_depth`, `ferox_rate_limit` |
| `[ai] local_url`, `local_model` | `"http://localhost:1234/v1"`, `""` | Local AI server and model |
| `[ai] cloud_model`, `research_model` | `"anthropic/claude-sonnet-5.5"`, `"anthropic/claude-opus-5.5"` | Cloud models |
| `[ai] max_daily_usd`, `max_daily_calls` | `1.0`, `20` | Daily cloud caps, all sessions together |
| `[ai] cloud_notes` | `false` | Send your notes, masked, to the cloud |

---

## Troubleshooting

### `meow update` says `<path> is not a meow git checkout` or `/private/tmp/... is a temporary build folder`

- **Homebrew:** `meow update` finds a Homebrew install by itself. If an older meow prints the temporary build folder message, use Homebrew directly: `brew update && brew upgrade meow`. To switch to the `main` branch: `brew uninstall meow && brew install --HEAD meow`. If `brew upgrade meow` says `Error: jrdelt/meow/meow not installed`, run `brew install meow` first.
- **A clone you deleted or moved:** pass `--source <path-to-meow-clone>` (or set `MEOW_SOURCE=<path-to-meow-clone>`), or install a release download. A release install updates itself from GitHub Releases, SHA-256 verified.

### `meow update` refuses the clone

It checks the clone before git first reads it, also with `--check` and `--source`. Remove what the message names, or clone meow again.

- **A `.git/config` setting:** the file is read alone, without includes. It may hold only what `git clone` writes (`core.repositoryformatversion`, `filemode`, `bare`, `logallrefupdates`, `ignorecase`, `precomposeunicode`, `symlinks`; `extensions.objectformat`, `refstorage`; `remote.<name>.url`, `fetch`, `tagopt`; `branch.<name>.remote`, `merge`, `rebase`) plus `user.name`, `user.email`, `pull.rebase`, `pull.ff`, `gc.auto`, `maintenance.auto` and `maintenance.strategy`.
- **A submodule, or `.git/commondir`:** neither is allowed.
- **`refusing to build <dir>: <path> ..., and cargo would use it`:** a folder above has a `.cargo`, `.cargo/config`, `.cargo/config.toml`, `rust-toolchain` or `rust-toolchain.toml` that is a link, another user's, or changeable by others. A `.cargo` link is fine when it is yours (or root's) and leads to a folder of yours alone, such as `~/.cargo` on another disk.
- **`<path> can be changed by other users, so meow does not build in it`:** make `~/.meow` and `~/.meow/build` yours alone. Deleting `~/.meow/build` is safe.
- **Windows, `<path> can be changed by other accounts, so nothing is run in it`:** for example a clone right under `C:\`. Clone meow into your user folder and run `.\install.ps1` there, or pass `--source <folder>`. Related: `... belongs to another account`, `... cannot be checked`.

### macOS blocks the `.pkg` installer

macOS says it "cannot be opened because it is from an unidentified developer". On macOS 15 (Sequoia) and newer, open **System Settings → Privacy & Security**, scroll down and click **Open Anyway**. On macOS 14 and earlier, Control-click the `.pkg` in Finder and choose **Open**. Or install from the terminal:

```sh
sudo installer -pkg meow-0.2.6-macos-arm64.pkg -target /
```

### `meow recon` is refused in `light` mode

`light` sends no packets to hosts. Run `meow mode mild` (or `aggressive`) first.

### Missing `nmap`, `katana`, `feroxbuster`, wordlist or location database

Run `meow tools`. It shows what is installed and installs what is missing. Without the location database, the map says `the location database is not installed: run meow tools`.

### The `udp` stage is skipped

It runs only in aggressive mode and as root: UDP scans send raw packets and are slow. To run it yourself and add the result:

```sh
sudo nmap -sU -sV -p U:53,67,69,88,111,123,137,161,389,500,514,520,623,1194,1434,1900,2049,4500,5060,5353,5683,11211,51820 <target> -oX udp.xml
meow add udp.xml
```

### `meow map` opens no browser tab (SSH, headless Linux)

`meow map --no-open` prints the URL. Open it by hand, or forward the local port over SSH.

### Session messages

| Message | What to do |
| :--- | :--- |
| `Nested meow sessions are disabled (active: <name>)` | You are inside a session. Run helpers directly, or `exit` first to switch sessions |
| `Files changed outside meow: ...` at every start | git tracks the session files. Run `git rm -r --cached meow` in the folder that holds `./meow` |
| `git did not answer in 3 s: session files not checked` | Check that `git status` works there. meow asks again when git's index changes |
| `meow did not end cleanly last time` | Nothing; the history is kept |
| `Not using the session in <folder>: <reason>. <fix>, or delete <dir> yourself` | Do the fix. See [Folders meow refuses](#folders-meow-refuses) |
| `meow add is still writing '<name>': try again when it ends` | Wait for that `meow add` or `meow report` |
| `session '<name>' (pid N) is not responding` | The session is starting or suspended (`meow add` waits 10 s for it). Resume or exit it, then try again |

### Cloud or local AI requests fail

Run `meow setup --check` to see which server or key needs attention.

- **OpenRouter** (`sk-or-...`) or **Claude API** (`sk-ant-...`): run `meow setup` to enter the key again or switch services.
- **Ollama** (`http://localhost:11434`) or **LM Studio** (`http://localhost:1234`): check that the server runs and has a model (`ollama list`).
- A local server meow cannot see as yours gets masked text and no key ([AI tiers](#ai-tiers)).
- `one call could cost up to $X; $Y left today`: raise `max_daily_usd`, or wait for tomorrow.
- `cloud AI off: ai-usage unreadable`: the full message says why `~/.meow/ai-usage` cannot be read. Cloud AI stays off until that is fixed.

---

## Removing meow

- **Homebrew:** `brew uninstall meow && brew untap Jrdelt/meow`
- **Release download:** delete `/usr/local/bin/meow`, or your `meow.exe`.
- **Built from source:** delete `~/.cargo/bin/meow` (`meow.exe` on Windows).
- **Data:** delete `~/.meow` and the `meow/` session folders (`meow list` shows them; an old `./.meow/` shows only from its folder). fish keeps session histories in its data folder as `meow_<hash>_history`.

---

## Security and License

See [SECURITY.md](SECURITY.md) to report a problem privately and for what meow protects. Released under the [MIT License](LICENSE).
