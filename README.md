# meow

```text
  /\_/\
 ( ^w^ )  meow — local security triage shell, topology mapper & grounded audit workspace
  > ^ <
```

`meow` wraps your normal shell (`zsh`, `bash`, `fish` or PowerShell) and watches what your commands print. It records hosts, ports, services, web paths and config diffs, and looks up known CVEs for the versions it finds. It maps your route and the target network live, and writes a Markdown or printable PDF report.

meow keeps session data on your machine, in a private session folder, and masks private values before any text goes to a cloud AI.

> **Authorized use only.** Use meow only on systems you own or have written permission to test. meow lists services, settings and public advisories so you can patch and verify. It never writes exploits or attacks.

## Install

**Homebrew** (macOS and Linux) also installs `nmap`, `katana`, `feroxbuster` and the SecLists `common.txt` wordlist:

```sh
brew tap Jrdelt/meow https://github.com/Jrdelt/meow.git
brew trust Jrdelt/meow   # Homebrew 7+
brew install meow        # --HEAD for the main branch
```

**Release downloads** ([latest release](https://github.com/Jrdelt/meow/releases/latest)) each have a `.sha256` file:

- **macOS:** `meow-<version>-macos-arm64.pkg` (Apple Silicon) or `-macos-x86_64.pkg` (Intel) installs `/usr/local/bin/meow`. If macOS blocks it, see [Other problems](#other-problems), or run `sudo installer -pkg meow-0.2.6-macos-arm64.pkg -target /`.
- **Linux:** `meow-<version>-linux-x86_64.tar.gz` or `-linux-arm64.tar.gz`. Run `sha256sum -c meow-0.2.6-linux-x86_64.tar.gz.sha256`, unpack it, then `sudo install -m 0755 meow /usr/local/bin/meow`.
- **Windows:** `meow-<version>-windows-x86_64.zip` (x64, or ARM64 under emulation). Check it with `Get-FileHash`, unzip it, and put `meow.exe` in a folder on your `PATH`.

After either, run `meow tools` to add any missing scanner, wordlist or location database.

**From source** on macOS or Linux:

```sh
git clone https://github.com/Jrdelt/meow.git && cd meow && ./install.sh
```

It adds a C compiler and Rust 1.89 or newer (through `rustup`) if missing, and builds the clone into `~/.cargo/bin/meow`. Then it adds what is missing of `nmap`, `katana`, `feroxbuster`, the wordlist (`~/.meow/wordlists/common.txt`) and the DB-IP Lite location database (`~/.meow/geo/`, fetched again after 30 days). Flags: `--yes`, `--dry-run`, `--no-tools` (no scanners or wordlist), `--no-geo`, `--tools-only` (no build).

On Windows, run `powershell -ExecutionPolicy Bypass -File .\install.ps1` in the clone, with `-Yes`, `-DryRun`, `-NoTools`, `-NoGeo` or `-ToolsOnly`. It uses `winget` or `scoop`. It stops if this folder or one above has a `.cargo`, `.cargo\config`, `.cargo\config.toml`, `rust-toolchain` or `rust-toolchain.toml` that is a link, or that another account owns or can change. A link is fine in a folder only you can change, if it leads to something of yours.

### Updating

`meow update` upgrades meow itself; `--check` only shows what is new.

- **Release download:** gets the newest full release, checks its SHA-256 and replaces meow, nothing else.
- **Homebrew:** `brew update`, then `brew upgrade meow` (`--fetch-HEAD` for `--HEAD`). This also upgrades outdated `nmap`, `katana` and `feroxbuster`.
- **`install.sh`:** pulls into the folder meow was built from and runs `install.sh --yes`. It rebuilds meow, adds missing data files, and adds only the missing tools it can install without sudo.
- **`install.ps1`:** pulls, then asks you to close meow and run `install.ps1 -Yes`.

A source update only fast-forwards, never over local changes. `--source <dir>` or `MEOW_SOURCE=<dir>` names another clone; only then may its remote be a local folder, not `https://` or ssh. git never asks for a password, so a private https remote needs your own credential helper, or ssh. On macOS and Linux, meow builds in `~/.meow/build` (private, kept, safe to delete).

## First-Time Setup

On a new machine, `meow` opens the full-screen setup; `meow setup` opens it again. Five steps, one question each. The defaults work, and `?` explains the step.

| Step | What you choose |
| :--- | :--- |
| 1 Mode | What `meow recon` may send: `light`, `mild`, or `aggressive` for labs and authorized hosts only ([Modes](#modes)) |
| 2 Local AI | LM Studio, Ollama, llama.cpp or your own URL on this machine. $0; host data stays here |
| 3 Cloud AI | **Off** (locks cloud AI off), **Claude API** or **OpenRouter / other**, with key and models. The key is hidden, kept in `ai.toml` and sent only to that service |
| 4 Lookups & tools | Software versions go to NVD, OSV.dev and CISA KEV (NVD key optional), your public IP to ipinfo.io, the rough area to EOX for the map. No lookup carries a scanned host's address or name. Shows whether `nmap`, `katana`, `feroxbuster`, the wordlist and the location database are installed |
| 5 Save | Review, test the connections, save to `~/.meow` (only you can read it), maybe open a first session |

Typing on a key row opens the hidden key box, which takes only keys of 16 or more characters. For a shorter key, or to remove one, press `Enter` first. `meow setup --plain` (or `TERM=dumb`) is a line menu; entry `6` turns cloud AI off.

## Quick Start

```sh
meow acme
```

A new session asks where to save it; Enter keeps this folder:

```text
[?] Save session 'acme' in:
    Folder: /Users/you/projects/audit
    -> /Users/you/projects/audit/meow/acme
```

Your shell then opens in the session, and meow says where it is saved. Each session has its own history for `history`, the up arrow and `Ctrl-R` (unless a shell started inside sets `HISTFILE`). `exit` or `Ctrl-D` closes it; `meow acme` opens it again from any folder. meow does not change your prompt; `$MEOW_SESSION`, `$MEOW_MODE` and `$MEOW_WORKSPACE` hold the session, mode and folder.

meow watches what you run (`nmap`, `ping`, `curl`, `ssh`, `dig`, `git diff`). When output shows a host, open port, banner, HTTP path or config diff, meow records it and looks up CVEs in the background. Lookups for hosts seen only in terminal text or `meow add` wait behind those for `meow recon`, and stop at 256 per session; a notice says when.

To scan an authorized target, switch to `mild` and queue a recon; extra `nmap` flags go after `--`:

```sh
meow mode mild
meow recon example.com
meow recon 192.0.2.0/24 -- -p 22,80,443,8080
meow map       # live map in your browser
meow hud       # the same in this terminal
meow report    # REPORT.md in the session folder; not masked
```

## Command Reference

| Command | What it does |
| :--- | :--- |
| `meow` | Setup on a new machine; else list your sessions |
| `meow <name>` | Open or make a session (`./meow/<name>/` by default) |
| `meow <name> --local` / `--home` | Use `./meow/<name>/` here, or `~/.meow/workspaces/<name>/`, without asking |
| `meow list` (`ls`, `status`) | Your sessions, where they are, which are running |
| `meow delete <name>` (`rm`) | Delete a session (`--local`: the one here; `-y`: do not ask) |
| `meow mode <light\|mild\|aggressive>` | Switch the session's mode |
| `meow recon <target> [-- <nmap flags>]` | Queue the inventory of a host, domain, IP or CIDR range (`--install-tools`: add a missing tool without asking) |
| `meow map [--no-open]` | Open the live map, or print its URL |
| `meow hud` | Watch the session in this terminal |
| `meow add <file> [--no-cve]` | Import Nmap XML, katana or feroxbuster JSONL, a log or a `git diff` (`--no-cve`: no CVE lookups) |
| `meow report` | Write `REPORT.md` |
| `meow setup` | Change the setup ([flags](#ai-and-settings)) |
| `meow tools [--yes]` | Check and install the scanners, wordlist and location database |
| `meow update [--check] [--source <dir>]` | Upgrade meow itself ([Updating](#updating)) |

The helper commands `mode`, `recon`, `map`, `hud`, `add` and `report` find the session they run in; elsewhere, add `--session <name>`, or `--local` for the one in `./meow/` here. `meow recon` and `meow map` need a running session. Inside a session, `meow <name>` says `Nested meow sessions are disabled (active: <name>)`: run the helper commands directly, or `exit` first.

## Session Folders

Sessions saved in one folder share its `meow/` folder (`meow/acme/`, `meow/beta/`).

- The folders are private (`0700`; on Windows, an access list for you alone). meow never follows a link there.
- `.gitignore` files keep them out of git. A running session puts back a `.gitignore` of its own that a pull changed.
- meow asks git whether it tracks session files. That git runs none of the repository's programs and reaches no remote.
- Older sessions in `~/.meow/workspaces/<name>/` and `./.meow/` keep working. `meow list` shows an old `./.meow/` only from its own folder.
- A session that came with a cloned, unpacked or copied folder opens only after you accept it, in your default mode. It loses its shell history, last folder and queued scans, and never takes the name of one of yours.

On macOS and Linux, meow refuses a folder that another user owns or can write to, also through a shared group, or one inside a folder they can change. A sticky folder like `/tmp` is fine. It checks again at each open, use or delete. On macOS, `staff` write access counts even with an access list, so folders older versions accepted (after `chmod 775 ~`, say) may be refused. On Linux, meow refuses an SMB share, and an NFS or FUSE folder with group write. A path that is not valid UTF-8 is refused. [SECURITY.md](SECURITY.md#known-limits) lists what these checks miss.

| Message | Meaning |
| :--- | :--- |
| `Files changed outside meow: shell history and last folder not used` | Files were replaced between sessions (a pull, a checkout, an archive), or by a `git pull` during one. The last folder is where the shell starts |
| `git tracks session files (...)` | Run `git rm -r --cached meow` as it says. Until then, a session whose history or state git tracks ends as above |
| `meow did not end cleanly last time` | After `kill -9`, a crash, power loss, or a `meow add` or `meow report` cut short. The history stays unless files were replaced |
| `Session moved from <old path>` | A moved folder keeps its session and history if the old folder is gone and the files are unchanged |

## Modes

| Mode | `meow recon` | Scans |
| :--- | :--- | :--- |
| `light` (default) | Refused | None: 0 packets to hosts |
| `mild` | On | `nmap -sS -T3 --top-ports 1000`, `katana` depth 2, `feroxbuster` 20 requests/s |
| `aggressive` | On | `nmap -sS -T4 -p- -O`, `katana` depth 4, `feroxbuster --auto-tune` |

Every mode watches the shell; switch with `meow mode light`, `mild` or `aggressive`. Light mode cannot stop a command you type, but in bash and zsh it warns before `nmap -T4`, `-T5` or `-A`, `masscan` or `--min-rate`. Flags after `--` must be safe nmap flags, 32 at most, with no file outputs, target files or unsafe scripts. For anything else, run nmap yourself and `meow add` its XML.

## What `meow recon` Does

`meow recon <target>` runs these 17 stages one at a time in the background:

1. `lan`: gateway and LAN neighbours from your ARP/NDP cache and routes (sends nothing)
2. `dns`: A, AAAA, CNAME, MX, NS, TXT and PTR records
3. `asn`: ASN, BGP prefix, provider and country
4. `subdomains`: subdomains from Certificate Transparency logs (`crt.sh`)
5. `mail-dns`: A–F grade for SPF, DMARC, DKIM, CAA and DNSSEC; published services (AD, Microsoft 365); wildcard DNS
6. `ports`: open TCP ports (`nmap`)
7. `trace`: route hops and latency to the address `ports` scanned
8. `udp`: key UDP services such as SNMP, IPMI, NTP and DNS (aggressive mode, as root)
9. `services`: service versions and CPEs on the open ports (`nmap -sV`)
10. `headers`: web stack, cookie flags, security-header grade, title, `robots.txt`, `security.txt`
11. `waf-cdn`: WAF or CDN in front of the site
12. `tls-audit`: certificate details and TLS versions
13. `ssh-audit`: SSH algorithms, weak ones flagged
14. `cves`: known vulnerabilities for the versions found (OSV, NVD, CISA KEV)
15. `crawl`: linked pages (`katana`)
16. `js`: API endpoints and exposed keys in the site's own scripts
17. `dirs`: unlinked files and folders (`feroxbuster`)

### Progress and stopping

- The HUD and map show each stage as done, running, waiting, skipped, failed or stopped, with nmap's percent and time left.
- A missing tool skips its stage. If the port scan fails, every later stage but `trace` is skipped. `meow mode light` pauses a recon; `mild` or `aggressive` continues it.
- Ending the session stops the running stage and every program it started. Finished stages stay, the rest show as `not run`, and the next start says `Recon <target> cut short at <stage>`. Nothing restarts by itself.
- A session ends this way on `exit`, a closed terminal, `kill` (TERM, HUP, INT, QUIT), and `Ctrl-C` or `Ctrl-\` with output to a pipe or file. On Windows, also on a closed console, log-off or shutdown.
- If meow is killed outright, a guard process stops the scans: `meow-guard` on Linux, `meow __guard` on macOS. If that dies too, the next `meow`, `meow list` or session start does. On Windows the scans end with meow's process.

### Targets, DNS and privacy

- nmap scans a domain at the address `dns` picked: the first IPv4 one, or IPv6 with `-- -6`. `-Pn`, `-P*`, `-n`, `-R`, `--system-dns`, `-4` and `-6` apply to every nmap scan, after `--` or in a mode's `nmap_ports`.
- If nothing answers nmap's up check, `ports` and `udp` suggest `-- -Pn` (unless it is set). `trace` (`traceroute`, `tracepath` or `tracert`, 15 hops) records only hops the tool printed.
- DNS questions go to your own resolvers, following split DNS on macOS and Windows (VPN, `/etc/resolver/*`, NRPT). `.local` names never go to a DNS server. The target's address is the one your system gives (`/etc/hosts` included), as for `nmap`.
- DNS-over-HTTPS is used only when your resolvers give no answer, for public names no VPN or resolver rule sends elsewhere. It and `crt.sh` never get an internal target or name (such as `.local`, `.lan`, `.corp`), or a name with a non-public address.
- `mail-dns` only asks DNS questions, the same way. The domain's own DNS servers see them all, including two made-up names for the wildcard check.
- A check with no definite answer says `could not be checked`, or `this machine's DNS server does not know <name>`. The grade is `?` unless SPF, DMARC and one more check were done.

### Web stages and CVEs

- `js` reads only the site's own scripts (15 in mild, 40 in aggressive). A key it finds goes straight into the Privacy Vault: you see only a placeholder like `<<SEC_03>>`, and the report lists it to rotate. Endpoints keep parameter names, never values.
- Cookie values are never stored. `dirs` skips sites behind a WAF or CDN in mild mode.
- A port's new software replaces the old, whose CVEs go at the next full lookup. TLS findings are replaced only when every handshake answered. A new `headers` result replaces the site's software list, so an updated jQuery no longer shows as outdated.

## Live Map, HUD and Report

`meow map` opens the map in your browser, on `127.0.0.1`, with the session's token.

- **Drawing:** you, your router, your public address or VPN, the Internet (click it for each hop's place, network and latency), then the hosts by network and provider. A red glow is a CVE that is known exploited, critical or high. The legend lists only what is drawn.
- **Location:** a satellite map, top right. **−** folds it; it also folds by itself when it would cover a device. **Expand** fills the window; **Esc** goes back.
- **This machine:** only what could be read: system, interfaces with their gateway, listening ports. Routes, neighbours and all interfaces fold away below.
- **Host tabs:** Overview, Ports, Web & TLS, DNS & Mail, CVEs, Notes & AI (`←`/`→` or `1`–`6`). Hover a row for details. **All hosts** (or **Esc**) goes back to the list.
- **Check now** (mild and aggressive mode): one connection to up to 6 known open ports.
- **CVEs:** one line per update, hosts with known exploited CVEs first, such as `Update nginx 1.18.0 to 1.20.1 or later, or close 80/tcp and 443/tcp if the service is not needed.` Each line unfolds into its CVEs.
- **AI:** **Local AI**, **Cloud AI** and **Research**, with today's cloud spend and cap. Answers come as a **Red team** plan (authorized testing, no exploit code) and a **Blue team** plan (defense). Saved notes show under the host and in the report.
- **Report:** **Download .md** or **Print / PDF**; **Host report .md** on a host's card.
- **Badge:** `live`, `reconnecting…`, `session closed` (reconnecting failed) or `session ended` (something else answers on the port).

`meow hud` shows it in this terminal. With no session running, it opens the files read-only. `?` lists its keys: `Tab` CVEs, `L`/`C`/`R` ask AI, `a` answer, `m` this machine, `n` note, `1`/`2`/`3` mode.

`REPORT.md` counts only hosts on the map. Names seen only in the shell, a log or the certificate logs share one line: `Only mentioned, not scanned: ...`.

## AI and Settings

| Key | Tier | What it sends |
| :--- | :--- | :--- |
| `L` | Local AI | The host's evidence, unmasked, to a local AI server ($0) |
| `C` | Cloud AI | Masked evidence, to the Claude API or OpenRouter. Without a key, or past the daily cap, local AI answers |
| `R` | Research | Cloud AI with web search (2 searches at most) on which CVEs apply and which versions fix them. Sends only software names, versions and advisory IDs, masked |

- Before anything goes to a cloud AI, meow replaces IP addresses, host names, domains, email user names, MAC addresses, file paths, user names and secrets with placeholders such as `<<HOST_01>>`, `<<DOM_01>>` and `<<SEC_01>>`.
- A reply gets back only the triaged host's own address and names, in prose. Code, command-like lines and lines naming another host keep placeholders.
- Secrets always stay placeholders. Notes go out only with `cloud_notes = true`.
- A local AI server gets unmasked text and keys only when meow sees it is yours. [SECURITY.md](SECURITY.md#known-limits) says when that is, and what masking misses.

**Daily cap.** `max_daily_usd` ($1.00) and `max_daily_calls` (20) are one budget for all your sessions per local day, kept in `~/.meow/ai-usage`. If that file cannot be read, cloud AI is off (`cloud AI off: ai-usage unreadable`).

- On the Claude API, meow counts a call at its highest cost until its real cost is known. A call that could cost more than is left is refused: `one call could cost up to $X; $Y left today (raise max_daily_usd)`. Research with Fable, Mythos or an unknown Claude model (about $1.36 a call) does not fit the default cap.
- OpenRouter and other services give the cost only after the call, so a day can end over the cap.

**`meow setup` flags:**

```sh
meow setup --show           # the AI setup, never the key
meow setup --check          # test the local AI server and the cloud AI key
meow setup --provider openrouter --api-key-stdin   # or claude; the key stays out of shell history
meow setup --local-url http://localhost:11434/v1 --local-model qwen2.5-coder:14b
meow setup --forget-key     # removes the key; --cloud-off: local AI only
```

`--cloud-url`, `--cloud-model`, `--research-model` and `--fallback-models` set the matching `[ai]` keys.

- Without `--provider` or `--cloud-url`, an `sk-ant-` key picks the Claude API and an `sk-or-` key OpenRouter; to keep a gateway, name it too. A key meant for the other service is refused. Setup prints `Key saved for <host>`, never the key.
- An exported `OPENROUTER_API_KEY` or `ANTHROPIC_API_KEY` wins over `ai.toml` (`ai.toml key not used`).
- `--cloud-off` cannot be combined with `--provider`, `--cloud-url` or `--api-key-stdin`. A later one of those turns the cloud on again.

**Files.** Settings live in `~/.meow/` (or `$MEOW_HOME`), with files `0600` and folders `0700`: `config.toml` (made on first run, with comments), `ai.toml` (your AI setup and key; overrides `[ai]`), `ai-usage`, `local-workspaces` (where your project-folder sessions are), `session-files/` (sizes and times of session files, not copies), `run/` (running scan tools), `build/`, `geo/`, `wordlists/` (extra `.txt` lists) and `workspaces/` (`--home` sessions).

**`config.toml`** and its defaults (unknown keys are ignored):

```toml
default_mode = "light"
# shell = "/bin/zsh"    # else $SHELL (macOS, Linux, BSD), else zsh (macOS), bash (Linux), PowerShell (Windows)

[location]
enabled = true
map = true
# url = "https://ipinfo.io/json"
# tiles = "<EOX Sentinel-2 cloudless>"
# database = ""         # ~/.meow/geo/

[cve]
enabled = true
# nvd_api_key = "..."   # pacing 0.7 s instead of 6.5 s

[recon]
stage_timeout_secs = 1800
output_cap_mb = 50
# nmap, katana, feroxbuster: program names or paths
# wordlist_path = "/usr/share/seclists/Discovery/Web-Content/common.txt"
# skip = ["udp", "js"]
# [recon.mild], [recon.aggressive]: nmap_ports, nmap_services, katana_depth, ferox_rate_limit

[ai]
local_url = "http://localhost:1234/v1"
# local_model = ""
# cloud_url = "https://openrouter.ai/api/v1"
# cloud_provider = "openai"   # or "anthropic"; else from cloud_url
cloud_model = "anthropic/claude-sonnet-5.5"
research_model = "anthropic/claude-opus-5.5"
# cloud_fallbacks = [...]     # [] lets the Claude API choose
# openrouter_api_key = ""
# disable_cloud = false
max_daily_usd = 1.0
max_daily_calls = 20
# cloud_notes = false
```

- `[location] enabled`: from the first map page until the session ends, meow estimates this machine's place from its public address. It asks once, then again when the network changes or a try failed, never while a VPN carries all traffic. `false` also stops all map pictures.
- `[location] map`: the satellite map fetches up to 18 pictures from EOX for each place shown, this machine's or a selected host's from the offline database. EOX learns that rough area, never an address.

## Troubleshooting

### `meow update` says `<path> is not a meow git checkout` or `/private/tmp/... is a temporary build folder`

- **Homebrew:** `meow update` finds a Homebrew install by itself. If an older meow prints the temporary build folder message, run `brew update && brew upgrade meow`. To switch to `main`: `brew uninstall meow && brew install --HEAD meow`. If `brew upgrade meow` says `Error: jrdelt/meow/meow not installed`, run `brew install meow` first.
- **A clone you deleted or moved:** pass `--source <path-to-meow-clone>` (or set `MEOW_SOURCE`), or install a release download.

### `meow update` refuses the clone

meow checks the clone before it fetches, also with `--check`. Remove what the message names, or clone meow again.

- Refused: submodules, a `.git/commondir` and (macOS, Linux) a folder above that others can write to.
- `.git/config`, read without includes, may hold only what `git clone` writes and some harmless settings.
- On Windows, a clone outside your user folder is usually refused.

### Other problems

- **macOS blocks the `.pkg`** ("cannot be opened because it is from an unidentified developer"): on macOS 15 (Sequoia) and newer, open **System Settings → Privacy & Security**, scroll down and click **Open Anyway**. On macOS 14 and earlier, Control-click the `.pkg` in Finder and choose **Open**.
- **`meow recon` is refused in `light` mode:** run `meow mode mild` (or `aggressive`) first.
- **Missing `nmap`, `katana`, `feroxbuster`, wordlist or location database:** run `meow tools`.
- **`meow map` opens no browser tab** (SSH, headless Linux): `meow map --no-open` prints the URL. Open it by hand, or forward the local port over SSH.
- **Cloud or local AI requests fail:** `meow setup --check` names the server or key at fault. For a key (`sk-or-...`, `sk-ant-...`), run `meow setup` again. For Ollama (`http://localhost:11434`) or LM Studio (`http://localhost:1234`), check that it runs and has a model (`ollama list`).
- **The `udp` stage is skipped:** it runs only in aggressive mode and as root, since UDP scans send raw packets and are slow. To run it yourself and add the result:

  ```sh
  sudo nmap -sU -sV -p U:53,67,69,88,111,123,137,161,389,500,514,520,623,1194,1434,1900,2049,4500,5060,5353,5683,11211,51820 <target> -oX udp.xml
  meow add udp.xml
  ```

## Removing meow

- **Homebrew:** `brew uninstall meow && brew untap Jrdelt/meow`
- **Release download:** delete `/usr/local/bin/meow`, or your `meow.exe`.
- **Built from source:** delete `~/.cargo/bin/meow` (`meow.exe` on Windows).
- **Data:** delete `~/.meow` and the `meow/` session folders (`meow list` shows them). fish keeps session histories in its data folder as `meow_<hash>_history`.

## Security and License

See [SECURITY.md](SECURITY.md) to report a problem privately and for what meow protects. Released under the [MIT License](LICENSE).
