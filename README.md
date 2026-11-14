# meow

```text
   /\_/\    _ __ ___   ___  _____      __
  ( o.o )  | '_ ` _ \ / _ \/ _ \ \ /\ / /
   > ^ <   | | | | | |  __/ (_) \ V  V /
  /|   |\  |_| |_| |_|\___|\___/ \_/\_/
 (_|   |_)  local security triage, topology & audit shell
```

A local security triage shell, live topology mapper and grounded audit
workspace for authorized defensive work. Rust with a small C11 stream filter.

`meow <name>` wraps your normal shell. While you work, it quietly builds a
graph of the hosts, ports, paths and software it sees, matches that software
against public vulnerability databases, and keeps every raw observation apart
from every conclusion. Nothing leaves your machine unless you ask for it.

The full specification is in [`SPEC.md`](SPEC.md). Notes for contributors and
coding agents are in [`AGENTS.md`](AGENTS.md).

## Install

On Linux (Kali, Debian, Ubuntu, Fedora, Arch, ...) and macOS, from a clone of
this repository. No Homebrew is needed on Linux: the script uses the system's
package manager.

```sh
git clone https://github.com/Jrdelt/meow.git
cd meow
./install.sh
```

Or with Homebrew, on macOS (or Linux where Homebrew is already installed;
Kali and most distributions do not have it):

```sh
brew tap Jrdelt/meow https://github.com/Jrdelt/meow.git
brew trust Jrdelt/meow        # required once on Homebrew 7+
brew install meow             # tagged release (or `brew install --HEAD meow`)
```

Or on Windows (PowerShell):

```powershell
.\install.ps1
```

The script checks what is missing, shows what it will do, asks once, and then
does it, all in one go:

- a C compiler if there is none (the Xcode Command Line Tools on macOS, the
  distribution's compiler package on Linux);
- the Rust toolchain through `rustup` if there is none or it is older than 1.88;
- meow itself, built and installed as `~/.cargo/bin/meow`;
- the scanners `meow recon` drives: `nmap`, `katana` and `feroxbuster`, with
  Homebrew on macOS or the system package manager on Linux (`feroxbuster` is
  built with cargo, and `katana` with Go, where no package has them);
- a wordlist for the directory stage: the SecLists web-content list, downloaded
  from GitHub to `~/.meow/wordlists/common.txt`.

Anything already present is left alone, so it is safe to run again. A tool
that cannot be installed is reported and skipped; meow works without it.

| Option | Effect |
|---|---|
| `--dry-run` | Only show the plan. |
| `--yes` | Do not ask before starting. |
| `--no-tools` | Leave out the scanners and the wordlist. |
| `--tools-only` | Only the scanners and the wordlist; meow is not rebuilt. |

### Updating

```sh
meow update            # pull the latest from GitHub, rebuild, add new tools
meow update --check    # only show what is new
```

`meow update` works in the folder meow was installed from (or `--source
<folder>`). It pulls only when that folder has no local changes and the pull is
a fast-forward, then runs `./install.sh --yes` there (on Windows, where a
running executable cannot overwrite itself, it prints the `.\install.ps1 -Yes`
command to finish rebuilding after closing `meow`). Sessions that are open keep
the old version until they are closed and reopened. `git pull && ./install.sh`
in the folder does the same by hand.

Works on macOS (Apple silicon and Intel, with Homebrew for the scanners), on
Linux with `apt`, `dnf`, `yum`, `pacman`, `zypper` or `apk`, and on Windows
via `.\install.ps1` (`winget` or `scoop` for Visual Studio Build Tools and
scanners, or manual Rust from <https://rustup.rs> + `cargo install --path . --locked`).

To build by hand instead (Rust 1.88 or newer and a C compiler):

```sh
cargo build --release        # binary: target/release/meow
cargo test                   # the full test suite
```

## Commands

| Command | What it does |
|---|---|
| `meow list` | Lists every saved workspace (and `./.meow/` of the current directory): whether its session is running, mode, host count, unfinished tasks, last activity. `meow ls` and a bare `meow` do the same (on a brand-new install, bare `meow` opens the interactive Cat Setup GUI first); inside a session use `meow list`. |
| `meow delete <name>` | Deletes a saved workspace and everything in it (command log, graph, notes, AI chats, report), after asking. `--yes` skips the question; `--local` deletes `./.meow/` of the current directory. Refused while a session is open on it. `meow rm` does the same. |
| `meow <name>` | Creates or resumes `~/.meow/workspaces/<name>/` and starts the session shell. `--local` uses `./.meow/` instead. |
| `meow mode <light\|mild\|aggressive>` | Switches the discovery profile. |
| `meow recon <target> [-- <nmap flags>]` | Queues a four-stage inventory of a host or CIDR range. Runs in the background of the session, one tool at a time. |
| `meow map` | Opens the live topology map in your browser. `--no-open` prints the URL. |
| `meow hud` | Opens the terminal panel: this machine's connection and VPN, hosts, inspector, checklist, CVE feed, queue, notes, AI. |
| `meow add <file>` | Imports an Nmap XML, JSON Lines, log or `git diff` file. `--no-cve` skips the vulnerability lookups. |
| `meow report` | Writes `REPORT.md` into the workspace. No AI, no network. |
| `meow setup` | Opens the interactive Cat Setup GUI (`--plain` for the line-by-line terminal menu): default discovery mode, local model server, cloud AI key, live CVE grounding / optional NVD key, scanner readiness and live endpoint check. See [Your own AI](#your-own-ai-meow-setup). |
| `meow tools` | Shows which of the tools `meow recon` uses are installed, and offers to install the missing ones (`--yes` installs without asking). |
| `meow update` | Pulls the latest meow from GitHub and rebuilds it, with every tool it uses. `--check` only shows what is new. See [Updating](#updating). |

Inside a session the helper commands find it by themselves. From another
terminal, add `--session <name>` or `--local`.

## The map

`meow map` draws the network the way it is sketched on a whiteboard, left to
right: the Internet cloud, routers, firewalls, servers, network segments and
clients, with this machine marked as "You".

| Drawn as | Because |
|---|---|
| Internet cloud | The routing table has a default route. Nothing is sent there. |
| Router | It is a gateway in the routing table, or its OS guess or a service banner says so. |
| Firewall, switch | Its OS guess or a service banner names one. |
| Server | A port on it was seen open, or a service on it was mentioned. |
| Client | Nothing is known to listen on it. Devices in the neighbour table (ARP, NDP) are drawn as clients without becoming hosts: reading that table sends nothing. |
| Network segment | One per active interface: the LAN, Wi-Fi or VPN this machine is attached to. Crowded segments stack their devices in rows above and below the line. |

A name that only appeared in text (a URL printed in the session shell, such
as `curl https://example.com/install.sh`) is not drawn: nothing was seen on
it and it has no address to place it by. Such names are listed under
**Names only mentioned** in the Hosts card, and after the machines in the HUD.

The page around the drawing is a dashboard of cards, each with a heading and
rows of label and value:

- **Topology**, **This Machine** and the selected node side by side at the top.
- **Advisory**, across the page: what needs a decision, most urgent first.
  Confirmed findings, known-exploited matches to verify, other matches to
  verify, informational notes and false positives each fold open. An entry
  unfolds into its verification checklist and the buttons to confirm it, mark
  it a false positive or reopen it. Without a selection it covers every host.
- For a selected host: **Open Ports**, **Web** (server headers, certificate
  names and paths, when there are any), **Ask AI**, **Evidence**, **Add a note**.
- **Hosts** (click one to select it), **Routes**, **Neighbours**,
  **All interfaces**, **Background Tasks** and **Notices**.

Only cards that have something to say are shown.

The picture is a drawing hint, not a finding. Click any node to read what it
was derived from. A host with hypotheses to verify gets an amber marker, one
with a confirmed finding a red one, and a dashed red frame means a match is in
the CISA known-exploited catalog.

## This machine

The top right of both `meow map` and `meow hud` sums up the machine meow runs
on in a few lines:

```
192.168.50.5 -> MacBook Pro -> macOS -> 15.1
Open ports  none listening
Interfaces  en0  192.168.50.5/28  gateway 192.168.50.1
            utun5  10.99.2.24/32  VPN, carries 10.0.0.0/8, 172.16.0.0/12 and 5 single hosts
```

That is its address, what kind of machine it is, its operating system and
version, the ports open on it (those only this machine can reach are listed
apart) and one line per interface in use, saying what each is for. An interface
is shown by its IPv4 address. A VPN also gets a badge in the map header, and
the local link stays listed while one is up.

The tables behind this are folded away: on the map they unfold on a click, in
the HUD press `m`. Routes are cut down to the ones that say where traffic goes;
single hosts, multicast, link-local and idle interfaces are left out and
counted. Everything is read from the operating system every 30 seconds, and
nothing is sent to find it out.

A selected host gets the same one-line answer, for example
`10.20.30.41 -> Server -> Ubuntu -> 24.04 (OS read off a service banner)`,
followed by its open ports. Without an OS scan the system is read off service
banners where they give it away, and marked as such.

If one of the system tools behind these tables cannot be run, the session says
so when it starts (`[!] Local network not fully read: ...`) and the summary
lists it under "Could not be read". An empty table then means it was not read,
not that there is nothing there.

## Modes

- **light** (default): sends no packets to targets. Reads the local interface,
  route, neighbour and listener tables, and warns about route problems. Refuses
  `meow recon` and warns when you type a high-rate scan by hand.
- **mild**: rate-limited inventory (`nmap -T3`, top 1000 ports, katana depth 2,
  feroxbuster at 20 requests per second).
- **aggressive**: full port range, `-T4`, OS detection, katana depth 4,
  feroxbuster auto-tune.

Recon stages: port inventory, service inventory on the open ports only, web
crawl (`katana`, kept on the host being crawled: links to other sites are
neither followed nor stored), directory inventory (`feroxbuster`). Before a
recon is queued, meow checks that `nmap`, `katana`, `feroxbuster` and a
wordlist are there. If any is missing it lists them with the stage each one
is needed for, and asks whether to install them now (`--install-tools`
installs without asking). Whatever is still missing skips its stage, and the
map and HUD say so. `meow tools` does the same check at any time. A wordlist
is looked for in `recon.wordlist_path`, then in the usual system places, then
in `~/.meow/wordlists/` (the first `.txt` file there). Without root, `-sS` becomes `-sT` and `-O` is dropped.
Each tool has a time limit and a 50 MB output cap, and is killed with
everything it started when the session ends. Unfinished tasks are offered for
resume the next time the workspace is opened.

## Evidence and conclusions

Every fact carries five fields: `source`, `timestamp_utc`, `confidence`, the
raw `evidence`, and a `verification_status`. Parsed facts are `Observed`.
Vulnerability matches are `UnverifiedHypothesis`. Only you can mark one
`Confirmed` or `FalsePositive` (in the HUD or the map), and an observation can
never jump straight to confirmed.

Vulnerability lookups use NIST NVD (by CPE name and by keyword), OSV.dev and
the CISA KEV catalog. They send only software names and versions, are paced to
NVD's rate limit, cached in the workspace, and fail fast when offline.

A match means "this version number appears in the advisory", nothing more. An
old server can match a hundred advisories at once, so the map, the HUD and the
report start with **What to update**: one line per piece of software, naming
the release that answers all of its matches (`Update Apache httpd 2.4.34 to
2.4.60 or later, or close 8080/tcp if the service is not needed`) and whether
that host is this machine or another one. Left out are advisories that name
the software only as the platform another product runs on, and ones tied to an
operating system the host does not run. After the update, scan the host again:
matches the databases no longer return are removed, while anything you marked
`Confirmed` or `FalsePositive` stays.

## AI tiers (optional, started by hand)

From the HUD: `L`, `C` and `R`. From the map: the buttons on a host.

- **L, local**: an OpenAI-compatible server on your machine
  (`http://localhost:1234/v1`). Free; nothing leaves.
- **C, cloud triage**: three short sections: risk and a verification question,
  hardening, and a detection rule.
- **R, grounded research** (with web search): available once a hypothesis has
  enough stack and route evidence. Sends public identifiers only.

`C` and `R` run on the service you set up: the Claude API with your own Claude
API key, or OpenRouter (or, for `C`, any other OpenAI-style service).

Before any cloud request, addresses, internal names, paths, user names and
secrets are replaced by placeholders such as `<<HOST_01>>`, and the request is
refused if anything private is still detected. Replies are unmasked locally
and saved to `chats/<host>.md`. Scanned text is passed to the model as data in
one JSON field, never as instructions. Cloud use is capped per day
(`max_daily_usd`, `max_daily_calls`); when the cap is reached, `C` answers
locally. Identical questions are answered from a cache at no cost.

### Your own AI: `meow setup`

Nothing about anyone's AI is built in. Each person who uses meow points it at
their own model server or adds their own API key:

```sh
meow setup            # full-screen Cat TUI wizard (on first bare `meow` too!)
meow setup --plain    # plain line-by-line terminal menu
```

Running `meow` with no arguments on a brand-new install (or running `meow setup`
anytime) opens the interactive Cat-themed setup GUI: pick your default discovery
mode, sniff local model servers (`p`), paste a cloud or optional NVD API key
with hidden input, check scanner/wordlist readiness, test endpoints (`t`), and
optionally launch straight into your first workspace.

- **A model on your machine**: it looks for LM Studio, Ollama and llama.cpp on
  their usual ports, lists the models the server offers, and lets you pick one
  or type another address.
- **Your Claude API key**: the Claude API is used directly, with
  `claude-opus-5-5` for both `C` and `R`. Research uses Claude's own web
  search.
- **Your OpenRouter key**, or another OpenAI-style service by its address
  (`R` needs OpenRouter or a Claude key, for the web search).
- **Remove the key**, or **check that it works** (with a Claude key this also
  checks that the key is offered every model you named).

A key is hidden as you type or paste it. Your setup is kept in
`~/.meow/ai.toml`, which only you can read. It is not part of any workspace or
repository, a key is never printed (only its last four characters), and a
session that is already running uses the new setup for its next request.

**When a model declines.** With a Claude key, a request that a model's safety
filter declines is asked again on the next model of your chain, in order. The
default is `claude-opus-5-5`, then `claude-opus-4-6`, then `claude-opus-4-8`.
Change it with `--fallback-models`; an empty chain leaves the choice to the
Claude API. If every model declines, meow says so and names them. Declined
attempts count toward the daily budget.

**Cost with a Claude key.** The Claude API reports tokens, not money, so meow
works the cost out from the list prices built into it (as published on
2026-11-03; a model it does not know is priced as the most expensive one) plus
one cent per web search. Treat the daily budget as a close estimate there.
OpenRouter reports the exact cost itself.

The same without questions, for scripts:

```sh
meow setup --provider claude --api-key-stdin < my-claude-key.txt
meow setup --fallback-models claude-opus-4-6,claude-opus-4-8
meow setup --provider openrouter --api-key-stdin < my-key.txt   # never as an argument
meow setup --local-url http://localhost:11434/v1 --local-model llama3.2
meow setup --show                            # what is set, and where the key comes from
meow setup --check                           # try it all, exit 1 if something fails
meow setup --forget-key
```

A key in the environment also works and wins over the file: `ANTHROPIC_API_KEY`
when the Claude API is in use, `OPENROUTER_API_KEY` otherwise. It is read when
the session starts. Without any key, `C` answers with the local model and `R`
is unavailable; the map and the HUD say so.

## Configuration

`~/.meow/config.toml` is created on first use, with comments. Sections:
`default_mode`, `shell`, `[cve]`, `[recon]`, `[ai]`. Per-workspace overrides
live in `profile.toml`. Your own AI setup is in `~/.meow/ai.toml` and overrides
`[ai]`. `MEOW_HOME` moves the base directory.

## Workspace files

```
~/.meow/workspaces/<name>/
  session.lock    kernel lock held by the running session
  runtime.json    port and token of the running session (removed at exit)
  profile.toml    mode and tool flag overrides
  replay.sh       every command with its directory and exit code
  graph.json      hosts, ports, paths, evidence, advisories
  state.db        tasks, caches, vault, AI usage (SQLite)
  chats/          AI replies per host
  tmp/            shell shims and tool output being parsed
  REPORT.md       written by `meow report`
```

Directories are `0700` and files `0600`. Your own shell startup files are
never modified.

## Platform status

Be aware of what has and has not been exercised:

- **macOS**: developed and verified on Apple silicon (`cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, and the full `330`-test suite
  including real PTY, Zsh/Bash shims, Cat Setup TUI, HUD, coordinator, CVE,
  installer and updater tests), plus end-to-end `./install.sh` and Homebrew tap
  (`Formula/meow.rb`) verification.
- **Linux**: developed and tested here, including real `nmap` runs against
  `127.0.0.1` and live NVD, OSV and KEV lookups.
- **Windows**: `install.ps1` and the Rust codebase (`x86_64-pc-windows-gnu`
  ACL setup, console modes, Job Objects and PowerShell shim) compile and lint
  cleanly, but have not yet been executed on a live Windows host.
- `katana`, `feroxbuster`, OpenRouter and a local model server are exercised
  through deterministic stand-ins in the automated test suite.

Use it only on systems you are authorized to assess.
