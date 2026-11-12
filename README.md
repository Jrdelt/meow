# meow

A local security triage shell, live topology mapper and grounded audit
workspace for authorized defensive work. Rust with a small C11 stream filter.

`meow <name>` wraps your normal shell. While you work, it quietly builds a
graph of the hosts, ports, paths and software it sees, matches that software
against public vulnerability databases, and keeps every raw observation apart
from every conclusion. Nothing leaves your machine unless you ask for it.

The full specification is in [`SPEC.md`](SPEC.md). Notes for contributors and
coding agents are in [`AGENTS.md`](AGENTS.md).

## Install

On macOS or Linux, from a clone of this repository:

```sh
./install.sh
```

The script checks what is missing, shows what it will do, asks once, and then
does it. It installs a C compiler if there is none (the Xcode Command Line
Tools on macOS, the distribution's compiler package on Linux) and the Rust
toolchain through `rustup` if there is none or it is older than 1.88. Then it
builds meow and installs it as `~/.cargo/bin/meow`. Anything already present is
left alone, so it is safe to run again after a `git pull`.

| Option | Effect |
|---|---|
| `--dry-run` | Only show the plan. |
| `--yes` | Do not ask before starting. |
| `--with-tools` | Also install `nmap`, `katana` and `feroxbuster` where Homebrew or the system package manager offers them. |

On Windows, install Rust from <https://rustup.rs> with the Visual Studio C++
build tools, then run `cargo install --path . --locked`.

To build by hand instead (Rust 1.88 or newer and a C compiler):

```sh
cargo build --release        # binary: target/release/meow
cargo test                   # the full test suite
```

## Commands

| Command | What it does |
|---|---|
| `meow list` | Lists every saved workspace (and `./.meow/` of the current directory): whether its session is running, mode, host count, unfinished tasks, last activity. `meow ls` and a bare `meow` do the same; inside a session use `meow list`. |
| `meow delete <name>` | Deletes a saved workspace and everything in it (command log, graph, notes, AI chats, report), after asking. `--yes` skips the question; `--local` deletes `./.meow/` of the current directory. Refused while a session is open on it. `meow rm` does the same. |
| `meow <name>` | Creates or resumes `~/.meow/workspaces/<name>/` and starts the session shell. `--local` uses `./.meow/` instead. |
| `meow mode <light\|mild\|aggressive>` | Switches the discovery profile. |
| `meow recon <target> [-- <nmap flags>]` | Queues a four-stage inventory of a host or CIDR range. Runs in the background of the session, one tool at a time. |
| `meow map` | Opens the live topology map in your browser. `--no-open` prints the URL. |
| `meow hud` | Opens the terminal panel: hosts, inspector, checklist, CVE feed, queue, notes, AI. |
| `meow add <file>` | Imports an Nmap XML, JSON Lines, log or `git diff` file. `--no-cve` skips the vulnerability lookups. |
| `meow report` | Writes `REPORT.md` into the workspace. No AI, no network. |

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

The picture is a drawing hint, not a finding. Click any node to read what it
was derived from. A host with hypotheses to verify gets an amber marker, one
with a confirmed finding a red one, and a dashed red frame means a match is in
the CISA known-exploited catalog.

## Modes

- **light** (default): sends no packets to targets. Reads the local interface,
  route, neighbour and listener tables, and warns about route problems. Refuses
  `meow recon` and warns when you type a high-rate scan by hand.
- **mild**: rate-limited inventory (`nmap -T3`, top 1000 ports, katana depth 2,
  feroxbuster at 20 requests per second).
- **aggressive**: full port range, `-T4`, OS detection, katana depth 4,
  feroxbuster auto-tune.

Recon stages: port inventory, service inventory on the open ports only, web
crawl (`katana`), directory inventory (`feroxbuster`). A missing tool or
wordlist skips its stage. Without root, `-sS` becomes `-sT` and `-O` is dropped.
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

## AI tiers (optional, started by hand)

From the HUD: `L`, `C` and `R`. From the map: the buttons on a host.

- **L, local**: an OpenAI-compatible server on your machine
  (`http://localhost:1234/v1`). Free; nothing leaves.
- **C, cloud triage** (OpenRouter): three short sections: risk and a
  verification question, hardening, and a detection rule.
- **R, grounded research** (OpenRouter web search): available once a hypothesis
  has enough stack and route evidence. Sends public identifiers only.

Before any cloud request, addresses, internal names, paths, user names and
secrets are replaced by placeholders such as `<<HOST_01>>`, and the request is
refused if anything private is still detected. Replies are unmasked locally
and saved to `chats/<host>.md`. Scanned text is passed to the model as data in
one JSON field, never as instructions. Cloud use is capped per day
(`max_daily_usd`, `max_daily_calls`); when the cap is reached, `C` answers
locally. Identical questions are answered from a cache at no cost.

Set the key in the environment before starting the session:
`export OPENROUTER_API_KEY=...`, then `meow <name>`. The session reads it when
it starts, so exporting it inside a running session has no effect. Without a
key, `C` answers with the local model and `R` is unavailable; the map and the
HUD say so.

## Configuration

`~/.meow/config.toml` is created on first use, with comments. Sections:
`default_mode`, `shell`, `[cve]`, `[recon]`, `[ai]`. Per-workspace overrides
live in `profile.toml`. `MEOW_HOME` moves the base directory.

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

- **Linux**: developed and tested here, including real `nmap` runs against
  `127.0.0.1` and live NVD, OSV and KEV lookups.
- **macOS**: builds, and a session starts with zsh (first run on a real Mac).
  The full test suite has not yet passed there, and `install.sh` has not been
  run on a Mac.
- **Windows**: compiles and lints for `x86_64-pc-windows-gnu`, but has never
  been run. This covers the ACL setup, console modes, Job Objects and the
  PowerShell shim.
- `katana`, `feroxbuster`, OpenRouter and a local model server have only been
  exercised through stand-ins in the test suite.

Use it only on systems you are authorized to assess.
