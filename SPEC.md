# Project Specification: `meow` — Local Security Triage Shell, Topology Mapper & Grounded Audit Workspace

`meow` is a cross-platform (macOS, Linux, Windows) local-only CLI wrapper, live network topology mapper, and grounded defensive security audit workspace written in **Rust (MSRV 1.88+) + C11 (via FFI)**.

## Strict Execution & Multi-Agent Continuity Rules
1. **Proceed one phase and one file/step at a time.** Never dump the entire codebase at once or leave `// TODO` placeholders.
2. **Cold-Start Resume Check (Run First if Repo Exists):** Before writing code in an existing repo, read `AGENTS.md`, `SPEC.md`, `git status`, and `git log -n 5 --oneline`, then run `cargo test` to verify baseline health and continue from `Next Exact Action` in `AGENTS.md`.
3. **Zero Hidden Setup:** Show exact file paths and terminal commands to build and verify each step. Wait for confirmation (or run verification directly if executing inside an agent CLI) before advancing.
4. **Atomic GitHub Checkpoint After Every Verified Step:**
   - Gate every commit on `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.
   - Update the `## Current Handoff State` block inside `AGENTS.md` **in-place** (keep `AGENTS.md` under 100 lines; rely on `git log` for history).
   - Stage only source/doc files (never `.meow/`, `*.db*`, `runtime.json`, `session.lock`, or `.env`), commit using `feat(phaseX-stepY): <concise summary>`, and push via `git push -u origin HEAD`.
   - Never run `git push --force` or destructive resets. If `origin` is not set yet or `git push` awaits hardware SSH/FIDO2 key touch, print the exact command and wait cleanly.

---

## 1. Repository Continuity Files (`AGENTS.md`, `CLAUDE.md`, `SPEC.md`, `.gitignore`)
Created in Phase 1, Step 1 so any AI coding agent can take over seamlessly at any commit:
- **`SPEC.md`:** Stores this complete specification in the repository root so incoming agents never need prior chat history.
- **`CLAUDE.md`:** Single-line `@AGENTS.md` import bridge so Claude Code, Codex, Cursor, Copilot, and Gemini CLI share one instruction source across macOS, Linux, and Windows.
- **`.gitignore`:** Excludes `/target`, `.meow/`, `*.db`, `*.db-wal`, `*.db-shm`, `runtime.json`, `session.lock`, `tmp/`, and `.env*`.
- **`AGENTS.md` (<100 Lines Strict Cap):**
  1. **Toolchain Commands:** Exact `cargo build`, `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` commands.
  2. **Non-Negotiable Boundaries ("Never" Rules):**
     - Never place `tap_filter.c` inline with PTY `stdout` (clone read-only slices via `try_send` only).
     - Never call `crossterm::event::read()` in the PTY host (`std::io::stdin()` owns raw input).
     - Never promote `Observed` banners/headers directly to `Confirmed` findings.
     - Never use `NamedTempFile::new()` across mount points (`NamedTempFile::new_in(&workspace_dir)` only).
     - Never send unvaulted IPs, hostnames, paths, or secrets to cloud APIs, or commit workspace/secret files.
     - Never force-push or commit unverified code.
  3. **Handoff Protocol:** Cold-start resume steps + pre-push verification checklist.
  4. **`## Current Handoff State` (Updated In-Place Every Step):**
     - `Active Phase & Step:`
     - `Last Verified Commit:`
     - `Completed Files:`
     - `In-Progress / Partial Work:`
     - `Next Exact Action:`
     - `Blockers / Notes:`

---

## 2. Single-Host Coordinator Architecture & Plain-English CLI (`clap`)
The primary `meow <name>` process acts as the single session coordinator: it owns the PTY shell, SQLite writer, background task queue, and loopback `Axum` IPC/UI server (`127.0.0.1:8765+`), writing `runtime.json` (`0600` permissions: `{ "pid", "port", "token" }`, removed via RAII `Drop`). Helper subcommands read `MEOW_SESSION` + `runtime.json` and communicate with the coordinator over loopback HTTP/WebSocket (`Authorization: Bearer <token>`), falling back to direct `state.db`/`graph.json` access when offline:

- `meow` / `meow list` (`ls`) — On an unconfigured interactive terminal, bare `meow` opens the first-run **Interactive Cat Setup GUI** (`src/wizard.rs`) and spawns any requested initial workspace in a clean child process so the PTY host never invokes `crossterm::event::read()`. Thereafter, lists saved workspaces sorted by most recently active (live session status, mode, host count, unfinished tasks).
- `meow <name>` — Creates or resumes `~/.meow/workspaces/<name>/` (`--local` uses `./.meow/`). Enforces `0700` dir / `0600` file permissions (current-user NTFS ACL on Windows), prints a mode-reactive Cat ASCII session header on TTYs, restores `last_cwd`, starts the loopback coordinator (`127.0.0.1:8765+`), defaults to passive `light` mode, and prompts `[Y/n]` to resume any `interrupted` background tasks.
- `meow setup` — Launches the 5-step `Ratatui` Interactive Cat Setup GUI (`--plain` for line-by-line mode, plus non-interactive `--provider`, `--api-key-stdin`, `--local-url`, `--show`, `--check`, `--forget-key` flags) writing atomic `0600` settings to `~/.meow/ai.toml` and `~/.meow/config.toml` without ever echoing raw API keys.
- `meow delete <name>` (`rm`) — Deletes a saved workspace (or `--local` `./.meow/`) after confirmation (`--yes` skips), refusing while a session holds `session.lock`.
- `meow update` — Verifies clean git state and HTTPS/SSH remote URL with hooks disabled (`core.hooksPath=/dev/null`), fast-forward pulls from upstream (`--check` previews only), and runs `./install.sh --yes` (or prints the `.\install.ps1 -Yes` rebuild command on Windows).
- `meow mode <light|mild|aggressive>` — Updates the active session's discovery/rate profile via coordinator IPC and persists it in `profile.toml`.
- `meow recon <target> [-- <extra_nmap_flags>]` — Submits an authorized asset/service inventory job to the coordinator's 1-at-a-time background queue using presets from `config.toml`/`profile.toml` plus validated `nmap` overrides after `--` (rejecting unsafe script/file-write flags).
- `meow map` — Opens `http://127.0.0.1:<port>/` via a single-use `0600` local bootstrap HTML redirect that exchanges the bearer token via `POST /api/session` into an `HttpOnly; SameSite=Strict` loopback cookie (keeping bearer tokens out of URL bars/history while enforcing strict `Origin` validation on WebSocket upgrades).
- `meow hud` — Launches the `Ratatui` (`0.30`) companion TUI (`=^..^= meow hud`) connected to the coordinator WebSocket (node/endpoint inspector, Evidence vs. Hypothesis checklist, live CVE feed, queue status, manual catch-up notes box, and `[L]`/`[C]`/`[R]` AI triggers).
- `meow add <file>` — Parses an external Nmap XML, JSONL, log, or `git diff` file into the workspace at $0 AI cost.
- `meow report` — Compiles `graph.json` (Mermaid.js topology), `Confirmed` findings vs. `UnverifiedHypothesis` items, `replay.sh`, and `chats/*.md` into `REPORT.md` at $0 AI cost.

---

## 3. Crash-Safe Locks, Split PTY Stream, Non-Invasive Shell Shims & C Filter
- **Anti-Nesting & Kernel Advisory Lock (`main.rs`):**
  1. **Block Nested Shells:** If `MEOW_SESSION` is set and the user invokes `meow` or `meow <name>`, print `[!] Nested meow sessions are disabled (active: <name>)` and exit with code `1` before touching terminal state. Allow helper subcommands inside an active session.
  2. **Stale-Proof Kernel Lock (`fd-lock`):** Hold an OS kernel advisory lock (`flock` on Unix / `LockFileEx` on Windows) on `session.lock` so crashes or power loss release the lock automatically.
- **Zero-Interference Dual-Stream PTY (`portable-pty = "0.9"` + `ratatui::crossterm`):**
  - **No Competing `stdin` Readers:** `std::io::stdin()` owns 100% of raw input bytes forwarded to `pty_writer`. Never run `crossterm::event::read()` inside the PTY wrapper. Handle window resize events via `signal-hook` (`SIGWINCH`) on `#[cfg(unix)]` and a `250ms` `terminal::size()` poller on `#[cfg(windows)]`, calling `master_pty.resize()` immediately.
  - **Clean Terminal Restore (`Drop` Guard):** On exit or panic, disable Raw Mode AND write `\x1b[?1049l\x1b[?1000l\x1b[?2004l\x1b[?25h` to `stdout` to clear stuck alternate-screen, mouse-tracking, or bracketed-paste modes.
  - **Strict Stream Split:**
    1. **Display Fast-Path:** Raw PTY bytes write straight to `stdout` untouched so `vim`, `ssh`, `tmux`, and `htop` never lag or break.
    2. **Read-Only Analysis Tap:** Clone slices into a bounded channel via non-blocking `try_send` to the C filter worker (dropping analysis chunks cleanly on backpressure).
- **Non-Invasive Per-Session Shell Shims (`<workspace>/tmp/shell/`):**
  - Never modify the user's `~/.zshrc` or `~/.bashrc`. Generate ephemeral startup shims that source the user's real RC file first, then attach clean command/exit-code/CWD hooks for `replay.sh` and `last_cwd`:
    - **Zsh:** `ZDOTDIR=<workspace>/tmp/shell` using `add-zsh-hook preexec` and `add-zsh-hook precmd`.
    - **Bash:** `--rcfile <workspace>/tmp/shell/bashrc` using Bash 4.4+ `PS0` and `PROMPT_COMMAND`.
    - **PowerShell:** `-NoExit -File <workspace>/tmp/shell/init.ps1` wrapping `prompt` with `$LASTEXITCODE`.
- **Stateful VT500 / ECMA-48 Stream Filter (`src/c/tap_filter.c` via `cc`):**
  - Portable C11 using only `<stddef.h>` and `<stdint.h>`.
  - Persistent `tap_state_t` struct across `4096`-byte chunks (`GROUND`, `ESCAPE`, `CSI`, `OSC`, plus UTF-8 multi-byte continuation state).
  - **Stream Guards:** (1) Rewind current line buffer to `0` on bare `\r` not followed by `\n` so progress spinners do not flood parsers; (2) pause scraping between `\x1b[?1049h` and `\x1b[?1049l` (`smcup`/`rmcup` full-screen apps); (3) drop non-UTF8/binary floods and interactive password prompts (`sudo`, `ssh`, `passphrase`).

---

## 4. Discovery Modes, Validated Presets & Process-Grouped Queue
`meow` sends zero outbound target packets unless the user runs a shell command or queues `meow recon <target>` in `mild` or `aggressive` mode:
- **`light` Mode (Default — Zero Outbound Packets):**
  - Rejects active `meow recon` jobs and warns on high-rate manual flags.
  - Passively reads local OS network tables (`arp`, routes, active sockets/interfaces without `sudo`) to map gateways/VPN interfaces (`utun`/`tun`/`eth`) and warn on subnet/interface routing mismatches.
  - Location estimate (`src/location.rs`, `[location]` in `config.toml`, on by default): only after the map sends `locate`, one parameterless GET to a lookup service (default `https://ipinfo.io/json`), repeated only when the active VPNs, default gateway or primary address change (or 15 min after a failure). Skipped entirely while a VPN carries all traffic (default route or both `/1` halves); the map then shows a blue VPN pill marked "location hidden". Targets are never sent anywhere for this. With `[location] map` on (default), the session then fetches the Web Mercator tiles around the estimate (`src/tiles.rs`: at most six, one zoom level closer than shown and drawn at half size; default Sentinel-2 cloudless 2016 by EOX, CC BY 4.0, its credit shown on the map), keeps only JPEG/PNG pictures up to 1 MB, holds them in memory (dropped when the location changes or is hidden) and serves them at `/map/tile/{z}/{x}/{y}` behind the session token. The page loads pictures from the session only; tile requests carry only tile numbers. The map is round, with a pin at the estimate and a fixed 25 km circle for the rough area (the zoom has a fraction, so the circle is the same size everywhere), the city, state and coordinates on one line under it; without pictures it falls back to a compass.
- **Sequential 1-at-a-Time Coordinator Queue (`tokio::sync::Semaphore` = 1):**
  - Spawns child tools with `Stdio::null()` on `stdin` inside OS process groups (`setpgid` on Unix / Job Objects on Windows) with `kill_on_drop(true)`, a configurable stage wall-clock timeout, and a `50 MB` output cap, writing structured files to `<workspace>/tmp/`:
    1. **Port Inventory (`nmap`):** Uses configured flags + `-oX <tmp>/nmap_ports.xml`. **Privilege Check:** If unprivileged (`geteuid() != 0` on Unix / non-elevated Windows), automatically replaces `-sS` with `-sT` and strips `-O`, logging a notice in `meow hud`.
    2. **Service & Header Inventory (`nmap -sV`):** Probes only open ports found in Stage 1 (`-p <ports> -oX <tmp>/nmap_svc.xml`) plus HTTP/TLS SAN metadata. Operator scripts (`-sC`, `-A`, `--script <default|safe|vuln|discovery|version>`) run here as one `--script` expression that always excludes `intrusive`, `external`, `brute`, `dos`, `exploit`, `fuzzer`, `malware` and `broadcast`; script paths, script arguments and other expressions are refused. Every script's output (port and host scripts) is kept as an `Observed` fact; `smb-os-discovery` names the OS when OS detection did not.
    3. **Web Link & JS Route Crawl (`katana`, if HTTP/HTTPS open):** Outputs structured JSONL (`-j -silent -nc -jc -fs fqdn -ct 5m -o <tmp>/katana.jsonl`), staying on the crawled host; links to other sites are left out of the graph.
    4. **Directory/Endpoint Inventory (`feroxbuster`, if HTTP/HTTPS open & wordlist verified):** Validates `wordlist_path` in `config.toml` or standard system paths first (skipping cleanly with a HUD notice if absent on macOS/Windows). Enforces mutual-exclusion rules (`--rate-limit` + `--scan-limit 1` + `--auto-bail` in `mild`; `--auto-tune` without `--rate-limit` in `aggressive`) writing structured `--json -o <tmp>/ferox.jsonl` with `--quiet --no-state`.
  - Persists stage status (`pending`, `running`, `interrupted`, `done`) in `state.db` for `[Y/n]` resume on reopen.

---

## 5. Strict Evidence Schema, IPv6/SAN Normalization & Live CVE Grounding
Never conflate raw observations with confirmed vulnerabilities:
- **Mandatory 5-Field `EvidenceRecord`:** Every item carries `source`, `timestamp_utc` (RFC-3339), `confidence` (`Low`/`Medium`/`High`), `evidence` (raw header, XML/JSON field, or `git diff`), and `verification_status` (`Observed` -> `UnverifiedHypothesis` -> `Confirmed` | `FalsePositive`).
- **IPv6, TLS SAN & Sub-Path Normalization:** Normalize `[ipv6]:port` endpoints via `std::net::SocketAddr` / `ipnetwork`; extract TLS Subject Alternative Names (SANs) and `Location:` hostnames into the Privacy Vault; attach nested URL trees per web port.
- **Rate-Safe Dual CVE Grounding ($0 AI Cost, `2s` Offline Connect Timeout):**
  - **NIST NVD v2.0 + CISA KEV:** Convert Nmap CPE 2.2 (`cpe:/a:...`) to CPE 2.3 (`cpe:2.3:a:...`), pace requests (`>= 6.5s` unauthenticated / `0.7s` with `nvd_api_key`), pair `cpeName=` (with `isVulnerable`) with `keywordSearch=` (reading CNA `affected` ranges for `Deferred` CVEs), and cross-check a 7-day cached local CISA KEV catalog. Drop records that name the product only as a platform, or only on an operating system the host does not run; keep each match's fixed release.
  - **What to update:** Group a host's matches by the software they were matched on and say, in one line each, which release answers them. After a complete lookup, remove unverified matches it no longer returns; operator verdicts stay.
  - **`OSV.dev` Batch API:** Query `POST https://api.osv.dev/v1/querybatch` using `{ package: { name, ecosystem }, version }` or `purl` objects with `next_page_token` pagination.
  - Attach matches strictly as `UnverifiedHypothesis` items with a progressive verification checklist in `meow hud` that unlocks **`[R] Deep Research Ready`** once stack + route evidence is sufficient.

---

## 6. Same-FS Atomic Storage, Boundary-Safe Vault & Budget-Capped AI
Workspace layout inside `~/.meow/workspaces/<name>/` (`0700` permissions):

    ~/.meow/workspaces/<session-name>/
    ├── session.lock    # Kernel advisory lockfile (fd-lock)
    ├── runtime.json    # Ephemeral 0600 { pid, port, token } coordinator IPC state
    ├── profile.toml    # Active mode & configurable tool flags
    ├── replay.sh       # Verified command trail (PS0/preexec exit-code shim + # [CWD])
    ├── graph.json      # Same-FS atomic write (NamedTempFile::new_in -> sync_all -> persist)
    ├── state.db        # SQLite (WAL + synchronous=NORMAL + busy_timeout=5000)
    ├── tmp/            # Ephemeral shell shims & structured XML/JSONL outputs
    └── chats/          # Unmasked local Markdown triage & remediation reports per host

- **Boundary-Safe Bidirectional Privacy Vault (`state.db`):**
  - Tokenizes IPv4/IPv6 addresses, domains/SANs, internal paths, usernames, and secrets (Authorization headers, JWTs, Base64/URL-encoded credentials, SSH keys, high-entropy strings) into `<<HOST_01>>`, `<<DOM_01>>`, `<<PATH_01>>`, `<<SEC_01>>` using longest-match-first sorting inside JSON string values only. Uses a `<<...>>` token holdback buffer when unmasking streamed responses locally.
- **OWASP LLM01 Sandboxing:** Strip control characters from scraped banners/headers and isolate them as untrusted JSON fields.
- **On-Demand Defensive AI Tiers & Hard Spend Caps (`~/.meow/config.toml` + `~/.meow/ai.toml`):**
  - **`[L]` Local ($0.00):** Sends compact host JSON + `Observed` facts + `UnverifiedHypothesis` CVEs + notes to a local OpenAI-compatible server (`http://localhost:1234/v1`, Ollama `:11434`, or `llama.cpp` `:8080`).
  - **`[C]` Cloud Triage (Anthropic Claude API `src/anthropic.rs` or OpenRouter/OpenAI-compatible `src/ai.rs`):** Enforces HTTPS on non-loopback endpoints, checks SHA-256 prompt cache and `max_daily_usd` / `max_daily_calls` first (auto-fallback to `[L]`), and walks the user's configured fallback model chain on safety-filter refusals. Outputs: (1) Evidence-Backed Risk & Verification Question, (2) Hardening / Code Patch, (3) Detection Signature (WAF / firewall / Sigma / log rule).
  - **`[R]` Grounded Research (Claude native `web_search` or `openrouter:web_search` Server Tool):** Queries strictly on vaulted/public stack identifiers once stack + route evidence unlocks `[R]`, recording exact/estimated USD cost + web search requests into `state.db`.
- **Cross-Platform Packaging & Installers:**
  - `install.sh` (macOS & Linux), `install.ps1` (Windows `winget`/`scoop`), and `Formula/meow.rb` (Homebrew tap `Jrdelt/meow`, tagged `v0.1.0` + `--HEAD`), pinning SecLists `common.txt` by SHA-256 and preserving user shell startup files (`--no-modify-path`).

---

## 7. Phased Implementation Roadmap & Verified 2026 Crates
Verified crate baseline: `clap = { version = "4.5", features = ["derive", "env"] }`, `portable-pty = "0.9"`, `ratatui = "0.30"` (using `ratatui::crossterm`; `signal-hook = "0.3"` on Unix), `fd-lock = "4.0"`, `rusqlite = { version = "0.32", features = ["bundled"] }`, `tokio = { version = "1", features = ["full"] }`, `axum = { version = "0.8", features = ["ws"] }`, `petgraph = "0.7"`, `reqwest = { version = "0.13", features = ["json"] }`, `ipnetwork = "0.20"`, `tempfile = "3"`, `cc = "1.2"`.

- **Phase 1:** Repo & handoff scaffold (`Cargo.toml`, `build.rs`, `.gitignore`, `AGENTS.md`, `CLAUDE.md`, `SPEC.md` + initial Git checkpoint), CLI (`clap`), `0700` workspace + `config.toml`/`profile.toml` loader, anti-nesting + `fd-lock` guard, stateful VT500 C filter (`\r` rewind, `?1049h` pause, UTF-8 chunk state) with FFI unit tests, dual-stream Raw-Mode PTY shell (no competing `stdin` readers + full ANSI reset on `Drop`), and non-invasive Zsh/Bash/PowerShell shims writing `replay.sh` and `last_cwd`.
- **Phase 2:** SQLite (`state.db` WAL + `busy_timeout`), passive local route/interface observer, IPv6-safe XML/JSONL/regex parsers enforcing `EvidenceRecord` + TLS SANs + sub-path trees, CPE 2.2->2.3 converter, rate-paced NVD v2.0 + `OSV.dev` + CISA KEV client, progressive verification checklist, `meow add`, and same-FS atomic `graph.json` persistence.
- **Phase 3:** Loopback `Axum` coordinator (`runtime.json` IPC + `Origin`/token-guarded WebSocket), process-grouped 1-at-a-time `meow recon` queue (privilege + wordlist checks, timeouts, auto-resume), `Cytoscape.js` browser map (`meow map`), and `Ratatui 0.30` TUI (`meow hud`) with manual catch-up box.
- **Phase 4:** Boundary/stream-safe Privacy Vault, OWASP LLM01 sandboxing, `[L]` MLX + `[C]` OpenRouter + `[R]` `openrouter:web_search` (`max_uses: 2`) clients with exact `usage` USD budget lock, `chats/<host>.md` writer, and `meow report`.
