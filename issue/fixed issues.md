# Fixed Security & Triage Issues (`meow`)

Verified fixes moved here from `issue/issues.md` after passing `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.

---

### `ISS-001` [Medium / Baseline] — Non-TTY Terminal Takeover & Raw-Mode Restoration Guards
- **Locations Fixed:** `src/hud.rs:13-16, 1079-1109`, `src/setup.rs:412-460, 706-710`, `src/pty.rs:94-100`, `tests/hud.rs:290-354`
- **Problem:**
  - `hud::run` called `ratatui::try_init()` without verifying `stdin().is_terminal() && stdout().is_terminal()`. When invoked with redirected stdio inside an interactive macOS terminal session (including `cargo test`), `crossterm` opened `/dev/tty`, switched the operator's controlling terminal into raw mode, failed `kqueue` registration on `/dev/tty` in `mio`, closed the input channel, and exited `0` instead of `1` (failing `tests/hud.rs::hud_without_a_terminal_fails_with_a_clear_message`).
  - `hud::run` called `ratatui::restore()` sequentially after `event_loop` without a `Drop` guard; `setup::ask_hidden` lacked a `Drop` guard around `enable_raw_mode()` and a non-TTY guard; `setup::run` and `pty::TerminalGuard::enter` checked `stdin().is_terminal()` without `stdout().is_terminal()`.
- **Resolution:**
  - Added `stdin().is_terminal() && stdout().is_terminal()` guards to `hud::run`, `setup::ask_hidden`, `setup::run`, and `pty::TerminalGuard::enter`.
  - Added `TerminalRestore` (`Drop` -> `ratatui::restore()`) in `src/hud.rs` and `RawModeGuard` (`Drop` -> `disable_raw_mode()`) in `src/setup.rs`.
  - Extended `tests/hud.rs` to verify both headless pipes and real-PTY sessions with redirected `stdout` fail `meow hud` cleanly (exit `1`, zero escape bytes on stdout) and run `meow setup` non-interactively.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed on macOS (`stable-aarch64-apple-darwin`).

### `ISS-002` [High] — Untrusted `PATH` and Windows CWD Binary Hijacking in Local Observer
- **Locations Fixed:** `src/observer.rs:10-13, 1127-1269, 1965-2075`, `tests/cli.rs:1044-1066`
- **Problem:** `observer::run_from` invoked `Command::new(program)` on bare binary names (`ifconfig`, `netstat`, `arp`, `sysctl`, `sw_vers`, `ip`, `ss`, `route`, `cmd`) via untrusted `PATH` before checking `SYSTEM_DIRS`, and `SYSTEM_DIRS` was empty on Windows where `CreateProcessW` searches the current working directory first.
- **Resolution:**
  - Removed bare `Command::new(program)` fallback; `resolve_in_dirs` resolves executables strictly inside absolute trusted system directories (`/usr/sbin`, `/sbin`, `/usr/bin`, `/bin` on Unix; validated drive-rooted `%SystemRoot%\System32` with `C:\Windows\System32` fallback and `.exe` lookup on Windows), rejecting traversal/relative names and non-executable files.
  - Scrubbed child `PATH` to the trusted directory list when executing resolved OS inspection tools.
  - Added unit tests in `src/observer.rs` (`PATH` isolation, `.exe` lookup, non-executable/traversal rejection, `windows_system32` UNC/relative/traversal rejection) and an end-to-end CWD + `PATH` poisoning test in `tests/cli.rs`.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed (`303` tests, `0` failures).

### `ISS-003` [High] — Unrestricted `nmap` Extra Flags Allow RCE, Arbitrary File Write & Target Scope Bypass
- **Locations Fixed:** `src/queue.rs:266-555, 619-660, 935-940, 1154-1168, 1450-1620`, `src/coordinator.rs:413-420`, `tests/recon.rs:202-215, 307-333`
- **Problem:** `ports_command` appended unvalidated `nmap_flags` directly to `nmap` without an allowlist or `--` separator before the target, allowing NSE script execution (`--script`, `-sC`, `-A`), arbitrary file reads/writes (`-oN`/`-oG`/`-oA`, `--datadir`, `--servicedb`, `--resume`), target scope bypass (`-iL`, `-iR`, positional targets), and option-eating via dangling flags (`-p`).
- **Resolution:**
  - Implemented `validate_nmap_flags` and `validate_preset_nmap_flags` using a strict option/value allowlist (bounding flag count, validating port specs/counts/durations/exclude targets, blocking scripts/file I/O/target files/proxies/spoofing/dangling options, and restricting `nmap_services` presets to safe built-in header/TLS NSE script names only).
  - Enforced validation at coordinator intake (`Command::Recon`), persistence (`queue::enqueue`), and stage execution (`queue::run_stage` for resumed `state.db` tasks and `profile.toml` presets).
  - Placed `"--"` immediately before the target operand in both `ports_command` and `services_command`.
  - Added unit and coordinator integration tests covering safe tuning flags and all blocked flag classes.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed (`304` tests, `0` failures).

### `ISS-004` [High] — Terminal Escape Sequence Injection via Unsanitized Graph, Advisory & Observer Fields
- **Locations Fixed:** `src/evidence.rs:180-191, 345-370`, `src/graph.rs:27-28, 224-239, 464-785, 1005-1065, 1568-1765`, `src/parsers/nmap.rs:131-137, 392-422`, `src/observer.rs:102-238, 284-415, 551-565, 1259-1402, 2490-2540`, `src/coordinator.rs:244-258`, `src/main.rs:355-358, 396-401, 434-436`, `src/hud.rs:178-190, 794-812, 1662-1715`
- **Problem:** `Port.protocol` was lowercased without allowlisting, letting arbitrary or C0/C1-escaped tokens enter `Port::key()`, `FixItem.action`, CLI output, and HUD spans. `Graph::add_advisory` sanitized `title` only, leaving `id`, `severity`, `cvss`, `matched`, `port`, `fixed_in`, `last_affected`, `references`, and `record` unsanitized. `Graph::load` and `hud::Model::apply_message` deserialized `Graph`/`Snapshot` payloads without field sanitization, and `observer.rs`, `State::notice`, and `main.rs` passed interface/MAC/OS/error strings without stripping terminal escape sequences.
- **Resolution:**
  - Added `graph::normalize_protocol` (`tcp`, `udp`, `sctp`, `dccp`, `ip`) and enforced it in `parsers::nmap::parse`, `Graph::port_entry`, `observer::listener_from`, `Advisory.port` (`normalize_port_key`), and `Graph::sanitize_loaded`.
  - Added `EvidenceRecord::sanitize_fields` (preserving `Source::GitDiff` multi-line blocks while stripping C0/C1/ESC/bidi controls everywhere) and `sanitize_advisory` (cleaning all `Advisory` strings, validating `cvss` in `0.0..=10.0`, normalizing `port`, and restricting `references` to bounded `http(s)://` URLs).
  - Enforced `Graph::sanitize_loaded` in `Graph::load` and `hud::Model::apply_message`, sanitized `Fact` claims/records in `push_fact`, sanitized interface names, hex MAC addresses, OS fields, and tool notes in `observer.rs`, and sanitized coordinator notices, HUD task rows, and CLI error/task lines.
  - Added unit tests across `evidence.rs`, `graph.rs`, `parsers/nmap.rs` (including XML 1.0 C1 OSC character references), `observer.rs`, and `hud.rs`.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed (`310` tests, `0` failures).

### `ISS-005` [Medium] — `EvidenceRecord` Deserialization Bypasses State Machine + Mermaid/Report Escaping Gaps
- **Locations Fixed:** `src/evidence.rs:56-64, 200-225, 407-439`, `src/graph.rs:489-544, 601-612, 1020-1040, 1768-1832`, `src/coordinator.rs:1485-1513`, `src/topology.rs:711-733, 1365-1390`, `src/report.rs:58-190, 222-278, 355-360, 412-496, 515-523, 582-586, 898-927`
- **Problem:**
  - `Command::Observations` and `Graph::load` deserialized `EvidenceRecord` directly without clamping `verification_status`, allowing banner/scanner observations or newly added advisories to smuggle `VerificationStatus::Confirmed` without going through `EvidenceRecord::transition`.
  - `Topology::mermaid` did not strip control characters or escape `\`, so labels ending in `\` escaped the closing quote in `n0["...\"]`.
  - `report.rs` wrote `advisory.port`, `port.key()`, and timestamp fields without `md()`, and appended raw `chats/*.md` without escaping raw HTML tags outside code spans/fences or closing dangling code fences.
- **Resolution:**
  - Added `Source::is_advisory_source`, `EvidenceRecord::normalize_observed`, `EvidenceRecord::normalize_new_advisory`, and `EvidenceRecord::normalize_loaded_advisory`, enforcing them across `push_fact`, `Observation::Path`, `sanitize_path_node`, and `sanitize_advisory` (`Graph::add_advisory` and `Graph::sanitize_loaded`).
  - Sanitized and replaced `\` in `Topology::mermaid` node labels.
  - Passed `advisory.port`, `port.key()`, and timestamps through `md()` in `report.rs`, and added `render_chat_markdown` to strip control/bidi characters, escape `<`/`>` outside inline code and fenced code blocks, preserve `#` comments inside code fences, and close dangling fences.
  - Added unit and coordinator IPC tests in `evidence.rs`, `graph.rs`, `coordinator.rs`, `topology.rs`, and `report.rs`.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed (`312` tests, `0` failures).

### `ISS-006` [Medium] — IPC Stale `runtime.json` Bearer Token Leak & Port Reuse Handling
- **Locations Fixed:** `src/lock.rs:84-127, 179-194`, `src/workspace.rs:37-40`, `src/coordinator.rs:70-84, 1038-1068, 1401-1438`, `src/ipc.rs:25-135, 151-286`, `src/hud.rs:1007-1016, 1105-1108, 1712-1755`
- **Problem:**
  - If a session exited uncleanly (`SIGKILL`) leaving `runtime.json` on disk and an unrelated local process later bound that loopback port, `ipc::send`, `ipc::is_live`, and `hud::connect` sent `Authorization: Bearer <token>` or `/ws?token=<token>` before checking whether `session.lock` was actually held by a live session.
  - `ipc::send_to` parsed `response.json()` before checking HTTP status codes (`401`/`404`/`405`/redirects) and allowed `reqwest`'s default redirect policy, failing with `"the session coordinator sent an invalid reply"` instead of returning `Ok(None)` when a reused port returned non-JSON responses.
- **Resolution:**
  - Added read-only `SessionLock::is_held` (`src/lock.rs`) and enforced it in `ipc::runtime_info_in` / `ipc::runtime_info` across `ipc::send`, `ipc::is_live`, `meow map`, and `hud::connect`.
  - Hardened `RuntimeInfo::read` to validate non-zero ports and URL/header-safe token characters, disabled HTTP redirects (`Policy::none()`) in `ipc::client`, checked HTTP status codes before `response.json()` so non-coordinator statuses (`401`, `403`, `404`, `405`, `3xx`, `5xx`, non-JSON `400`) fall back cleanly to `Ok(None)`, and sanitized coordinator error messages.
  - Added unit tests in `src/lock.rs`, `src/ipc.rs`, and `src/hud.rs` simulating stale `runtime.json` files pointing at foreign loopback listeners and verifying zero connections and zero bearer-token transmission, plus reused-port non-JSON status handling.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed (`315` tests, `0` failures).

---

## Priority 2 — Privacy Vault & Cloud AI Hardening

### `ISS-007` [High] — Unvaulted HTTP Redirect Hostnames, Missing Modern Key Prefixes, `[R]` Banner Leak & Cleartext `cloud_url`
- **Locations:** `src/vault.rs`, `src/ai.rs`, `src/setup.rs`, `src/anthropic.rs`
- **Resolution:**
  - Added `extract_redirect_host` in `src/vault.rs` and updated `Vault::register_graph` to register hostnames and IP addresses from `port.http.location` (both full `http(s)://` and protocol-relative `//` URLs) alongside `port.tls_sans`.
  - Expanded `KNOWN_KEY` and `JWT` in `src/vault.rs` to cover `ASIA...`, `sk-ant-...`, `sk-or-v1-...`, `sk-proj-...`, `sk-...`, `gh[pousr]_...`, `github_pat_...`, `glpat-...`, and 2/3-segment `eyJ...` tokens.
  - Removed raw `http_server` banner strings from `research_prompt` (`[R]`) in `src/ai.rs`, keeping normalized public identifiers (`product`, `version`, `cpes`, and `unverified_advisories`) only.
  - Added `ai::validate_cloud_url` and enforced `https://` for `cloud_url` across `src/ai.rs`, `src/setup.rs`, and `src/anthropic.rs` unless the parsed host is loopback (`localhost`, `127.0.0.0/8`, `::1`), plus disabled HTTP redirects (`Policy::none()`) on AI/setup HTTP clients.
  - Added unit tests in `src/vault.rs`, `src/ai.rs`, and `src/setup.rs`.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed.

---

## Priority 3 — Supply Chain, DoS Caps & CVE Grounding Accuracy

### `ISS-008` [High] — Installer Supply-Chain & Shell-Config Hardening (`install.sh`)
- **Locations:** `install.sh`, `tests/install.rs`
- **Resolution:**
  - Passed `--no-modify-path` to `rustup-init` in `install.sh` so user shell rc files are never modified.
  - Added `--https-only` to `wget` invocations in `install.sh`.
  - Pinned `KATANA_GO` to `v1.1.2` and `WORDLIST_URL` to an immutable SecLists commit hash with `verify_sha256` checksum verification against `WORDLIST_SHA256`.
  - Used `mktemp "$wordlist_dir/.common.txt.XXXXXX"` and registered `trap cleanup EXIT INT TERM` to clean up temporary files (`rustup_init` and `wordlist_part`).
  - Added `supply_chain_and_shell_profile_hardening_in_install_script` in `tests/install.rs`.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --test install` passed.

### `ISS-009` [Medium] — `meow update` Git Hook Execution, Unchecked Remote & Unattended `sudo`
- **Locations:** `src/update.rs`, `install.sh`, `tests/update.rs`
- **Resolution:**
  - Resolved `git` and `sh` from trusted system directories (`resolve_git`, `resolve_sh`) in `src/update.rs` rather than untrusted `PATH`.
  - Passed `-c core.hooksPath=/dev/null`, `-c protocol.ext.allow=never`, and `-c protocol.file.allow=never` (allowing verified local bare directories only when `--source` is explicitly passed) to `git` commands in `src/update.rs`.
  - Added `validate_remote_url` in `src/update.rs` to require `https://`, `ssh://`, or `git@...:` before fetching.
  - Passed `MEOW_NO_SUDO=1` when `meow update` invokes `install.sh --yes` and honored `MEOW_NO_SUDO=1` in `install.sh` `pm_install` so unattended updates never run privileged `sudo` commands.
  - Added `hooks_are_disabled_and_untrusted_remotes_are_refused` in `tests/update.rs`.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --test update` passed.

### `ISS-010` [Medium] — Graph/Parser DoS Bounds & Outbound Lookup Scope (`graph.rs`, `cve.rs`)
- **Locations:** `src/graph.rs`, `src/cve.rs`
- **Resolution:**
  - Tracked cached subtree node counts (`total_nodes`) on `PathNode` across `insert_path`, `merge_paths`, and `sanitize_path_node` so `port.paths.count()` runs in $O(1)$ time and path insertion updates counts in $O(\text{depth})$ time.
  - Added `MAX_GRAPH_BYTES` (64 MiB) check in `Graph::load` and collection caps (`MAX_HOSTS`, `MAX_PORTS_PER_HOST`, `MAX_HOSTNAMES_PER_HOST`, `MAX_CPES_PER_PORT`, `MAX_TLS_SANS_PER_PORT`, `MAX_ADVISORIES_PER_HOST`) across live `Graph` mutations and `Graph::sanitize_loaded`.
  - Added `read_json_bounded` (32 MiB cap) for NVD, KEV, and OSV HTTP responses in `src/cve.rs`, validated `osv_details` IDs with `validate_osv_id` (`^[A-Za-z0-9._-]+$`, `<= 128` chars), and restricted PURL extraction in `cve::plan` to `Source::ManualNote` facts only.
  - Added unit tests in `src/graph.rs` and `src/cve.rs`.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed.

### `ISS-011` [High] — CVE Version Comparison & Lookup False Negatives (`cve.rs`, `cpe.rs`, `text.rs`)
- **Locations:** `src/cve.rs`, `src/cpe.rs`, `src/parsers/text.rs`
- **Resolution:**
  - Updated `cmp_versions` in `src/cve.rs` to rank pre-release tags (`alpha`, `beta`, `rc`, `pre`, `dev`) before final releases (`1.20.1-rc1 < 1.20.1`), patch suffixes after base versions (`8.2 < 8.2p1`, `1.1.1 < 1.1.1k`), trailing `.0` segments as equal (`1.0.0 == 1.0`), and strip distribution revision suffixes (`2.4.52-1ubuntu4 == 2.4.52`).
  - Added multi-page NVD pagination (`startIndex` / `totalResults` up to `NVD_MAX_PAGES = 5`) in `CveClient::nvd_query`.
  - Updated `cpe::clean_version` in `src/cpe.rs` to preserve multi-segment underscore versions (`openssl_1_1_1k` -> `1.1.1k`, `for_windows_9.5` -> `9.5`).
  - Updated `cve::plan` so only application CPEs (`parts.part == 'a'`) set `keyworded = true`.
  - Added `split_service_info` in `src/parsers/text.rs` to split Nmap service banners into `product`, `version`, and `extra_info`.
  - Added unit and mock-server pagination tests in `src/cve.rs`, `src/cpe.rs`, and `src/parsers/text.rs`.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --no-fail-fast` passed (`322` tests, `0` failures).

### `ISS-012` [Low / Usability] — API Key Prompts Swallowed Ctrl+V and Hid Whether a Paste Arrived
- **Locations Fixed:** `src/setup.rs` (`ask_hidden`, `PASTE_HINT`), `src/wizard.rs` (`EditState::paste_hint`, `on_key`, `draw_footer`), `tests/pty.rs`, `src/wizard.rs` tests
- **Problem:** Reported on Kali: "meow setup doesn't let me paste the key". In a terminal Ctrl+V sends a control key, not the clipboard. Both key prompts stored it as a literal `v`, so the saved key was wrong and the Claude API answered `invalid x-api-key`. The plain prompt also echoed nothing at all, so a paste that worked looked the same as one that did not.
- **Resolution:** Ctrl+V (and other Ctrl/Alt chords) no longer add characters; both prompts say to paste with Ctrl+Shift+V or right-click. The plain prompt enables bracketed paste and prints one `*` per character received (the wizard already did); the wizard's edit box names the paste keys.
- **Verified:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` passed (Linux).
