# AGENTS.md — `meow`

Local security triage shell, topology mapper and grounded audit workspace.
Rust (MSRV 1.88) + C11 via FFI. The full specification is in `SPEC.md`; read it
before changing anything. This file must stay under 100 lines.

## Toolchain Commands

```sh
cargo build                                  # debug build (compiles src/c/tap_filter.c via build.rs)
cargo test                                   # unit + FFI tests
cargo fmt --check                            # formatting gate
cargo clippy --all-targets -- -D warnings    # lint gate
```

All three gates (`fmt`, `clippy`, `test`) must pass before every commit.

## Non-Negotiable Boundaries

- Never place `tap_filter.c` inline with PTY `stdout`; clone read-only slices
  to the filter worker via `try_send` only.
- Never call `crossterm::event::read()` in the PTY host; `std::io::stdin()`
  owns raw input.
- Never promote `Observed` banners/headers directly to `Confirmed` findings.
- Never use `NamedTempFile::new()` across mount points; use
  `NamedTempFile::new_in(&workspace_dir)` only.
- Never send unvaulted IPs, hostnames, paths, or secrets to cloud APIs.
- Never commit workspace or secret files (`.meow/`, `*.db*`, `runtime.json`,
  `session.lock`, `.env*`).
- Never force-push, run destructive resets, or commit unverified code.
- Never modify the user's `~/.zshrc` / `~/.bashrc`; use per-session shims.
- Never leave `// TODO` placeholders or implement more than one step at a time.

## Handoff Protocol

Cold start (run before writing any code):

1. Read `AGENTS.md` and `SPEC.md`.
2. `git status` and `git log -n 5 --oneline`.
3. `cargo test` to confirm baseline health.
4. Continue from `Next Exact Action` below.

Before every push:

1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. Update `## Current Handoff State` in place.
5. Stage source/doc files only, then
   `git commit -m "feat(phaseX-stepY): <summary>"` and `git push -u origin HEAD`.
6. If the push needs a hardware key touch or `origin` is missing, print the
   exact command and wait.

## Current Handoff State

- **Active Phase & Step:** Phase 3, Step 3 complete (`meow map`: petgraph
  topology + embedded Cytoscape page). Owner asked to build straight through
  Phases 2-4 without pausing; checkpoint after every step.
- **Last Verified Commit:** `feat(phase3-step3)` — see `git log -n 1
  --oneline`.
- **Completed Files:** Phase 1 (`tap`, `cli`, `mode`, `workspace`, `lock`,
  `pty`, `shims`, `main`, C filter); Phase 2 (`db`, `timeutil`, `evidence`,
  `endpoint`, `graph`, `cpe`, `parsers/*`, `observer`, `cve`, `checklist`);
  Phase 3 so far: `coordinator`, `ipc`, `queue`, `topology`, `webui`,
  `assets/`. Tests: unit tests per module plus
  `tests/{cli,pty,shims,cve,recon}.rs`.
- **In-Progress / Partial Work:** `hud` and `report` report "not built yet".
  `vault`/`ai_usage`/`prompt_cache` tables are unused.
- **Next Exact Action:** Phase 3, Step 4 — `src/hud.rs`: Ratatui 0.30 TUI over
  the coordinator WebSocket (`tokio-tungstenite`): host list, node/endpoint
  inspector, Evidence vs Hypothesis checklist, CVE feed, queue status,
  notices, manual catch-up notes box, verdict keys, and `[L]`/`[C]`/`[R]`
  triggers (wired to AI in Phase 4). Render logic must be testable with
  `ratatui::backend::TestBackend`.
- **Blockers / Notes:**
  - Add a crate only in the step that first uses it (owner decision).
    Terminal control via `ratatui::crossterm` only.
  - Parsers emit `graph::Observation`; only `Graph::apply` mutates hosts.
    Advisories enter via `Graph::add_advisory` as `UnverifiedHypothesis`.
  - While a session is live the coordinator is the only writer of
    `graph.json`; helpers call `ipc::send` and fall back to the files when
    it returns `None`. New requests go into `coordinator::Command`.
  - Helper targeting: `--local`, `--session`, `$MEOW_WORKSPACE`,
    `$MEOW_SESSION`. Only `meow <name>` takes `SessionLock`.
  - `$MEOW_HOME` overrides `~/.meow` (tests). `$MEOW_TAP_LOG=<file>` dumps
    clean tap lines. Create files via `private_open_options()` /
    `write_private_atomic()` only.
  - Shims: zsh/bash tested end to end; `init.ps1` never run. Bash strips
    `ignoredups`/`erasedups` in-session; `MEOW_BASH_LEGACY=1` forces no-`PS0`.
  - Windows code is compile-checked only (`cargo clippy --target
    x86_64-pc-windows-gnu --all-targets -- -D warnings`, needs
    `gcc-mingw-w64-x86-64`); macOS has never been built.
  - CI workflow deferred: repo is private, macOS runners cost Actions minutes.
  - Map page: `assets/map.{html,js,css}` + vendored `cytoscape.min.js`
    (3.33.1, MIT). No inline scripts and no `innerHTML`: scraped text must
    stay inert. Checked by hand in Chromium via Playwright, not in `cargo test`.
  - Recon runs only inside a live session; light mode refuses it and pauses
    queued stages. Tests use stand-in tools (`tests/recon.rs`); real `nmap`
    was smoke-tested on 127.0.0.1 only, `katana`/`feroxbuster` never.
