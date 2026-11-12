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

- **Active Phase & Step:** Phase 4, Step 2 complete (AI tiers [L]/[C]/[R],
  LLM01 sandboxing, budget lock, chats). Owner asked to build straight through
  Phase 4 without pausing.
- **Last Verified Commit:** `feat(phase4-step2)` — see `git log -n 1
  --oneline`.
- **Completed Files:** Phase 1 (`tap`, `cli`, `mode`, `workspace`, `lock`,
  `pty`, `shims`, `main`, C filter); Phase 2 (`db`, `timeutil`, `evidence`,
  `endpoint`, `graph`, `cpe`, `parsers/*`, `observer`, `cve`, `checklist`);
  Phase 3 (`coordinator`, `ipc`, `queue`, `topology`, `webui`, `hud`,
  `assets/`). Tests: per module plus `tests/{cli,pty,shims,cve,recon,hud}.rs`.
- **In-Progress / Partial Work:** `meow report` reports "not built yet"; it is
  the only command left. AI tiers were tested against stand-in servers only:
  no real OpenRouter or local-model request has ever been made.
- **Next Exact Action:** Phase 4, Step 3 — `src/report.rs` + `meow report`:
  compile `REPORT.md` in the workspace from `graph.json` (Mermaid topology via
  `Topology::mermaid`), `Confirmed` findings separate from
  `UnverifiedHypothesis` items (and false positives), route warnings, secrets
  to rotate (`Vault::exposed_secrets`), task history, `replay.sh` and
  `chats/*.md`; no AI, no network. Then finish: README, final handoff.
- **Blockers / Notes:**
  - Add a crate only in the step that first uses it. Terminal control via
    `ratatui::crossterm` only (the HUD may read crossterm events; the PTY
    host must not).
  - Parsers emit `graph::Observation`; only `Graph::apply` mutates hosts.
    Advisories enter via `Graph::add_advisory` as `UnverifiedHypothesis`.
  - A live coordinator is the only writer of `graph.json`; helpers call
    `ipc::send` and fall back to the files on `None`. New requests go into
    `coordinator::Command` (HTTP `/api/command` and WebSocket share it).
  - Helper targeting: `--local`, `--session`, `$MEOW_WORKSPACE`,
    `$MEOW_SESSION`. Only `meow <name>` takes `SessionLock`.
  - `$MEOW_HOME` overrides `~/.meow` (tests). Create files via
    `private_open_options()` / `write_private_atomic()` only.
  - Map page: no inline scripts, no `innerHTML`; checked by hand in Chromium
    (Playwright), not in `cargo test`. Cytoscape 3.33.1 is vendored (MIT).
  - Recon tests use stand-in tools; real `nmap` was smoke-tested on 127.0.0.1
    only, `katana`/`feroxbuster` never. `init.ps1` has never been run.
  - Windows is compile-checked only (`cargo clippy --target
    x86_64-pc-windows-gnu --all-targets -- -D warnings`, needs
    `gcc-mingw-w64-x86-64`); macOS has never been built. No CI: the repo is
    private and macOS runners cost Actions minutes.
