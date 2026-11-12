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

- **Active Phase & Step:** Phase 2, Step 4 complete (passive local network
  observer). Owner asked to build straight through Phases 2-4 without pausing;
  checkpoint after every step.
- **Last Verified Commit:** `feat(phase2-step4)` — see `git log -n 1
  --oneline`.
- **Completed Files:** Phase 1 (`tap`, `cli`, `mode`, `workspace`, `lock`,
  `pty`, `shims`, `main`, C filter); Phase 2 so far: `db`, `timeutil`,
  `evidence`, `endpoint`, `graph`, `cpe`, `parsers/{nmap,jsonl,text,diff}`,
  `observer`. Tests: unit tests in each module plus
  `tests/{cli,pty,shims}.rs`.
- **In-Progress / Partial Work:** `recon`/`map`/`hud`/`report` report "not
  built yet". `db.rs` tables are unused. The observer runs once at session
  start (periodic polling and live PTY tap parsing come with the Phase 3
  coordinator). macOS/Windows observer parsers are tested on fixtures only.
- **Next Exact Action:** Phase 2, Step 5 — `src/cve.rs`: add `tokio` +
  `reqwest`; rate-paced NVD v2.0 client (`cpeName=` + `keywordSearch=`, 6.5 s
  / 0.7 s pacing, 2 s connect timeout), OSV `querybatch` with
  `next_page_token`, 7-day cached CISA KEV, all attaching
  `UnverifiedHypothesis` advisories; then the verification checklist
  (`src/checklist.rs`).
- **Blockers / Notes:**
  - Add a crate only in the step that first uses it (owner decision).
    Terminal control via `ratatui::crossterm` only.
  - Parsers emit `graph::Observation`; only `Graph::apply` mutates hosts.
    Advisories enter via `Graph::add_advisory` as `UnverifiedHypothesis`.
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
  - Listing lacks host count / unfinished tasks until Phase 3.
