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

1. Read `AGENTS.md`, `SPEC.md`, and `issue/issues.md`.
2. `git status` and `git log -n 5 --oneline`.
3. `cargo test` to confirm baseline health.
4. Continue from `Next Exact Action` below.

Issue tracking (`issue/`):

- Log any newly discovered bug or security finding in `issue/issues.md`.
- Once a fix passes `fmt`, `clippy`, and `test`, move its entry from
  `issue/issues.md` to `issue/fixed issues.md`.

Before every push:

1. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
2. Move resolved entries from `issue/issues.md` to `issue/fixed issues.md` and
   update `## Current Handoff State` in place.
3. Stage source/doc files only, then
   `git commit -m "<type>(<scope>): <summary>"` and `git push -u origin HEAD`.
4. If the push needs a hardware key touch or `origin` is missing, print the
   exact command and wait.

## Current Handoff State

- **Active Phase & Step:** `v0.1.0` release: Cat Setup GUI (`src/wizard.rs`), hardening (`ISS-001`..`ISS-011`), installers & GitHub/local sync complete; `meow tools` (recon checks and offers to install its tools).
- **Last Verified Commit:** See `git log -n 1 --oneline`.
- **In-Progress / Partial Work:** None (`341` tests passing).
- **Next Exact Action:** Log any newly discovered issues in `issue/issues.md`.
- **Blockers / Notes:**
  - Add a crate only in the step that first uses it. Terminal control via
    `ratatui::crossterm` only (the HUD may read crossterm events; the PTY
    host must not).
  - Parsers emit `graph::Observation`; only `Graph::apply` mutates hosts.
    Advisories enter via `cve::merge`, unverified; `cve::fix_plan` groups them.
  - A live coordinator is the only writer of `graph.json`; helpers call
    `ipc::send` and fall back to the files on `None`. New requests go into
    `coordinator::Command` (HTTP `/api/command` and WebSocket share it).
  - Helper targeting: `--local`, `--session`, `$MEOW_WORKSPACE`,
    `$MEOW_SESSION`. Only `meow <name>` takes `SessionLock`; `meow delete`
    needs it free. `meow list` pings each session (`ipc::is_live`).
  - `$MEOW_HOME` overrides `~/.meow` (tests). Create files via
    `private_open_options()` / `write_private_atomic()` only. `meow setup`
    keeps each user's AI in `~/.meow/ai.toml`, re-read per request. Shared
    repository: never print a key, never commit real addresses or keys.
  - Cloud tiers: `src/anthropic.rs` speaks the Claude API natively (raw
    HTTP; prices and model families are tables there), `ai.rs` the
    OpenAI-style one. A refusal walks the user's fallback chain in order.
  - zsh: the shim `.zshenv` restores the user's `ZDOTDIR` first, so system and
    user startup files load natively. Never keep it on the shim after that.
  - Map page: a dashboard of cards; no inline scripts, no `innerHTML`; checked
    by hand in Chromium (Playwright). The topology is a top-down diagram (a bar
    per interface, `link` colours it); `topology::Role` carries the reason; the
    Internet and neighbour clients are drawn only, never hosts. `observer::machine_report` words "this machine" for map and HUD.
  - Recon tests use stand-in tools; `katana`/`feroxbuster` have never run
    for real. `init.ps1` has never been run.
  - Windows is compile-checked only (`cargo clippy --target
    x86_64-pc-windows-gnu --all-targets -- -D warnings`). Public repo: CI in
    `.github/workflows/checks.yml` (gates, Windows lint, `cargo audit`).
  - macOS (owner's machine): `fmt`, `clippy`, and `cargo test --no-fail-fast`
    all pass. Tests must not depend on the login name, `/usr/bin/zsh`,
    bash >= 4.4 or unresolved temp paths.
