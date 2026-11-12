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

- **Active Phase & Step:** All four phases complete, plus `install.sh`, `meow
  list`, `meow delete`, the sketched map and fixes from real macOS runs.
- **Last Verified Commit:** `feat(summary)` — see `git log -n 1 --oneline`.
- **Completed Files:** Phase 1 (`tap`, `cli`, `mode`, `workspace`, `lock`,
  `pty`, `shims`, `main`, C filter); Phase 2 (`db`, `timeutil`, `evidence`,
  `endpoint`, `graph`, `cpe`, `parsers/*`, `observer`, `cve`, `checklist`);
  Phase 3 (`coordinator`, `ipc`, `queue`, `topology`, `webui`, `hud`,
  `assets/`); Phase 4 (`vault`, `ai`, `report`); `install.sh`; `tests/*.rs`.
- **In-Progress / Partial Work:** None.
- **Next Exact Action:** Wait for the owner's macOS results: `cargo test
  --no-fail-fast`, how the map looks, and the session banner (`not fully read`
  names an OS tool that failed). Unverified: real `katana`/`feroxbuster`, a
  real `[L]`/`[C]`/`[R]` request, Windows.
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
    `$MEOW_SESSION`. Only `meow <name>` takes `SessionLock`; `meow delete`
    needs it free. `meow list` pings each session (`ipc::is_live`).
  - `$MEOW_HOME` overrides `~/.meow` (tests). Create files via
    `private_open_options()` / `write_private_atomic()` only.
  - zsh: the shim `.zshenv` restores the user's `ZDOTDIR` first, so system
    files (Apple's pick the history location from it) and the user's
    `.zshrc` load natively. Never keep `ZDOTDIR` on the shim past `.zshenv`.
  - Map page: no inline scripts, no `innerHTML`; look and layout are checked
    by hand in Chromium (Playwright). `topology::Role` picks a node's icon
    and carries the reason; the cloud and neighbour-table clients are drawn
    only, never hosts. `observer::machine_report` words "this machine" once
    for the map and the HUD (`m`). Cytoscape 3.33.1 is vendored (MIT).
  - Recon tests use stand-in tools; real `nmap` was smoke-tested on 127.0.0.1
    only, `katana`/`feroxbuster` never. `init.ps1` has never been run.
  - Windows is compile-checked only (`cargo clippy --target
    x86_64-pc-windows-gnu --all-targets -- -D warnings`, needs
    `gcc-mingw-w64-x86-64`). No CI: private repo, paid macOS runners.
  - macOS (owner's machine): sessions, `meow report` and the listing work; no
    full test run reported yet. Tests must not depend on the login name,
    `/usr/bin/zsh`, bash >= 4.4 or unresolved temp paths. `install.sh` has
    run for real on Linux only.
