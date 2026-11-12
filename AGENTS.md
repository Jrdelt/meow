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

- **Active Phase & Step:** Phase 1 complete (Step 7, shell shims, was last).
- **Last Verified Commit:** `feat(phase1-step7)` — see `git log -n 1 --oneline`.
- **Completed Files:** scaffold, `src/c/tap_filter.{h,c}`, `src/{tap,cli,mode,
  workspace,lock,pty,shims,lib,main}.rs`, `tests/{cli,pty,shims}.rs`
  (95 tests + 1 ignored helper).
- **In-Progress / Partial Work:** none in Phase 1. `recon`/`map`/`hud`/
  `add`/`report` report "not built yet" (exit 1) until their phases.
- **Next Exact Action:** Ask the owner which comes first: (a) a GitHub
  Actions CI workflow running the three gates on Linux, macOS and Windows
  (offered, not yet approved), or (b) Phase 2, Step 1 — add `rusqlite`
  (`bundled`) and write `src/db.rs`: open `<workspace>/state.db` with
  `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, a
  `schema_version` table and migrations, file created `0600`.
- **Blockers / Notes:**
  - `Cargo.toml` lists only crates in use (owner decision); add later-phase
    crates from SPEC §7 in the step that first uses them.
  - Terminal control comes from `ratatui::crossterm`; never add a direct
    `crossterm` dependency. Library modules are exposed via `src/lib.rs`.
  - `TapFilter` sizes `tap_state_t` via `tap_state_size()`; never mirror it.
  - Helper targeting order: `--local`, `--session`, `$MEOW_WORKSPACE`,
    `$MEOW_SESSION`. Only `meow <name>` takes `SessionLock`; mutate the
    workspace as a session only after it (`record_open`).
  - `$MEOW_HOME` overrides `~/.meow` (tests rely on it). `$MEOW_TAP_LOG=<file>`
    appends the tap's clean lines to a file (debug aid; nothing else consumes
    tap lines until Phase 2). Create files with `private_open_options()` /
    `write_private_atomic()` only.
  - Shims: zsh and bash are tested end to end; `init.ps1` has never been run.
    Bash strips `ignoredups`/`erasedups` from `HISTCONTROL` in-session (a new
    history number identifies a command); history-excluded commands are
    logged as `# [UNRECORDED]`. `MEOW_BASH_LEGACY=1` forces the no-`PS0` path.
    Other shells (sh, fish, wsl) run unhooked with a notice.
  - Non-tty stdin: no raw mode, no reset sequence; at input EOF Ctrl-D is
    retyped every 250 ms until the shell exits.
  - Windows code is compile-checked only, never run: `rustup target add
    x86_64-pc-windows-gnu`, install `gcc-mingw-w64-x86-64`, then
    `cargo clippy --target x86_64-pc-windows-gnu --all-targets -- -D warnings`.
  - Listing lacks host count / unfinished tasks until Phases 2 and 3.
  - Exit codes: `meow <name>` returns the shell's; otherwise 1 = failure,
    2 = usage error.
