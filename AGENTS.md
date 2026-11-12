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

- **Active Phase & Step:** Phase 1, Step 4 complete (workspace + config).
- **Last Verified Commit:** `feat(phase1-step4)` — see `git log -n 1 --oneline`.
- **Completed Files:** scaffold, `src/c/tap_filter.{h,c}`, `src/tap.rs`,
  `src/cli.rs`, `src/mode.rs`, `src/workspace.rs`, `src/lib.rs`,
  `src/main.rs`, `tests/cli.rs` (59 tests total).
- **In-Progress / Partial Work:** `main.rs::run` implements bare `meow`
  (listing), workspace create/resume, and `meow mode` (direct `profile.toml`
  write). `meow <name>` then stops with "session shell is not built yet";
  `recon`/`map`/`hud`/`add`/`report` report "not built yet" (exit 1).
- **Next Exact Action:** Phase 1, Step 5 — write `src/lock.rs`: hold an
  `fd-lock` write lock on `Workspace::lock_path()` (file opened with
  `workspace::private_open_options()`) for the life of the session; a second
  `meow <name>` on the same workspace must fail fast with a clear message.
  Wire it into `main.rs` right after `Workspace::open_or_create`.
- **Blockers / Notes:**
  - `Cargo.toml` lists only crates in use (owner decision); add each
    later-phase crate from the SPEC §7 baseline in the step that first uses it.
  - Terminal control comes from `ratatui::crossterm`; do not add a direct
    `crossterm` dependency.
  - Library modules are exposed through `src/lib.rs` so unused public APIs
    pass `clippy -D warnings` before the binary wires them up.
  - `TapFilter` allocates `tap_state_t` using `tap_state_size()` from C; never
    mirror the struct layout in Rust.
  - Helper targeting order: `--local`, `--session`, `$MEOW_WORKSPACE`,
    `$MEOW_SESSION`. The PTY step must export `MEOW_SESSION`,
    `MEOW_WORKSPACE` (= `Workspace::dir`, already absolute) and `MEOW_MODE`.
  - `$MEOW_HOME` overrides `~/.meow`; tests rely on it. Create files with
    `private_open_options()` / `write_private_atomic()` only.
  - Windows ACL (`icacls` in `workspace.rs`) has never been compiled or run.
  - Listing shows name/mode/last-active; host count and unfinished tasks join
    when `graph.json` (Phase 2) and `state.db` tasks (Phase 3) exist.
  - Exit codes: 1 = runtime refusal/failure, 2 = usage error (clap).
