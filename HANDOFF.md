# Session handoff — `claude/tender-hopper-v6ollc`

Notes from a cloud Claude Code session, for a session continuing the work
elsewhere. Read `AGENTS.md` (rules, gates, handoff state), `SPEC.md` and
`issue/issues.md` first; this file only adds what those do not say.

Branch head when written: `f6d830b`. The tree was clean and pushed; nothing
is in progress.

## What the owner asked for in this chat (oldest first)

1. `meow list` showing every session, and `meow delete <session>`.
2. The topology drawn like a hand-sketched network diagram (Internet cloud →
   router → firewall → servers → segments → clients).
3. Map and HUD showing this machine: local connection, VPN, IPv4 address,
   and at the top right `address -> machine type -> OS -> version`, open
   ports and interfaces, kept short.
4. Each user sets up their own AI (`meow setup`): own Claude API key or
   local model. Claude API directly; default `claude-opus-5-5`, then
   `claude-opus-4-6`, then `claude-opus-4-8` when a model declines.
5. A map layout like web-check.xyz: dark dashboard of cards, only the
   sections that apply.
6. "These are vulnerabilities on my machine, how do I fix them?" — they were
   on a different host behind the VPN; added a "What to update" summary.
7. "What is all this?" — names printed in the terminal were drawn as
   servers; then katana's links to outside sites were drawn as servers.
8. Install everything in one go, including the scanners and a wordlist, and
   update by pulling from GitHub (`meow update`).
9. Old recon runs piling up; Host Info repeating the open ports.
10. Instead of skipping a stage for a missing tool, check before recon and
    offer to install (`meow tools`).
11. Questions only (answered, no code): installing on Linux/Kali, whether
    Kali works, where the map is served (127.0.0.1 only, 8765 upward, with a
    token), not being seen hosting anything, what `meow recon` does.

## Finished in this chat (all pushed)

| Commit | What |
|---|---|
| `d1d804a` | `meow list` / `meow ls` |
| `786173b` | Sketched topology with device icons and tiers |
| `21ab1a1` | Clearer AI fallback errors; interfaces labelled by routable address |
| `a8e4236` | `meow delete` (asks; refused while the session is open) |
| `5fe45e6`, `d3ac587`, `4e361ce` | "This machine" in map and HUD; VPN; IPv4 first |
| `068560b` | `address -> type -> OS -> version` summary; slow-link CVE timeouts |
| `c82d1ed` | Test fixtures use documentation addresses only |
| `abd6253` | `meow setup` with per-user `~/.meow/ai.toml` |
| `c6b9d06` | Dark dashboard map with an Advisory card |
| `8b12063` | Native Claude API (`src/anthropic.rs`) with a fallback chain |
| `a57a30e` | CVE: "What to update" per software; drops platform-only and other-OS matches; stale matches removed after a complete lookup; HUD notices wrap |
| `5b0b7b9` | Names only printed in the terminal are listed, not drawn |
| `6b50fd5` | Skip reasons visible on the map; `~/.meow/wordlists/` searched |
| `2c54e94` | `install.sh` installs scanners + wordlist by default; `meow update` |
| `00d246c` | katana kept on the crawled host (`-fs fqdn`), off-target crawl results dropped, old ones removed once on load (graph v2); newest run per target; leaner Host Info; key prompt hides input from the first keystroke |
| `f6d830b` | `meow recon` checks its tools first and offers to install; `meow tools`; `install.sh --tools-only` |

The owner's own commits `9fea381`..`1fd3151` (security hardening, Cat setup
wizard, Homebrew formula, `install.ps1`) were pushed from elsewhere while this
chat ran; `f6d830b` was rebased on top of them. 334 tests passed on the
combined code (Linux), plus both clippy gates and `fmt`.

## Left to do / unverified

- Nothing was in progress. No open entries in `issue/issues.md`.
- Never run for real: `katana`, `feroxbuster`, the installer against real
  Homebrew/apt (only stand-ins), `meow tools` installing for real, the
  Claude API with a real key, OpenRouter, Kali, Windows (compile-checked
  only; `install.ps1` never run here).
- The owner had not yet confirmed on their Mac: the "What to update" line,
  the crawl fix and its one-time cleanup, `meow update`, `meow tools`.
- `AGENTS.md` handoff state still says "330 tests"; it was 334 after
  `f6d830b`.
- Early commits in the branch history contain the owner's real addresses
  (fixed going forward in `c82d1ed`). Rewriting history needs the owner's
  decision; force-push is forbidden by `AGENTS.md`.

## Decisions and preferences the owner stated

- Simple, short output; only show sections that have something in them.
- No prompt marker in the session shell ("no need").
- Shared tool on GitHub: every user brings their own key or local model;
  never print a key, never commit real addresses or keys.
- Claude fallback chain: `claude-opus-5-5` → `claude-opus-4-6` →
  `claude-opus-4-8`.
- Everything in one install, scanners included; updates pull from GitHub
  and rebuild.
- The machine must not be seen hosting anything: the map stays on
  127.0.0.1; remote viewing only through an SSH forward the owner starts.
- Do not open pull requests unless asked; do not push to `main`.

## Known problems

- `tests/pty.rs` `setup_asks_on_the_terminal_and_never_shows_the_key` was
  flaky under load until `00d246c` (the key prompt now turns echo off first);
  0 failures in 15 runs after the fix.
- `meow recon` checks tools with the helper's `PATH`; the session's
  background worker uses the `PATH` it started with. A tool installed into a
  folder added to `PATH` later (e.g. `~/go/bin`) may need the session
  reopened.
