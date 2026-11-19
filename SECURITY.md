# Security policy

## Reporting a vulnerability

Please report security problems in meow privately, not in a public issue:
use **Report a vulnerability** on this repository's **Security** tab
(GitHub private vulnerability reporting). Include what you found, how to
reproduce it, and the commit or version you tested.

You will get an answer as soon as the maintainer can look at it. A fix is
made on `main` first; the report stays private until the fix is published.

## What is in scope

meow itself, for example:

- the installers (`install.sh`, `install.ps1`, `Formula/meow.rb`) and
  `meow update` (SHA-256 verified GitHub release upgrades and hardened git
  source updates), `meow tools`;
- the local map server and the HUD connection (they listen on `127.0.0.1`
  only, enforce strict `Host`/`Origin` checks, and require the session token);
- the secret vault, local-only AI lock (`disable_cloud = true` in
  `~/.meow/ai.toml`), and anything that could send unvaulted addresses, host
  names, paths or keys to a cloud AI;
- location and map tile privacy (`[location] enabled` and `map` in
  `~/.meow/config.toml`, full-tunnel VPN auto-suppression, HTTPS/redirect
  enforcement, and offline DB-IP lookups);
- the handling of untrusted input: scan files, terminal output, web pages,
  SQLite workspace state (`SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema = OFF`),
  and API answers that reach the graph, the terminal or a report;
- ownership, symlink refusal, and `0700`/`0600` (or Windows current-user SID
  ACL) permissions of workspaces and `~/.meow/ai.toml`.

Out of scope: vulnerabilities in the systems you scan (that is what meow
reports on), and problems in nmap, katana or feroxbuster themselves, which
belong to those projects.

## Session folders (`./meow/`)

New sessions are saved in `./meow/<name>/` of the folder you pick (the one
meow runs from by default). On macOS and Linux meow refuses a folder that
another user owns or can write to (also through a group they share, such
as macOS's `staff`, or an ACL), or that sits in one they could change (a
sticky folder like `/tmp` is fine), and checks this again each time a
session there is opened, used or deleted. On Linux it does not use SMB
shares, whose access lists it cannot read. It keeps `./meow` private
(`0700`, or a current-user ACL on Windows), never follows a link there, and
disables SQLite schema execution (`trusted_schema = OFF`). A session that
came with a cloned, unpacked, copied or moved folder is not opened until
you accept it, and never under the name of one of yours. If a `git pull`
or an unpacked archive replaces files of your own session, meow says so,
drops its shell history and last folder, and resumes its scans only on a
yes. `./meow` and each session in it have a `.gitignore`. A running
session puts back one a pull changed and warns when git tracks session
files; between sessions, a pull that knows a session's name can still let
git take its files in. On Windows, and when working inside untrusted or
shared directories, use `meow <name> --home` (`~/.meow/workspaces/`).

## Supported versions

Only the latest commit on `main` and the latest tagged release get fixes.
Update with `meow update`.

## Using meow responsibly

meow drives network scanners. Use `meow recon` only against systems you own
or are explicitly authorised to test. The default `light` mode sends nothing
to any target.

