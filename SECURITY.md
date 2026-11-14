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
  `meow update`, `meow tools`;
- the local map server and the HUD connection (they listen on `127.0.0.1`
  only and require the session token);
- the secret vault and anything that could send unvaulted addresses, host
  names, paths or keys to a cloud AI;
- the handling of untrusted input: scan files, terminal output, web pages
  and API answers that reach the graph, the terminal or a report;
- file permissions of the workspace and of `~/.meow/ai.toml`.

Out of scope: vulnerabilities in the systems you scan (that is what meow
reports on), and problems in nmap, katana or feroxbuster themselves, which
belong to those projects.

## Supported versions

Only the latest commit on `main` and the latest tagged release get fixes.
Update with `meow update`.

## Using meow responsibly

meow drives network scanners. Use `meow recon` only against systems you own
or are explicitly authorised to test. The default `light` mode sends nothing
to any target.
