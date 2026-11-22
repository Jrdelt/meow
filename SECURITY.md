# Security policy

## Reporting a vulnerability

Report security problems in meow privately, not in a public issue. Use **Report a vulnerability** on this repository's **Security** tab (GitHub private vulnerability reporting). Say what you found, how to reproduce it, and which commit or version you tested.

The maintainer answers as soon as possible. The fix goes to `main` first, and the report stays private until the fix is published.

## Scope

In scope is meow itself and the promises below. The [README](README.md) says how.

- **Installers and updates:** `install.sh`, `install.ps1`, `Formula/meow.rb`, `meow update` and `meow tools`. A release install checks the download's SHA-256 and never installs a pre-release. Before git reads a source clone, also with `--check`, meow checks that the clone and its `.git` are yours alone, not links, and set up like a plain clone. On Windows, administrators and SYSTEM count as you. Before it fetches or builds, it checks every tracked file and git's own files. It refuses submodules, and cargo or rustup settings above the clone that are links or not yours (or root's) alone. Cargo takes no `Cargo.toml` or `Cargo.lock` from above it. Releases publish only after tests pass; actions, formula and wordlist are pinned.
- **Map server and HUD connection:** `127.0.0.1` only, `Host` and `Origin` checks, and the session token. The browser never gets the URL with the token. A map page sends and shows nothing until the session proves itself. A clean end removes `runtime.json` (with the token) and the opener page.
- **Privacy Vault and cloud AI:** masking before anything goes out, with scan text sent as data apart from the instructions. Replies are filled back only for the triaged host, only in prose. `#` lines in a reply are nested in `REPORT.md`. A key, also one in `config.toml`, goes only to its own service and is never printed; setup input not read at exit never reaches the shell. `disable_cloud = true` in `~/.meow/ai.toml` (**Off** in `meow setup`, or `--cloud-off`) keeps cloud AI off even with an exported key. Cloud AI is also off while `ai.toml` or `~/.meow/ai-usage` cannot be read.
- **Location and map pictures:** `https://` only, no redirects. No location lookup while a VPN carries all traffic. Scanned hosts are placed only from the offline DB-IP database.
- **Untrusted input:** scan files, terminal output, web pages, git repositories, the session database (`SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema = OFF`) and API answers that reach the graph, the terminal or a report. In a git folder, meow runs git only on the top repository. It reaches no remote, ignores that repository's `core.sshCommand` and credential helpers, never asks for a password, and stops after 3 s.
- **Session folders and `~/.meow`:** private (`0700` folders, `0600` files; on Windows, an access list for you alone), with no links followed. On macOS and Linux, meow refuses a folder others own or can change. A session from a cloned, unpacked or copied folder opens only after you accept it, and a scan queued in session files never runs.
- **Scans:** every scan tool stops with its session, also when meow is killed. Only processes meow started are stopped.

Out of scope: the systems you scan, and nmap, katana or feroxbuster themselves.

## Known limits

- **Windows:** meow does not read the access lists of session folders, and does not check who owns `.git`. Use `meow <name> --home` there, and in any repository you do not trust.
- Linked work trees, submodules and, on macOS and Linux, shared or other users' `.git` folders get no git check, only the `.gitignore` files. A pull there during a session is not noticed. Between sessions, a pull that knows a session's name can let git take its files in; the next open warns.
- A file copied over the shell history during a session is not noticed. After an end meow did not see, a `graph.json` or history replaced without git looks like meow's own rewrite.
- A program a scan tool starts in a session or process group of its own (`setsid`, `sudo` with its own terminal) is not stopped.
- A local AI server gets unmasked text and keys when meow sees it is yours. On Linux that includes a server run by root or a system account (user ID below 1000), and a port with no listener meow can see (forwarded into a container or network namespace). Everywhere, it includes a port you forward to another machine (`ssh -L`). Another user's server, or one on another machine, gets masked text and no key. So does one meow cannot check: on Windows a system or service process, or a port whose process has exited; on macOS, when `lsof` fails.
- Masking misses dotted numbers of 2 or 3 parts, each 255 or less (`52.12.7`), read as versions in prose. A one-word name from one host's banner goes as a bare word in other hosts' requests. A name with an advisory-shaped suffix (`FILESRV-2024-001`) is left in clear. Notes are free text that masking may miss.
- With OpenRouter and the like, a day can end over the cap. A research call the API finishes after meow stopped waiting may cost more than was counted.
- The location lookup (ipinfo.io by default) starts with the first map page. Until the session ends, it runs again when the network changes or a try failed. It sends no parameters; the service sees your public address.
- Map pictures come from EOX through meow: up to 18 around this machine's estimate, and as many around a selected host's database place. EOX learns those rough areas.
- `install.sh` run by hand does not check cargo or rustup settings above it; `meow update` and `install.ps1` do.

## Supported versions

Only the latest commit on `main` and the latest tagged release get fixes. Update with `meow update`.

## Using meow responsibly

meow drives network scanners. Use `meow recon` only on systems you own or are explicitly authorized to test. The default `light` mode sends nothing to any target.
