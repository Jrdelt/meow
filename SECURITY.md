# Security policy

## Reporting a vulnerability

Report security problems in meow privately, not in a public issue. Use **Report a vulnerability** on this repository's **Security** tab (GitHub private vulnerability reporting). Say what you found, how to reproduce it, and which commit or version you tested.

The maintainer answers as soon as possible. The fix goes to `main` first, and the report stays private until the fix is published.

## What is in scope

meow itself, for example:

- the installers (`install.sh`, `install.ps1`, `Formula/meow.rb`), `meow update` and `meow tools`;
- the map server and the HUD connection;
- the Privacy Vault, the cloud-off lock, the daily usage record, and anything that could send unmasked addresses, host names, paths or keys to a cloud AI;
- location and map picture privacy;
- untrusted input: scan files, terminal output, web pages, git repositories, the session database, and API answers that reach the graph, the terminal or a report;
- ownership, link refusal and permissions of session folders and `~/.meow` (`0700` folders and `0600` files, or a current-user access list on Windows).

Out of scope: problems in the systems you scan, which meow reports on. Problems in nmap, katana or feroxbuster belong to those projects.

## Session folders

New sessions are saved in `./meow/<name>/` of the folder you pick.

- **Who may write.** On macOS and Linux, meow refuses a folder that another user owns or can write to. Write access through a shared group (such as macOS's `staff`, even beside an ACL like "everyone deny delete") or an ACL counts. So does a folder above that others could change; a sticky folder like `/tmp` is fine. A folder named through a link is checked as the real folder. meow checks again each time a session there is opened, used or deleted.
- **Shares.** On Linux, meow does not use an SMB share, whose access list it cannot read. An NFS or FUSE folder whose access list it cannot read is refused when group write is set.
- **Privacy.** meow keeps `./meow` private (`0700`, or an access list for the current user on Windows) and never follows a link there. SQLite runs with `SQLITE_DBCONFIG_DEFENSIVE` and `trusted_schema = OFF`.
- **Sessions from elsewhere.** A session that came with a cloned, unpacked, copied or moved folder opens only after you accept it. It never opens under the name of one of yours. Accepting it drops its shell history, start folder and queued scans.
- **Queued scans.** A scan queued in a session's files never runs. A recon ends with the session that started it, and a session runs only what you queue in it.
- **Replaced files.** meow records each session's files in `~/.meow/session-files/`: as open when a session starts, and again at a clean end. If files were replaced between sessions, or by a `git pull` during one, the next open drops the shell history and last folder.
- **Helpers.** `meow add` and `meow report` with no session running hold `helper.lock` and mark the record open while they write.

Limits:

- A file copied or unpacked over the shell history while a session runs is not noticed. `graph.json`, `last_cwd`, `replay.sh`, `state.db` and chats are covered.
- After an end meow did not see (`kill -9`, a crash), a `graph.json` or history replaced without git looks like meow's own rewrite.
- **Windows:** meow does not read the access lists of the folders that hold a session, so another account that can write there is not noticed. On Windows, use `meow <name> --home` (`~/.meow/workspaces/`).

## git in a session folder

When a session opens, and while it runs, meow asks git whether it tracks, or would add, session files. A repository is untrusted input, so git runs under these rules:

- git runs only on the repository at the top of the work tree, and only when its `.git` is a folder of yours alone. A folder below the top that looks like a repository cannot take its place.
- Linked work trees, submodules, and `.git` folders that are shared or another user's are not checked. They get only the `.gitignore` files.
- git reaches no remote. Lazy fetch is off, and no transport is allowed (ssh, https, http, ftp, ftps, file, git, ext, fd or a remote helper), whatever the repository's config says. This holds even with a git too old for `GIT_NO_LAZY_FETCH`.
- The repository's `core.sshCommand` and credential helpers are ignored, and git never asks for a password.
- git gets 3 s per check. Past that, git and what it started are killed. `Ctrl-C` while meow waits at open ends git too, and a git still checking when the session ends is killed.

So opening a session in a downloaded, unpacked or cloned repository runs none of its programs and contacts nothing.

Each `.gitignore` of meow's that a pull changes is put back while the session runs. Limit: between sessions, a pull that knows a session's name can still let git take its files in. The next open puts the `.gitignore` files back and warns if git tracks session files.

## `meow update` from a source folder

Before git first reads the clone, also with `--check` and `--source` (or `MEOW_SOURCE`), meow checks:

- that the folder, `.git`, `.git/config`, every file git tracks and git's own files are yours alone. On Windows this reads the owner and access list; you, SYSTEM, Administrators and TrustedInstaller are trusted. A clone right under `C:\` is refused;
- that its key paths are not links, and that no folder above it is a link (on macOS and Linux, one owned by root is allowed);
- that `.git/config`, read as a file without includes, holds only what a plain clone has plus a few safe keys (listed in the README);
- that there is no `.git/commondir` and no submodule;
- that no folder above it has a `.cargo`, `.cargo/config`, `.cargo/config.toml`, `rust-toolchain` or `rust-toolchain.toml` that is a link, another account's, or changeable by others. A `.cargo` link is fine when it is yours (or root's, SYSTEM's or Administrators') and leads to a folder of yours alone.

More rules:

- `Cargo.toml` has an empty `[workspace]`, so cargo never takes a `Cargo.toml`, `Cargo.lock` or `[patch]` from a folder above the clone. For an older clone without it, meow refuses a `Cargo.toml` or `Cargo.lock` above that another account can change.
- The remote must be `https://` or ssh; a local folder only with `--source`. Pulls only fast-forward, and nothing is pulled over local changes.
- Every git call runs with lazy fetch off and no password prompt. Read-only calls reach no remote. Environment variables that redirect git (`GIT_DIR`, `GIT_SSH_COMMAND`, `GIT_CONFIG_*` and others) are removed.
- On macOS and Linux the build runs in `~/.meow/build`, not the system temp folder. It is made private (`0700`) and checked before each use. If `~/.meow` or the build folder is another user's or others can change it, the update stops.
- `install.ps1` checks the same `.cargo` and `rust-toolchain` paths above the current folder. It checks before `rustc` or `cargo` first runs and again before the build, also with `-ToolsOnly`.

Limit: `install.sh` run by hand does not check the `.cargo` and `rust-toolchain` paths above it. `meow update` checks them before it runs `install.sh`.

## Releases and other installs

- A release install asks GitHub for the newest release, downloads this system's archive and its `.sha256`, and checks it before it replaces meow. The requests name nothing about you or your work.
- A version with a pre-release part (`0.3.0-rc.1`) is published as a GitHub pre-release, never as the latest. `meow update` ignores it unless the running meow is a pre-release.
- The release workflow publishes nothing until its test job passes: `cargo fmt --check`, `clippy -D warnings` and the unit tests. Build jobs get a read-only token. The publish job takes each platform's files only with the SHA-256 its build job reported. Actions are pinned to a commit.
- The Homebrew formula is pinned to the release tag's commit. The SecLists wordlist is pinned to a commit and a SHA-256 in the formula and both installers.

## Scans after meow ends

- On Linux and macOS each scan tool runs in a process group of its own, and the whole group is stopped when the session ends.
- If meow is killed outright, a helper process (`meow-guard` on Linux, `meow __guard` on macOS) stops the groups. If both die, the next `meow`, `meow list` or session start stops them, using the records in `~/.meow/run`. It stops only processes meow started, matched by their exact start time.
- On Windows the tools run in Job Objects that close with meow's process.

Limit: a program a tool starts in a session or process group of its own (`setsid`, `sudo` with its own terminal) is not stopped.

## AI and the Privacy Vault

- **Masking.** Before anything goes to a cloud AI, meow replaces IP addresses, host names, domains, email user names, MAC addresses, file paths, user names and secrets with placeholders. Scan text travels as data in one field (`untrusted_scan_data`), never mixed with the instructions.
- **Filling the reply.** Only the triaged host's own address and names are filled back, and only in prose. They stay masked in inline code, fenced or indented code, and lines that look like commands. Command-like means shell prompts, pipes, redirects, `$VAR`, `NAME=`, `&&`, `$( )`, flags, or a network tool given an argument (`curl`, `wget`, `nc`, `ssh`, `dig`, `nslookup`, `host` and the like, in any letter case).
- **Other hosts.** They also stay masked on a line that names another host: any top-level domain, IPv6, or IPv4 in any notation. The same holds in a name built on a placeholder (`<<HOST_01>>.x`). They stay masked on any line where a name only the host's certificate gives stands beside another of its values.
- **Learnt names.** Advisory and database words (`cve`, `ghsa`, `nvd`, `kev`, `cwe`, `osv` and others) are never learnt as names. Ones that older versions learnt are removed when a session opens. A learnt name is skipped only before an advisory number, so `CVE-2021-23017` stays whole and `ACME-01` is masked.
- **One-word names.** A one-word name from a host's certificate or scan text (`Computer name:`, `Domain:`, Workgroup, NetBIOS, LDAP `DC=`/`CN=`) belongs to that host. It is masked everywhere in that host's requests. In other hosts' requests it is masked where it stands as a host: `//name`, `user@name`, `\\name\`, `name:port`, `NAME\user`. A name that a scan or DNS gives as a hostname is masked everywhere.
- **Notes.** Your notes are not sent to a cloud AI unless `cloud_notes = true`.
- **Reports.** `#` lines in an AI reply, also inside its code blocks, are nested in `REPORT.md`, so a reply cannot add report sections.
- **Local servers.** A model server on this machine gets unmasked text and API keys only when meow sees it is yours. On Linux, one run by you, root or a system account (user ID below 1000) counts as yours. On macOS, only one meow sees running as you. Another user's server, one on another machine, or one meow cannot check gets masked text and no key.
- **Keys.** A key goes only to the service it was set for. `meow setup` refuses a key whose prefix names the other known service, and never prints a key. Input typed or pasted but not read when the setup closes is discarded, so it never reaches the shell.
- **Cloud-off lock.** `disable_cloud = true` in `~/.meow/ai.toml` (`meow setup --cloud-off`) keeps cloud AI off even with `OPENROUTER_API_KEY` or `ANTHROPIC_API_KEY` exported. If `ai.toml` cannot be read, cloud AI stays off.
- **Daily usage record.** `~/.meow/ai-usage` is private and changed under a lock. Each cloud call is set aside at its highest cost before it is sent and settled to its real cost after. A call cut off when the session ends is settled to its input cost. If the file cannot be read, cloud AI is off; if a record cannot be written, the call is refused.

Limits:

- Dotted numbers of 2 or 3 parts, each 255 or less (`52.12.7`), are read as versions, not addresses, in prose. Commands holding them are still caught.
- A one-word name learnt from one host's banner is sent as a bare word in another host's request, unless it stands as a host there.
- A name with an advisory-shaped suffix (`FILESRV-2024-001`) is left in clear.
- A research call that the API finishes after meow stopped waiting may be billed above the amount settled.

## Map, HUD and location

- The map server and the HUD connection listen on `127.0.0.1` only, check `Host` and `Origin`, and need the session token.
- The browser opener gets the path of a private page, never the URL with the token, because program arguments are visible to every user.
- A map page sends nothing, and shows nothing it receives, until the session proves itself with the page key. A tab reloaded after its session ended gets an HTTP 401 page with no secrets.
- When a session ends in order, `runtime.json` (with the token) and the map's opener page are removed.
- The location lookup (`https://ipinfo.io/json` by default) runs only while the map is open, then again only when the network changes. It carries no parameters and never runs while a VPN carries all traffic.
- Map pictures come from EOX: at most six around the estimate, served to the page by meow.
- Both addresses must be `https://`, and redirects are not followed.
- `[location] enabled = false` turns both off, and `map = false` turns off the pictures.
- Scanned hosts are placed only from the offline DB-IP database. Their addresses are never sent anywhere for this.

## Supported versions

Only the latest commit on `main` and the latest tagged release get fixes. Update with `meow update`.

## Using meow responsibly

meow drives network scanners. Use `meow recon` only on systems you own or are explicitly authorized to test. The default `light` mode sends nothing to any target.
