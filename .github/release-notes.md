### What's New in `meow` v0.2.8

- **Security: `meow update` from source checks folders above.** On macOS and Linux, before any fetch, it refuses a clone in a folder another user owns or can write to (even /tmp, even via a relative `--source`), and a `~/.meow` another user could move.
- **Security: no planted AI answers.** A session that came with a cloned or copied folder, or whose files changed outside meow, loses its cached AI answers and CVE lookups.
- **`meow update` from source:** links to cargo settings files (as dotfile managers make) and common git settings now pass. Its build folder gets a `CACHEDIR.TAG` and, on macOS, is left out of Time Machine. On Windows, a clone others can change is refused with the `icacls` command that makes it yours alone.
- **Git checks:** at exit meow waits for a running one and no longer wrongly drops your shell history. Unreadable repositories get one note; a project's own `Meow/` on Linux gets no session-file warnings.
- **Rescans:** a port a rescan finds closed or filtered leaves the open list; its CVEs move to a port with the same software, or go. Only SYN, connect, UDP and SCTP INIT scans the host answered close a port.
- **Recon results:** a guessed JS CVE goes once the page shows only another version. The map shows the latest traceroute. `waf-cdn` and `asn` add no extra hosts.
- **Smaller recon fixes:** `meow tools` and `install.sh` check for traceroute and add it on Linux. A name with no address says why instead of suggesting `-Pn`. `meow list` and `meow add` count only map hosts.
- **AI replies fill in more.** Lines naming a common file, package, setting, size or port (`my.cnf`, `22/tcp`) get your target's name and address back. Code, commands and lines naming other hosts stay masked.
- **Daily AI cap:** a call blocked only by another session's running call says so. Cap changes in `config.toml` apply at once, and while it cannot be read, cloud AI is off. A killed session's call counts only its input.
- **Map:** a large session no longer shows "session ended" while its state loads. Reports download only while connected. Screen readers skip the avatar letter and announce error messages.
- **HUD:** reads big sessions (up to 128 MiB of state) or says it cannot. An AI reply cut off when the session ends shows as stopped, here and on the map.
- **Docs:** the [threat model](https://github.com/Jrdelt/meow/blob/main/docs/THREAT_MODEL.md)'s outbound table lists what `meow tools` and `meow update` download, some without asking.

---

### Installation

Download the file for your computer below.

**Mac:** `meow-<version>-macos-arm64.pkg` (Apple Silicon: M1 and newer) or
`meow-<version>-macos-x86_64.pkg` (Intel). Double-click it; because it is not
signed with a paid Apple Developer certificate, macOS blocks it the first time.
On macOS 15 (Sequoia) and newer, open **System Settings → Privacy & Security**,
scroll down, and click **Open Anyway** (on macOS 14 and earlier, Control-click
the `.pkg` and choose **Open → Open**). `meow` is installed to
`/usr/local/bin/meow`.

**Linux / Kali:** `meow-<version>-linux-x86_64.tar.gz` (or `-linux-arm64`):

    sha256sum -c meow-*-linux-*.tar.gz.sha256
    tar -xzf meow-*-linux-*.tar.gz
    sudo install -m 0755 meow /usr/local/bin/meow

**Windows:** `meow-<version>-windows-x86_64.zip` (x64, or runs under emulation
on ARM64): verify against `.sha256` with `Get-FileHash`, unzip it, and place
`meow.exe` in a folder on your `PATH`.

Then run `meow`. On first run, the interactive Cat Setup wizard configures your
mode and privacy preferences and `meow tools` offers to install the optional
scanners (`nmap`, `katana`, `feroxbuster`), wordlist, and offline DB-IP Lite
location database. Later, `meow update` downloads a newer release, checks
its SHA-256 and installs it.
