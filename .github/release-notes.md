### What's New in `meow` v0.2.6

- **Security (high): a downloaded or cloned git folder can no longer run its own program.** Opening a session inside such a folder could run a program the folder named. Now meow's git check runs only on the top repository, reaches no remote, ignores the folder's `core.sshCommand` and credential helpers, never asks for a password, and stops after 3 s.
- **Security: safer `meow update` from source.** It checks the clone before git first reads it, also with `--check`. It refuses `.cargo` or `rust-toolchain` settings above the clone that others can change, and builds in a private `~/.meow/build` instead of the temp folder. On Windows it checks the owner and access list of every tracked file, and `install.ps1` checks `.cargo` too.
- **Security: AI replies keep placeholders in code and commands.** The host's own address and names come back only in prose. Words like `cve` are never taken for host names, and one-word names from certificates and banners are masked per host.
- **Security: one daily cloud cap for all sessions.** `max_daily_usd` and `max_daily_calls` now count every session together, per local day, in `~/.meow/ai-usage`. If that file cannot be read, cloud AI stays off.
- **Security: session files and keys.** A `git pull` during a session is now noticed, and the next start drops the shell history and last folder. Folder checks are stricter and name the reason and the fix. Setup refuses a key meant for the other service, and `mail-dns` test names no longer say "meow".
- **New: `meow setup --cloud-off`** (and entry `6` in `meow setup --plain`) turns cloud AI off and removes the stored key.
- **Recon: `trace` now runs after `ports`.** It traces the address nmap scanned and records only real hops. nmap scans a name at the address the `dns` stage found, so all findings land on one host, and `-6` or `-Pn` reach every scan.
- **DNS: clearer answers.** Split DNS on macOS and Windows is followed, and up to 3 servers are asked. A failed lookup says `could not be checked` instead of "no record".
- **CVEs and report.** Software is looked up once per host, fix lines name every port it runs on, and a rescan drops old versions. The report counts only scanned hosts.
- **Map.** A connection badge (`live`, `reconnecting…`, `session closed`, `session ended`), a 2000-byte note limit with a counter, and at most 24 devices in a row (`+N more in Hosts`).
- **Clean endings.** `kill -INT`, `Ctrl-C` with piped output, and closing a Windows console window now end the session in order. A moved project folder keeps its session and history.
- **Releases.** Pre-releases are never marked Latest, and `meow update` skips them. Nothing is published until the tests pass.

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
location database. Later, `meow update` downloads, SHA-256 verifies, and
installs newer releases automatically.
