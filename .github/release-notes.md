### What's New in `meow` v0.2.6

- **Security (high): a cloned or unpacked git folder can no longer run its own programs.** meow's git check now reaches no remote, ignores the folder's `core.sshCommand` and credential helpers, and never asks for a password.
- **Security: safer `meow update` from source.** It checks the clone before git reads it, refuses cargo settings above it that others can change, and builds in a private `~/.meow/build`.
- **Security: AI replies keep placeholders in code and commands.** A one-word name from a host's certificate or banner is masked everywhere in that host's requests. Elsewhere, only where it stands as a host.
- **Security: a `git pull` during a session is noticed.** The next start drops the shell history and last folder.
- **Security: stricter folder checks,** with the reason in each refusal.
- **Security: setup refuses a key meant for the other service.**
- **New: `meow setup --cloud-off`** (entry `6` in `--plain`) turns cloud AI off and removes the key.
- **One daily cloud cap for all sessions,** kept in `~/.meow/ai-usage`.
- **Recon:** `trace` runs after `ports` and records only real hops. `-6` and `-Pn` reach every scan.
- **DNS:** split DNS is followed on macOS and Windows. A failed lookup says `could not be checked`. `mail-dns` test names no longer say "meow".
- **CVEs and report:** fix lines name every port, rescans drop old versions, and the report counts only hosts on the map.
- **Map:** a connection badge and a 2000-byte note limit.
- **Clean endings:** `kill -INT`, `Ctrl-C` with piped output and a closed Windows console end the session in order.
- **Moved project folders** keep their session and history.
- **Releases:** pre-releases are never marked Latest or installed by `meow update`. Nothing is published until the tests pass.

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
