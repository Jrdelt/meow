### What's New in `meow` v0.2.3

- **Fixed: `exit` could hang and recon stopped halfway.** After a mild or aggressive `meow recon` reached the `waf-cdn` stage, that stage locked up, so the later stages (tls-audit, ssh-audit, cves, crawl, js, dirs) never ran and `exit` waited for ever with the terminal left raw. Recon now runs every stage, and leaving a session always gives your shell back within a few seconds.
- **Sessions are saved where you run meow.** A new session asks where to save it, with the current folder filled in (edit it or press Enter). Sessions live in `./meow/<name>/` there, next to your other files, with a `.gitignore` so git leaves them out. `meow <name>` still reopens a session from any folder, and `meow list` shows where each one lives. `--home` keeps the old `~/.meow/workspaces/` place; sessions made by earlier versions keep working.
- **Each session has its own shell history.** `history`, the up arrow and `Ctrl-R` show only that session's commands, and they stay out of your normal shell history (zsh, bash, PowerShell, fish). macOS Terminal's "Saving session…" no longer runs inside meow.
- **CVEs are shown plainly.** They are grouped by the software and version they were found from, known-exploited first, with severity and the version that fixes them — on the map, in the HUD and in the report. The confirm / false-positive steps and the Evidence tab are gone.

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
