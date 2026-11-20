### What's New in `meow` v0.2.4

A security release: a third full audit found 31 issues (none high), and all are fixed.

- **Session folders.** meow refuses a folder that another account can change (a shared group such as macOS `staff`, or an access list), and checks again each time a session is opened. If a `git pull` or an unpacked archive replaced a session's files, meow says so, drops that session's shell history and asks before resuming its scans.
- **Privacy with cloud AI.** Active Directory and NetBIOS names, and addresses written inside URLs and file names, are now masked. A reply gets back only the triaged host's own address and names; secrets and other hosts' values stay as placeholders. The "is this local server mine?" check now works on macOS and Windows.
- **DNS.** No fixed public resolvers any more, and DNS-over-HTTPS is never asked about an internal target. The target's address is the one your system gives, as for nmap (so `/etc/hosts` counts).
- **Imports and CVEs.** Host names in an imported nmap file can no longer move another host's notes and CVEs. CVE lookups started by terminal text are capped at 256 per session and wait behind those of `meow recon`.
- **Map.** A crafted AI reply can no longer freeze the tab, and a page on another local port can no longer detect a running session.
- **Updates and releases.** `meow update --source` accepts only the git settings a plain clone has and refuses submodules. Each platform's download is now checked against the job that built it.

Things you may notice:

- A session in a folder other accounts can write to is refused; use `meow <name> --home` or fix the folder's permissions.
- `meow update --source` may refuse a checkout whose `.git/config` has extra settings; the message names the setting.

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
