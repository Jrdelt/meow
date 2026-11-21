### What's New in `meow` v0.2.5

- **Recon progress in the map and the HUD.** A bar shows each stage as done, running, waiting, skipped, failed or stopped, with the running stage's name, nmap's own percent and time left, and the time so far. A finished recon keeps its stage names, so you can see what ran.
- **Closing the terminal ends the recon cleanly.** The running stage stops and every tool it started (nmap, katana, feroxbuster, traceroute) is killed; stages already done keep their results; stages that had not started are dropped. The next start says once where it stopped. A recon is never carried into a later session.
- **No leftover scanners.** If meow is killed outright, a small watchdog stops its tools; if both die, the next start finds and stops them (only processes meow started, matched by their exact start time).
- **Simpler screens.**
  - Setup: one question per step, one short line per choice, details behind `?` (about 55% fewer words; fits 80x24).
  - HUD: a numbers-first header (`acme · mild · 3 hosts · 4 CVEs · 1 exploited`), only known facts, only keys that work, `?` for the rest.
  - Map: one "Findings" card per host, short labels on the drawing, no "unknown" rows (about 45% fewer words).

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
