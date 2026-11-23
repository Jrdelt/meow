### What's New in `meow` v0.2.7

- **New look for the live map.** A dark theme with one top bar for the session, its counts and its status. The topology is drawn dark too: each device sits on a plate, a host with CVEs is ringed amber (or red when one is known exploited, critical or high), and the selected device is outlined in lime.
- **Map: back to all hosts.** An **All hosts** button beside the selected host's name, and **Esc**, bring the host list back and put the keyboard on it. Before, only a click on an empty part of the drawing did.
- **HUD and setup read in every terminal theme.** Secondary text, idle borders, panel titles and the key line no longer vanish in themes such as Solarized Dark. The selected row and the current setup step are black on lime.
- **Security: `url` 2.5.9** fixes RUSTSEC-2026-0592, a stack overflow in `Url::origin()` on nested `blob:` URLs.
- **Dependencies:** cc 1.11.2, clap 4.6.8, petgraph 0.8, rusqlite 0.43, sha2 0.11.
- **Fuzzing:** four cargo-fuzz targets cover the parsers and the C11 terminal filter, the C code under AddressSanitizer. They run weekly in CI.
- **Docs:** a demo, map screenshots and a sample report in the README; [architecture](https://github.com/Jrdelt/meow/blob/main/docs/ARCHITECTURE.md) and [threat model](https://github.com/Jrdelt/meow/blob/main/docs/THREAT_MODEL.md).

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
