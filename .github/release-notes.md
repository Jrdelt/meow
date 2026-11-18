### What's New in `meow` v0.2.2

- **Three new recon stages (17 in all):**
  - **`mail-dns`** grades a domain's mail and DNS protection A–F (SPF, DMARC, DKIM, CAA, DNSSEC), names its mail provider, lists services it publishes in DNS (Active Directory, Microsoft 365, SIP…), and spots wildcard DNS so made-up subdomains are not taken for real hosts.
  - **`udp`** checks 23 security-relevant UDP services such as SNMP, IPMI, NTP and DNS (aggressive mode, as root).
  - **`js`** reads the site's own JavaScript for API endpoints and exposed keys. A key goes straight into the Privacy Vault; only a placeholder like `<<SEC_03>>` is ever shown.
- **Web fingerprinting:** `headers` now names the software stack (flagging outdated libraries), checks cookie flags, and grades the security headers A–F.
- **Map:**
  - The drawing fills the window; your location floats in a corner and folds away. **Expand** gives the map the whole window.
  - A selected host's details are in tabs: Overview, Ports, Web & TLS, DNS & Mail, Advisories, Evidence, Notes & AI.
  - Much less text: explanations moved into hover hints, and empty cards are hidden.
- **AI triage and the report** now use the DNS & Mail grade, the stack, cookie and header findings, JS endpoints and exposed keys (by placeholder). New names are masked before anything reaches a cloud model.
- **`recon.skip`** in `config.toml` turns stages off, e.g. `skip = ["udp", "js"]`.
- **Security:** release builds no longer hold a write token; Windows folder permissions and installer downloads are now tested on Windows in CI; cookie values are no longer kept in stored header evidence.
- **Dependencies updated:** dirs 7, getrandom 0.4, ipnetwork 0.21, roxmltree 0.21, signal-hook 0.4, tokio-tungstenite 0.30, toml 1.2.

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
