### What's New in `meow` v0.2.1

- **Map: easier to read.**
  - **Ports** card shows each port on one line: number, state (open, filtered or closed), service and version. The separate versions section is gone; open ports come first.
  - **Notices** card is folded by default and shows a count; click it to open.
  - **Traceroute hops** show where each hop is (city, region, country), its network and ASN, reverse DNS, address type, round-trip time and the latency the hop adds (long links are flagged). The last hop is marked as the target, with its open ports and a button to open the host.
  - **Server Status** card on each host: whether a scan has seen it up, the last scan result, known open ports, and a **Check now** button that tries a few known ports (not in light mode).
- **Cloud triage in two parts:** a **Red Team** plan for an authorized penetration test (what to look at first, how to verify it without harm, what evidence to keep) and a **Blue Team** plan for a SOC (patches and hardening, detection, monitoring and response), shown side by side on the map.
- **Security fixes from a full audit:**
  - Names on a private network (and reverse lookups) are no longer sent to public DNS-over-HTTPS or to crt.sh; cloud metadata addresses are refused.
  - Downloads from NVD, CISA KEV, OSV and map tile servers have size limits; error messages no longer carry request URLs.
  - The map no longer keeps its session key in a cookie; a reload still works in the same tab.
  - `meow update` only fast-forwards from the configured remote; root-owned installs are replaced by renaming a full copy.
  - `install.sh` refuses to run from a pipe and limits download sizes.
  - Terminal filter: long OSC strings and odd DEC modes can no longer hide or stop capture; long lines of colons cost no extra time.
  - Recon stages stop when the mode changes mid-stage.

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
