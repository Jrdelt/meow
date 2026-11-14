Download the file for your computer below.

**Mac:** `meow-<version>-macos-arm64.pkg` (Apple Silicon: M1 and newer) or
`meow-<version>-macos-x86_64.pkg` (Intel). Double-click it; macOS warns that
the package is from an unidentified developer, so the first time right-click
it, choose **Open**, then **Open** again. meow is installed to
`/usr/local/bin/meow`.

**Linux / Kali:** `meow-<version>-linux-x86_64.tar.gz` (or `-linux-arm64`):

    tar -xzf meow-*-linux-*.tar.gz
    sudo install -m 0755 meow /usr/local/bin/meow

**Windows:** `meow-<version>-windows-x86_64.zip`: unzip it and put `meow.exe`
in a folder on your PATH.

Then run `meow`. The first time, it offers to install the scanners `meow
recon` uses (nmap, katana, feroxbuster), the wordlist and the location
database. Later, `meow update` downloads and installs newer releases by
itself. Each file has a `.sha256` file next to it to check the download.
