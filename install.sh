#!/bin/sh
# Builds and installs meow with everything it uses, first installing what
# is missing: a C compiler, the Rust toolchain, the scanners `meow recon`
# drives (nmap, katana, feroxbuster) and a wordlist for the directory stage.
# For macOS and Linux. `meow update` pulls the latest code and runs this again.
#
#   ./install.sh               show the plan, ask once, then do it
#   ./install.sh --yes         do not ask
#   ./install.sh --dry-run     only show what would be done
#   ./install.sh --no-tools    leave out the scanners and the wordlist
#   ./install.sh --tools-only  only the scanners and the wordlist (what
#                              `meow recon` and `meow tools` run)
#
# Nothing is installed that is already present, so it is safe to run again.

set -eu

MIN_RUST_MINOR=88
RUSTUP_URL="https://sh.rustup.rs"
# The SecLists web-content wordlist (about 4,700 entries), pinned to an immutable commit.
WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/f68bef9c49622d9f76c7cae7a8c2dae24da2d236/Discovery/Web-Content/common.txt"
WORDLIST_SHA256="${MEOW_WORDLIST_SHA256:-78e7be2efbbbfef8ef1eb02116189087fd9205ef2bf997e68b29b45bfeb8ab52}"
KATANA_GO="github.com/projectdiscovery/katana/cmd/katana@v1.1.2"

rustup_init=""
wordlist_part=""
cleanup() {
    [ -n "$rustup_init" ] && rm -f "$rustup_init"
    [ -n "$wordlist_part" ] && rm -f "$wordlist_part"
    return 0
}
trap cleanup EXIT INT TERM

say() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die() {
    warn "$*"
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

assume_yes=no
dry_run=no
with_tools=yes
tools_only=no
for arg in "$@"; do
    case "$arg" in
    -y | --yes) assume_yes=yes ;;
    -n | --dry-run) dry_run=yes ;;
    --with-tools) with_tools=yes ;;
    --no-tools) with_tools=no ;;
    --tools-only) tools_only=yes ;;
    -h | --help)
        sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *) die "Unknown option: $arg (try --help)" ;;
    esac
done

# The tools need no source tree: meow runs this script from its own copy.
if [ "$tools_only" = no ]; then
    cd "$(dirname "$0")"
    if [ ! -f Cargo.toml ] || ! grep -q '^name = "meow"' Cargo.toml; then
        die "Run this script from the meow repository (Cargo.toml not found next to it)."
    fi
fi

case "$(uname -s)" in
Darwin) os=macos ;;
Linux) os=linux ;;
*)
    die "This installer supports macOS and Linux. On Windows, run .\install.ps1 in PowerShell (or install Rust from https://rustup.rs and the Visual Studio C++ build tools, then run: cargo install --path . --locked)"
    ;;
esac

original_path=$PATH
cargo_home=${CARGO_HOME:-$HOME/.cargo}
# A toolchain installed by rustup may not be on PATH in this shell yet.
if ! have cargo && [ -f "$cargo_home/env" ]; then
    # shellcheck disable=SC1091
    . "$cargo_home/env"
fi

# --- What is available to install with -----------------------------------

pm=""
if [ "$os" = linux ]; then
    for candidate in apt-get dnf yum pacman zypper apk; do
        if have "$candidate"; then
            pm=$candidate
            break
        fi
    done
elif have brew; then
    pm=brew
fi

sudo=""
if [ "$os" = linux ] && [ "$(id -u)" -ne 0 ]; then
    sudo=sudo
fi

pm_install() {
    if [ "${MEOW_NO_SUDO:-0}" = 1 ] && [ -n "$sudo" ]; then
        return 1
    fi
    case "$pm" in
    apt-get)
        # $sudo is deliberately unquoted: it is empty when running as root.
        $sudo apt-get update -qq && $sudo apt-get install -y "$@"
        ;;
    dnf | yum) $sudo "$pm" install -y "$@" ;;
    pacman) $sudo pacman -S --needed --noconfirm "$@" ;;
    zypper) $sudo zypper --non-interactive install "$@" ;;
    apk) $sudo apk add "$@" ;;
    brew) brew install "$@" ;;
    *) return 1 ;;
    esac
}

compiler_packages() {
    case "$pm" in
    apt-get) echo "build-essential" ;;
    pacman) echo "base-devel" ;;
    apk) echo "build-base" ;;
    *) echo "gcc" ;;
    esac
}

rust_minor() {
    rustc --version 2>/dev/null | sed -n 's/^rustc 1\.\([0-9][0-9]*\).*/\1/p'
}

# --- What is missing ------------------------------------------------------

need_compiler=no
if [ "$os" = macos ]; then
    # /usr/bin/cc exists on every Mac but only works once the Command Line
    # Tools (or Xcode) are installed.
    xcode-select -p >/dev/null 2>&1 || need_compiler=yes
elif ! have cc && ! have gcc && ! have clang; then
    need_compiler=yes
fi

need_rust=no
update_rust=no
found_rust=""
if ! have cargo || ! have rustc; then
    need_rust=yes
else
    found_rust=$(rust_minor)
    if [ -z "$found_rust" ] || [ "$found_rust" -lt "$MIN_RUST_MINOR" ]; then
        if have rustup; then
            update_rust=yes
        else
            # Rust from a distribution package that is too old: rustup
            # installs a current toolchain alongside it.
            need_rust=yes
        fi
    fi
fi

if [ "$tools_only" = yes ]; then
    with_tools=yes
    need_compiler=no
    need_rust=no
    update_rust=no
fi

missing_tools=""
for tool in nmap katana feroxbuster; do
    have "$tool" || missing_tools="$missing_tools $tool"
done
missing_tools=${missing_tools# }

# A wordlist anywhere meow looks for one (see queue.rs) is enough.
meow_home=${MEOW_HOME:-$HOME/.meow}
wordlist_dir="$meow_home/wordlists"
need_wordlist=yes
for list in \
    /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    /usr/share/seclists/Discovery/Web-Content/common.txt \
    /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
    /usr/share/wordlists/dirb/common.txt \
    /usr/share/dirb/wordlists/common.txt \
    /opt/homebrew/share/seclists/Discovery/Web-Content/common.txt \
    /usr/local/share/seclists/Discovery/Web-Content/common.txt \
    /home/linuxbrew/.linuxbrew/share/seclists/Discovery/Web-Content/common.txt \
    "$wordlist_dir"/*.txt; do
    if [ -f "$list" ]; then
        need_wordlist=no
        break
    fi
done
[ "$with_tools" = yes ] || need_wordlist=no

need_fetcher=no
if [ "$need_rust$need_wordlist" != nono ] && ! have curl && ! have wget; then
    need_fetcher=yes
fi

fetch() {
    if have curl; then
        curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"
    else
        wget --https-only -q -O "$2" "$1"
    fi
}

verify_sha256() {
    file=$1
    expected=$2
    if have sha256sum; then
        actual=$(sha256sum "$file" | sed 's/ .*//')
    elif have shasum; then
        actual=$(shasum -a 256 "$file" | sed 's/ .*//')
    elif have openssl; then
        actual=$(openssl dgst -sha256 "$file" | sed 's/.*= //')
    else
        warn "No SHA-256 tool (sha256sum, shasum, openssl) found; cannot verify wordlist digest."
        return 1
    fi
    [ "$actual" = "$expected" ]
}

# --- The plan -------------------------------------------------------------

printf '%s\n' \
    '   /\_/\    _ __ ___   ___  _____      __' \
    "  ( o.o )  | '_ \` _ \\ / _ \\/ _ \\ \\ /\\ / /" \
    '   > ^ <   | | | | | |  __/ (_) \ V  V /' \
    '  /|   |\  |_| |_| |_|\___|\___/ \_/\_/' \
    ' (_|   |_)  local security triage & topology shell' \
    ''
say "meow installer for $os"
echo "This will:"
if [ "$need_compiler" = yes ]; then
    if [ "$os" = macos ]; then
        echo "  - install the Xcode Command Line Tools (the C compiler); macOS shows a dialog to confirm"
    else
        echo "  - install a C compiler with ${pm:-your package manager}: $(compiler_packages)${sudo:+ (uses sudo)}"
    fi
fi
if [ "$need_fetcher" = yes ]; then
    echo "  - install curl with ${pm:-your package manager}${sudo:+ (uses sudo)}"
fi
if [ "$need_rust" = yes ]; then
    echo "  - install the Rust toolchain with rustup into $cargo_home and ~/.rustup"
    echo "    (without modifying your shell profile; add $cargo_home/bin to PATH)"
fi
if [ "$update_rust" = yes ]; then
    echo "  - update Rust to the latest stable (meow needs 1.$MIN_RUST_MINOR or newer; found 1.$found_rust)"
fi
[ "$tools_only" = yes ] || echo "  - build meow in release mode and install it to $cargo_home/bin/meow"
if [ "$with_tools" = yes ] && [ -n "$missing_tools" ]; then
    echo "  - install the scanners meow recon drives: $missing_tools"
    echo "    (with ${pm:-a package manager}${sudo:+, using sudo}; feroxbuster can also be built with cargo, katana with go)"
fi
if [ "$need_wordlist" = yes ]; then
    echo "  - download the SecLists web-content wordlist from GitHub to $wordlist_dir/common.txt"
fi
if [ "$tools_only" = no ] && [ "$need_compiler$need_rust$update_rust" = "nonono" ]; then
    echo "The C compiler and Rust are already installed."
fi
if [ "$tools_only" = yes ] && [ -z "$missing_tools" ] && [ "$need_wordlist" = no ]; then
    say "Every tool meow recon uses is already installed."
    exit 0
fi

if [ "$dry_run" = yes ]; then
    say "Dry run: nothing was changed."
    exit 0
fi

# Problems that would stop the install half-way are reported before it
# starts. Only the wordlist needing curl is not one: it is skipped instead.
must_fetch=no
[ "$need_fetcher$need_rust" = yesyes ] && must_fetch=yes
if [ "$os" = linux ] && [ "$need_compiler$must_fetch" != "nono" ]; then
    [ -n "$pm" ] || die "No supported package manager found. Install a C compiler (gcc) and curl yourself, then rerun this script."
    if [ -n "$sudo" ] && ! have sudo; then
        die "Installing packages needs root. Rerun this script as root, or install $(compiler_packages) and curl yourself."
    fi
fi

if [ "$assume_yes" != yes ]; then
    [ -t 0 ] || die "Not running in a terminal, so I cannot ask. Rerun with --yes to proceed."
    printf 'Proceed? [Y/n] '
    read -r answer
    case "$answer" in
    n | N | no | No | NO) die "Cancelled; nothing was changed." ;;
    esac
fi

# --- Prerequisites --------------------------------------------------------

if [ "$need_compiler" = yes ]; then
    if [ "$os" = macos ]; then
        say "Installing the Xcode Command Line Tools: confirm the dialog macOS shows"
        xcode-select --install >/dev/null 2>&1 || true
        waited=0
        until xcode-select -p >/dev/null 2>&1; do
            sleep 5
            waited=$((waited + 5))
            if [ "$waited" -ge 3600 ]; then
                die "The Command Line Tools did not finish installing. Run 'xcode-select --install' yourself, then rerun this script."
            fi
        done
        say "Command Line Tools installed"
    else
        say "Installing a C compiler"
        # Word splitting is wanted: the list may hold several packages.
        # shellcheck disable=SC2046
        pm_install $(compiler_packages) || die "Could not install the C compiler."
    fi
fi

if [ "$need_fetcher" = yes ]; then
    say "Installing curl"
    if ! pm_install curl; then
        [ "$must_fetch" = no ] || die "Could not install curl."
        warn "Could not install curl, so the wordlist is not downloaded. Put any .txt wordlist in $wordlist_dir and meow will use it."
        need_wordlist=no
    fi
fi

if [ "$need_rust" = yes ]; then
    say "Installing Rust with rustup"
    rustup_init=$(mktemp)
    # Downloaded to a file first: a failed download must not run as an
    # empty script.
    if have curl; then
        curl --proto '=https' --tlsv1.2 -sSf -o "$rustup_init" "$RUSTUP_URL" ||
            die "Could not download the Rust installer from $RUSTUP_URL."
    else
        wget --https-only -q -O "$rustup_init" "$RUSTUP_URL" ||
            die "Could not download the Rust installer from $RUSTUP_URL."
    fi
    sh "$rustup_init" -y --profile minimal --no-modify-path || die "The Rust installer failed."
    # shellcheck disable=SC1091
    . "$cargo_home/env"
fi

if [ "$update_rust" = yes ]; then
    say "Updating Rust"
    rustup update stable || die "Could not update Rust."
fi

if [ "$tools_only" = no ]; then
    have cargo || die "Rust is installed but cargo is not on PATH. Open a new terminal and rerun this script."
    now_rust=$(rust_minor)
    if [ -z "$now_rust" ] || [ "$now_rust" -lt "$MIN_RUST_MINOR" ]; then
        die "meow needs Rust 1.$MIN_RUST_MINOR or newer, but this is $(rustc --version 2>/dev/null || echo unknown). Run: rustup update stable"
    fi
fi

# --- meow itself ----------------------------------------------------------

if [ "$tools_only" = no ]; then
    say "Building meow (release). The first build takes a few minutes."
    cargo install --path . --locked || die "The build failed. The messages above say why."

    installed="$cargo_home/bin/meow"
    [ -x "$installed" ] || die "The build finished but $installed is missing."
    say "Installed $("$installed" --version) at $installed"
fi

# --- Scanners and wordlist -----------------------------------------------
# A tool that cannot be installed is reported and skipped: meow works
# without it, and `meow recon` says which stage it leaves out.

install_tool() {
    tool=$1
    if [ -n "$pm" ] && pm_install "$tool"; then
        return 0
    fi
    case "$tool" in
    feroxbuster)
        have cargo || return 1
        say "Building feroxbuster with cargo (a few minutes)"
        cargo install feroxbuster --locked
        ;;
    katana)
        if have go; then
            say "Building katana with go"
            go install "$KATANA_GO" && say "katana is in $(go env GOPATH)/bin; that folder must be on PATH"
        else
            return 1
        fi
        ;;
    *) return 1 ;;
    esac
}

if [ "$with_tools" = yes ] && [ -n "$missing_tools" ]; then
    for tool in $missing_tools; do
        say "Installing $tool"
        install_tool "$tool" && continue
        if [ "$os" = macos ] && [ -z "$pm" ]; then
            warn "Could not install $tool: Homebrew is not installed. Install it from https://brew.sh, then run ./install.sh again."
        elif [ -z "$pm" ]; then
            warn "Could not install $tool: no supported package manager found. Install it yourself."
        elif [ "$tool" = katana ]; then
            warn "Could not install katana: $pm has no package and Go is not installed. With Go: go install $KATANA_GO"
        else
            warn "Could not install $tool with $pm."
        fi
    done
fi

if [ "$need_wordlist" = yes ]; then
    say "Downloading the wordlist"
    mkdir -p "$wordlist_dir"
    wordlist_part=$(mktemp "$wordlist_dir/.common.txt.XXXXXX")
    if fetch "$WORDLIST_URL" "$wordlist_part" &&
        [ -s "$wordlist_part" ] &&
        ! grep -qi '<html' "$wordlist_part" &&
        verify_sha256 "$wordlist_part" "$WORDLIST_SHA256"; then
        mv "$wordlist_part" "$wordlist_dir/common.txt"
        wordlist_part=""
        say "Wordlist saved to $wordlist_dir/common.txt"
    else
        rm -f "$wordlist_part"
        wordlist_part=""
        warn "Could not download the wordlist from $WORDLIST_URL (or its SHA-256 digest did not match). Put any .txt wordlist in $wordlist_dir and meow will use it."
    fi
fi

if [ "$tools_only" = yes ]; then
    say "Done."
    exit 0
fi

case ":$original_path:" in
*":$cargo_home/bin:"*) say "Ready. Run 'meow' for the interactive setup GUI, or 'meow <name>' to open a session" ;;
*)
    say "Ready. Open a new terminal (or run: . \"$cargo_home/env\"), then run 'meow' for the interactive setup GUI or 'meow <name>'"
    ;;
esac
