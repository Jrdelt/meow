#!/bin/sh
# Builds and installs meow, first installing whatever it needs that is
# missing: a C compiler and the Rust toolchain. For macOS and Linux.
#
#   ./install.sh               show the plan, ask once, then do it
#   ./install.sh --yes         do not ask
#   ./install.sh --dry-run     only show what would be done
#   ./install.sh --with-tools  also install the scanners that `meow recon`
#                              drives (nmap, katana, feroxbuster) where a
#                              package manager offers them
#
# Nothing is installed that is already present, so it is safe to run again.

set -eu

MIN_RUST_MINOR=88
RUSTUP_URL="https://sh.rustup.rs"

say() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die() {
    warn "$*"
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

assume_yes=no
dry_run=no
with_tools=no
for arg in "$@"; do
    case "$arg" in
    -y | --yes) assume_yes=yes ;;
    -n | --dry-run) dry_run=yes ;;
    --with-tools) with_tools=yes ;;
    -h | --help)
        sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *) die "Unknown option: $arg (try --help)" ;;
    esac
done

cd "$(dirname "$0")"
if [ ! -f Cargo.toml ] || ! grep -q '^name = "meow"' Cargo.toml; then
    die "Run this script from the meow repository (Cargo.toml not found next to it)."
fi

case "$(uname -s)" in
Darwin) os=macos ;;
Linux) os=linux ;;
*)
    die "This installer supports macOS and Linux. On Windows, install Rust from https://rustup.rs and the Visual Studio C++ build tools, then run: cargo install --path . --locked"
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

need_fetcher=no
if [ "$need_rust" = yes ] && ! have curl && ! have wget; then
    need_fetcher=yes
fi

missing_tools=""
for tool in nmap katana feroxbuster; do
    have "$tool" || missing_tools="$missing_tools $tool"
done
missing_tools=${missing_tools# }

# --- The plan -------------------------------------------------------------

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
    echo "    (rustup adds $cargo_home/bin to PATH in your shell profile)"
fi
if [ "$update_rust" = yes ]; then
    echo "  - update Rust to the latest stable (meow needs 1.$MIN_RUST_MINOR or newer; found 1.$found_rust)"
fi
echo "  - build meow in release mode and install it to $cargo_home/bin/meow"
if [ "$with_tools" = yes ] && [ -n "$missing_tools" ]; then
    echo "  - try to install with ${pm:-a package manager}: $missing_tools"
fi
if [ "$need_compiler$need_fetcher$need_rust$update_rust" = "nononono" ]; then
    echo "The C compiler and Rust are already installed; nothing else is needed."
fi

if [ "$dry_run" = yes ]; then
    say "Dry run: nothing was changed."
    exit 0
fi

# Problems that would stop the install half-way are reported before it starts.
if [ "$os" = linux ] && [ "$need_compiler$need_fetcher" != "nono" ]; then
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
    pm_install curl || die "Could not install curl."
fi

if [ "$need_rust" = yes ]; then
    say "Installing Rust with rustup"
    rustup_init=$(mktemp)
    trap 'rm -f "$rustup_init"' EXIT
    # Downloaded to a file first: a failed download must not run as an
    # empty script.
    if have curl; then
        curl --proto '=https' --tlsv1.2 -sSf -o "$rustup_init" "$RUSTUP_URL" ||
            die "Could not download the Rust installer from $RUSTUP_URL."
    else
        wget -q -O "$rustup_init" "$RUSTUP_URL" ||
            die "Could not download the Rust installer from $RUSTUP_URL."
    fi
    sh "$rustup_init" -y --profile minimal || die "The Rust installer failed."
    # shellcheck disable=SC1091
    . "$cargo_home/env"
fi

if [ "$update_rust" = yes ]; then
    say "Updating Rust"
    rustup update stable || die "Could not update Rust."
fi

have cargo || die "Rust is installed but cargo is not on PATH. Open a new terminal and rerun this script."
now_rust=$(rust_minor)
if [ -z "$now_rust" ] || [ "$now_rust" -lt "$MIN_RUST_MINOR" ]; then
    die "meow needs Rust 1.$MIN_RUST_MINOR or newer, but this is $(rustc --version 2>/dev/null || echo unknown). Run: rustup update stable"
fi

# --- meow itself ----------------------------------------------------------

say "Building meow (release). The first build takes a few minutes."
cargo install --path . --locked || die "The build failed. The messages above say why."

installed="$cargo_home/bin/meow"
[ -x "$installed" ] || die "The build finished but $installed is missing."
say "Installed $("$installed" --version) at $installed"

# --- Optional scanners ----------------------------------------------------

if [ "$with_tools" = yes ] && [ -n "$missing_tools" ]; then
    if [ -z "$pm" ]; then
        if [ "$os" = macos ]; then
            warn "Homebrew is not installed, so the scanners were not installed. Install it from https://brew.sh, then run: brew install $missing_tools"
        else
            warn "No supported package manager found; install these yourself: $missing_tools"
        fi
    else
        for tool in $missing_tools; do
            say "Installing $tool"
            if ! pm_install "$tool"; then
                case "$tool" in
                katana) warn "$pm has no katana package. With Go installed: go install github.com/projectdiscovery/katana/cmd/katana@latest" ;;
                feroxbuster) warn "$pm has no feroxbuster package. Alternative: cargo install feroxbuster" ;;
                *) warn "Could not install $tool with $pm." ;;
                esac
            fi
        done
    fi
elif [ -n "$missing_tools" ]; then
    say "Optional scanners not found: $missing_tools. meow works without them; rerun with --with-tools to install them."
fi

case ":$original_path:" in
*":$cargo_home/bin:"*) say "Ready. Start with: meow <name>" ;;
*)
    say "Ready. Open a new terminal (or run: . \"$cargo_home/env\"), then start with: meow <name>"
    ;;
esac
