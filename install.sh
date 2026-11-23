#!/bin/sh
# Builds and installs meow with everything it uses, first installing what
# is missing: a C compiler, the Rust toolchain, the scanners `meow recon`
# drives (nmap, katana, feroxbuster, traceroute) and a wordlist for the
# directory stage.
# For macOS and Linux. `meow update` pulls the latest code and runs this again.
#
#   ./install.sh               show the plan, ask once, then do it
#   ./install.sh --yes         do not ask
#   ./install.sh --dry-run     only show what would be done
#   ./install.sh --no-tools    leave out the scanners and the wordlist
#   ./install.sh --no-geo      leave out the location database (the map's
#                              round map then shows only your own place)
#   ./install.sh --tools-only  only the scanners, the wordlist and the
#                              location database (with --no-geo, without it)
#
# Nothing is installed that is already present, so it is safe to run again.

set -eu
unset CDPATH

MIN_RUST_MINOR=89
RUSTUP_URL="https://sh.rustup.rs"
# The SecLists web-content wordlist (about 4,700 entries), pinned to an immutable commit.
WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/0c618cfc28d1e68811b95c61cc9ab05bc10b0a02/Discovery/Web-Content/common.txt"
WORDLIST_SHA256="47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a"
# The most a location database file may weigh, packed and unpacked.
GEO_MAX_PACKED=209715200
GEO_MAX_BYTES=536870912
KATANA_GO="github.com/projectdiscovery/katana/cmd/katana@v1.1.2"
FEROXBUSTER_VERSION="2.11.0"

rustup_init=""
wordlist_part=""
geo_part=""
cleanup() {
    [ -n "$rustup_init" ] && rm -f "$rustup_init"
    [ -n "$wordlist_part" ] && rm -f "$wordlist_part"
    [ -n "$geo_part" ] && rm -f "$geo_part" "$geo_part.gz"
    return 0
}
# Ctrl-C stops the script: without the exit the shell would carry on with
# the next download or package install after cleaning up.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

say() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die() {
    warn "$*"
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

# Strip empty and relative PATH segments so command lookups never run binaries from CWD.
clean_path=""
old_ifs=$IFS
IFS=:
for path_entry in ${PATH:-}; do
    case "$path_entry" in
    /*) clean_path="${clean_path:+$clean_path:}$path_entry" ;;
    esac
done
IFS=$old_ifs
PATH=$clean_path
export PATH

assume_yes=no
dry_run=no
with_tools=yes
tools_only=no
with_geo=yes
for arg in "$@"; do
    case "$arg" in
    -y | --yes) assume_yes=yes ;;
    -n | --dry-run) dry_run=yes ;;
    --with-tools) with_tools=yes ;;
    --no-tools) with_tools=no ;;
    --tools-only) tools_only=yes ;;
    --no-geo) with_geo=no ;;
    -h | --help)
        sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *) die "Unknown option: $arg (try --help)" ;;
    esac
done

# The tools need no source tree: meow runs this script from its own copy.
if [ "$tools_only" = no ]; then
    # Piped into sh ($0 is then "sh"), this would build whatever folder the
    # user happens to be in. It builds only the clone it is part of.
    if [ ! -f "$0" ] || [ "$(basename -- "$0")" != install.sh ]; then
        die "Clone the repository and run ./install.sh from it (piping this script into sh is not supported):
    git clone https://github.com/Jrdelt/meow.git && cd meow && ./install.sh"
    fi
    case "$0" in
    /* | ./* | ../*) script_dir=$(dirname "$0") ;;
    *) script_dir=$(dirname "./$0") ;;
    esac
    cd -- "$script_dir"
    if [ ! -f Cargo.toml ] || ! grep -q '^name = "meow"' Cargo.toml; then
        die "Run this script from the meow repository (Cargo.toml not found next to it)."
    fi
else
    # Nothing below needs the folder the user is in, and rustup's cargo and
    # rustc would obey a rust-toolchain.toml found there.
    cd / || die "Cannot change to the root directory."
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
if [ "$dry_run" = no ] && ! have cargo && [ -f "$cargo_home/env" ] && [ ! -L "$cargo_home/env" ]; then
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
if [ "$tools_only" = yes ]; then
    :
elif [ "$os" = macos ]; then
    # /usr/bin/cc exists on every Mac but only works once the Command Line
    # Tools (or Xcode) are installed.
    xcode-select -p >/dev/null 2>&1 || need_compiler=yes
elif ! have cc && ! have gcc && ! have clang; then
    need_compiler=yes
fi

need_rust=no
update_rust=no
found_rust=""
if [ "$tools_only" = yes ]; then
    : # meow is not rebuilt, so Rust is not looked at.
elif ! have cargo || ! have rustc; then
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
# The route stage (trace) runs traceroute, or tracepath. macOS has its own.
if [ "$os" = linux ] && ! have traceroute && ! have tracepath; then
    missing_tools="$missing_tools traceroute"
fi
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
    /opt/homebrew/share/meow/wordlists/common.txt \
    /usr/local/share/meow/wordlists/common.txt \
    /home/linuxbrew/.linuxbrew/share/meow/wordlists/common.txt \
    /opt/homebrew/share/seclists/Discovery/Web-Content/common.txt \
    /usr/local/share/seclists/Discovery/Web-Content/common.txt \
    /home/linuxbrew/.linuxbrew/share/seclists/Discovery/Web-Content/common.txt \
    "$wordlist_dir"/*.txt; do
    if [ -f "$list" ] && [ ! -L "$list" ] && [ -s "$list" ]; then
        need_wordlist=no
        break
    fi
done
[ "$with_tools" = yes ] || need_wordlist=no

# The location database (DB-IP Lite, CC BY 4.0) puts scanned servers on the
# map without sending their addresses anywhere. DB-IP publishes a new one
# each month; a copy younger than 30 days is kept.
geo_dir="$meow_home/geo"
need_geo=$with_geo
if [ -n "$(find "$geo_dir/dbip-city-lite.mmdb" -mtime -30 2>/dev/null)" ] &&
    [ -n "$(find "$geo_dir/dbip-asn-lite.mmdb" -mtime -30 2>/dev/null)" ]; then
    need_geo=no
fi
if [ "$need_geo" = yes ] && ! have gzip; then
    warn "gzip is not installed, so the location database is not downloaded."
    need_geo=no
fi

need_fetcher=no
if [ "$need_rust$need_wordlist$need_geo" != nonono ] && ! have curl && ! have wget; then
    need_fetcher=yes
fi

fetch() {
    case "$1" in
    https://*) ;;
    *) return 1 ;;
    esac
    max_dl=${3:-$GEO_MAX_PACKED}
    # Both tools write to a pipe that stops after max_dl + 1 bytes: curl's
    # --max-filesize only holds when the server states the size (before curl
    # 8.4), and wget has no such option. The exit status is kept in a file
    # inside a private folder made for this download, never at a name in a
    # shared /tmp that someone else could have prepared.
    rc_dir=$(mktemp -d "${TMPDIR:-/tmp}/meow-fetch.XXXXXX") || return 1
    if have curl; then
        { curl --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 \
            --max-filesize "$max_dl" -fsSL "$1" || echo $? >"$rc_dir/rc"; } \
            | head -c "$((max_dl + 1))" >"$2"
    else
        # wget follows a redirect to http:// even with --https-only, so it
        # follows none.
        { wget --https-only --max-redirect=0 -q -O - "$1" || echo $? >"$rc_dir/rc"; } \
            | head -c "$((max_dl + 1))" >"$2"
    fi
    if [ -f "$rc_dir/rc" ]; then
        rm -rf "$rc_dir"
        rm -f "$2"
        return 1
    fi
    rm -rf "$rc_dir"
    actual_dl=$(wc -c <"$2" | tr -d ' ')
    if [ "${actual_dl:-0}" -gt "$max_dl" ]; then
        rm -f "$2"
        return 1
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
if [ "$need_geo" = yes ]; then
    echo "  - download the DB-IP Lite location database (about 65 MB, 135 MB unpacked) to $geo_dir"
fi
if [ "$tools_only" = no ] && [ "$need_compiler$need_rust$update_rust" = "nonono" ]; then
    echo "The C compiler and Rust are already installed."
fi
if [ "$tools_only" = yes ] && [ -z "$missing_tools" ] && [ "$need_wordlist" = no ] && [ "$need_geo" = no ]; then
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
        need_geo=no
    fi
fi

if [ "$need_rust" = yes ]; then
    say "Installing Rust with rustup"
    tmp_base=${TMPDIR:-/tmp}
    tmp_base=${tmp_base%/}
    rustup_init=$(mktemp "${tmp_base:-/tmp}/meow-rustup.XXXXXX")
    # Downloaded to a file first: a failed download must not run as an
    # empty script.
    fetch "$RUSTUP_URL" "$rustup_init" 67108864 ||
        die "Could not download the Rust installer from $RUSTUP_URL."
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
        cargo install feroxbuster --locked --version "$FEROXBUSTER_VERSION"
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
    if [ -L "$meow_home" ] || [ -L "$wordlist_dir" ] || [ -L "$wordlist_dir/common.txt" ]; then
        warn "Refusing to write wordlist through a symbolic link under $meow_home."
    else
        (umask 077 && mkdir -p "$meow_home" "$wordlist_dir")
        chmod 0700 "$meow_home" "$wordlist_dir" 2>/dev/null || true
        wordlist_part=$(mktemp "$wordlist_dir/.common.txt.XXXXXX")
        if fetch "$WORDLIST_URL" "$wordlist_part" 16777216 &&
            [ -s "$wordlist_part" ] &&
            ! grep -qi '<html' "$wordlist_part" &&
            verify_sha256 "$wordlist_part" "$WORDLIST_SHA256" &&
            [ ! -L "$wordlist_dir/common.txt" ]; then
            chmod 0600 "$wordlist_part" 2>/dev/null || true
            mv "$wordlist_part" "$wordlist_dir/common.txt"
            wordlist_part=""
            say "Wordlist saved to $wordlist_dir/common.txt"
        else
            rm -f "$wordlist_part"
            wordlist_part=""
            warn "Could not download the wordlist from $WORDLIST_URL (or its SHA-256 digest did not match). Put any .txt wordlist in $wordlist_dir and meow will use it."
        fi
    fi
fi

# This month's file, or last month's early in a month before it is out.
geo_get() {
    name=$1
    [ ! -L "$geo_dir/$name.mmdb" ] || return 1
    year=$(date -u +%Y)
    mon=$(date -u +%m)
    mon_num=${mon#0}
    this_month=$(printf '%04d-%02d' "$year" "$mon_num")
    if [ "$mon_num" -eq 1 ]; then
        last_month=$(printf '%04d-12' "$((year - 1))")
    else
        last_month=$(printf '%04d-%02d' "$year" "$((mon_num - 1))")
    fi
    geo_part=$(mktemp "$geo_dir/.$name.XXXXXX")
    for month in "$this_month" "$last_month"; do
        # Bounded at every step: the download, and what it unpacks to.
        if fetch "https://download.db-ip.com/free/$name-$month.mmdb.gz" "$geo_part.gz" "$GEO_MAX_PACKED" &&
            [ "$(wc -c <"$geo_part.gz")" -le "$GEO_MAX_PACKED" ] &&
            gzip -dc "$geo_part.gz" | head -c "$((GEO_MAX_BYTES + 1))" >"$geo_part" &&
            [ "$(wc -c <"$geo_part")" -le "$GEO_MAX_BYTES" ] &&
            gzip -t "$geo_part.gz" >/dev/null 2>&1 &&
            tail -c 100000 "$geo_part" | LC_ALL=C tr -cd '\40-\176\n' | grep -q 'MaxMind\.com' &&
            [ ! -L "$geo_dir/$name.mmdb" ]; then
            rm -f "$geo_part.gz"
            chmod 0600 "$geo_part" 2>/dev/null || true
            mv "$geo_part" "$geo_dir/$name.mmdb"
            geo_part=""
            return 0
        fi
        rm -f "$geo_part" "$geo_part.gz"
    done
    geo_part=""
    return 1
}

if [ "$need_geo" = yes ]; then
    say "Downloading the location database (IP Geolocation by DB-IP, https://db-ip.com)"
    if [ -L "$meow_home" ] || [ -L "$geo_dir" ]; then
        warn "Refusing to write location database through a symbolic link under $meow_home."
    else
        (umask 077 && mkdir -p "$meow_home" "$geo_dir")
        chmod 0700 "$meow_home" "$geo_dir" 2>/dev/null || true
        if geo_get dbip-city-lite && geo_get dbip-asn-lite; then
            say "Location database saved to $geo_dir"
        else
            warn "Could not download the location database from download.db-ip.com. The map still shows your own place; run this again later."
        fi
    fi
fi

if [ "$tools_only" = yes ]; then
    say "Done."
    exit 0
fi

# Another program called `meow` (one prints ASCII cats) may be what the
# user's shell finds first.
other=$(
    PATH=$original_path
    command -v meow 2>/dev/null || true
)
if [ -n "$other" ] && [ "$other" != "$installed" ]; then
    warn "Another program called meow is at $other, and your shell runs it instead of this one."
    warn "Remove it (for a package: dpkg -S $other, then sudo apt remove <package>), or keep $cargo_home/bin first on PATH."
fi

case ":$original_path:" in
*":$cargo_home/bin:"*) say "Ready. Run 'meow' for the interactive setup GUI, or 'meow <name>' to open a session" ;;
*)
    # Nothing adds this folder to PATH by itself (rustup runs with
    # --no-modify-path, and a distribution's Rust never does).
    case "$(basename "${SHELL:-sh}")" in
    zsh) profile="$HOME/.zshrc" ;;
    bash) profile="$HOME/.bashrc" ;;
    *) profile="$HOME/.profile" ;;
    esac
    say "Ready, but $cargo_home/bin is not on your PATH yet, so your shell cannot find meow. Add it once:"
    echo "    echo 'export PATH=\"$cargo_home/bin:\$PATH\"' >> $profile"
    echo "    export PATH=\"$cargo_home/bin:\$PATH\""
    say "Then run 'meow' for the interactive setup GUI, or 'meow <name>' to open a session"
    ;;
esac
