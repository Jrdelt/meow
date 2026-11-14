//! `install.sh` driven with stand-in tools on a private PATH, so its
//! decisions can be checked without installing anything.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh");

struct Machine {
    tmp: tempfile::TempDir,
}

impl Machine {
    /// A machine with only the basic tools the script itself needs.
    fn bare() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("bin")).unwrap();
        std::fs::create_dir(tmp.path().join("home")).unwrap();
        let machine = Self { tmp };
        for tool in [
            "dirname", "grep", "uname", "id", "sed", "mkdir", "chmod", "cat", "mktemp", "rm", "mv",
        ] {
            let real = std::env::var_os("PATH")
                .and_then(|paths| {
                    std::env::split_paths(&paths)
                        .map(|dir| dir.join(tool))
                        .find(|candidate| candidate.is_file())
                })
                .unwrap_or_else(|| panic!("{tool} not found on this machine"));
            std::os::unix::fs::symlink(real, machine.bin().join(tool)).unwrap();
        }
        machine
    }

    fn bin(&self) -> PathBuf {
        self.tmp.path().join("bin")
    }

    fn home(&self) -> PathBuf {
        self.tmp.path().join("home")
    }

    /// Adds a stand-in program.
    fn tool(&self, name: &str, body: &str) -> &Self {
        let path = self.bin().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        self
    }

    /// A C compiler, on both macOS (Command Line Tools) and Linux.
    fn with_compiler(&self) -> &Self {
        self.tool("cc", "exit 0").tool("xcode-select", "exit 0")
    }

    /// A Rust toolchain of the given minor version. `cargo install` records
    /// its arguments and "installs" a stand-in meow.
    fn with_rust(&self, minor: u32) -> &Self {
        self.tool(
            "rustc",
            &format!("echo 'rustc 1.{minor}.0 (abcdef 2026-01-01)'"),
        )
        .tool(
            "cargo",
            "echo \"$*\" >> \"$HOME/cargo-calls\"\n\
                 mkdir -p \"$HOME/.cargo/bin\"\n\
                 printf '#!/bin/sh\\necho meow 9.9.9\\n' > \"$HOME/.cargo/bin/meow\"\n\
                 chmod +x \"$HOME/.cargo/bin/meow\"",
        )
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new("/bin/sh")
            .arg(SCRIPT)
            .args(args)
            .env_clear()
            .env("PATH", self.bin())
            .env("HOME", self.home())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// A `curl` that serves `body` for every download, paired with a stand-in
    /// `sha256sum` matching the pinned wordlist digest unless overridden.
    fn with_curl(&self, body: &str) -> &Self {
        self.tool(
            "curl",
            &format!(
                "while [ $# -gt 0 ]; do [ \"$1\" = -o ] && out=$2; shift; done\n\
                 printf '%s' '{body}' > \"$out\""
            ),
        )
        .tool(
            "sha256sum",
            "echo '78e7be2efbbbfef8ef1eb02116189087fd9205ef2bf997e68b29b45bfeb8ab52  $1'",
        )
    }

    fn wordlist(&self) -> PathBuf {
        self.home().join(".meow/wordlists/common.txt")
    }

    /// Runs the meow binary itself on this machine's PATH.
    fn meow(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_meow"))
            .args(args)
            .env_clear()
            .env("PATH", self.bin())
            .env("HOME", self.home())
            .env("MEOW_HOME", self.home().join(".meow"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// The system package manager, as a stand-in that "installs" a program
    /// by writing it into bin. `sudo` just runs the command.
    fn with_package_manager(&self) -> &Self {
        let bin = self.bin();
        let body = format!(
            "for name in \"$@\"; do case \"$name\" in -*|install|update) ;; *)\n\
             printf '#!/bin/sh\\nexit 0\\n' > '{bin}'/\"$name\"; chmod +x '{bin}'/\"$name\"\n\
             echo \"$name\" >> \"$HOME/installed\" ;; esac; done",
            bin = bin.display()
        );
        let manager = if cfg!(target_os = "macos") {
            "brew"
        } else {
            "apt-get"
        };
        self.tool(manager, &body).tool("sudo", "exec \"$@\"")
    }

    fn cargo_calls(&self) -> String {
        std::fs::read_to_string(self.home().join("cargo-calls")).unwrap_or_default()
    }
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn bare_machine_plan_lists_compiler_and_rust() {
    let machine = Machine::bare();
    let output = machine.run(&["--dry-run"]);
    let text = out(&output);
    assert!(output.status.success(), "{}", err(&output));
    let compiler = if cfg!(target_os = "macos") {
        "install the Xcode Command Line Tools (the C compiler)"
    } else {
        "install a C compiler with your package manager"
    };
    assert!(text.contains(compiler), "{text}");
    assert!(
        text.contains("install the Rust toolchain with rustup"),
        "{text}"
    );
    assert!(
        text.contains("without modifying your shell profile"),
        "the non-destructive PATH behavior is announced: {text}"
    );
    let target = format!("install it to {}/.cargo/bin/meow", machine.home().display());
    assert!(text.contains(&target), "{text}");
    assert!(text.contains("Dry run: nothing was changed."), "{text}");
    // A dry run really changes nothing.
    assert_eq!(std::fs::read_dir(machine.home()).unwrap().count(), 0);
}

#[test]
fn ready_machine_plan_only_builds() {
    let machine = Machine::bare();
    machine.with_compiler().with_rust(90);
    let text = out(&machine.run(&["--dry-run"]));
    assert!(
        text.contains("The C compiler and Rust are already installed"),
        "{text}"
    );
    assert!(!text.contains("rustup"), "{text}");
    assert!(!text.contains("C compiler with"), "{text}");
    assert!(!text.contains("Command Line Tools"), "{text}");
    assert!(machine.cargo_calls().is_empty(), "a dry run must not build");
}

#[test]
fn old_rust_is_updated_or_replaced() {
    let with_rustup = Machine::bare();
    with_rustup
        .with_compiler()
        .with_rust(70)
        .tool("rustup", "exit 0");
    let text = out(&with_rustup.run(&["--dry-run"]));
    assert!(
        text.contains("update Rust to the latest stable (meow needs 1.88 or newer; found 1.70)"),
        "{text}"
    );

    // A distribution's old Rust without rustup: rustup is installed alongside.
    let distro = Machine::bare();
    distro.with_compiler().with_rust(70);
    let text = out(&distro.run(&["--dry-run"]));
    assert!(
        text.contains("install the Rust toolchain with rustup"),
        "{text}"
    );
}

#[test]
fn nothing_happens_without_consent() {
    let machine = Machine::bare();
    machine.with_compiler().with_rust(90);
    // No --yes and no terminal to ask on.
    let output = machine.run(&[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        err(&output).contains("Rerun with --yes to proceed"),
        "{}",
        err(&output)
    );
    assert!(machine.cargo_calls().is_empty());

    let output = machine.run(&["--frobnicate"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(err(&output).contains("Unknown option"));
}

#[test]
fn yes_builds_installs_and_explains_the_path() {
    let machine = Machine::bare();
    machine
        .with_compiler()
        .with_rust(90)
        .with_curl("admin\nlogin\n");
    let output = machine.run(&["--yes"]);
    let text = out(&output);
    assert!(output.status.success(), "{}\n{}", text, err(&output));
    let calls = machine.cargo_calls();
    assert_eq!(calls.lines().next(), Some("install --path . --locked"));
    let installed = machine.home().join(".cargo/bin/meow");
    assert!(
        text.contains(&format!("Installed meow 9.9.9 at {}", installed.display())),
        "{text}"
    );
    // ~/.cargo/bin is not on this shell's PATH, so the user is told how to
    // get it there.
    assert!(text.contains("Open a new terminal"), "{text}");

    // Everything meow recon drives comes along by default.
    assert!(
        calls.contains("install feroxbuster --locked"),
        "feroxbuster is built with cargo when no package has it: {calls}"
    );
    assert_eq!(
        std::fs::read_to_string(machine.wordlist()).unwrap(),
        "admin\nlogin\n"
    );
    assert!(
        text.contains(&format!(
            "Wordlist saved to {}",
            machine.wordlist().display()
        )),
        "{text}"
    );

    // With everything present there is nothing more to do.
    machine
        .tool("nmap", "exit 0")
        .tool("katana", "exit 0")
        .tool("feroxbuster", "exit 0");
    let text = out(&machine.run(&["--yes"]));
    assert!(!text.contains("Installing"), "{text}");
    assert!(!text.contains("wordlist"), "{text}");
}

#[test]
fn scanners_need_a_package_manager() {
    let machine = Machine::bare();
    machine.with_compiler().with_rust(90).with_curl("admin\n");
    let plan = out(&machine.run(&["--dry-run"]));
    assert!(
        plan.contains("install the scanners meow recon drives: nmap katana feroxbuster"),
        "{plan}"
    );
    assert!(
        plan.contains("download the SecLists web-content wordlist from GitHub"),
        "{plan}"
    );

    let output = machine.run(&["--yes"]);
    assert!(
        output.status.success(),
        "the missing scanners must not fail the install"
    );
    let warning = err(&output);
    let expected = if cfg!(target_os = "macos") {
        "Could not install nmap: Homebrew is not installed"
    } else {
        "Could not install nmap: no supported package manager found"
    };
    assert!(warning.contains(expected), "{warning}");
    assert!(warning.contains("Could not install katana"), "{warning}");
    assert!(
        !warning.contains("feroxbuster"),
        "built with cargo: {warning}"
    );
}

#[test]
fn no_tools_installs_meow_alone_and_a_failed_download_is_only_a_warning() {
    let machine = Machine::bare();
    machine
        .with_compiler()
        .with_rust(90)
        .tool("curl", "exit 22");
    let plan = out(&machine.run(&["--dry-run", "--no-tools"]));
    assert!(!plan.contains("scanners"), "{plan}");
    assert!(!plan.contains("wordlist"), "{plan}");
    let output = machine.run(&["--yes", "--no-tools"]);
    assert!(output.status.success(), "{}", err(&output));
    assert_eq!(machine.cargo_calls().trim(), "install --path . --locked");
    assert!(!machine.wordlist().exists());

    // GitHub not answering leaves no half-written wordlist behind.
    let output = machine.run(&["--yes"]);
    assert!(output.status.success(), "{}", err(&output));
    assert!(
        err(&output).contains("Could not download the wordlist"),
        "{}",
        err(&output)
    );
    let dir = machine.wordlist().parent().unwrap().to_path_buf();
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
}

#[test]
fn a_failed_build_is_reported() {
    let machine = Machine::bare();
    machine
        .with_compiler()
        .with_rust(90)
        .tool("cargo", "exit 101");
    let output = machine.run(&["--yes"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        err(&output).contains("The build failed."),
        "{}",
        err(&output)
    );
}

#[test]
fn minimum_rust_version_matches_the_manifest() {
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let minor = script
        .lines()
        .find_map(|line| line.strip_prefix("MIN_RUST_MINOR="))
        .expect("MIN_RUST_MINOR is set in install.sh");
    assert!(
        manifest.contains(&format!("rust-version = \"1.{minor}\"")),
        "install.sh requires Rust 1.{minor} but Cargo.toml says otherwise"
    );
}

#[test]
fn supply_chain_and_shell_profile_hardening_in_install_script() {
    let script = std::fs::read_to_string(SCRIPT).unwrap();
    assert!(
        script.contains("--no-modify-path"),
        "rustup-init must be called with --no-modify-path"
    );
    assert!(
        script.contains("wget --https-only"),
        "wget must enforce --https-only"
    );
    assert!(
        !script.contains("@latest"),
        "katana go install must be pinned to a release tag"
    );
    assert!(
        !script.contains("/SecLists/master/"),
        "WORDLIST_URL must be pinned to a commit hash"
    );
    assert!(
        script.contains("trap cleanup EXIT INT TERM"),
        "cleanup trap must cover EXIT INT TERM"
    );

    // Mismatched SHA-256 digest rejects the wordlist and leaves no temp file.
    let machine = Machine::bare();
    machine
        .with_compiler()
        .with_rust(90)
        .with_curl("tampered\n")
        .tool(
            "sha256sum",
            "echo '0000000000000000000000000000000000000000000000000000000000000000  $1'",
        );
    let output = machine.run(&["--yes"]);
    assert!(output.status.success(), "{}", err(&output));
    assert!(
        err(&output).contains("Could not download the wordlist"),
        "{}",
        err(&output)
    );
    assert!(!machine.wordlist().exists());
    let dir = machine.wordlist().parent().unwrap().to_path_buf();
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
}

#[test]
fn homebrew_formula_and_windows_installer_match_unix_installer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let unix = std::fs::read_to_string(SCRIPT).unwrap();
    let formula = std::fs::read_to_string(root.join("Formula/meow.rb")).unwrap();
    let windows = std::fs::read_to_string(root.join("install.ps1")).unwrap();

    let extract = |prefix: &str| -> String {
        unix.lines()
            .find_map(|l| l.strip_prefix(prefix))
            .unwrap()
            .trim_matches('"')
            .to_owned()
    };
    let wordlist_url = extract("WORDLIST_URL=");
    let katana_go = extract("KATANA_GO=");
    let sha256 = "78e7be2efbbbfef8ef1eb02116189087fd9205ef2bf997e68b29b45bfeb8ab52";

    assert!(
        formula.contains(&wordlist_url),
        "Formula/meow.rb must use pinned WORDLIST_URL"
    );
    assert!(
        formula.contains(sha256),
        "Formula/meow.rb must verify WORDLIST_SHA256"
    );
    assert!(
        formula.contains("std_cargo_args"),
        "Formula/meow.rb must install via cargo"
    );

    assert!(
        windows.contains(&wordlist_url),
        "install.ps1 must use pinned WORDLIST_URL"
    );
    assert!(
        windows.contains(sha256),
        "install.ps1 must verify WORDLIST_SHA256"
    );
    assert!(
        windows.contains(&katana_go),
        "install.ps1 must use pinned KATANA_GO"
    );
    assert!(
        windows.contains("--no-modify-path"),
        "install.ps1 must pass --no-modify-path to rustup-init"
    );
    assert!(
        windows.contains("MIN_RUST_MINOR = 88"),
        "install.ps1 must require MSRV 1.88"
    );
}

#[test]
fn meow_tools_lists_what_recon_lacks_and_installs_it_on_request() {
    let machine = Machine::bare();
    machine.with_curl("admin\n");

    // Without a terminal and without --yes: only the list, nothing installed.
    let output = machine.meow(&["tools"]);
    let text = out(&output);
    assert!(output.status.success(), "{text}{}", err(&output));
    for line in [
        "[!] nmap         not installed",
        "[!] katana       not installed",
        "[!] feroxbuster  not installed",
        "without it meow skips the web crawl",
        "Not on a terminal, so nothing is installed",
    ] {
        assert!(text.contains(line), "missing {line:?} in {text}");
    }
    assert!(!machine.home().join("installed").exists());

    // --yes runs meow's own copy of the installer for the tools alone.
    machine.with_package_manager();
    let output = machine.meow(&["tools", "--yes"]);
    let text = out(&output);
    assert!(output.status.success(), "{text}{}", err(&output));
    let installed = std::fs::read_to_string(machine.home().join("installed")).unwrap();
    assert_eq!(
        installed.split_whitespace().collect::<Vec<_>>(),
        ["nmap", "katana", "feroxbuster"]
    );
    assert!(
        text.contains("Every tool recon uses is installed."),
        "{text}"
    );
    assert!(!text.contains("build meow"), "only the tools: {text}");
    assert!(machine.cargo_calls().is_empty(), "meow is not rebuilt");
    assert_eq!(
        std::fs::read_to_string(machine.wordlist()).unwrap(),
        "admin\n"
    );

    // Nothing left to do.
    let text = out(&machine.meow(&["tools"]));
    assert!(!text.contains("not installed"), "{text}");
}
