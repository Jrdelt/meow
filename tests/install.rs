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
            "dirname", "grep", "uname", "id", "sed", "mkdir", "chmod", "cat", "mktemp", "rm",
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
        text.contains("rustup adds"),
        "the profile change is announced: {text}"
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
    machine.with_compiler().with_rust(90);
    let output = machine.run(&["--yes"]);
    let text = out(&output);
    assert!(output.status.success(), "{}\n{}", text, err(&output));
    assert_eq!(machine.cargo_calls().trim(), "install --path . --locked");
    let installed = machine.home().join(".cargo/bin/meow");
    assert!(
        text.contains(&format!("Installed meow 9.9.9 at {}", installed.display())),
        "{text}"
    );
    assert!(
        text.contains("Optional scanners not found: nmap katana feroxbuster"),
        "{text}"
    );
    // ~/.cargo/bin is not on this shell's PATH, so the user is told how to
    // get it there.
    assert!(text.contains("Open a new terminal"), "{text}");

    // With the scanners present there is nothing to mention.
    machine
        .tool("nmap", "exit 0")
        .tool("katana", "exit 0")
        .tool("feroxbuster", "exit 0");
    let text = out(&machine.run(&["--yes", "--with-tools"]));
    assert!(!text.contains("scanners"), "{text}");
}

#[test]
fn scanners_need_a_package_manager() {
    let machine = Machine::bare();
    machine.with_compiler().with_rust(90);
    let output = machine.run(&["--yes", "--with-tools"]);
    assert!(
        output.status.success(),
        "the missing scanners must not fail the install"
    );
    let warning = err(&output);
    let expected = if cfg!(target_os = "macos") {
        "Homebrew is not installed"
    } else {
        "No supported package manager found"
    };
    assert!(warning.contains(expected), "{warning}");
    assert!(warning.contains("nmap katana feroxbuster"), "{warning}");
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
