//! End-to-end checks of the `meow` binary's argument handling and exit codes.

use std::process::{Command, Output};

fn meow(args: &[&str], session: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_meow"));
    command.args(args).env_remove("MEOW_SESSION");
    if let Some(session) = session {
        command.env("MEOW_SESSION", session);
    }
    command.output().expect("failed to run meow")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn nested_session_is_refused_with_exit_code_1() {
    for args in [&[][..], &["other"][..], &["other", "--local"][..]] {
        let output = meow(args, Some("acme"));
        assert_eq!(output.status.code(), Some(1), "args {args:?}");
        assert_eq!(
            stderr(&output).trim(),
            "[!] Nested meow sessions are disabled (active: acme)"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn helper_subcommands_are_allowed_inside_a_session() {
    let output = meow(&["report"], Some("acme"));
    let text = stderr(&output);
    assert!(!text.contains("Nested"), "{text}");
    assert!(text.contains("session: acme"), "{text}");
}

#[test]
fn helper_subcommands_need_a_session() {
    let output = meow(&["hud"], None);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("No active meow session"));

    let output = meow(&["hud", "--session", "acme"], None);
    assert!(stderr(&output).contains("session: acme"));

    let output = meow(&["hud"], Some("../escape"));
    assert_eq!(output.status.code(), Some(1));
    assert!(!stderr(&output).contains("session: ../escape"));
}

#[test]
fn usage_errors_exit_with_code_2() {
    for args in [&["--local"][..], &["mode", "insane"][..], &["bad/name"][..]] {
        assert_eq!(meow(args, None).status.code(), Some(2), "args {args:?}");
    }
}

#[test]
fn version_and_help_succeed() {
    let output = meow(&["--version"], None);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        concat!("meow ", env!("CARGO_PKG_VERSION"))
    );

    let output = meow(&["--help"], Some("acme"));
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for word in ["mode", "recon", "map", "hud", "add", "report", "--local"] {
        assert!(help.contains(word), "help is missing {word}");
    }
}
