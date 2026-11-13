//! Compiles the stateful ECMA-48 tap filter (`src/c/tap_filter.c`) into a
//! static library that Cargo links into the `meow` binary.

const C_SOURCE: &str = "src/c/tap_filter.c";
const C_HEADER: &str = "src/c/tap_filter.h";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={C_SOURCE}");
    println!("cargo:rerun-if-changed={C_HEADER}");

    let mut build = cc::Build::new();
    build.file(C_SOURCE).include("src/c").warnings(true);

    // The filter is strict portable C11. MSVC spells the flags differently
    // from GCC/Clang, so pick per compiler family rather than per OS
    // (clang-cl and MinGW both exist on Windows).
    if build.get_compiler().is_like_msvc() {
        build.flag_if_supported("/std:c11").flag_if_supported("/W4");
    } else {
        build
            .flag_if_supported("-std=c11")
            .flag_if_supported("-Wall")
            .flag_if_supported("-Wextra")
            .flag_if_supported("-Wpedantic")
            .flag_if_supported("-Wconversion")
            .flag_if_supported("-Wshadow");
    }

    build.compile("tap_filter");

    // The commit this binary is built from, so `meow update` can tell when
    // the checkout has moved on since. Empty outside a git checkout.
    // A path that does not exist would rerun this script on every build.
    for watched in [".git/HEAD", ".git/refs/heads"] {
        if std::path::Path::new(watched).exists() {
            println!("cargo:rerun-if-changed={watched}");
        }
    }
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    println!("cargo:rustc-env=MEOW_BUILD_COMMIT={commit}");
}
