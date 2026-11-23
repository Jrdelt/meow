//! Compiles the stateful ECMA-48 tap filter (`src/c/tap_filter.c`) into a
//! static library linked into meow, and gives meow the commit it is built
//! from (`MEOW_BUILD_COMMIT`; see `src/build_commit.rs`).

#[path = "src/build_commit.rs"]
mod build_commit;

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

    build_commit::emit();
}
