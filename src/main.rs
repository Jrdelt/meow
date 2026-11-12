//! `meow` entry point. The CLI is added in the next step; until then the
//! binary only reports its version.

fn main() {
    println!("meow {}", env!("CARGO_PKG_VERSION"));
}
