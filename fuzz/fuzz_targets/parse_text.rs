//! `meow add`: any file's text goes through format detection and then the
//! Nmap XML, JSONL (katana, feroxbuster), git diff or log parser. None may
//! panic, whatever the bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = meow::parsers::parse_text(&text);
});
