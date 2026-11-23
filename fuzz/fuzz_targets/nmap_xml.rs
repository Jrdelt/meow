//! Nmap XML straight to its parser, as a recon's own scan is read (its
//! names trusted) and as an imported file is (its names only claims).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let xml = String::from_utf8_lossy(data);
    let _ = meow::parsers::nmap::parse(&xml, true);
    let _ = meow::parsers::nmap::parse(&xml, false);
    let _ = meow::parsers::nmap::open_tcp_ports(&xml);
});
