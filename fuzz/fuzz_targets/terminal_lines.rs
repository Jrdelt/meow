//! Lines a scanned host can make appear in the terminal (banners, headers,
//! tool output) go to the line parser one at a time, as the live tap feeds
//! it; state carries from line to line.
#![no_main]

use libfuzzer_sys::fuzz_target;
use meow::evidence::Source;
use meow::parsers::text::TextParser;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut parser = TextParser::new(Source::PtyRegex);
    for line in text.lines() {
        let _ = parser.feed(line);
    }
});
