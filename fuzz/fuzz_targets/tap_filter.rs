//! The C11 ECMA-48 filter that turns raw terminal bytes into text lines.
//! The first byte picks a chunk size, so escape sequences and UTF-8
//! characters get split across `feed` calls the way PTY reads split them.
#![no_main]

use libfuzzer_sys::fuzz_target;
use meow::tap::TapFilter;

fuzz_target!(|data: &[u8]| {
    let Some((&size, bytes)) = data.split_first() else {
        return;
    };
    let size = usize::from(size).max(1);
    let mut filter = TapFilter::new();
    for chunk in bytes.chunks(size) {
        for line in filter.feed(chunk) {
            // Every line handed on is UTF-8 by type; it must also be one line.
            assert!(!line.contains('\n'), "a line with a newline: {line:?}");
        }
    }
    let _ = filter.flush();
    // The wrapper sizes the C filter's output buffer for the worst case, so
    // no line is ever lost for want of room.
    assert_eq!(
        filter.stats().dropped_nospace,
        0,
        "a line was lost for room"
    );
});
