#![no_main]
//! Fuzz the deniable header opener with arbitrary blobs and a fixed
//! passphrase. Random bytes must fail generically without panicking; this is
//! the path that guarantees a hidden header is indistinguishable from random.
use libfuzzer_sys::fuzz_target;
use tesseract_core::header::open_deniable;

fuzz_target!(|data: &[u8]| {
    let _ = open_deniable(data, b"fuzz-passphrase", &[], 0);
});
