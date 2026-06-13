#![no_main]
//! Fuzz the file-mode header parser (verify-before-parse, bounded sizes).
use libfuzzer_sys::fuzz_target;
use tesseract_core::filemode::FileHeader;

fuzz_target!(|data: &[u8]| {
    let _ = FileHeader::from_bytes(data);
});
