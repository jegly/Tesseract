#![no_main]
//! Fuzz the volume header parser. verify-before-parse must hold: malformed
//! input returns an error, never a panic, and never reads past the checksum.
use libfuzzer_sys::fuzz_target;
use tesseract_core::header::VolumeHeader;

fuzz_target!(|data: &[u8]| {
    let _ = VolumeHeader::from_bytes(data);
});
