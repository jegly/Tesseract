#![no_main]
//! Fuzz the keyslot CBOR decoder via the header path (slots are validated
//! during VolumeHeader::validate). Also exercise a direct minicbor decode of
//! a KeySlot to hit the decoder in isolation.
use libfuzzer_sys::fuzz_target;
use tesseract_core::keyslot::KeySlot;

fuzz_target!(|data: &[u8]| {
    let _: Result<KeySlot, _> = minicbor::decode(data);
});
