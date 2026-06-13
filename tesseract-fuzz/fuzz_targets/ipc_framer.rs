#![no_main]
//! Fuzz the IPC frame header decoder and the JSON control-frame parser.
use libfuzzer_sys::fuzz_target;
use tesseract_proto::{decode_frame_header, RequestEnvelope};

fuzz_target!(|data: &[u8]| {
    let _ = decode_frame_header(data);
    // control frames are JSON; the agent treats any parse error as a
    // protocol violation. Make sure that never panics.
    let _: Result<RequestEnvelope, _> = serde_json::from_slice(data);
});
