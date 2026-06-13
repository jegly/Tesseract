# tesseract-fuzz

cargo-fuzz (libFuzzer) targets for Tesseract's untrusted-input parsers. This
crate is **not** a workspace member so the stable toolchain builds the rest of
the project; fuzzing needs nightly.

```sh
cargo install cargo-fuzz
cd tesseract-fuzz            # or run from repo root with --fuzz-dir
cargo +nightly fuzz run header_parser
cargo +nightly fuzz run keyslot_decoder
cargo +nightly fuzz run ipc_framer
cargo +nightly fuzz run file_header
cargo +nightly fuzz run deniable_open
```

Each target asserts the same invariant: malformed input produces an `Err`,
never a panic, OOB read, or hang. The header and file-header parsers verify a
BLAKE3 checksum and bounded lengths *before* the CBOR decoder runs
(verify-before-parse); the CBOR decoder itself (minicbor) rejects
indefinite-length items and enforces depth/size bounds.
