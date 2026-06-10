#![no_main]
//! Fuzz the SNSS record-stream reader: header + length-prefixed record framing
//! over an arbitrary byte stream. Must never panic on a malformed/truncated file.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = snss::read_records(Cursor::new(data));
});
