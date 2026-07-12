#![no_main]
//! Fuzz the Safari `Cache.db` `response_object` parser — the archived
//! `NSHTTPURLResponse` binary property list, the attacker-controllable byte
//! surface of a Safari cache entry. Invariant: arbitrary bytes must never panic;
//! a malformed plist recovers what it can and returns empties.

use browser_forensic_cache::parse_safari_response_object;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_safari_response_object(data);
});
