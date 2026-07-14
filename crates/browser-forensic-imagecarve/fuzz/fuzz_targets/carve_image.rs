#![no_main]
//! Fuzz the whole-image signature carver over arbitrary bytes.
//!
//! Invariant: [`carve_image_with`] must never panic and must stay bounded in
//! memory on ANY input — a real disk/memory image is attacker-influenceable
//! (lying SQLite headers, all-magic slack, boundary-straddling signatures). The
//! first two bytes seed a small window/overlap so the fuzzer explores the
//! window-boundary straddling of the signature locator; the remaining bytes are
//! the image served through an in-memory [`ImageSource`].

use std::path::Path;

use browser_forensic_imagecarve::{carve_image_with, OVERLAP, WINDOW};
use forensic_vfs::{ImageSource, VfsResult};
use libfuzzer_sys::fuzz_target;

/// An in-memory [`ImageSource`] over a byte slice (a simulated raw image).
struct SliceSource<'a>(&'a [u8]);

impl ImageSource for SliceSource<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.0.len());
        let avail = &self.0[start..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
}

fuzz_target!(|data: &[u8]| {
    // Seed a small window/overlap from the first bytes so the scanner is driven
    // across many boundary alignments; `carve_image_with` clamps both to sane
    // bounds, so any seed is safe. Small windows keep the run fast and bounded.
    let (window, overlap, body) = if data.len() >= 2 {
        let window = 4096usize + usize::from(data[0]) * 32;
        let overlap = usize::from(data[1]) * 8;
        (window, overlap, &data[2..])
    } else {
        (WINDOW, OVERLAP, data)
    };
    let src = SliceSource(body);
    let _ = carve_image_with(&src, Path::new("fuzz.img"), window, overlap);
});
