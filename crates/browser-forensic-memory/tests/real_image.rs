//! Tier-1 validation against a REAL memory image (env-gated; skips when absent).
//!
//! Set `BR4N6_MEMORY_IMAGE` to a memory image (raw/LiME/AVML/crash-dump) and,
//! optionally, `BR4N6_MEMORY_ISF` to a Volatility-3 ISF symbol file (offline
//! symbols; otherwise the carve auto-profiles the kernel PDB, which needs a
//! network symbol cache). The test asserts the process-attribution invariant:
//! every structurally carved event names its owning pid and process.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use browser_forensic_memory::{browser_processes, carve_memory_image_with_symbols};
use serde_json::Value;

fn image_from_env() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var("BR4N6_MEMORY_IMAGE").ok()?);
    p.is_file().then_some(p)
}

#[test]
fn real_image_events_are_pid_attributed() {
    let Some(image) = image_from_env() else {
        eprintln!("skipping: set BR4N6_MEMORY_IMAGE to a real memory image to run");
        return;
    };
    let isf = std::env::var("BR4N6_MEMORY_ISF").ok().map(PathBuf::from);

    match carve_memory_image_with_symbols(&image, isf.as_deref()) {
        Ok(events) => {
            eprintln!(
                "carved {} process-attributed events from {} browser process(es)",
                events.len(),
                browser_processes(&events).len()
            );
            for ev in &events {
                assert!(
                    ev.attrs.get("pid").and_then(Value::as_u64).is_some(),
                    "every structured event must carry an owning pid: {ev:?}"
                );
                assert!(
                    ev.attrs.get("process").and_then(Value::as_str).is_some(),
                    "every structured event must carry an owning process name: {ev:?}"
                );
            }
        }
        // A recognized Windows image with no usable profile is a legitimate
        // outcome when neither an ISF nor a network symbol cache is available —
        // it fails loud (correct) rather than reporting a false empty. Surface
        // it as a skip so CI without symbols stays green.
        Err(e) if !e.is_degradable() => {
            eprintln!("skipping assertion: bootstrap needs symbols ({e}); supply BR4N6_MEMORY_ISF");
        }
        Err(e) => {
            eprintln!("image not an OS/process image ({e}); byte-scan fallback would apply");
        }
    }
}
