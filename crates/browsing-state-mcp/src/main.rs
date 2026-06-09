//! `browsing-state-mcp` server: a newline-delimited JSON-RPC MCP server over
//! stdio. All request routing lives in the unit-tested
//! [`browsing_state_mcp::server::dispatch`]; this file only owns I/O.
//!
//! The agent-facing allow-list is read from `BROWSING_STATE_ALLOWLIST`
//! (comma-separated domains, or `*` to allow all). Unset means **nothing** is
//! exposed — the secure default. Secrets are never reachable: this binary links
//! only the non-secret reader.

use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use browsing_state_mcp::context::Allowlist;
use browsing_state_mcp::{reader, server};
use serde_json::Value;

fn main() -> io::Result<()> {
    let allow = load_allowlist();
    let records = reader::collect_default().unwrap_or_default();
    eprintln!("browsing-state-mcp: {} record(s) loaded; ready on stdio.", records.len());

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(&line) else {
            continue; // ignore malformed lines
        };
        if let Some(resp) = server::dispatch(&req, &records, &allow, now_ns()) {
            writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap_or_default())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// Build the allow-list from `BROWSING_STATE_ALLOWLIST`. Unset → permit nothing.
fn load_allowlist() -> Allowlist {
    match std::env::var("BROWSING_STATE_ALLOWLIST") {
        Ok(v) if v.trim() == "*" => Allowlist::allow_all(),
        Ok(v) => Allowlist::new(
            v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        ),
        Err(_) => Allowlist::new(std::iter::empty()),
    }
}

fn now_ns() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}
