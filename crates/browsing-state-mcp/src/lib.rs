#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! `browsing-state-mcp` — an MCP server that exposes browser **history and state**
//! (visits, open/closed tabs, searches) to AI agents.
//!
//! The two walls that keep secrets away from the model (see the fleet design doc):
//! 1. **No secret readers are called** — this crate reads only history/session/
//!    discovery surfaces, never cookies, Login Data, autofill, or any decryptor.
//! 2. **PII is redacted** ([`redact`]) from URLs/titles/searches before anything
//!    leaves the process, because history text itself carries tokens and PII.

pub mod context;
pub mod reader;
pub mod redact;
pub mod server;
