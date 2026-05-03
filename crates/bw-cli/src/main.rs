//! `bw` — browser forensic CLI.
//!
//! Subcommands:
//!   bw timeline <PATH>   — chronological history from a browser history file

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// bw — browser forensic analysis CLI.
#[derive(Parser, Debug)]
#[command(name = "bw", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse browser history and output a chronological timeline.
    Timeline {
        /// Path to a browser history file (Chrome `History` or Firefox `places.sqlite`).
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format: text (default), jsonl.
        #[arg(long, default_value = "text")]
        format: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Timeline { path, format } => timeline(&path, &format),
    }
}

fn timeline(path: &std::path::Path, format: &str) -> Result<()> {
    use browser_core::{detect_browser, BrowserFamily};

    let family = detect_browser(path)
        .ok_or_else(|| anyhow::anyhow!("unrecognised browser history file: {}", path.display()))?;

    let mut events = match family {
        BrowserFamily::Chromium => browser_chrome::parse_history(path)?,
        BrowserFamily::Firefox => browser_firefox::parse_history(path)?,
        BrowserFamily::Safari => {
            eprintln!("Use specific artifact subcommands for Safari (e.g., bw history <path>)");
            std::process::exit(1);
        }
    };
    events.sort_by_key(|e| e.timestamp_ns);

    match format {
        "jsonl" => {
            for ev in &events {
                println!("{}", serde_json::to_string(ev)?);
            }
        }
        _ => {
            for ev in &events {
                let ts = if ev.timestamp_ns == 0 {
                    "unknown".to_string()
                } else {
                    use chrono::{DateTime, Utc};
                    let secs = ev.timestamp_ns / 1_000_000_000;
                    let nanos = u32::try_from(ev.timestamp_ns % 1_000_000_000).unwrap_or(0);
                    DateTime::<Utc>::from_timestamp(secs, nanos)
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_else(|| "invalid".to_string())
                };
                println!("[{ts}] {:?}: {}", ev.browser, ev.description);
            }
        }
    }
    Ok(())
}
