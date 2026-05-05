//! `bw` — browser forensic CLI.

mod format;

use std::path::PathBuf;

use anyhow::Result;
use browser_core::BrowserFamily;
use clap::{Parser, Subcommand, ValueEnum};

/// bw — browser forensic analysis CLI.
#[derive(Parser, Debug)]
#[command(name = "bw", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, ValueEnum, Default)]
enum OutputFormat {
    #[default]
    Text,
    Jsonl,
    Csv,
}

#[derive(Parser, Debug)]
struct ArtifactArgs {
    /// Path to the browser artifact file or directory.
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Output format: text (default), jsonl, csv.
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
}

#[derive(Parser, Debug)]
struct ProfilesArgs {
    /// Output format: text (default), jsonl, csv.
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
}

#[derive(Parser, Debug)]
struct AnalyzeArgs {
    /// Path to a browser history file.
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Show domains visited at most this many times (cap).
    #[arg(long, default_value = "5")]
    cap: usize,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse browser history and output a chronological timeline.
    Timeline(ArtifactArgs),
    /// Parse browser history events.
    History(ArtifactArgs),
    /// Parse browser cookies.
    Cookies(ArtifactArgs),
    /// Parse browser downloads.
    Downloads(ArtifactArgs),
    /// Parse browser bookmarks.
    Bookmarks(ArtifactArgs),
    /// Parse browser extensions.
    Extensions(ArtifactArgs),
    /// Parse browser login data (passwords NEVER exposed).
    LoginData(ArtifactArgs),
    /// Parse browser autofill data.
    Autofill(ArtifactArgs),
    /// Parse Firefox session store.
    Session(ArtifactArgs),
    /// Parse browser cache.
    Cache(ArtifactArgs),
    /// Discover browser profiles on this system.
    Profiles(ProfilesArgs),
    /// Analyze browser history for rarely-visited domains.
    Analyze(AnalyzeArgs),
    /// Run integrity checks on a browser artifact.
    Integrity(ArtifactArgs),
    /// Carve deleted records from a browser SQLite database.
    Carve(ArtifactArgs),
    /// Run full triage: discover profiles, parse, check integrity, carve.
    Triage(TriageArgs),
}

#[derive(Parser, Debug)]
struct TriageArgs {
    /// Home directory to scan for browser profiles.
    #[arg(long, value_name = "DIR")]
    home: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Timeline(args) | Commands::History(args) => run_artifact(args, ArtifactType::History),
        Commands::Cookies(args) => run_artifact(args, ArtifactType::Cookies),
        Commands::Downloads(args) => run_artifact(args, ArtifactType::Downloads),
        Commands::Bookmarks(args) => run_artifact(args, ArtifactType::Bookmarks),
        Commands::Extensions(args) => run_artifact(args, ArtifactType::Extensions),
        Commands::LoginData(args) => run_artifact(args, ArtifactType::LoginData),
        Commands::Autofill(args) => run_artifact(args, ArtifactType::Autofill),
        Commands::Session(args) => run_artifact(args, ArtifactType::Session),
        Commands::Cache(args) => run_artifact(args, ArtifactType::Cache),
        Commands::Profiles(args) => run_profiles(args),
        Commands::Analyze(args) => run_analyze(args),
        Commands::Integrity(args) => run_integrity(args),
        Commands::Carve(args) => run_carve(args),
        Commands::Triage(args) => run_triage(args),
    }
}

enum ArtifactType {
    History,
    Cookies,
    Downloads,
    Bookmarks,
    Extensions,
    LoginData,
    Autofill,
    Session,
    Cache,
}

fn run_artifact(args: ArtifactArgs, artifact: ArtifactType) -> Result<()> {
    use browser_core::{detect_browser, BrowserFamily};

    let path = &args.path;

    // Detect browser from path
    let family = detect_browser(path)
        .or_else(|| infer_browser_from_filename(path));

    let family = match family {
        Some(f) => f,
        None => {
            eprintln!("error: cannot determine browser from path: {}", path.display());
            std::process::exit(1);
        }
    };

    let mut events = match (&family, &artifact) {
        (BrowserFamily::Chromium, ArtifactType::History) => browser_chrome::parse_history(path)?,
        (BrowserFamily::Firefox, ArtifactType::History) => browser_firefox::parse_history(path)?,
        (BrowserFamily::Safari, ArtifactType::History) => browser_safari::parse_history(path)?,

        (BrowserFamily::Chromium, ArtifactType::Cookies) => browser_chrome::parse_cookies(path)?,
        (BrowserFamily::Firefox, ArtifactType::Cookies) => browser_firefox::parse_cookies(path)?,
        (BrowserFamily::Safari, ArtifactType::Cookies) => browser_safari::parse_cookies(path)?,

        (BrowserFamily::Chromium, ArtifactType::Downloads) => browser_chrome::parse_downloads(path)?,
        (BrowserFamily::Firefox, ArtifactType::Downloads) => browser_firefox::parse_downloads(path)?,
        (BrowserFamily::Safari, ArtifactType::Downloads) => browser_safari::parse_downloads(path)?,

        (BrowserFamily::Chromium, ArtifactType::Bookmarks) => browser_chrome::parse_bookmarks(path)?,
        (BrowserFamily::Firefox, ArtifactType::Bookmarks) => browser_firefox::parse_bookmarks(path)?,
        (BrowserFamily::Safari, ArtifactType::Bookmarks) => browser_safari::parse_bookmarks(path)?,

        (BrowserFamily::Chromium, ArtifactType::Extensions) => browser_chrome::parse_extensions(path)?,
        (BrowserFamily::Firefox, ArtifactType::Extensions) => browser_firefox::parse_extensions(path)?,
        (BrowserFamily::Safari, ArtifactType::Extensions) => browser_safari::parse_extensions(path)?,

        (BrowserFamily::Chromium, ArtifactType::LoginData) => browser_chrome::parse_login_data(path)?,
        (BrowserFamily::Firefox, ArtifactType::LoginData) => browser_firefox::parse_login_data(path)?,
        (BrowserFamily::Safari, ArtifactType::LoginData) => {
            eprintln!("error: Safari login data not supported");
            std::process::exit(1);
        }

        (BrowserFamily::Chromium, ArtifactType::Autofill) => browser_chrome::parse_autofill(path)?,
        (BrowserFamily::Firefox, ArtifactType::Autofill) => browser_firefox::parse_autofill(path)?,
        (BrowserFamily::Safari, ArtifactType::Autofill) => {
            eprintln!("error: Safari autofill not supported");
            std::process::exit(1);
        }

        (BrowserFamily::Firefox, ArtifactType::Session) => browser_firefox::parse_session(path)?,
        (_, ArtifactType::Session) => {
            eprintln!("error: session only supported for Firefox");
            std::process::exit(1);
        }

        (BrowserFamily::Chromium, ArtifactType::Cache) => browser_chrome::parse_cache(path)?,
        (BrowserFamily::Firefox, ArtifactType::Cache) => browser_firefox::parse_cache(path)?,
        (BrowserFamily::Safari, ArtifactType::Cache) => {
            eprintln!("error: Safari cache not supported");
            std::process::exit(1);
        }
    };

    events.sort_by_key(|e| e.timestamp_ns);
    print_events(&events, &args.format);
    Ok(())
}

fn run_profiles(args: ProfilesArgs) -> Result<()> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
    let profiles = browser_discovery::discover_profiles(&home);

    match args.format {
        OutputFormat::Csv => {
            println!("browser,name,path");
            for p in &profiles {
                println!("{},{},{}", p.browser, format::csv_escape(&p.name), format::csv_escape(&p.path.to_string_lossy()));
            }
        }
        OutputFormat::Jsonl => {
            for p in &profiles {
                println!("{{\"browser\":\"{}\",\"name\":\"{}\",\"path\":\"{}\"}}",
                    p.browser, p.name, p.path.display());
            }
        }
        OutputFormat::Text => {
            for p in &profiles {
                println!("{} \u{2014} {} ({})", p.browser, p.name, p.path.display());
            }
        }
    }
    Ok(())
}

fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    use browser_core::{detect_browser, BrowserFamily};

    let path = &args.path;
    let family = detect_browser(path)
        .or_else(|| infer_browser_from_filename(path));

    let events = match family {
        Some(BrowserFamily::Chromium) => browser_chrome::parse_history(path)?,
        Some(BrowserFamily::Firefox) => browser_firefox::parse_history(path)?,
        Some(BrowserFamily::Safari) => browser_safari::parse_history(path)?,
        None => {
            eprintln!("error: cannot determine browser from path: {}", path.display());
            std::process::exit(1);
        }
    };

    let domains = browser_core::analyze::rare_domains(&events, args.cap);
    for (domain, count) in &domains {
        println!("{count}\t{domain}");
    }
    Ok(())
}

fn infer_browser_from_filename(path: &std::path::Path) -> Option<browser_core::BrowserFamily> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name == "history.db" {
        return Some(browser_core::BrowserFamily::Safari);
    }
    if name == "places.sqlite" || name == "formhistory.sqlite"
        || name == "cookies.sqlite" || name == "extensions.json"
        || name == "logins.json" || name == "sessionstore.jsonlz4"
    {
        return Some(browser_core::BrowserFamily::Firefox);
    }
    None
}

fn run_integrity(args: ArtifactArgs) -> Result<()> {
    let path = &args.path;

    // Default to Chromium for generic SQLite files
    let family = BrowserFamily::Chromium;

    let mut indicators = Vec::new();

    if let Ok(mut ind) = browser_integrity::check_database_integrity(path) {
        indicators.append(&mut ind);
    }
    if let Ok(mut ind) = browser_integrity::check_wal_state(path) {
        indicators.append(&mut ind);
    }
    if let Ok(mut ind) = browser_integrity::check_history_integrity(path, family.clone()) {
        indicators.append(&mut ind);
    }
    if let Ok(mut ind) = browser_integrity::check_cookie_integrity(path, family) {
        indicators.append(&mut ind);
    }

    if indicators.is_empty() {
        match args.format {
            OutputFormat::Text => println!("No integrity issues detected."),
            OutputFormat::Jsonl => println!("{{\"status\":\"clean\"}}"),
            OutputFormat::Csv => {
                println!("type,path,detail");
                println!("clean,{},no issues", path.display());
            }
        }
    } else {
        match args.format {
            OutputFormat::Text => {
                println!("Found {} integrity indicator(s):", indicators.len());
                for ind in &indicators {
                    println!("  {ind:?}");
                }
            }
            OutputFormat::Jsonl => {
                for ind in &indicators {
                    if let Ok(json) = serde_json::to_string(ind) {
                        println!("{json}");
                    }
                }
            }
            OutputFormat::Csv => {
                println!("type,detail");
                for ind in &indicators {
                    if let Ok(json) = serde_json::to_string(ind) {
                        println!("{json}");
                    }
                }
            }
        }
    }

    Ok(())
}

fn run_carve(args: ArtifactArgs) -> Result<()> {
    let path = &args.path;

    let empty = || browser_carve::CarveResult {
        records: Vec::new(),
        integrity: Vec::new(),
        stats: browser_carve::CarveStats::default(),
    };
    let free_result = browser_carve::carve_sqlite_free_pages(path).unwrap_or_else(|_| empty());
    let wal_result = browser_carve::recover_from_wal(path).unwrap_or_else(|_| empty());

    let mut all_records = free_result.records;
    all_records.extend(wal_result.records);

    let total_stats = browser_carve::CarveStats {
        bytes_scanned: free_result.stats.bytes_scanned + wal_result.stats.bytes_scanned,
        pages_scanned: free_result.stats.pages_scanned + wal_result.stats.pages_scanned,
        free_pages_found: free_result.stats.free_pages_found + wal_result.stats.free_pages_found,
        records_recovered: free_result.stats.records_recovered + wal_result.stats.records_recovered,
        records_partial: free_result.stats.records_partial + wal_result.stats.records_partial,
    };

    match args.format {
        OutputFormat::Text => {
            println!(
                "Carve stats: {} bytes scanned, {} pages, {} free pages, {} records recovered ({} partial)",
                total_stats.bytes_scanned,
                total_stats.pages_scanned,
                total_stats.free_pages_found,
                total_stats.records_recovered,
                total_stats.records_partial,
            );
            for rec in &all_records {
                println!(
                    "  offset={} table={} method={:?} quality={:?} fields={}",
                    rec.offset,
                    rec.table,
                    rec.method,
                    rec.quality,
                    serde_json::to_string(&rec.fields).unwrap_or_default(),
                );
            }
        }
        OutputFormat::Jsonl => {
            if let Ok(json) = serde_json::to_string(&total_stats) {
                println!("{json}");
            }
            for rec in &all_records {
                if let Ok(json) = serde_json::to_string(rec) {
                    println!("{json}");
                }
            }
        }
        OutputFormat::Csv => {
            println!("offset,table,method,quality,fields");
            for rec in &all_records {
                println!(
                    "{},{},{:?},{:?},{}",
                    rec.offset,
                    format::csv_escape(&rec.table),
                    rec.method,
                    rec.quality,
                    format::csv_escape(&serde_json::to_string(&rec.fields).unwrap_or_default()),
                );
            }
        }
    }

    Ok(())
}

fn run_triage(args: TriageArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(|| {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
    });

    let report = browser_rt::triage(&home)?;

    match args.format {
        OutputFormat::Text => {
            println!("Browser Forensic Triage Report");
            println!("==============================");
            println!("Generated: {}", report.generated_at_ns);
            println!("Profiles found: {}", report.profiles.len());
            println!("Events parsed: {}", report.events.len());
            println!("Integrity indicators: {}", report.integrity.len());
            println!("Carved records: {}", report.carved.len());

            if !report.events.is_empty() {
                println!("\nTimeline ({} events):", report.events.len());
                for ev in report.events.iter().take(50) {
                    println!("  {}", format::event_to_text(ev));
                }
                if report.events.len() > 50 {
                    println!("  ... and {} more events", report.events.len() - 50);
                }
            }
        }
        OutputFormat::Jsonl => {
            if let Ok(json) = serde_json::to_string(&report) {
                println!("{json}");
            }
        }
        OutputFormat::Csv => {
            println!("{}", format::TIMELINE_CSV_HEADER);
            for ev in &report.events {
                println!("{}", format::event_to_csv_row(ev));
            }
        }
    }

    Ok(())
}

fn print_events(events: &[browser_core::BrowserEvent], format: &OutputFormat) {
    match format {
        OutputFormat::Csv => {
            println!("{}", format::TIMELINE_CSV_HEADER);
            for ev in events {
                println!("{}", format::event_to_csv_row(ev));
            }
        }
        OutputFormat::Jsonl => {
            for ev in events {
                println!("{}", format::event_to_jsonl(ev));
            }
        }
        OutputFormat::Text => {
            for ev in events {
                println!("{}", format::event_to_text(ev));
            }
        }
    }
}
