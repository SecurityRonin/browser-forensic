//! Behavioural tests for the interpretation plugins. Expected timestamp strings
//! are cross-checked against the OS `date -u` oracle; the BIG-IP vector is the
//! documented F5 example (server 10.1.1.100:8080), verified independently with
//! Python `struct`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_interpret::{friendly_date, interpret_cookie, interpret_url};

// ---- friendly_date: magnitude ladder ----------------------------------------

#[test]
fn friendly_date_unix_seconds() {
    // 1700000000 -> 2023-11-14 22:13:20 UTC (oracle: `date -u -r 1700000000`)
    assert_eq!(
        friendly_date(1_700_000_000).unwrap(),
        "2023-11-14 22:13:20.000"
    );
}

#[test]
fn friendly_date_unix_millis() {
    // 13-digit -> milliseconds
    assert_eq!(
        friendly_date(1_700_000_000_000).unwrap(),
        "2023-11-14 22:13:20.000"
    );
}

#[test]
fn friendly_date_unix_micros() {
    // 16-digit -> microseconds
    assert_eq!(
        friendly_date(1_700_000_000_000_000).unwrap(),
        "2023-11-14 22:13:20.000"
    );
}

#[test]
fn friendly_date_webkit_micros() {
    // WebKit micros for 2023-11-14 22:13:20 = (1700000000 + 11644473600) * 1e6
    let webkit = (1_700_000_000_i64 + 11_644_473_600) * 1_000_000;
    assert_eq!(friendly_date(webkit).unwrap(), "2023-11-14 22:13:20.000");
}

// ---- google_searches --------------------------------------------------------

#[test]
fn google_search_basic_query() {
    let out = interpret_url("https://www.google.com/search?q=hello+world").unwrap();
    assert_eq!(out, "Searched for \"hello world\"");
}

#[test]
fn google_search_with_num_param() {
    let out = interpret_url("https://www.google.com/search?q=hello+world&num=20").unwrap();
    assert_eq!(
        out,
        "Searched for \"hello world\" [ Showing 20 results per page]"
    );
}

#[test]
fn google_search_cctld() {
    let out = interpret_url("https://www.google.co.uk/search?q=forensics").unwrap();
    assert_eq!(out, "Searched for \"forensics\"");
}

#[test]
fn google_search_requires_q() {
    // /search with no q -> not a search interpretation (falls through to query parser)
    let out = interpret_url("https://www.google.com/search?hl=en");
    // query-string parser still fires as fallback
    assert!(out.unwrap().contains("[Query String Parser]"));
}

#[test]
fn non_google_url_uses_query_parser() {
    let out = interpret_url("https://example.com/p?a=1&b=hello%20world").unwrap();
    assert_eq!(out, "a: 1 | b: hello world [Query String Parser]");
}

#[test]
fn url_without_query_is_none() {
    assert_eq!(interpret_url("https://example.com/plain"), None);
}

// ---- google_analytics -------------------------------------------------------

#[test]
fn ga_utma_cookie() {
    let out = interpret_cookie("__utma", "1.2.1700000000.1700000000.1700000000.3").unwrap();
    assert_eq!(
        out,
        "Domain Hash: 1 | Unique Visitor ID: 2 | First Visit: 2023-11-14 22:13:20.000 | \
         Previous Visit: 2023-11-14 22:13:20.000 | Last Visit: 2023-11-14 22:13:20.000 | \
         Number of Sessions: 3 | [Google Analytics Cookie]"
    );
}

#[test]
fn ga_utmb_cookie() {
    let out = interpret_cookie("__utmb", "1.5.10.1700000000").unwrap();
    assert_eq!(
        out,
        "Domain Hash: 1 | Pages Viewed: 5 | Last Visit: 2023-11-14 22:13:20.000 | \
         [Google Analytics Cookie]"
    );
}

#[test]
fn ga_ga_cookie() {
    let out = interpret_cookie("_ga", "GA1.2.1234567890.1700000000").unwrap();
    assert_eq!(
        out,
        "Client ID: 1234567890.1700000000 | First Visit: 2023-11-14 22:13:20.000 | \
         [Google Analytics Cookie]"
    );
}

// ---- quantcast --------------------------------------------------------------

#[test]
fn quantcast_qca_cookie_millis() {
    let out = interpret_cookie("__qca", "P0-123456789-1700000000000").unwrap();
    assert_eq!(out, "2023-11-14 22:13:20.000 [Quantcast Cookie Timestamp]");
}

// ---- load balancer (F5 BIG-IP) ----------------------------------------------

#[test]
fn bigip_cookie_documented_f5_example() {
    // BIGipServer<pool> = "1677787402.36895.0000" -> 10.1.1.100:8080
    let out = interpret_cookie("BIGipServerpool", "1677787402.36895.0000").unwrap();
    assert_eq!(
        out,
        "Server IP: 10.1.1.100 | Server Port: 8080 [BIG-IP Cookie]"
    );
}

#[test]
fn bigip_cookie_synthetic_vector() {
    // Encodes 1.2.3.4:80 (host 67305985, encoded port 20480), verified with struct.
    let out = interpret_cookie("BIGipServerX", "67305985.20480.0000").unwrap();
    assert_eq!(out, "Server IP: 1.2.3.4 | Server Port: 80 [BIG-IP Cookie]");
}

// ---- generic timestamps -----------------------------------------------------

#[test]
fn generic_whole_value_timestamp() {
    let out = interpret_cookie("some_cookie", "1700000000").unwrap();
    assert_eq!(out, "2023-11-14 22:13:20.000 [potential timestamp]");
}

#[test]
fn generic_embedded_timestamp() {
    let out = interpret_cookie("c", "{\"timestamp\":1700000000000}").unwrap();
    assert_eq!(out, "2023-11-14 22:13:20.000 [potential timestamp]");
}

#[test]
fn opaque_cookie_is_none() {
    assert_eq!(interpret_cookie("sid", "abc123def456"), None);
}
