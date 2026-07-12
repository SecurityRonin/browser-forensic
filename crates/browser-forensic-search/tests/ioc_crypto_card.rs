//! Crypto-address and credit-card candidate extraction.
//!
//! Ground truth is external and independently checkable:
//! - Card PANs are the card networks' published test numbers (all Luhn-valid).
//! - `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` is the Bitcoin genesis address.
//! - `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` is the BIP-173 bech32 example.
//! - `0x52908400098527886E0F7030069857D2E4169EE7` is an EIP-55 spec vector.
//!
//! Every reported entity is a *candidate*, never an assertion that the value is
//! a real card or wallet.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_search::ioc::{extract_from_text, IocKind};

fn hits(text: &str) -> Vec<(IocKind, String, Option<String>)> {
    extract_from_text(text)
        .into_iter()
        .map(|(k, v, _off, note)| (k, v, note))
        .collect()
}

fn value_note(text: &str, kind: IocKind, value: &str) -> Option<Option<String>> {
    hits(text)
        .into_iter()
        .find(|(k, v, _)| *k == kind && v == value)
        .map(|(_, _, note)| note)
}

// ---- credit card (Luhn) -----------------------------------------------------

#[test]
fn luhn_valid_visa_16() {
    let note = value_note(
        "card 4111111111111111 here",
        IocKind::CreditCard,
        "4111111111111111",
    )
    .expect("visa test PAN should be a candidate");
    assert_eq!(note.as_deref(), Some("Luhn-valid"));
}

#[test]
fn luhn_valid_amex_15() {
    assert!(value_note(
        "amex 378282246310005",
        IocKind::CreditCard,
        "378282246310005"
    )
    .is_some());
}

#[test]
fn luhn_invalid_16_rejected() {
    // One digit flipped from a valid Visa test number: fails Luhn.
    assert!(value_note(
        "bad 4111111111111112",
        IocKind::CreditCard,
        "4111111111111112"
    )
    .is_none());
}

#[test]
fn short_digit_run_not_a_card() {
    assert!(hits("order 12345678")
        .iter()
        .all(|(k, _, _)| *k != IocKind::CreditCard));
}

// ---- BTC base58check --------------------------------------------------------

#[test]
fn btc_base58_genesis_address() {
    let note = value_note(
        "donate 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa please",
        IocKind::BitcoinBase58,
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    )
    .expect("genesis address should be a checksum-valid candidate");
    assert_eq!(note.as_deref(), Some("checksum-valid"));
}

#[test]
fn btc_base58_bad_checksum_rejected() {
    // Final char altered: the base58check checksum no longer matches.
    assert!(hits("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
        .iter()
        .all(|(k, _, _)| *k != IocKind::BitcoinBase58));
}

// ---- BTC bech32 -------------------------------------------------------------

#[test]
fn btc_bech32_valid_address() {
    let note = value_note(
        "pay bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 now",
        IocKind::BitcoinBech32,
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    )
    .expect("BIP-173 bech32 example should be a checksum-valid candidate");
    assert_eq!(note.as_deref(), Some("checksum-valid"));
}

#[test]
fn btc_bech32_bad_checksum_rejected() {
    // Alter one data character: checksum fails.
    assert!(hits("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
        .iter()
        .all(|(k, _, _)| *k != IocKind::BitcoinBech32));
}

// ---- Ethereum ---------------------------------------------------------------

#[test]
fn eth_mixed_case_checksum_note() {
    let note = value_note(
        "send to 0x52908400098527886E0F7030069857D2E4169EE7",
        IocKind::Ethereum,
        "0x52908400098527886E0F7030069857D2E4169EE7",
    )
    .expect("eth candidate");
    let note = note.expect("eth should carry a checksum note");
    assert!(note.contains("mixed-case"), "note was: {note}");
}

#[test]
fn eth_all_lowercase_note() {
    let note = value_note(
        "wallet 0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        IocKind::Ethereum,
        "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
    )
    .expect("eth candidate");
    let note = note.expect("eth should carry a checksum note");
    assert!(note.contains("no case"), "note was: {note}");
}

#[test]
fn eth_wrong_length_rejected() {
    // 39 hex chars is not an address.
    assert!(hits("0x52908400098527886E0F7030069857D2E4169EE")
        .iter()
        .all(|(k, _, _)| *k != IocKind::Ethereum));
}
