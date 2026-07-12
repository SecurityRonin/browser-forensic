# Decryption validation

How each decryption path in `browser-forensic-decrypt` was checked, and by whom.
Tiers follow the project's evidence standard:

* **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or the data is real-world.
* **Tier 2** — real engine/tool output whose ground truth is derivable from the
  documented construction or confirmed by an independent oracle; genuinely
  checked, but the scenario was chosen here.
* **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching.

## Windows Chromium (Milestone 2b)

**No Windows profile exists on the build host, so this milestone is NOT validated
end-to-end against a real Windows profile.** Each path is validated as below;
vectors live in `crates/browser-forensic-decrypt/tests/data/win_dpapi_vectors.json`
(generator + provenance in `tests/data/README.md`).

| Path | Primitive | Validation | Tier |
|---|---|---|---|
| `decrypt_chromium_value_win` (`v10`/`v11`) | AES-256-GCM | RustCrypto `aes-gcm` (audited) decrypts a PyCryptodome-oracle value under an externally-fixed key → known plaintext; a flipped tag → `Err`. | 2 |
| AES-256-GCM primitive | AES-256-GCM | NIST CAVP KAT (`gcmEncryptExtIV256`, empty PT/AAD, published tag `bdc1ac88…76f0`) verifies; a flipped tag → `Err`. | 1 (primitive) |
| `decrypt_masterkey_file` | Microsoft iterated-HMAC-SHA512 KDF + AES-256-CBC + HMAC | A synthetic master-key file built to the `[MS-DPAPI]` layout is decrypted by **impacket** (`dpapi.py`, independent third-party) to the same 64-byte key; the same bytes are decrypted by this Rust code to the same key. Wrong password → `WrongDpapiPassword` (rejected by impacket too). | 2 |
| `decrypt_dpapi_blob` | HMAC-SHA512 session key + AES-256-CBC + PKCS7 + signature | impacket decrypts the same synthetic blob to the same 32-byte Chromium key; this Rust code independently recovers it; tampering → `Err`. | 2 |
| `decrypt_chromium_key_dpapi` (Local State) | base64 + `DPAPI` prefix + blob | End-to-end: `base64("DPAPI"+blob)` from a synthetic `Local State` → the 32-byte key, via a supplied master key and via password+SID+master-key file. | 2 |
| `v20` App-Bound detection | — | Refused with `AppBoundUnsupported` (needs the SYSTEM key); never fabricated. | 2 |

### What "tier-2, impacket-confirmed" means here

The DPAPI encoder in `tests/data/gen_win.py` is written to the `[MS-DPAPI]` spec.
impacket's decrypt path is unrelated third-party code; that it recovers the known
master key and Chromium key from our synthetic artifacts — and rejects a wrong
password — confirms the artifacts are genuine DPAPI structures for that password.
This Rust implementation then independently recovers the same values. This is
**not** a real-Windows-profile validation (tier 1); it is *"implemented to spec +
cross-checked against impacket on synthetic vectors."*

### Scope and honest limits

* Only the modern algorithm pair Chromium produces on Windows 10/11 is
  supported (`CALG_SHA_512` + `CALG_AES_256`). Any other algorithm id is refused
  loudly with the offending value — never fabricated, never silently wrong.
* Legacy 3DES/SHA1 DPAPI blobs are out of scope and rejected with a clear
  `UnsupportedAlgorithm` diagnostic rather than decrypted.
* The blob signature is verified with the standard HMAC construction used by
  modern Windows; the master-key iteration count is capped (`MAX_ITERATIONS`) so
  a hostile file is a loud error, not a hang.
* Robustness: the DPAPI blob + Local State parsers are exercised by the
  `fuzz_decrypt_dpapi` cargo-fuzz target (must-not-panic; 10.5M runs / 91s clean
  at time of writing).

## Firefox NSS + macOS Chromium (Milestone 2a)

* **Firefox NSS** (`ff3des`, `ffpbes2`) — validated against the unrelated
  **firepwd** tool (tier 1 on PBES2; the 3DES login step falls back to the
  firepwd-confirmed ASN.1 decoder + standard 3DES-CBC). See
  `tests/data/README.md`.
* **macOS Chromium `v10`** — validated against a Python `hashlib` + `cryptography`
  oracle with an externally-fixed key (tier 2).

## The four hard rules (all paths)

1. **RustCrypto only** — every primitive is an audited crate (`aes`, `aes-gcm`,
   `cbc`, `des`, `pbkdf2`, `hmac`, `sha1`, `sha2`); nothing hand-rolled. The
   DPAPI KDF composes audited HMAC-SHA512, it does not reinvent a primitive.
2. **Never fabricate** — a wrong/absent key or a failed authentication tag /
   signature / padding is always a typed `Err`, never plausible-but-wrong bytes.
3. **Secure by default** — decryption requires an explicitly supplied secret
   (password, master key, or Local State + DPAPI secret); never silent, never on
   by default.
4. **Passwords double-gated** — a plaintext *password* needs both `--decrypt` and
   `--include-passwords`; default output never contains one.
