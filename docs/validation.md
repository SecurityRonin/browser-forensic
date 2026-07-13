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

**The DPAPI format + crypto is delegated to the fleet `dpapi-core` crate**
(`dpapi-forensic`, Apache-2.0): the master-key file KDF, blob parse + session-key
derivation, and `Local State` base64/`DPAPI`-prefix strip all run in that audited,
fuzz-hardened, impacket-validated crate rather than hand-rolled here (DRY). This
crate keeps only thin glue — type-preserving wrappers, the
`DpapiError`→`DecryptError` mapping, and the `Local State` JSON extraction — plus
its own AES-256-GCM `v10`/`v11` value decryption and the `v20` App-Bound refusal.
`dpapi-core` additionally validates the `[MS-DPAPI]` provider GUID
(`df9d8cd0-1501-11d1-8c7a-00c04fc297eb`) in each blob, which the vectors now carry.

| Path | Primitive | Validation | Tier |
|---|---|---|---|
| `decrypt_chromium_value_win` (`v10`/`v11`) | AES-256-GCM | RustCrypto `aes-gcm` (audited) decrypts a PyCryptodome-oracle value under an externally-fixed key → known plaintext; a flipped tag → `Err`. | 2 |
| AES-256-GCM primitive | AES-256-GCM | NIST CAVP KAT (`gcmEncryptExtIV256`, empty PT/AAD, published tag `bdc1ac88…76f0`) verifies; a flipped tag → `Err`. | 1 (primitive) |
| `decrypt_masterkey_file` (→ `dpapi-core`) | Microsoft iterated-HMAC-SHA512 KDF + AES-256-CBC + HMAC | A synthetic master-key file built to the `[MS-DPAPI]` layout is decrypted by **impacket** (`dpapi.py`, independent third-party) to the same 64-byte key; the same bytes are decrypted by `dpapi-core` (via this wrapper) to the same key. Wrong password → `WrongDpapiPassword` (rejected by impacket too). | 2 |
| `decrypt_dpapi_blob` (→ `dpapi-core`) | HMAC-SHA512 session key + AES-256-CBC + PKCS7 + signature | impacket decrypts the same synthetic blob to the same 32-byte Chromium key; `dpapi-core` independently recovers it; tampering → `Err`. | 2 |
| `decrypt_chromium_key_dpapi` (Local State, → `dpapi-core`) | base64 + `DPAPI` prefix + blob | End-to-end: `base64("DPAPI"+blob)` from a synthetic `Local State` → the 32-byte key, via a supplied master key and via password+SID+master-key file. | 2 |
| `v20` App-Bound detection | — | Refused with `AppBoundUnsupported` (needs the SYSTEM key); never fabricated. | 2 |

### What "tier-2, impacket-confirmed" means here

The DPAPI encoder in `tests/data/gen_win.py` is written to the `[MS-DPAPI]` spec.
impacket's decrypt path is unrelated third-party code; that it recovers the known
master key and Chromium key from our synthetic artifacts — and rejects a wrong
password — confirms the artifacts are genuine DPAPI structures for that password.
The `dpapi-core` crate this code now delegates to then independently recovers the
same values (and is itself impacket-validated in its own repository). This is
**not** a real-Windows-profile validation (tier 1); it is *"implemented to spec +
cross-checked against impacket on synthetic vectors."*

### Scope and honest limits

* Only the modern algorithm pair Chromium produces on Windows 10/11 is
  supported (`CALG_SHA_512` + `CALG_AES_256`). Any other algorithm id is refused
  loudly with the offending value — never fabricated, never silently wrong.
* Legacy 3DES/SHA1 DPAPI blobs are out of scope and rejected with a clear
  `UnsupportedAlgorithm` diagnostic rather than decrypted.
* The blob signature is verified with the standard HMAC construction used by
  modern Windows; the master-key KDF (in `dpapi-core`) uses bounded arithmetic
  (saturating iteration loop), so a hostile file cannot overflow or panic.
* Robustness: the DPAPI blob + Local State parsers are exercised by the
  `fuzz_decrypt_dpapi` cargo-fuzz target (must-not-panic) through this crate's
  wrappers; `dpapi-core` carries its own fuzz targets upstream.

## macOS Chromium cookie domain-hash prefix (Milestone 2c)

Chromium cookie-DB schema **v24+** prepends the raw 32-byte `SHA-256(domain)`
digest to a cookie's plaintext value *before* `v10`/`v11` encryption, then
verifies and strips it on load. Per Chromium
`net/extras/sqlite/sqlite_persistent_cookie_store.cc`:

* encrypt — `EncryptString(StrCat({crypto::SHA256HashString(cc.Domain()),
  cc.Value()}), …)`;
* load — `StartsWith(value, crypto::SHA256HashString(domain))` then
  `value = value.substr(correct_hash.length())`, else `kHashFailed`.

`domain` is the `host_key` column verbatim (the cookie's canonical `Domain()`),
and the digest is the raw 32-byte SHA-256 output (not hex).

**macOS Chromium `v10` decryption is now TIER-1.** A throwaway cookie
`br4n6probe` on host `127.0.0.1` was written by a live Chrome, then its real
`Cookies` ciphertext was decrypted with the real macOS login-Keychain "Chrome
Safe Storage" key. The recovered plaintext was
`SHA-256("127.0.0.1") || "br4n6-tier1-probe-7f3a91c2"` — the planted known value
recovered EXACTLY behind the 32-byte domain-binding prefix. Both the value and
the key material were authored/held outside this code (Chrome + the OS Keychain),
so the answer key is independent. `strip_domain_hash_prefix` now removes and
verifies that prefix; `SHA-256("127.0.0.1") =
12ca17b49af2289436f303e0166030a21e525d266e209267433801a8fd4071a0` is confirmed
byte-identical by two unrelated tools (`shasum -a 256` and Python `hashlib`).

| Path | Validation | Tier |
|---|---|---|
| macOS `v10` decrypt of a live-Chrome cookie + real Keychain key | Planted value `br4n6-tier1-probe-7f3a91c2` recovered exactly behind the confirmed `SHA-256(host)` prefix | 1 |
| `strip_domain_hash_prefix` strip+verify | Reconstructed `SHA-256(host) \|\| value` → clean value + `verified=true`; the prefix equals the independent `SHA-256("127.0.0.1")` oracle | 1 (value)/2 (oracle) |
| Domain mismatch (moved between domains) | A 32-byte prefix that is not `SHA-256(host_key)` is surfaced RAW with `domain_bound=false` — never silently stripped | 2 |

The strip is **secure by default**: it only removes the prefix when the hash
matches, so a legitimately ≥32-byte value that is not domain-bound passes through
intact, and a mismatch is reported (`domain_bound=false`) rather than dropped —
consistent with the cookie value having been moved between domains.

## Firefox NSS + macOS Chromium primitive (Milestone 2a)

* **Firefox NSS** (`ff3des`, `ffpbes2`) — validated against the unrelated
  **firepwd** tool (tier 1 on PBES2; the 3DES login step falls back to the
  firepwd-confirmed ASN.1 decoder + standard 3DES-CBC). See
  `tests/data/README.md`.
* **macOS Chromium `v10` primitive** — the AES-128-CBC + PBKDF2 key derivation is
  additionally cross-checked against a Python `hashlib` + `cryptography` oracle
  with an externally-fixed key (tier 2); the end-to-end path is tier-1 above.

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
