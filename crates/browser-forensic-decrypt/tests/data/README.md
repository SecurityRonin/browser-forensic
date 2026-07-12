# Firefox NSS decryption test fixtures

Synthetic, self-generated Firefox profiles carrying **known** credentials, used
to validate `decrypt_firefox_logins` against a documented ground truth.

| Fixture | Scheme | Known username | Known password |
|---|---|---|---|
| `ff3des/` | legacy `pbeWithSha1AndTripleDES-CBC` (3DES) + `des-ede3-cbc` logins | `alice@example.com` | `S3cr3t-Passw0rd!` |
| `ffpbes2/` | modern PKCS#5 PBES2 (PBKDF2-HMAC-SHA256 → AES-256-CBC) + `aes256-CBC` logins | `alice@example.com` | `S3cr3t-Passw0rd!` |

Each profile has a minimal `key4.db` (`metadata` + `nssPrivate` tables, exactly
the rows/columns NSS decryption reads) and a `logins.json`. The master password
is empty.

## Provenance

* **Source / generator:** `gen_ff.py` (in this directory) — an *independent*
  NSS encoder built on `pycryptodome` primitives, written from the NSS PBE /
  PBES2 specification (firepwd, lclevy — <https://github.com/lclevy/firepwd>).
* **Ground-truth oracle (tier-1, third party):** the fixtures were decrypted with
  the unrelated **`firepwd.py`** tool. On `ffpbes2/` firepwd recovered the exact
  `alice@example.com` / `S3cr3t-Passw0rd!` pair, independently confirming the
  fixture is genuine (a wrong derivation would fail the `password-check` and
  yield garbage). On `ff3des/` firepwd confirmed the `password-check` and
  unwrapped the master key; its current `main()` cannot complete the 3DES login
  loop (it only handles 32/48-byte master keys), so the 3DES *login-blob* step is
  validated by the shared, firepwd-confirmed ASN.1 decoder plus standard 3DES-CBC.
* **License / redistribution:** wholly synthetic, contains no real personal data;
  freely redistributable under this repository's licence.

## Regenerate

```
python3 -m venv env && ./env/bin/pip install pycryptodome pyasn1
./env/bin/python gen_ff.py            # writes /tmp/ff3des and /tmp/ffpbes2
# cross-check with the third-party oracle:
./env/bin/python firepwd.py -d /tmp/ffpbes2
```

Regenerated files differ byte-for-byte (random salts/IVs/master key) but carry
the same known credentials.

# Windows Chromium (DPAPI + AES-256-GCM) test vectors — `win_dpapi_vectors.json`

Synthetic vectors for `chromium_win` / `dpapi`, carrying **known** ground truth
(masterkey `312a…6d9f`, 32-byte Chromium key `00010203…1e1f`, plaintext
`session-token=SECRET42`).

## Provenance / tiering

* **Source / generator:** `gen_win.py` (this directory) — an independent DPAPI
  encoder written to the `[MS-DPAPI]` masterkey/blob layout and Chromium's
  `os_crypt_win.cc` value format.
* **GCM `v10`/`v11` blobs — tier-2:** encrypted with **PyCryptodome** (an
  independent oracle) under an *externally-fixed* AES-256 key (`00..1f`); the
  Rust code recovers `session-token=SECRET42`.
* **`NIST_GCM_*` — tier-1 for the primitive:** the NIST CAVP AES-256-GCM KAT
  (`gcmEncryptExtIV256`, empty PT/AAD, tag `bdc1ac88…76f0`) — a published answer
  key, not one we authored.
* **DPAPI masterkey + blob — tier-2:** generated to the `[MS-DPAPI]` layout and
  **confirmed by impacket's `dpapi.py` decrypt path** (an unrelated third-party
  tool): impacket independently recovers the same masterkey and 32-byte key, and
  rejects a wrong password. The *same bytes* are the Rust vectors.
* **NOT tier-1 end-to-end:** these are **not** validated against a real Windows
  profile in this environment (no Windows host). See `docs/validation.md`.
* **License / redistribution:** wholly synthetic, no real personal data; freely
  redistributable under this repository's licence.

## Regenerate

```
python3 -m venv env && ./env/bin/pip install pycryptodome impacket
./env/bin/python gen_win.py win_dpapi_vectors.json   # re-asserts the impacket oracle
```
