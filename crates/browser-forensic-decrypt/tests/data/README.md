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
