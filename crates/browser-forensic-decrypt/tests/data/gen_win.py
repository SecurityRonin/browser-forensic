#!/usr/bin/env python3
"""Emit the committed Rust test-vector file for M2b (Windows Chromium).

Provenance / tiering (see docs/validation.md):
 * GCM v10/v11 blobs: encrypted with PyCryptodome (independent oracle) under an
   EXTERNALLY-FIXED key (0x00..0x1f) — tier-2.
 * NIST_GCM_*: NIST CAVP AES-256-GCM KAT (gcmEncryptExtIV256, empty PT/AAD) —
   published answer key — tier-1 for the primitive.
 * DPAPI masterkey + blob: synthetic, generated to [MS-DPAPI] layout and CONFIRMED
   by impacket's decrypt path (independent third-party oracle) — tier-2.
"""
import json, struct, hashlib, hmac, os, base64
from Cryptodome.Cipher import AES
from impacket import dpapi

PASSWORD = "Password123!"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
CHROMIUM_KEY = bytes(range(32))
CALG_SHA_512 = 0x800E
CALG_AES_256 = 0x6610

def prekey_sha1(pw, sid):
    ph = hashlib.sha1(pw.encode("utf-16le")).digest()
    return hmac.new(ph, (sid + "\0").encode("utf-16le"), hashlib.sha1).digest()

def ms_derive_key(passphrase, salt, keylen, count):
    prf = lambda p, s: hmac.new(p, s, hashlib.sha512).digest()
    out = b""; i = 1
    while len(out) < keylen:
        U = salt + struct.pack("!L", i); i += 1
        derived = prf(passphrase, U)
        for _ in range(count - 1):
            actual = prf(passphrase, derived)
            derived = (int.from_bytes(derived, "little") ^ int.from_bytes(actual, "little")).to_bytes(len(actual), "little")
        out += derived
    return out[:keylen]

def pkcs7(b, bs=16):
    p = bs - (len(b) % bs); return b + bytes([p]) * p

def build_masterkey_file(mk64, prekey, count=8000):
    salt = os.urandom(16)
    derived = ms_derive_key(prekey, salt, 48, count)
    ckey, iv = derived[:32], derived[32:48]
    hsalt = os.urandom(16)
    hkey = hmac.new(prekey, hsalt, hashlib.sha512).digest()
    themac = hmac.new(hkey, mk64, hashlib.sha512).digest()
    clear = hsalt + themac + mk64
    data = AES.new(ckey, AES.MODE_CBC, iv).encrypt(clear)
    mk = struct.pack("<L", 2) + salt + struct.pack("<L", count) + struct.pack("<L", CALG_SHA_512) + struct.pack("<L", CALG_AES_256) + data
    guid = "01234567-89ab-cdef-0123-456789abcdef".encode("utf-16le").ljust(72, b"\x00")[:72]
    mkf = struct.pack("<L", 2) + struct.pack("<L", 0) * 2 + guid + struct.pack("<L", 0) * 3 + \
          struct.pack("<Q", len(mk)) + struct.pack("<Q", 0) * 3 + mk
    return mkf

def build_blob(mk64, guid_mk, plaintext):
    keyhash = hashlib.sha1(mk64).digest()
    salt = os.urandom(16)
    session = hmac.new(keyhash, salt, hashlib.sha512).digest()
    data = AES.new(session[:32], AES.MODE_CBC, b"\x00" * 16).encrypt(pkcs7(plaintext))
    ssalt = os.urandom(16)
    def asm(sign):
        o = struct.pack("<L", 1) + b"\x00" * 16 + struct.pack("<L", 0) + guid_mk
        o += struct.pack("<L", 0) + struct.pack("<L", 0)
        o += struct.pack("<L", CALG_AES_256) + struct.pack("<L", 256)
        o += struct.pack("<L", len(salt)) + salt + struct.pack("<L", 0)
        o += struct.pack("<L", CALG_SHA_512) + struct.pack("<L", 512)
        o += struct.pack("<L", len(ssalt)) + ssalt
        o += struct.pack("<L", len(data)) + data
        o += struct.pack("<L", len(sign)) + sign
        return o
    tmp = asm(b"\x00" * 64)
    tosign = tmp[20: len(tmp) - 64 - 4]
    sign = hmac.new(keyhash, ssalt, hashlib.sha512); sign.update(tosign)
    return asm(sign.digest())

def gcm_vectors():
    key = bytes(range(32)); nonce = bytes.fromhex("0102030405060708090a0b0c")
    pt = b"session-token=SECRET42"
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(pt)
    return {
        "GCM_KEY_HEX": key.hex(),
        "GCM_PLAINTEXT": pt.decode(),
        "V10_BLOB_HEX": (b"v10" + nonce + ct + tag).hex(),
        "V11_BLOB_HEX": (b"v11" + nonce + ct + tag).hex(),
        # A v20 (App-Bound) blob: prefix only — offline-unrecoverable without SYSTEM key.
        "V20_BLOB_HEX": (b"v20" + os.urandom(24)).hex(),
        "NIST_GCM_KEY_HEX": "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        "NIST_GCM_IV_HEX": "516c33929df5a3284ff463d7",
        "NIST_GCM_CT_HEX": "",
        "NIST_GCM_TAG_HEX": "bdc1ac884d332457a1d2664f168c76f0",
    }

def main():
    mk64 = bytes.fromhex("312a41376b1c7a438d09f643d63bd30d147f18756232b62e204f7ddcabc5cd7b5e04f2e4bd8bddc9f80e08724ed88cf44c552a16335b3243f2d879be6b516d9f")
    prekey = prekey_sha1(PASSWORD, SID)
    guid_mk = bytes.fromhex("00112233445566778899aabbccddeeff")
    mkf = build_masterkey_file(mk64, prekey)
    blob = build_blob(mk64, guid_mk, CHROMIUM_KEY)
    # confirm with oracle
    m = dpapi.MasterKeyFile(mkf)
    mkobj = dpapi.MasterKey(mkf[len(m):len(m) + m["MasterKeyLen"]])
    dec = None
    for k in dpapi.deriveKeysFromUser(SID, PASSWORD):
        r = mkobj.decrypt(k)
        if r: dec = r; break
    assert dec == mk64
    assert dpapi.DPAPI_BLOB(blob).decrypt(dec) == CHROMIUM_KEY
    local_state = json.dumps({"os_crypt": {"encrypted_key": base64.b64encode(b"DPAPI" + blob).decode()}})
    out = {
        "_provenance": "GCM v10/v11: PyCryptodome oracle, fixed key (tier-2). NIST_GCM: CAVP KAT (tier-1). DPAPI mkf/blob: [MS-DPAPI] layout, confirmed by impacket decrypt (tier-2). NOT validated against a real Windows profile.",
        "PASSWORD": PASSWORD, "SID": SID,
        "PREKEY_HEX": prekey.hex(),
        "MASTERKEY64_HEX": mk64.hex(),
        "CHROMIUM_KEY_HEX": CHROMIUM_KEY.hex(),
        "MASTERKEY_FILE_HEX": mkf.hex(),
        "DPAPI_BLOB_HEX": blob.hex(),
        "LOCAL_STATE_JSON": local_state,
        **gcm_vectors(),
    }
    import sys
    json.dump(out, open(sys.argv[1], "w"), indent=2)
    print("ORACLE-CONFIRMED, wrote", sys.argv[1])

if __name__ == "__main__":
    main()
