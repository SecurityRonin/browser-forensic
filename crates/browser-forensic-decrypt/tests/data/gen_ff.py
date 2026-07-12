#!/usr/bin/env python3
"""Independent NSS fixture generator (pycryptodome primitives).

Mints a minimal key4.db + logins.json for KNOWN credentials, empty master
password, in both the legacy 3DES-CBC PBE scheme and the modern PBES2 scheme.
Validated by the third-party firepwd.py oracle (which fails loudly if the
derivation is wrong) — so it is a genuine independent anchor, not a self-test.
"""
import hashlib, hmac, os, sqlite3, json, base64, struct, sys
from hashlib import sha1, pbkdf2_hmac
from Crypto.Cipher import DES3, AES

KNOWN_USER = "alice@example.com"
KNOWN_PASS = "S3cr3t-Passw0rd!"
HOST = "https://accounts.example.com"
CKA_ID = bytes.fromhex("f8000000000000000000000000000001")

# ---- minimal DER encoder ----
def tlv(tag, body):
    if len(body) < 0x80:
        L = bytes([len(body)])
    elif len(body) < 0x100:
        L = bytes([0x81, len(body)])
    else:
        L = bytes([0x82, len(body) >> 8, len(body) & 0xff])
    return bytes([tag]) + L + body
def SEQ(*ch): return tlv(0x30, b"".join(ch))
def OCT(b): return tlv(0x04, b)
def OID(b): return tlv(0x06, b)
def INT(b): return tlv(0x02, b)

OID_PBE_3DES = bytes.fromhex("2a864886f70d010c050103")
OID_DES3     = bytes.fromhex("2a864886f70d0307")
OID_PBES2    = bytes.fromhex("2a864886f70d01050d")
OID_PBKDF2   = bytes.fromhex("2a864886f70d01050c")
OID_HMAC256  = bytes.fromhex("2a864886f70d0209")
OID_AES256   = bytes.fromhex("60864801650304012a")
CHECK = b"password-check\x02\x02"

def pkcs7(b, bs):
    p = bs - (len(b) % bs)
    return b + bytes([p]) * p

# ---- 3DES PBE key/iv derivation (mirrors NSS decryptMoz3DES) ----
def moz3des_kv(gsalt, mp, esalt):
    hp = sha1(gsalt + mp).digest()
    pes = esalt + b"\x00" * (20 - len(esalt))
    chp = sha1(hp + esalt).digest()
    k1 = hmac.new(chp, pes + esalt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + esalt, sha1).digest()
    k = k1 + k2
    return k[:24], k[-8:]

def pbe_3des_item(gsalt, mp, esalt, plaintext):
    key, iv = moz3des_kv(gsalt, mp, esalt)
    ct = DES3.new(key, DES3.MODE_CBC, iv).encrypt(plaintext)
    return SEQ(SEQ(OID(OID_PBE_3DES), SEQ(OCT(esalt), INT(b"\x01"))), OCT(ct))

def pbes2_key(gsalt, mp, esalt, it):
    return pbkdf2_hmac("sha256", sha1(gsalt + mp).digest(), esalt, it, 32)

def pbe_pbes2_item(gsalt, mp, esalt, it, iv14, plaintext):
    key = pbes2_key(gsalt, mp, esalt, it)
    iv = b"\x04\x0e" + iv14
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
    kdf = SEQ(OID(OID_PBKDF2), SEQ(OCT(esalt), INT(struct.pack(">I", it).lstrip(b"\x00") or b"\x00"), INT(b"\x20"), SEQ(OID(OID_HMAC256))))
    enc = SEQ(OID(OID_AES256), OCT(iv14))
    return SEQ(SEQ(OID(OID_PBES2), SEQ(kdf, enc)), OCT(ct))

def login_blob_3des(master_key, plaintext):
    iv = os.urandom(8)
    ct = DES3.new(master_key[:24], DES3.MODE_CBC, iv).encrypt(pkcs7(plaintext, 8))
    return base64.b64encode(SEQ(OCT(CKA_ID), SEQ(OID(OID_DES3), OCT(iv)), OCT(ct))).decode()

def login_blob_aes(master_key, plaintext):
    iv = os.urandom(16)
    ct = AES.new(master_key[:32], AES.MODE_CBC, iv).encrypt(pkcs7(plaintext, 16))
    return base64.b64encode(SEQ(OCT(CKA_ID), SEQ(OID(OID_AES256), OCT(iv)), OCT(ct))).decode()

def write_key4(path, gsalt, item2, a11):
    if os.path.exists(path): os.remove(path)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE metadata (id TEXT PRIMARY KEY, item1 BLOB, item2 BLOB)")
    c.execute("INSERT INTO metadata VALUES ('password', ?, ?)", (gsalt, item2))
    c.execute("CREATE TABLE nssPrivate (a11 BLOB, a102 BLOB)")
    c.execute("INSERT INTO nssPrivate VALUES (?, ?)", (a11, CKA_ID))
    c.commit(); c.close()

def write_logins(path, enc_user, enc_pass):
    json.dump({"logins": [{
        "hostname": HOST, "encryptedUsername": enc_user, "encryptedPassword": enc_pass,
        "timeCreated": 1648000000000, "usernameField": "email", "formSubmitURL": HOST}]},
        open(path, "w"))

def gen_3des(outdir):
    os.makedirs(outdir, exist_ok=True)
    mp = b""
    gsalt = os.urandom(20)
    mk = os.urandom(24)
    item2 = pbe_3des_item(gsalt, mp, os.urandom(20), CHECK)
    a11 = pbe_3des_item(gsalt, mp, os.urandom(20), pkcs7(mk, 8))
    write_key4(os.path.join(outdir, "key4.db"), gsalt, item2, a11)
    write_logins(os.path.join(outdir, "logins.json"),
                 login_blob_3des(mk, KNOWN_USER.encode()), login_blob_3des(mk, KNOWN_PASS.encode()))

def gen_pbes2(outdir):
    os.makedirs(outdir, exist_ok=True)
    mp = b""
    gsalt = os.urandom(32)
    mk = os.urandom(32)
    it = 10000
    item2 = pbe_pbes2_item(gsalt, mp, os.urandom(32), it, os.urandom(14), CHECK)
    a11 = pbe_pbes2_item(gsalt, mp, os.urandom(32), it, os.urandom(14), pkcs7(mk, 16))
    write_key4(os.path.join(outdir, "key4.db"), gsalt, item2, a11)
    write_logins(os.path.join(outdir, "logins.json"),
                 login_blob_aes(mk, KNOWN_USER.encode()), login_blob_aes(mk, KNOWN_PASS.encode()))

if __name__ == "__main__":
    gen_3des("/tmp/ff3des")
    gen_pbes2("/tmp/ffpbes2")
    print("KNOWN_USER", KNOWN_USER)
    print("KNOWN_PASS", KNOWN_PASS)
    print("generated /tmp/ff3des and /tmp/ffpbes2")
