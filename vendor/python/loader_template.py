# DEOBF-PY-V1
# Generated self-running stub. Decrypts the original script and execs it.
from __future__ import print_function
import base64, os, sys, tempfile, atexit

_DEOBF_KEY = bytes.fromhex("__DEOBF_KEY_HEX__")
_DEOBF_BLOB = base64.b64decode("""
__DEOBF_BLOB_B64__
""")

def _rotl(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 7)

def _rounds(s):
    for _ in range(10):
        _qr(s, 0, 4, 8, 12); _qr(s, 1, 5, 9, 13); _qr(s, 2, 6, 10, 14); _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15); _qr(s, 1, 6, 11, 12); _qr(s, 2, 7, 8, 13); _qr(s, 3, 4, 9, 14)

def _le32(b, i):
    return int.from_bytes(b[i:i + 4], "little")

def _hchacha20(key, nonce16):
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    s += [_le32(key, i * 4) for i in range(8)]
    s += [_le32(nonce16, i * 4) for i in range(4)]
    _rounds(s)
    return b"".join(s[i].to_bytes(4, "little") for i in (0, 1, 2, 3, 12, 13, 14, 15))

def _chacha_block(key, nonce12, counter):
    init = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    init += [_le32(key, i * 4) for i in range(8)]
    init += [counter & 0xffffffff, _le32(nonce12, 0), _le32(nonce12, 4), _le32(nonce12, 8)]
    s = list(init)
    _rounds(s)
    return b"".join(((s[i] + init[i]) & 0xffffffff).to_bytes(4, "little") for i in range(16))

def _chacha_xor(key, nonce12, counter, data):
    out = bytearray(len(data)); off = 0; n = counter
    while off < len(data):
        block = _chacha_block(key, nonce12, n)
        take = min(64, len(data) - off)
        for i in range(take):
            out[off + i] = data[off + i] ^ block[i]
        off += take; n += 1
    return bytes(out)

def _poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    h = 0
    p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        h = (h + n) * r % p
    return ((h + s) & ((1 << 128) - 1)).to_bytes(16, "little")

def _open(key, nonce24, ct_and_tag):
    if len(ct_and_tag) < 16:
        raise ValueError("truncated ciphertext")
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    sub = _hchacha20(key, nonce24[:16])
    n12 = b"\x00" * 4 + nonce24[16:]
    pad = (16 - (len(ct) % 16)) % 16
    mac = ct + b"\x00" * pad + (0).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    expected = _poly1305(_chacha_block(sub, n12, 0)[:32], mac)
    if expected != tag:
        raise ValueError("DEOBF wrapper authentication failed")
    return _chacha_xor(sub, n12, 1, ct)

def _decrypt_blob(key, blob):
    if blob[:8] != b"DEOBFW01" or len(blob) < 50:
        raise ValueError("not a DEOBF python wrapper")
    if blob[8] != 1:
        raise ValueError("unsupported wrapper version")
    return _open(key, blob[10:34], blob[34:])

def _run_plain(plain):
    if plain[:2] == b"PK":
        fd, path = tempfile.mkstemp(suffix=".pyz")
        try:
            os.write(fd, plain)
            os.close(fd)
            fd = None
            atexit.register(lambda p=path: os.path.exists(p) and os.remove(p))
            import runpy
            sys.path.insert(0, path)
            runpy.run_path(path, run_name="__main__")
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.remove(path)
            except Exception:
                pass
        return
    src = plain.decode("utf-8")
    ns = {"__name__": "__main__", "__file__": __file__, "__builtins__": __builtins__}
    exec(compile(src, __file__, "exec"), ns)

if __name__ == "__main__":
    _run_plain(_decrypt_blob(_DEOBF_KEY, _DEOBF_BLOB))
