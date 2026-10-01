"""Helpers shared by gen_scenarios.py, mockvt.py and run.py.

gen_bytes(size, seed) returns `size` pseudo-random bytes derived from `seed`
(a 1 MiB SHA-256 keystream block, repeated).  Inputs too large to generate
eagerly (64 MiB big-file uploads, the 32 MiB scanMemBuf limit) are written
at run time with write_gen(); the model hashes them with blob_of_gen().

blob(data) is the one description of a byte string used everywhere
(request bodies, multipart parts, created files): len + sha256, plus the
decoded text when it is short printable UTF-8 (for readable diffs only; the
checker compares len + sha256).
"""
import hashlib

_BLOCK = 1 << 20
_cache = {}


def _block(seed: str) -> bytes:
    b = _cache.get(seed)
    if b is None:
        out = bytearray()
        h = hashlib.sha256(seed.encode()).digest()
        while len(out) < _BLOCK:
            h = hashlib.sha256(h).digest()
            out += h
        b = bytes(out[:_BLOCK])
        _cache[seed] = b
    return b


def gen_bytes(size: int, seed: str) -> bytes:
    blk = _block(seed)
    reps, rem = divmod(size, _BLOCK)
    return blk * reps + blk[:rem]


def write_gen(path, size: int, seed: str):
    blk = _block(seed)
    reps, rem = divmod(size, _BLOCK)
    with open(path, "wb") as f:
        for _ in range(reps):
            f.write(blk)
        f.write(blk[:rem])


def blob(data: bytes):
    d = {"len": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    try:
        txt = data.decode("utf-8")
        if len(txt) <= 512 and txt.isprintable():
            d["text"] = txt
    except UnicodeDecodeError:
        pass
    return d


def blob_of_gen(size: int, seed: str):
    h = hashlib.sha256()
    blk = _block(seed)
    reps, rem = divmod(size, _BLOCK)
    for _ in range(reps):
        h.update(blk)
    h.update(blk[:rem])
    return {"len": size, "sha256": h.hexdigest()}
