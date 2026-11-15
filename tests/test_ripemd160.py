"""RIPEMD-160 fallback tests for scripts/check_name_tx.py. Run with python3 -I.

Claim: the pure fallback matches the published RIPEMD-160 test vectors and,
where this Python's hashlib has ripemd160, matches it on varied lengths
including every padding boundary; with hashlib's ripemd160 forced unavailable,
the synthetic name_new fixture commitment (written by make_fixture.py) still
verifies through the fallback and a wrong name still fails.
Limit: the one-million-'a' vector is skipped (too slow in pure Python).
"""
import hashlib
import importlib.util
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "scripts", "check_name_tx.py")
spec = importlib.util.spec_from_file_location("chk", target)
chk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chk)

fail = 0
passed = 0


def expect(cond, what):
    global fail, passed
    if cond:
        passed += 1
    else:
        fail += 1
        print("FAIL:", what)


# Published vectors (RIPEMD-160 home page, Bosselaers).
VECTORS = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
]
for msg, want in VECTORS:
    expect(chk.ripemd160_pure(msg).hex() == want, f"vector {msg[:16]!r}")

try:
    hashlib.new("ripemd160")
    have_lib = True
except ValueError:
    have_lib = False
print("hashlib ripemd160:", "available" if have_lib else "unavailable (fallback is the only path)")
if have_lib:
    for n in list(range(0, 130)) + [255, 256, 1000]:
        data = bytes((i * 7 + n) & 0xFF for i in range(n))
        expect(chk.ripemd160_pure(data) == hashlib.new("ripemd160", data).digest(), f"cross-check length {n}")

# Forced fallback: the real (never broadcast) name_new fixture still verifies.
real_new = hashlib.new


def no_ripemd(name, *a, **k):
    if name.lower() == "ripemd160":
        raise ValueError("unsupported hash type ripemd160")
    return real_new(name, *a, **k)


chk.hashlib.new = no_ripemd
try:
    d = json.load(open(os.path.join(here, "fixtures", "name_new.synthetic.json")))
    out = [o for o in d["vout"] if "nameOp" in o["scriptPubKey"]][0]
    rand = bytes.fromhex("33a50fe344d993d97cbb567a2ad6c28b4f561700")
    expect(chk.hash160(rand + b"id/example") == out["scriptPubKey"]["nameOp"]["hash"], "fixture commitment via fallback")
    expect(chk.hash160(rand + b"id/exampl3") != out["scriptPubKey"]["nameOp"]["hash"], "wrong name refused via fallback")
finally:
    chk.hashlib.new = real_new

print(f"ripemd160 pass={passed} fail={fail}")
sys.exit(1 if fail else 0)
