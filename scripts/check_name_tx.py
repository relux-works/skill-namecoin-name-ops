#!/usr/bin/env python3
"""Check a decoded Namecoin name transaction against what the operator intends.

Run with `python3 -I`. Standard library only. Reads JSON files that the node
produced (decoderawtransaction, optionally testmempoolaccept) and refuses,
with a named reason, unless every expectation holds. It never talks to the
node, never reads keys or wallets, and never broadcasts.

Exit codes: 0 all checks passed; 1 a check failed (reason on stderr);
2 bad arguments (argparse).
"""
import argparse
import decimal
import hashlib
import json
import re
import sys
from decimal import Decimal

NAME_LOCK = Decimal("0.01")
MAX_NAME_BYTES = 255   # Core rejects a longer name on reveal
MAX_VALUE_BYTES = 520
RAND_BYTES = 20        # namerawtransaction generates 20 bytes; Core rejects a longer reveal
HEX64 = re.compile(r"[0-9a-f]{64}")


class Refusal(Exception):
    pass


# RIPEMD-160 (Dobbertin, Bosselaers, Preneel, 1996). OpenSSL 3 moved it to the
# legacy provider, so hashlib often lacks it on current Linux; this pure
# implementation is the fallback. tests/test_ripemd160.py checks it against the
# published test vectors and against hashlib where hashlib has it.
_M = 0xFFFFFFFF
_RL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
       7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
       3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
       1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
       4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
_RR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
       6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
       15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
       8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
       12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
_SL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
       7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
       11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
       11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
       9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
_SR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
       9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
       9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
       15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
       8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160_pure(data: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytes(data) + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            r = j // 16
            t = (_rol((al + (_f(j, bl, cl, dl) & _M) + x[_RL[j]] + _KL[r]) & _M, _SL[j]) + el) & _M
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
            t = (_rol((ar + (_f(79 - j, br, cr, dr) & _M) + x[_RR[j]] + _KR[r]) & _M, _SR[j]) + er) & _M
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
        h = [(h[1] + cl + dr) & _M, (h[2] + dl + er) & _M, (h[3] + el + ar) & _M,
             (h[4] + al + br) & _M, (h[0] + bl + cr) & _M]
    return b"".join(v.to_bytes(4, "little") for v in h)


def ripemd160(data: bytes) -> bytes:
    try:
        rip = hashlib.new("ripemd160")
    except ValueError:
        return ripemd160_pure(data)
    rip.update(data)
    return rip.digest()


def hash160(data: bytes) -> str:
    return ripemd160(hashlib.sha256(data).digest()).hex()


def _no_constant(token):
    raise Refusal(f"INPUT_NONFINITE: {token} in JSON input")


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh, parse_float=Decimal, parse_constant=_no_constant)


def amount(x, what):
    """A JSON number (never a string or bool), finite and not negative."""
    if isinstance(x, bool) or not isinstance(x, (int, Decimal)):
        raise Refusal(f"{what}_NOT_A_NUMBER: {x!r}")
    d = Decimal(x)
    if not d.is_finite() or d < 0:
        raise Refusal(f"{what}_INVALID: {x!r}")
    return d


def cap(text, what):
    try:
        d = Decimal(text)
    except decimal.InvalidOperation as exc:
        raise Refusal(f"{what}_INVALID: {text!r}") from exc
    if not d.is_finite() or d < 0:
        raise Refusal(f"{what}_INVALID: {text!r}")
    return d


def outpoint(text):
    txid, sep, vout = text.partition(":")
    if not sep or not HEX64.fullmatch(txid) or not vout.isdigit():
        raise Refusal(f"OUTPOINT_INVALID: {text!r}, expected <64 lowercase hex>:<index>")
    return txid, int(vout)


def check(args):
    decoded = load(args.decoded)
    if not isinstance(decoded, dict):
        raise Refusal("DECODED_SHAPE: decoderawtransaction output is not an object")
    txid = decoded.get("txid")
    if not isinstance(txid, str) or not HEX64.fullmatch(txid):
        raise Refusal("DECODED_TXID_INVALID")
    vin, vout = decoded.get("vin"), decoded.get("vout")
    if not isinstance(vin, list) or not isinstance(vout, list) or not all(isinstance(o, dict) for o in vin + vout):
        raise Refusal("DECODED_SHAPE: vin/vout are not lists of objects")
    if not all(isinstance(o.get("scriptPubKey"), dict) for o in vout):
        raise Refusal("DECODED_SHAPE: an output has no scriptPubKey object")

    named = [i for i, o in enumerate(vout) if "nameOp" in o["scriptPubKey"]]
    if len(named) != 1:
        raise Refusal(f"NAME_OUTPUT_COUNT: expected exactly 1 name output, found {len(named)}")
    idx = named[0]
    if idx != args.name_vout or vout[idx].get("n", idx) != idx:
        raise Refusal(f"NAME_OUTPUT_INDEX: name output is vout {idx}, expected {args.name_vout}")
    out = vout[idx]
    spk = out["scriptPubKey"]
    nameop = spk["nameOp"]
    if not isinstance(nameop, dict):
        raise Refusal("DECODED_SHAPE: nameOp is not an object")

    if nameop.get("op") != args.op:
        raise Refusal(f"NAME_OP_MISMATCH: expected {args.op}, found {nameop.get('op')}")
    if amount(out.get("value"), "NAME_LOCK") != NAME_LOCK:
        raise Refusal(f"NAME_LOCK_AMOUNT: name output carries {out.get('value')}, expected {NAME_LOCK}")
    address = spk.get("address")
    if not isinstance(address, str) or address != args.owner_address:
        raise Refusal(f"OWNER_ADDRESS_MISMATCH: name output pays {address}, expected {args.owner_address}")
    name = args.name.encode("utf-8")
    if len(name) > MAX_NAME_BYTES:
        raise Refusal(f"NAME_TOO_LONG: {len(name)} bytes > {MAX_NAME_BYTES}; Core would refuse the reveal")

    if args.op == "name_new":
        try:
            rand = bytes.fromhex(args.rand)
        except ValueError as exc:
            raise Refusal("RAND_NOT_HEX") from exc
        if len(rand) != RAND_BYTES:
            raise Refusal(f"RAND_LENGTH: {len(rand)} bytes, expected {RAND_BYTES}; a longer nonce cannot be revealed")
        commitment = nameop.get("hash")
        if not isinstance(commitment, str) or commitment != hash160(rand + name):
            raise Refusal("NAME_NEW_COMMITMENT_MISMATCH: hash160(rand||name) does not match the output")
    else:
        if nameop.get("name") != args.name:
            raise Refusal(f"NAME_MISMATCH: output names {nameop.get('name')!r}, expected {args.name!r}")
        if nameop.get("name_encoding", "utf8") not in ("utf8", "ascii"):
            raise Refusal(f"NAME_ENCODING_UNEXPECTED: {nameop.get('name_encoding')}")
        value = nameop.get("value")
        if not isinstance(value, str):
            raise Refusal(f"VALUE_NOT_STRING: firstupdate/update output carries {type(value).__name__}")
        if nameop.get("value_encoding", "utf8") not in ("utf8", "ascii"):
            raise Refusal(f"VALUE_ENCODING_UNEXPECTED: {nameop.get('value_encoding')}")
        raw = value.encode("utf-8")
        if len(raw) > MAX_VALUE_BYTES:
            raise Refusal(f"VALUE_TOO_LONG: {len(raw)} bytes > {MAX_VALUE_BYTES}")
        got = hashlib.sha256(raw).hexdigest()
        if got != args.value_sha256:
            raise Refusal(f"VALUE_SHA256_MISMATCH: value hashes to {got}, expected {args.value_sha256}")
        prev = outpoint(args.prev_name_outpoint)
        if prev not in [(i.get("txid"), i.get("vout")) for i in vin]:
            raise Refusal(f"PREVIOUS_NAME_OUTPUT_NOT_SPENT: {args.prev_name_outpoint} is not an input")

    others = [o for i, o in enumerate(vout) if i != idx]
    if len(others) > 1:
        raise Refusal(f"CHANGE_OUTPUT_COUNT: {len(others)} non-name outputs, at most 1 (change) is allowed")
    for o in others:
        if o["scriptPubKey"].get("address") != args.change_address:
            raise Refusal(f"UNEXPECTED_OUTPUT: {o['scriptPubKey'].get('address')} is not the change address")

    ready = False
    if args.testmempoolaccept:
        tma = load(args.testmempoolaccept)
        if isinstance(tma, list):
            if len(tma) != 1:
                raise Refusal(f"TMA_SHAPE: expected one result, found {len(tma)}")
            tma = tma[0]
        if not isinstance(tma, dict):
            raise Refusal("TMA_SHAPE: result is not an object")
        if tma.get("txid") != txid:
            raise Refusal("TMA_TXID_MISMATCH: testmempoolaccept is for another transaction")
        allowed = tma.get("allowed")
        if allowed is False:
            raise Refusal(f"TMA_NOT_ALLOWED: {tma.get('reject-reason')}")
        if allowed is not True:
            raise Refusal(f"TMA_ALLOWED_NOT_BOOLEAN: {allowed!r}")
        fees = tma.get("fees")
        if not isinstance(fees, dict) or "base" not in fees:
            raise Refusal("FEE_UNKNOWN: testmempoolaccept reported no base fee")
        fee = amount(fees["base"], "FEE")
        if args.max_fee is None and args.max_total is None:
            raise Refusal("CAP_REQUIRED: give the owner's stated cap with --max-fee or --max-total")
        if args.max_fee is not None and fee > cap(args.max_fee, "MAX_FEE"):
            raise Refusal(f"FEE_OVER_CAP: fee {fee} NMC > cap {args.max_fee} NMC")
        if args.max_total is not None:
            spend = fee + (NAME_LOCK if args.op == "name_new" else 0)
            if spend > cap(args.max_total, "MAX_TOTAL"):
                raise Refusal(f"TOTAL_OVER_CAP: fee {fee} + new lock = {spend} NMC > cap {args.max_total} NMC")
        ready = True

    print(json.dumps({
        "result": "READY_TO_BROADCAST_ONCE" if ready else "STATIC_OK_RUN_TESTMEMPOOLACCEPT",
        "txid": txid,
        "op": args.op,
        "name": args.name,
        "name_vout": idx,
        "owner_address": args.owner_address,
        "vsize": decoded.get("vsize"),
    }))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--decoded", required=True, help="decoderawtransaction output (JSON file)")
    p.add_argument("--op", required=True, choices=["name_new", "name_firstupdate", "name_update"])
    p.add_argument("--name", required=True, help="exact name, e.g. id/alice")
    p.add_argument("--owner-address", required=True, help="address the name output must pay")
    p.add_argument("--name-vout", required=True, type=int, help="index the name output must have")
    p.add_argument("--change-address", required=True, help="the only address a non-name output may pay")
    p.add_argument("--value-sha256", help="sha256 of the exact intended value bytes (firstupdate/update)")
    p.add_argument("--rand", help="name_new nonce from namerawtransaction (hex, 20 bytes)")
    p.add_argument("--prev-name-outpoint", help="txid:vout the transaction must spend: the name_new output "
                   "(firstupdate) or the current name output (update)")
    p.add_argument("--testmempoolaccept", help="testmempoolaccept output (JSON file)")
    p.add_argument("--max-fee", help="owner's stated fee cap in NMC")
    p.add_argument("--max-total", help="owner's stated total cap in NMC: fee plus, for name_new, the 0.01 lock")
    args = p.parse_args(argv)
    if args.op == "name_new":
        if not args.rand:
            p.error("--rand is required for name_new")
    else:
        if not args.value_sha256 or not HEX64.fullmatch(args.value_sha256):
            p.error("--value-sha256 (64 lowercase hex) is required for name_firstupdate and name_update")
        if not args.prev_name_outpoint:
            p.error("--prev-name-outpoint is required for name_firstupdate and name_update")
    try:
        check(args)
    except Refusal as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError, decimal.InvalidOperation) as exc:
        print(f"REFUSED: INPUT_UNREADABLE: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
