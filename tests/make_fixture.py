"""Write tests/fixtures/name_new.synthetic.json: a SYNTHETIC decoded name_new.

Nothing here is a real transaction: the input outpoint is invented, there is no
signature, and the addresses come from hashes of fixed labels, so no wallet
holds their keys. Only the shape follows Namecoin Core's decoderawtransaction.
Run with python3 -I from the repository root; the output is deterministic.
"""
import hashlib
import importlib.util
import json
import os

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("chk", os.path.join(here, "..", "scripts", "check_name_tx.py"))
chk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chk)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def label_h160(label: str) -> str:
    return chk.ripemd160(hashlib.sha256(label.encode()).digest()).hex()


def p2pkh(h160: str) -> dict:
    return {"asm": f"OP_DUP OP_HASH160 {h160} OP_EQUALVERIFY OP_CHECKSIG",
            "hex": f"76a914{h160}88ac",
            "address": b58check(bytes([52]) + bytes.fromhex(h160)),  # Namecoin P2PKH version 52
            "type": "pubkeyhash"}


def label_address(label: str) -> str:
    return p2pkh(label_h160(label))["address"]


NAME = "id/example"
RAND = hashlib.sha256(b"synthetic-rand").hexdigest()[:40]
if __name__ != "__main__":
    raise SystemExit  # imported as a library: only the helpers above are used
owner_h, change_h = label_h160("synthetic-owner"), label_h160("synthetic-change")
commit = chk.hash160(bytes.fromhex(RAND) + NAME.encode())
name_spk = p2pkh(owner_h)
name_spk = {"nameOp": {"op": "name_new", "hash": commit},
            "asm": f"OP_NAME_NEW {commit} OP_2DROP " + name_spk["asm"],
            "hex": f"5114{commit}6d" + name_spk["hex"],
            "address": name_spk["address"], "type": "pubkeyhash"}
fixture = {
    "_comment": "SYNTHETIC test fixture, not a transaction: invented input, no signature, label-derived addresses",
    "txid": hashlib.sha256(b"synthetic-txid").hexdigest(),
    "hash": hashlib.sha256(b"synthetic-txid").hexdigest(),
    "version": 28928, "size": 248, "vsize": 248, "weight": 992, "locktime": 0,
    "vin": [{"txid": "11" * 32, "vout": 0, "scriptSig": {"asm": "", "hex": ""}, "sequence": 4294967293}],
    "vout": [{"value": 0.0843104, "n": 0, "scriptPubKey": p2pkh(change_h)},
             {"value": 0.01, "n": 1, "scriptPubKey": name_spk}],
}
with open(os.path.join(here, "fixtures", "name_new.synthetic.json"), "w") as fh:
    json.dump(fixture, fh, indent=1)
    fh.write("\n")
print(json.dumps({"name": NAME, "rand": RAND, "owner": name_spk["address"],
                  "change": fixture["vout"][0]["scriptPubKey"]["address"], "txid": fixture["txid"]}))
