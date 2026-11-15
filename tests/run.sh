#!/bin/sh
# Fixture tests for scripts/check_name_tx.py. Each refusal case sits beside a
# passing control; the script must refuse with the NAMED reason, not just fail.
# All fixtures are SYNTHETIC (tests/make_fixture.py): no real transaction, key
# or wallet is involved.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src="$here/../scripts/check_name_tx.py"
chk="python3 -I $src"
fx="$here/fixtures"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
pass=0; fail=0
ok()   { if out=$("$@" 2>&1); then pass=$((pass+1)); else echo "FAIL (expected pass): $*"; echo "$out"; fail=$((fail+1)); fi; }
refuse() { reason=$1; shift; if out=$("$@" 2>&1); then echo "FAIL (expected $reason): $*"; fail=$((fail+1)); elif echo "$out" | grep -q -- "$reason"; then pass=$((pass+1)); else echo "FAIL (wrong reason, want $reason): $out"; fail=$((fail+1)); fi; }

NEW="$fx/name_new.synthetic.json"
NAME=id/example
RAND=33a50fe344d993d97cbb567a2ad6c28b4f561700
OWNER=N3DuniLozu6e7RkYqp3M4czYo4fmeg88Bs
CHANGE=NJ6m7tdDY1JXfZGHxnQF73CH2MCjAiKRyB
STRANGER=NHPiXTkHryymQx1Pbu1JR1VbLqjxdbMjiL
base="--op name_new --name $NAME --owner-address $OWNER --name-vout 1 --change-address $CHANGE"

# Derived synthetic fixtures (shape variants of the synthetic name_new).
python3 -I - "$src" "$NEW" "$tmp" "$RAND" "$NAME" "$STRANGER" <<'PY'
import copy, hashlib, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("chk", sys.argv[1]); chk = importlib.util.module_from_spec(spec); spec.loader.exec_module(chk)
d = json.load(open(sys.argv[2])); tmp = sys.argv[3]; rand = bytes.fromhex(sys.argv[4]); name = sys.argv[5]; stranger = sys.argv[6]
def w(n, x): json.dump(x, open(f"{tmp}/{n}.json", "w"))
def commit(x, r, nm): x["vout"][1]["scriptPubKey"]["nameOp"]["hash"] = chk.hash160(r + nm.encode())
x = copy.deepcopy(d); commit(x, b"\x00" + rand, name); w("rand21", x)          # commitment matches a 21-byte nonce
x = copy.deepcopy(d); commit(x, rand, "id/" + "n" * 252); w("name255", x)      # 255-byte name
x = copy.deepcopy(d); commit(x, rand, "id/" + "n" * 253); w("name256", x)      # 256-byte name
x = copy.deepcopy(d); x["vout"][0]["scriptPubKey"]["address"] = stranger; x["vout"][0]["value"] = 0.2; w("stranger", x)
x = copy.deepcopy(d); s = copy.deepcopy(x["vout"][0]); s["n"] = 2; s["scriptPubKey"]["address"] = stranger; x["vout"].append(s); w("extra", x)
x = copy.deepcopy(d); x["vout"] = [x["vout"][1], x["vout"][0]]; x["vout"][0]["n"] = 0; x["vout"][1]["n"] = 1; w("swapped", x)
x = copy.deepcopy(d); x["vout"][0] = copy.deepcopy(x["vout"][1]); x["vout"][0]["n"] = 0; w("twonames", x)
x = copy.deepcopy(d); del x["txid"]; w("notxid", x)
# name_update variants: one name output carrying a value, spending aa..:1.
u = copy.deepcopy(d)
u["vout"][1]["scriptPubKey"]["nameOp"] = {"op": "name_update", "name": name, "name_encoding": "utf8", "value": "{\"swarma\":{}}", "value_encoding": "utf8"}
u["vin"] = [{"txid": "aa" * 32, "vout": 1}, {"txid": "bb" * 32, "vout": 0}]
w("upd", u)
x = copy.deepcopy(u); x["vout"][1]["value"] = 0.02; w("upd_lock", x)
x = copy.deepcopy(u); x["vout"][1]["scriptPubKey"]["nameOp"]["value"] = "x" * 521; w("upd_long", x)
x = copy.deepcopy(u); x["vout"][1]["scriptPubKey"]["nameOp"]["value"] = "x" * 520; w("upd_520", x)
x = copy.deepcopy(u); x["vout"][1]["scriptPubKey"]["nameOp"]["value"] = 5; w("upd_num", x)
# testmempoolaccept results.
t = d["txid"]
def tma(n, body): open(f"{tmp}/tma_{n}.json", "w").write(body)
tma("ok", f'[{{"txid":"{t}","allowed":true,"vsize":248,"fees":{{"base":0.00049600}}}}]')
tma("low", f'[{{"txid":"{t}","allowed":true,"vsize":248,"fees":{{"base":0.0001}}}}]')
tma("no", f'[{{"txid":"{t}","allowed":false,"reject-reason":"bad-txns-inputs-missingorspent"}}]')
tma("other", f'[{{"txid":"{"dd" * 32}","allowed":true,"fees":{{"base":0.000496}}}}]')
tma("notxid", '[{"allowed":true,"fees":{"base":0.000496}}]')
tma("strfalse", f'[{{"txid":"{t}","allowed":"false","fees":{{"base":0.000496}}}}]')
tma("strtrue", f'[{{"txid":"{t}","allowed":"true","fees":{{"base":0.000496}}}}]')
tma("negfee", f'[{{"txid":"{t}","allowed":true,"fees":{{"base":-0.0001}}}}]')
tma("strfee", f'[{{"txid":"{t}","allowed":true,"fees":{{"base":"0.0001"}}}}]')
tma("nanfee", f'[{{"txid":"{t}","allowed":true,"fees":{{"base":NaN}}}}]')
tma("null", '[null]')
tma("two", f'[{{"txid":"{t}","allowed":true,"fees":{{"base":0.0001}}}},{{"txid":"{t}","allowed":true,"fees":{{"base":0.0001}}}}]')
print(hashlib.sha256(b"x" * 520).hexdigest(), file=open(f"{tmp}/sha520", "w"))
PY

# name_new: the synthetic fixture verifies; each wrong expectation refuses.
ok     $chk --decoded "$NEW" $base --rand $RAND
refuse NAME_NEW_COMMITMENT_MISMATCH $chk --decoded "$NEW" $base --rand 34a50fe344d993d97cbb567a2ad6c28b4f561700
refuse NAME_NEW_COMMITMENT_MISMATCH $chk --decoded "$NEW" --op name_new --name id/exampl3 --owner-address $OWNER --name-vout 1 --change-address $CHANGE --rand $RAND
refuse RAND_LENGTH                  $chk --decoded "$tmp/rand21.json" $base --rand 00$RAND
refuse RAND_NOT_HEX                 $chk --decoded "$NEW" $base --rand zz$RAND
ok     $chk --decoded "$tmp/name255.json" --op name_new --name id/$(printf 'n%.0s' $(seq 252)) --owner-address $OWNER --name-vout 1 --change-address $CHANGE --rand $RAND
refuse NAME_TOO_LONG                $chk --decoded "$tmp/name256.json" --op name_new --name id/$(printf 'n%.0s' $(seq 253)) --owner-address $OWNER --name-vout 1 --change-address $CHANGE --rand $RAND
refuse OWNER_ADDRESS_MISMATCH       $chk --decoded "$NEW" --op name_new --name $NAME --owner-address $CHANGE --name-vout 1 --change-address $CHANGE --rand $RAND
refuse NAME_OP_MISMATCH             $chk --decoded "$NEW" --op name_update --name $NAME --owner-address $OWNER --name-vout 1 --change-address $CHANGE --value-sha256 $(printf '0%.0s' $(seq 64)) --prev-name-outpoint $(printf 'aa%.0s' $(seq 32)):1
refuse "rand is required"           $chk --decoded "$NEW" $base
# Outputs: change is mandatory and the only other output allowed.
refuse "change-address"             $chk --decoded "$NEW" --op name_new --name $NAME --owner-address $OWNER --name-vout 1 --rand $RAND
refuse UNEXPECTED_OUTPUT            $chk --decoded "$NEW" --op name_new --name $NAME --owner-address $OWNER --name-vout 1 --change-address $OWNER --rand $RAND
refuse UNEXPECTED_OUTPUT            $chk --decoded "$tmp/stranger.json" $base --rand $RAND
refuse CHANGE_OUTPUT_COUNT          $chk --decoded "$tmp/extra.json" $base --rand $RAND
refuse NAME_OUTPUT_COUNT            $chk --decoded "$tmp/twonames.json" $base --rand $RAND
# The name output index is bound.
refuse NAME_OUTPUT_INDEX            $chk --decoded "$NEW" --op name_new --name $NAME --owner-address $OWNER --name-vout 0 --change-address $CHANGE --rand $RAND
refuse NAME_OUTPUT_INDEX            $chk --decoded "$tmp/swapped.json" $base --rand $RAND
ok     $chk --decoded "$tmp/swapped.json" --op name_new --name $NAME --owner-address $OWNER --name-vout 0 --change-address $CHANGE --rand $RAND
refuse DECODED_TXID_INVALID         $chk --decoded "$tmp/notxid.json" $base --rand $RAND

# name_update.
VSHA=$(printf '%s' '{"swarma":{}}' | shasum -a 256 | cut -c1-64)
PREV=$(printf 'aa%.0s' $(seq 32)):1
ubase="--op name_update --name $NAME --owner-address $OWNER --name-vout 1 --change-address $CHANGE"
ok     $chk --decoded "$tmp/upd.json" $ubase --value-sha256 $VSHA --prev-name-outpoint $PREV
refuse "prev-name-outpoint is required" $chk --decoded "$tmp/upd.json" $ubase --value-sha256 $VSHA
refuse OUTPOINT_INVALID             $chk --decoded "$tmp/upd.json" $ubase --value-sha256 $VSHA --prev-name-outpoint xyz:1
refuse VALUE_SHA256_MISMATCH        $chk --decoded "$tmp/upd.json" $ubase --value-sha256 $(printf '0%.0s' $(seq 64)) --prev-name-outpoint $PREV
refuse NAME_MISMATCH                $chk --decoded "$tmp/upd.json" --op name_update --name id/exampl3 --owner-address $OWNER --name-vout 1 --change-address $CHANGE --value-sha256 $VSHA --prev-name-outpoint $PREV
refuse PREVIOUS_NAME_OUTPUT_NOT_SPENT $chk --decoded "$tmp/upd.json" $ubase --value-sha256 $VSHA --prev-name-outpoint $(printf 'cc%.0s' $(seq 32)):1
refuse NAME_LOCK_AMOUNT             $chk --decoded "$tmp/upd_lock.json" $ubase --value-sha256 $VSHA --prev-name-outpoint $PREV
ok     $chk --decoded "$tmp/upd_520.json" $ubase --value-sha256 $(cat "$tmp/sha520") --prev-name-outpoint $PREV
refuse VALUE_TOO_LONG               $chk --decoded "$tmp/upd_long.json" $ubase --value-sha256 $VSHA --prev-name-outpoint $PREV
refuse VALUE_NOT_STRING             $chk --decoded "$tmp/upd_num.json" $ubase --value-sha256 $VSHA --prev-name-outpoint $PREV

# testmempoolaccept gate and caps.
tb="--decoded $NEW $base --rand $RAND --testmempoolaccept"
ok     $chk $tb "$tmp/tma_ok.json" --max-fee 0.0005
refuse FEE_OVER_CAP      $chk $tb "$tmp/tma_ok.json" --max-fee 0.0004
refuse CAP_REQUIRED      $chk $tb "$tmp/tma_ok.json"
ok     $chk $tb "$tmp/tma_ok.json" --max-total 0.0106
refuse TOTAL_OVER_CAP    $chk $tb "$tmp/tma_low.json" --max-total 0.01005
refuse MAX_FEE_INVALID   $chk $tb "$tmp/tma_ok.json" --max-fee Infinity
refuse MAX_FEE_INVALID   $chk $tb "$tmp/tma_ok.json" --max-fee NaN
refuse MAX_FEE_INVALID   $chk $tb "$tmp/tma_ok.json" --max-fee -1
refuse MAX_TOTAL_INVALID $chk $tb "$tmp/tma_ok.json" --max-total inf
refuse TMA_NOT_ALLOWED   $chk $tb "$tmp/tma_no.json" --max-fee 0.0005
refuse TMA_TXID_MISMATCH $chk $tb "$tmp/tma_other.json" --max-fee 0.0005
refuse TMA_TXID_MISMATCH $chk $tb "$tmp/tma_notxid.json" --max-fee 0.0005
refuse TMA_ALLOWED_NOT_BOOLEAN $chk $tb "$tmp/tma_strfalse.json" --max-fee 0.0005
refuse TMA_ALLOWED_NOT_BOOLEAN $chk $tb "$tmp/tma_strtrue.json" --max-fee 0.0005
refuse FEE_INVALID       $chk $tb "$tmp/tma_negfee.json" --max-fee 0.0005
refuse FEE_NOT_A_NUMBER  $chk $tb "$tmp/tma_strfee.json" --max-fee 0.0005
refuse INPUT_NONFINITE   $chk $tb "$tmp/tma_nanfee.json" --max-fee 0.0005
refuse TMA_SHAPE         $chk $tb "$tmp/tma_null.json" --max-fee 0.0005
refuse TMA_SHAPE         $chk $tb "$tmp/tma_two.json" --max-fee 0.0005

# RIPEMD-160 fallback (OpenSSL 3 often lacks ripemd160 in hashlib).
ok     python3 -I "$here/test_ripemd160.py"
# The committed fixture is exactly what the generator writes.
ok     sh -c "cd '$tmp' && mkdir -p g/tests/fixtures g/scripts && cp '$src' g/scripts/ && cp '$here/make_fixture.py' g/tests/ && python3 -I g/tests/make_fixture.py >/dev/null && cmp g/tests/fixtures/name_new.synthetic.json '$NEW'"

# Detector controls: each planted mutant must be caught. A plant that did not
# apply (unchanged file) fails the control instead of passing silently.
plant() {
  python3 -I - "$1" "$2" "$3" "$4" <<'PY'
import sys
s = open(sys.argv[1]).read()
if s.count(sys.argv[3]) != 1:
    sys.exit("plant did not apply: " + sys.argv[3])
open(sys.argv[2], "w").write(s.replace(sys.argv[3], sys.argv[4]))
PY
}
mutant_caught() { if "$@" >/dev/null 2>&1; then pass=$((pass+1)); else echo "FAIL (mutant survived or did not run): $*"; fail=$((fail+1)); fi; }
# Mutant 1: owner check disabled -> the wrong-owner case is no longer refused.
if plant "$src" "$tmp/m_owner.py" "if not isinstance(address, str) or address != args.owner_address:" "if False:"; then
  mutant_caught python3 -I "$tmp/m_owner.py" --decoded "$NEW" --op name_new --name $NAME --owner-address $CHANGE --name-vout 1 --change-address $CHANGE --rand $RAND
else fail=$((fail+1)); fi
# Mutant 2: nonce length check disabled -> the 21-byte nonce is accepted.
if plant "$src" "$tmp/m_rand.py" "if len(rand) != RAND_BYTES:" "if False:"; then
  mutant_caught python3 -I "$tmp/m_rand.py" --decoded "$tmp/rand21.json" $base --rand 00$RAND
else fail=$((fail+1)); fi
# Mutant 3: one RIPEMD-160 round constant off by one -> the vector test fails.
if plant "$src" "$tmp/m_rip.py" "0x5A827999" "0x5A827998"; then
  if python3 -I "$here/test_ripemd160.py" "$tmp/m_rip.py" >/dev/null 2>&1; then echo "FAIL (ripemd mutant survived)"; fail=$((fail+1)); else pass=$((pass+1)); fi
else fail=$((fail+1)); fi

echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
