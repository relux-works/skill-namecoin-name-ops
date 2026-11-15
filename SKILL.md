---
name: namecoin-name-ops
description: Register, update, re-own and renew Namecoin names (id/, d/) from your own Namecoin Core node and wallet, including writing public keys into a name's value and rotating them, with a mandatory pre-broadcast check (decode, scripted expectation check, testmempoolaccept, broadcast once, lock). Use for "register a Namecoin name", "name_new / name_firstupdate / name_update", "put my grant key into my id/ name", "rotate my grant key", "move my names to a cold wallet", "renew a name before it expires".
---

# Namecoin name operations

Operate Namecoin names from a node and wallet you control. Every transaction
that spends money or changes a name goes through the same five steps, and the
owner states the operation, the name, the destination and the money limit in
words before anything is broadcast.

## Hard rules

- Never print, copy, log or persist a private key, seed, descriptor with private
  parts, or wallet passphrase. The human types the passphrase; unlock for the
  shortest time (`walletpassphrase` with a small timeout) and `walletlock` right
  after signing.
- The owner's word names: the operation, the exact name, the owner address the
  name output pays, the value (or its sha256), and the money limit. The limit is
  either a fee cap (`--max-fee`) or a total cap (`--max-total`: the fee plus, for
  name_new, the new 0.01 lock); pass it as the owner said it, never convert one
  into the other. A bare "yes" is not enough; ask for the full sentence.
- Broadcast each transaction ONCE. If the result is uncertain (timeout, lost
  reply), look it up (`getrawtransaction`, `name_pending`, `getmempoolentry`)
  before anything else; never rebroadcast blind.
- Keep wallets apart: a funding wallet pays fees and the 0.01 NMC lock; a cold
  wallet owns names. A name output goes only to an address the owner named.
- Use only your own synced node: `getblockchaininfo` must show
  `headers == blocks` and `initialblockdownload: false` before you build.

## Facts you need

- A name output locks exactly 0.01 NMC.
- Registration is two transactions: `name_new` (a commitment to a random nonce
  plus the name), then, at least 12 blocks later, `name_firstupdate` (reveals the
  name, sets the value). Keep the nonce (`rand`) until firstupdate confirms.
- `name_update` spends the current name output and creates the next one; it can
  change the value, the owner address, or neither (a renewal).
- A name expires 36000 blocks (about 250 days) after its last update. Renew
  before that with a `name_update` (value unchanged).
- A value is at most 520 bytes. Swarma values are compact JSON with an exact
  shape (see references/value-shapes.md); build them with your project's value
  builder, record their sha256, and compare the decoded value's sha256 before
  broadcast.
- Measured mainnet sizes: name_new about 248 vB, name_firstupdate 499-655 vB,
  name_update about 565 vB. Fee = vsize x feerate; state the cap in NMC.

## The five steps (every operation)

1. **Build** the raw transaction with `createrawtransaction` (inputs and outputs,
   with the 0.01 NMC name output to the owner address at index 0), then add the
   name operation with `namerawtransaction "<hex>" 0 '{"op":...,"name":...,...}'`.
   For `name_new` save the returned 20-byte `rand`. Fund and sign with the wallet
   (`fundrawtransaction` with `changeAddress`, `changePosition: 1` and a
   `fee_rate`, then `signrawtransactionwithwallet`); without `changePosition`
   Core puts change at a random index. For `name_firstupdate` the inputs must
   include the name_new output; for `name_update`, the current name output.
2. **Decode** with `decoderawtransaction` into a file.
3. **Check** with this skill's script; it refuses with a named reason unless
   everything matches:

   ```
   python3 -I scripts/check_name_tx.py --decoded decoded.json \
     --op name_update --name id/alice --name-vout 0 \
     --owner-address <owner address> --change-address <change address> \
     --value-sha256 <sha256 of the value bytes> --prev-name-outpoint <txid:vout>
   ```

   `--name-vout` and `--change-address` are always required: the name output
   must sit at that index, and the only other output allowed is one change
   output to that address. For `name_new` pass `--rand <hex>` instead of
   `--value-sha256` and `--prev-name-outpoint`; for `name_firstupdate`,
   `--prev-name-outpoint` is the name_new output.
4. **testmempoolaccept** the signed hex, save the JSON, and run the check again
   with `--testmempoolaccept tma.json` and the owner's cap (`--max-fee` or
   `--max-total`). Only `READY_TO_BROADCAST_ONCE` lets you continue.
5. **Broadcast once** with `sendrawtransaction`, record the txid, `walletlock`,
   then read back after confirmation. For `name_new`: `gettransaction <txid>`
   shows confirmations and the name output; `name_show` knows nothing yet, since
   a name_new only commits a hash. For `name_firstupdate` and `name_update`:
   `name_show <name>` must show the expected value (compare its sha256) and the
   owner address.

## Operations

- **Register** (`name_new` -> wait 12 blocks -> `name_firstupdate`): two owner
  sentences or one that covers both; the name output of firstupdate pays the
  owner address; value is the full intended value.
- **Update the value with public keys** (`name_update`, value changed, owner
  address unchanged): use when you publish a new grant key, social (Nostr) key or
  relay hints. Check that every other member of the value is unchanged.
- **Rotate a key** (`name_update` that replaces the key in the value): in Swarma
  grants v4 a grant lives only while name updates change neither the owner nor
  the `swarma` member (LIP-0008), so every grant issued under the old key stops
  and must be re-issued under the new one; say this to the owner before asking
  for the word.
- **Re-own** (`name_update`, value unchanged, name output to a new owner
  address): move names to a cold wallet; probe with ONE name first, then the rest.
- **Renew** (`name_update`, value and owner unchanged) before 36000 blocks pass.

## When something goes wrong

- `testmempoolaccept` refuses: do not broadcast; read the reason
  (`bad-txns-inputs-missingorspent`, fee too low, a name already pending) and
  rebuild.
- `name_new` broadcast but firstupdate not yet sent: the commitment stays valid;
  keep `rand`, wait, then build firstupdate. Do not create a second name_new.
- A name you meant to register is already taken: stop, report, do not guess
  another spelling without the owner.

## Verified tests

`sh tests/run.sh` runs the checker against SYNTHETIC fixtures
(`tests/make_fixture.py`: an invented input, no signature, label-derived
addresses; never a real transaction): every refusal sits beside a passing
control, including unbound outputs, the name output index, nonce and name
lengths, non-finite or negative caps and fees, and malformed evidence. It also checks the RIPEMD-160 fallback (OpenSSL 3 often drops
ripemd160 from hashlib) against the published vectors, against hashlib where
present, and on the fixture commitment with hashlib's ripemd160 forced off. Three
planted mutants (owner check disabled, nonce length check disabled, one
RIPEMD-160 constant changed) must be caught. CI runs the suite on Linux and macOS.
