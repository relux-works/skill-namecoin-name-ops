# skill-namecoin-name-ops

An agent skill for operating Namecoin names (`id/`, `d/`) from your own Namecoin
Core node and wallet: register, update a name's value with public keys, rotate
keys, re-own to a cold wallet, renew. Every money-spending step goes through a
scripted pre-broadcast check and is broadcast once.

- `SKILL.md`: the procedure and rules.
- `scripts/check_name_tx.py`: refuses a decoded transaction, with a named reason,
  unless the operation, name, owner address, value hash, name lock, previous
  name output, change outputs and fee cap all match (standard library only; it
  never touches keys, wallets or the network).
- `tests/run.sh`: fixture tests, each refusal beside a passing control, plus
  RIPEMD-160 vectors and planted-mutant controls; CI runs it on Linux and macOS.

## Why Python and not Go

The checker is one file of standard-library Python that an operator can read in
full before running it next to a wallet. It needs no build, no released binary
and no signing or distribution channel: `python3 -I` is present wherever
Namecoin Core runs, and the skill ships as plain text at a tagged version. A Go
tool would be a compiled artifact that needs its own reproducible, signed
release per platform to be trusted the same way. If the checker grows beyond
checking the node's own decode (for example parsing raw transactions
independently of the node), moving it to Go next to our other tooling becomes
worth that cost.

Install it as a Curator skill from this repository at a tagged version.
