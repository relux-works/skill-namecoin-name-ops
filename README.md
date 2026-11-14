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
- `tests/run.sh`: fixture tests, each refusal beside a passing control.

Install it as a Curator skill from this repository at a tagged version.
