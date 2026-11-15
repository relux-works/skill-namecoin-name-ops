# Swarma name values

The authoritative definition of a Swarma name value is the Swarma Link
specification, LIP-0004 section 1 (grants v3, the `swarma` member and the
`nostr` descriptor) and, for v4 issuers, LIP-0008 section 3 and LIP-0021.
This skill does not restate the byte rules; it relies on them:

- the value is exact compact UTF-8 JSON, no newline, at most 520 bytes;
- keys are lowercase 64-hex secp256k1 x-only public keys;
- a social (Nostr) key and a grant key are independent: equality is allowed,
  never required or inferred;
- a value with members outside the specified shape makes grants under the name
  refuse (LIP-0016, Motivation), so never add ad-hoc members.

Build the value with your project's value builder, print its sha256, and give
that sha256 to `check_name_tx.py --value-sha256`. After confirmation,
`name_show` must return a value with the same sha256.
