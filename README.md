# povv-verify

Offline, zero-trust verifier for **POVV audit receipts**.

POVV seals every audit into an append-only, hash-linked, Ed25519-signed ledger and
periodically anchors the Merkle root to an external witness. This tool lets anyone —
an enterprise client, an auditor, a regulator — independently verify a sealed audit
**without trusting POVV's servers**. You only need the receipt JSON and POVV's
published public key.

## What it checks

1. **Hash integrity** — recomputes `sha256(canonical(sealed_payload))` and checks it
   equals the receipt's `integrity_hash`. The payload commits to the code evidence,
   both LLM auditor reasonings, the delivery contract, the model provenance, and the
   previous seal in the chain.
2. **Ed25519 signature** — verifies the signature over the integrity hash against
   POVV's published key (JWKS at `/.well-known/povv-ledger-keys`, or a local PEM).
   This proves POVV — and only the holder of the private key — produced the verdict.
3. **Merkle inclusion** — if the seal has been anchored, verifies the inclusion proof
   reproduces the checkpoint's Merkle root (which is committed to an external GitHub
   witness, fixing the verdict in time).

## Install

```bash
npm install -g povv-verify
# or run directly:
node packages/povv-verify/cli.mjs <receipt.json>
```

## Get a receipt

```bash
curl -H "Authorization: Bearer <token>" \
  https://povv.io/api/ledger/receipt/<audit_run_id> > receipt.json
```

## Verify

```bash
# Check against POVV's published key set (default; the receipt's own jwks_url is ignored):
povv-verify receipt.json

# Pin a key set you trust (for example a mirror you control):
povv-verify receipt.json --jwks https://povv.io/.well-known/povv-ledger-keys

# Fully offline with a local public key, no network:
povv-verify receipt.json --pubkey povv-public.pem --no-fetch
```

Exit code `0` = VERIFIED, `1` = NOT VERIFIED, `2` = usage/IO error.

## Programmatic use

```js
import { verifyReceipt } from "povv-verify";
import { readFileSync } from "node:fs";

const receipt = JSON.parse(readFileSync("receipt.json", "utf8"));
const result = await verifyReceipt(receipt, { fetchKey: true });
console.log(result.ok, result.checks);
```

## Trust model and security fix (1.1.0)

The key a receipt is checked against must come from someone other than the receipt's author.
Since 1.1.0 the verifier fetches keys only from POVV's published key set
(`https://povv.io/.well-known/povv-ledger-keys`) or from a key set / PEM **you** pin with
`--jwks` / `--pubkey`. The `jwks_url` written inside a receipt is reported, never followed,
and a `key_id` that is not in the trusted set fails verification instead of falling back
to another key.

Versions before 1.1.0 followed the receipt's own `jwks_url` by default, so a forger could
sign a fabricated receipt with their own key, publish that key, and get `VERIFIED`.
POVV's own Full Repo audit of this repository flagged the path (one confirmed finding on
the key fallback, three coverage gaps on the receipt-directed fetch); reading the full
source confirmed it, and `test.mjs` now reproduces the forgery and requires it to fail.

Run the tests with `npm test` (Node ≥ 18, no dependencies, no network).

## Canonicalization

The hash is computed over JSON with **recursively sorted object keys** (arrays keep
their order). This exact function is shared by the POVV server signer and this
verifier, so independently recomputed hashes always match byte-for-byte.

MIT licensed.

## Verified by POVV

[![POVV Verified](https://povv.io/api/badge/be965c4656046de89ab52f20af8596788725c19ea8e2fc35046d4645857ab82c)](https://povv.io/v/be965c4656046de89ab52f20af8596788725c19ea8e2fc35046d4645857ab82c)

This repository is audited by [POVV](https://povv.io)'s adversarial AI swarm. The sealed
verdict — including its full disclosed evidence base and machine-verified receipts — is
public at the badge link, and its Ed25519 signature can be checked offline with this very
package:

```bash
curl -H "Authorization: Bearer <token>" https://povv.io/api/ledger/receipt/<audit_run_id> > receipt.json
node cli.mjs receipt.json
```
