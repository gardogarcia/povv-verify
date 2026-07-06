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
  https://app.povv.io/api/ledger/receipt/<audit_run_id> > receipt.json
```

## Verify

```bash
# Use the JWKS URL embedded in the receipt (default):
povv-verify receipt.json

# Pin a specific JWKS endpoint:
povv-verify receipt.json --jwks https://app.povv.io/.well-known/povv-ledger-keys

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

## Canonicalization

The hash is computed over JSON with **recursively sorted object keys** (arrays keep
their order). This exact function is shared by the POVV server signer and this
verifier, so independently recomputed hashes always match byte-for-byte.

MIT licensed.
