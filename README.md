# povv-verify

Offline, zero-trust verifier for **POVV audit receipts**.

POVV seals every audit into an append-only, hash-linked, Ed25519-signed ledger. The
ledger is designed to anchor Merkle roots to an external witness; that anchoring is not
active yet, and this tool does not check a witness (see below). This tool lets anyone —
an enterprise client, an auditor, a regulator — independently verify a sealed audit
**without trusting POVV's servers**: pin POVV's published public key once (`--pubkey`)
and verification needs no POVV server at all. Without a pinned key, the CLI fetches it
from POVV's published key set, so that fetch is the one thing you trust POVV for.

## What it checks

1. **Hash integrity** — recomputes `sha256(canonical(sealed_payload))` and checks it
   equals the receipt's `integrity_hash`. The payload commits to the code evidence,
   both LLM auditor reasonings, the delivery contract, the model provenance, and the
   previous seal in the chain.
2. **Ed25519 signature** — verifies the signature over the integrity hash against
   POVV's published key (JWKS at `/.well-known/povv-ledger-keys`, or a local PEM).
   This proves POVV — and only the holder of the private key — produced the verdict.
3. **Merkle inclusion** — if the receipt carries an anchor, verifies the inclusion proof
   reproduces the Merkle root **written in that receipt**. The root is not compared with
   any external witness, so this is a consistency check, not proof of when the seal was
   made. `ok` requires the hash, the signature and, when the signed payload names an
   audit id, a matching receipt label (`checks.idBound`); a receipt without an anchor can
   still be `ok` (`checks.inclusionValid` is `null`). `errors` also carries informational
   notes, so gate on `ok`, not on `errors.length`.

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

# Offline with a pinned key set (key ids are checked), rejecting receipts older than a year:
povv-verify receipt.json --jwks-file povv-keys.json --no-fetch --max-age 365
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

## Second self-audit fixes (1.1.1)

POVV re-audited 1.1.0 (every file read) and confirmed one more defect, plus a coverage gap:

- **`__proto__` smuggling.** `canonicalize` rebuilt objects with `acc[k] = v[k]`. For an own
  `__proto__` member (which `JSON.parse` creates) that assignment hits the prototype setter,
  so the member vanished from the hashed bytes: extra, unsigned content could ride inside a
  receipt that still printed `VERIFIED`. Keys are now defined as own properties, so any
  added member changes the hash. Receipts without such a member hash exactly as before
  (POVV checked its production data: no sealed payload contains one).
- **Unsigned id label.** The CLI printed the receipt's top-level `audit_run_id`, which the
  signature does not cover. It now prints the id from the signed payload, and a receipt
  whose label disagrees with the signed id fails (`checks.idBound`).

`test.mjs` reproduces both and requires them to fail.

## Third self-audit clarifications (1.1.2)

The third audit (every file read, 0 confirmed findings) raised four open questions about
the Merkle anchor. Reading the code confirmed the substance: the anchor root and proof come
from the receipt, and the old text claimed a GitHub witness fixed the verdict in time,
which this tool never checked. The README and CLI now say exactly what is checked, and a
malformed proof returns `false` instead of throwing.

## Fourth self-audit fixes (1.1.3)

The fourth audit (every file read) confirmed one medium finding: the npm `description`
still promised verification "against the anchored checkpoint". It now matches the code.
Reading the open questions confirmed two more:

- **Terminal spoofing.** Receipt-controlled text (for example a forged `jwks_url`) reached
  the terminal unescaped, so ANSI escapes or newlines could print or overwrite a
  `VERIFIED` line. Every receipt-derived string is now passed through `printable()`.
- **`--pubkey` / `--jwks` without a value** silently fell back to fetching keys over the
  network. It is now a usage error (exit `2`).

Known limitation, not a defect today: the Merkle tree hashes leaves and interior nodes
without domain tags. That only matters once an anchor is trusted as evidence; because this
tool does not trust anchors (see 1.1.2), tags will be added on both sides before anchoring
is switched on.

MIT licensed.

## Regression fixtures, CI and time checks (1.2.0)

Suggested publicly by [@jeff_mitchog](https://www.threads.com/@jeff_mitchog) on Threads: keep every broken
receipt as a fixture in CI, including a changed signing key, a `__proto__` receipt and a stale
timestamp, and make the verifier fail before it prints VERIFIED. He was right on all three:

- The tests only ran by hand. GitHub Actions now runs `npm test` on every push and pull
  request (Node 18, 20, 22).
- `fixtures/broken/` holds nine signed or forged receipts. Each goes through the real CLI and
  must end in exactly one `RESULT: NOT VERIFIED` line (see `fixtures/README.md`).
- The verifier ignored `sealed_at`. It now prints the signed time, rejects a time in the future
  (1.1.4 printed VERIFIED for a receipt sealed "in 2099"), and `--max-age <days>` fails receipts
  older than you accept. A signature proves who sealed a receipt, not that it is recent.
- `--jwks-file <keys.json>` pins a key set you hold locally, with the same key id rules as the
  published set and no network.

## Verified by POVV

[![POVV Verified](https://povv.io/api/badge/verified/c40e2a0f-8fc5-4ed9-8e0c-d366ff584739)](https://povv.io/verified/c40e2a0f-8fc5-4ed9-8e0c-d366ff584739)

Commit `494cd55` (1.1.3) holds POVV's first public **POVV Verified** certificate: every
file read in full, no confirmed critical or high finding open. It took five Full Repo
audits; the fixes are listed above (1.1.0–1.1.3). The fifth audit left five open questions
(key trust wording, key type, notes in `errors`, offline default), answered in 1.1.4 by
documentation and an Ed25519 key-type check. The certificate covers `494cd55` only.

Audit receipts can be checked offline with this package:

```bash
curl -H "Authorization: Bearer <token>" https://povv.io/api/ledger/receipt/<audit_run_id> > receipt.json
node cli.mjs receipt.json
```
