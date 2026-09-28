# Regression receipts

Signed with a throwaway Ed25519 key that existed only while `generate.mjs` ran.
Only its public half is here (`test-jwks.json`, `test-key.pem`). `npm test` runs every
file in `broken/` through the real CLI and requires exactly one `RESULT: NOT VERIFIED`.

| File | Why it must fail |
|---|---|
| `broken/changed-signing-key.json` | signed by a different key that claims the trusted key id |
| `broken/unknown-key-id.json` | names a key id that is not in the pinned key set |
| `broken/proto-smuggled.json` | an own `__proto__` member added after signing |
| `broken/tampered-payload.json` | payload changed after signing |
| `broken/relabelled-id.json` | unsigned top-level `audit_run_id` disagrees with the signed one |
| `broken/future-timestamp.json` | genuinely signed, but `sealed_at` is in 2099 |
| `broken/ansi-forged.json` | forged signature plus ANSI escapes and a fake `RESULT: VERIFIED` line in `jwks_url` |
| `broken/unsigned.json` | no signature value |
| `broken/malformed-proof.json` | anchor proof with a malformed node |

`valid.json` must verify. `stale.json` is authentic and verifies, and fails only with `--max-age`.
Add a file here for every new way a receipt could be broken.
