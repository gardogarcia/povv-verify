#!/usr/bin/env node
// povv-verify CLI — verify a POVV audit receipt offline.
//
// Usage:
//   povv-verify <receipt.json> [--jwks <url>] [--pubkey <public.pem>]
//
// If neither --jwks nor --pubkey is given, the JWKS URL embedded in the receipt
// is used (set --no-fetch to forbid network access and require a local key).

import { readFileSync } from "node:fs";
import { verifyReceipt } from "./index.mjs";

function parseArgs(argv) {
  const args = { _: [], fetch: true };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--jwks") args.jwks = argv[++i];
    else if (a === "--pubkey") args.pubkey = argv[++i];
    else if (a === "--no-fetch") args.fetch = false;
    else args._.push(a);
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const file = args._[0];
  if (!file) {
    console.error("Usage: povv-verify <receipt.json> [--jwks <url>] [--pubkey <public.pem>] [--no-fetch]");
    process.exit(2);
  }

  let receipt;
  try {
    receipt = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    console.error(`Failed to read receipt: ${e.message}`);
    process.exit(2);
  }

  const options = { fetchKey: args.fetch && !args.pubkey && !args.jwks };
  if (args.pubkey) options.pem = readFileSync(args.pubkey, "utf8");
  if (args.jwks) {
    // Override the receipt's JWKS URL with an explicitly trusted one.
    receipt = { ...receipt, signature: { ...receipt.signature, jwks_url: args.jwks } };
    options.fetchKey = true;
  }

  const result = await verifyReceipt(receipt, options);

  const mark = (v) => (v === true ? "PASS" : v === false ? "FAIL" : "n/a ");
  console.log("POVV receipt verification");
  console.log(`  audit_run_id      : ${receipt.audit_run_id}`);
  console.log(`  integrity_hash    : ${receipt.integrity_hash}`);
  console.log(`  hash recomputed   : ${mark(result.checks.hashValid)}`);
  console.log(`  ed25519 signature : ${mark(result.checks.signatureValid)}`);
  console.log(`  merkle inclusion  : ${mark(result.checks.inclusionValid)}`);
  if (result.errors.length > 0) {
    console.log("  notes:");
    for (const e of result.errors) console.log(`    - ${e}`);
  }
  console.log(`RESULT: ${result.ok ? "VERIFIED ✓" : "NOT VERIFIED ✗"}`);
  process.exit(result.ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
