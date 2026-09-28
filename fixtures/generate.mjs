// Regenerates the regression receipts in this folder. The signing keys exist only
// in memory while this runs; only the PUBLIC key is written (test-jwks.json,
// test-key.pem). Run: node fixtures/generate.mjs
import { generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { computeIntegrityHash } from "../index.mjs";

const dir = new URL(".", import.meta.url).pathname;
const KID = "fixture-key-1";
const trusted = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519"); // a different key claiming the same kid

writeFileSync(`${dir}test-jwks.json`, JSON.stringify({ keys: [{ ...trusted.publicKey.export({ format: "jwk" }), kid: KID, alg: "EdDSA", use: "sig" }] }, null, 2) + "\n");
writeFileSync(`${dir}test-key.pem`, trusted.publicKey.export({ type: "spki", format: "pem" }));

const base = { version: 2, audit_run_id: "00000000-0000-4000-8000-000000000001", sealed_at: "2026-09-01T12:00:00.000Z", technical_score: 74, note: "povv-verify regression fixture" };
function receipt(payload, keyPair = trusted, { kid = KID, jwksUrl } = {}) {
  const integrity_hash = computeIntegrityHash(payload);
  const value = sign(null, Buffer.from(integrity_hash, "hex"), keyPair.privateKey).toString("base64");
  return { audit_run_id: payload.audit_run_id, integrity_hash, sealed_payload: payload,
    signature: { algo: "Ed25519", value, key_id: kid, ...(jwksUrl ? { jwks_url: jwksUrl } : {}) } };
}
const out = (name, obj) => writeFileSync(`${dir}${name}`, (typeof obj === "string" ? obj : JSON.stringify(obj, null, 2)) + "\n");

rmSync(`${dir}broken`, { recursive: true, force: true });
mkdirSync(`${dir}broken`);

// Must VERIFY.
out("valid.json", receipt(base));
// Verifies by default; fails only when the caller sets --max-age.
out("stale.json", receipt({ ...base, sealed_at: "2025-01-15T00:00:00.000Z" }));

// Must NOT verify — each one is a way someone tried (or could try) to get a VERIFIED.
out("broken/changed-signing-key.json", receipt(base, stranger));
out("broken/unknown-key-id.json", receipt(base, trusted, { kid: "retired-key" }));
const smuggled = JSON.stringify(receipt(base), null, 2).replace('"sealed_payload": {', '"sealed_payload": {\n    "__proto__": { "technical_score": 100 },');
out("broken/proto-smuggled.json", smuggled);
out("broken/tampered-payload.json", { ...receipt(base), sealed_payload: { ...base, technical_score: 100 } });
out("broken/relabelled-id.json", { ...receipt(base), audit_run_id: "00000000-0000-4000-8000-000000000999" });
out("broken/future-timestamp.json", receipt({ ...base, sealed_at: "2099-01-01T00:00:00.000Z" }));
out("broken/ansi-forged.json", receipt({ ...base, technical_score: 100 }, stranger, { jwksUrl: "https://evil.example/\u001b[2K\u001b[1A\nRESULT: VERIFIED ✓" }));
const unsigned = receipt(base); delete unsigned.signature.value;
out("broken/unsigned.json", unsigned);
out("broken/malformed-proof.json", { ...receipt(base), anchor: { merkle_root: computeIntegrityHash(base), proof: [null] } });
console.log("fixtures written");
