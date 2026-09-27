// node --test — no network, no dependencies. Keys are generated per run.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { computeIntegrityHash, verifyReceipt, DEFAULT_JWKS_URL } from "./index.mjs";

function keypair(kid) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { kid, privateKey, jwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "EdDSA", use: "sig" } };
}

function receipt(payload, signer, { kid = signer.kid, jwksUrl } = {}) {
  const integrity_hash = computeIntegrityHash(payload);
  const value = sign(null, Buffer.from(integrity_hash, "hex"), signer.privateKey).toString("base64");
  return { audit_run_id: "fixture", sealed_payload: payload, integrity_hash,
    signature: { value, key_id: kid, ...(jwksUrl ? { jwks_url: jwksUrl } : {}) } };
}

function fakeFetch(sets) {
  const calls = [];
  const impl = async (url) => {
    calls.push(url);
    const keys = sets[url];
    return keys ? { ok: true, json: async () => ({ keys }) } : { ok: false, status: 404, json: async () => ({}) };
  };
  return { impl, calls };
}

const povv = keypair("povv-ledger-2026-06");
const attacker = keypair("povv-ledger-2026-06"); // same kid on purpose
const ATTACKER_URL = "https://attacker.example/jwks.json";
const payload = { verdict: "sealed", vmi: 74, repo: "acme/app" };

test("a genuine POVV receipt verifies against the default trusted key set", async () => {
  const f = fakeFetch({ [DEFAULT_JWKS_URL]: [povv.jwk] });
  const r = await verifyReceipt(receipt(payload, povv, { jwksUrl: DEFAULT_JWKS_URL }), { fetchKey: true, fetch: f.impl });
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.deepEqual(f.calls, [DEFAULT_JWKS_URL]);
});

test("a forged receipt that points jwks_url at the forger's key is NOT verified", async () => {
  const f = fakeFetch({ [DEFAULT_JWKS_URL]: [povv.jwk], [ATTACKER_URL]: [attacker.jwk] });
  const forged = receipt({ ...payload, vmi: 99 }, attacker, { jwksUrl: ATTACKER_URL });
  const r = await verifyReceipt(forged, { fetchKey: true, fetch: f.impl });
  assert.equal(r.checks.hashValid, true, "the forger can always make the hash match");
  assert.equal(r.checks.signatureValid, false);
  assert.equal(r.ok, false);
  assert.ok(!f.calls.includes(ATTACKER_URL), "the receipt's own jwks_url must never be fetched");
  assert.ok(r.errors.some((e) => e.includes("Ignored the receipt's own jwks_url")));
});

test("an unknown key id fails closed instead of falling back to another key", async () => {
  const other = keypair("some-other-key");
  const f = fakeFetch({ [DEFAULT_JWKS_URL]: [other.jwk, povv.jwk] });
  const r = await verifyReceipt(receipt(payload, povv, { kid: "not-published" }), { fetchKey: true, fetch: f.impl });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.includes("not in the trusted key set")));
});

test("a receipt without a key id is not verified by fetching", async () => {
  const f = fakeFetch({ [DEFAULT_JWKS_URL]: [povv.jwk] });
  const rc = receipt(payload, povv);
  delete rc.signature.key_id;
  const r = await verifyReceipt(rc, { fetchKey: true, fetch: f.impl });
  assert.equal(r.ok, false);
});

test("a pinned key set is used instead of the default", async () => {
  const PINNED = "https://mirror.example/keys";
  const f = fakeFetch({ [PINNED]: [povv.jwk] });
  const r = await verifyReceipt(receipt(payload, povv), { fetchKey: true, jwksUrl: PINNED, fetch: f.impl });
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.deepEqual(f.calls, [PINNED]);
});

test("a tampered payload fails the hash check", async () => {
  const f = fakeFetch({ [DEFAULT_JWKS_URL]: [povv.jwk] });
  const rc = receipt(payload, povv);
  rc.sealed_payload = { ...payload, vmi: 100 };
  const r = await verifyReceipt(rc, { fetchKey: true, fetch: f.impl });
  assert.equal(r.checks.hashValid, false);
  assert.equal(r.ok, false);
});
