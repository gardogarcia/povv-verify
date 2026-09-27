// povv-verify — offline, zero-trust verification of POVV audit receipts.
//
// No dependencies beyond Node's built-in crypto. Given a receipt exported from
// GET /api/ledger/receipt/:id, this:
//   1. recomputes the integrity hash from the exact canonical sealed_payload and
//      checks it equals the receipt's integrity_hash,
//   2. verifies the Ed25519 signature against a public key (JWKS or PEM),
//   3. (if anchored) verifies the Merkle inclusion proof against the checkpoint root.
//
// The verifier NEVER trusts POVV's servers: it only needs the receipt JSON and the
// published public key. The same canonicalization is used by the server signer.

import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

/**
 * Deterministic JSON with recursively sorted object keys (arrays preserved).
 * Keys are defined, not assigned: `acc["__proto__"] = x` would hit the prototype
 * setter and silently drop an own `__proto__` member from the hashed bytes.
 */
export function canonicalize(value) {
  return JSON.stringify(value, (_key, v) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      return Object.keys(v)
        .sort()
        .reduce((acc, k) => {
          Object.defineProperty(acc, k, { value: v[k], enumerable: true, writable: true, configurable: true });
          return acc;
        }, {});
    }
    return v;
  });
}

/**
 * Render a receipt-controlled value for a terminal or log: control characters (C0, DEL,
 * C1 — ANSI escapes live here), line/paragraph separators and bidi overrides become
 * visible \uXXXX escapes, so a forged receipt cannot print or overwrite a "VERIFIED" line.
 */
export function printable(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

export function sha256Hex(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export function computeIntegrityHash(sealedPayload) {
  return sha256Hex(canonicalize(sealedPayload));
}

function hashPair(a, b) {
  return createHash("sha256").update(Buffer.concat([a, b])).digest();
}

const HEX64 = /^[0-9a-f]{64}$/i;

/**
 * Verify a Merkle inclusion proof produced by buildMerkleProof on the server.
 * A malformed proof returns false instead of throwing. This proves the leaf is under
 * `rootHex` — not that the root was ever published; see verifyReceipt's anchor note.
 */
export function verifyMerkleProof(leafHex, proof, rootHex) {
  if (!HEX64.test(String(leafHex)) || !HEX64.test(String(rootHex)) || !Array.isArray(proof)) return false;
  let acc = Buffer.from(leafHex, "hex");
  for (const node of proof) {
    if (!node || !HEX64.test(String(node.hash)) || (node.position !== "left" && node.position !== "right")) return false;
    const sibling = Buffer.from(node.hash, "hex");
    acc = node.position === "left" ? hashPair(sibling, acc) : hashPair(acc, sibling);
  }
  return acc.toString("hex") === String(rootHex).toLowerCase();
}

function loadPublicKey({ jwk, pem }) {
  if (pem) return createPublicKey({ key: pem, format: "pem" });
  if (jwk) return createPublicKey({ key: jwk, format: "jwk" });
  throw new Error("No public key provided (jwk or pem).");
}

/** Verify the Ed25519 signature over the raw 32 bytes of the hex integrity hash. */
export function verifySignature(integrityHashHex, signatureB64, key) {
  if (!signatureB64) return false;
  if (!/^[0-9a-f]{64}$/.test(integrityHashHex)) return false;
  const publicKey = loadPublicKey(key);
  return edVerify(null, Buffer.from(integrityHashHex, "hex"), publicKey, Buffer.from(signatureB64, "base64"));
}

/**
 * The key set a receipt is checked against by default: POVV's published ledger
 * keys. A receipt's own `signature.jwks_url` is NEVER trusted — whoever writes a
 * receipt could point it at a key they control and sign a forgery with it.
 */
export const DEFAULT_JWKS_URL = "https://povv.io/.well-known/povv-ledger-keys";

/**
 * Fetch a TRUSTED JWKS and return the JWK whose `kid` equals `keyId`.
 * Fails closed: a missing key id or a key id that is not in the set is an error,
 * never a fallback to some other key.
 */
export async function fetchJwk(jwksUrl, keyId, fetchImpl = fetch) {
  if (!keyId) throw new Error("Receipt names no signing key id (signature.key_id).");
  const res = await fetchImpl(jwksUrl);
  if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
  const body = await res.json();
  const keys = Array.isArray(body.keys) ? body.keys : [];
  const match = keys.find((k) => k && k.kid === keyId);
  if (!match) throw new Error(`Key "${keyId}" is not in the trusted key set at ${jwksUrl}.`);
  if (match.kty !== "OKP" || match.crv !== "Ed25519") throw new Error(`Key "${keyId}" is not an Ed25519 key.`);
  return match;
}

/**
 * Verify a full receipt. Pass either { jwk } / { pem } directly, or set
 * fetchKey:true to fetch the key named by receipt.signature.key_id from a TRUSTED
 * key set: options.jwksUrl if you pin one, otherwise DEFAULT_JWKS_URL. The URL
 * embedded in the receipt is reported, never followed.
 *
 * Returns { ok, checks: { hashValid, signatureValid, inclusionValid|null, idBound|null }, errors }.
 */
export async function verifyReceipt(receipt, options = {}) {
  const errors = [];
  const checks = { hashValid: false, signatureValid: false, inclusionValid: null, idBound: null };

  if (!receipt || typeof receipt !== "object" || !receipt.sealed_payload) {
    return { ok: false, checks, errors: ["Receipt missing sealed_payload."] };
  }

  // 1) Hash integrity.
  const recomputed = computeIntegrityHash(receipt.sealed_payload);
  checks.hashValid = recomputed === receipt.integrity_hash;
  if (!checks.hashValid) {
    errors.push(`integrity_hash mismatch: recomputed ${recomputed} != receipt ${printable(receipt.integrity_hash)}`);
  }

  // 1b) The top-level audit_run_id is an unsigned label; the signed one lives in
  // sealed_payload. A receipt relabelled with another audit's id must not pass.
  const signedId = receipt.sealed_payload.audit_run_id;
  if (signedId !== undefined) {
    checks.idBound = receipt.audit_run_id === undefined || receipt.audit_run_id === signedId;
    if (!checks.idBound) {
      errors.push(`audit_run_id mismatch: receipt says ${printable(receipt.audit_run_id)}, signed payload says ${printable(signedId)}`);
    }
  }

  // 2) Signature.
  let key = null;
  if (options.pem) key = { pem: options.pem };
  else if (options.jwk) key = { jwk: options.jwk };
  else if (options.fetchKey) {
    const trustedUrl = options.jwksUrl || DEFAULT_JWKS_URL;
    const claimedUrl = receipt.signature?.jwks_url;
    if (claimedUrl && claimedUrl !== trustedUrl) {
      errors.push(`Ignored the receipt's own jwks_url (${printable(claimedUrl)}); checked against ${printable(trustedUrl)}.`);
    }
    try {
      const jwk = await fetchJwk(trustedUrl, receipt.signature?.key_id, options.fetch || fetch);
      key = { jwk };
    } catch (e) {
      errors.push(`JWKS error: ${printable(e.message)}`);
    }
  }

  if (!receipt.signature?.value) {
    errors.push("Receipt is UNSIGNED (no signature value).");
  } else if (key) {
    try {
      checks.signatureValid = verifySignature(receipt.integrity_hash, receipt.signature.value, key);
      if (!checks.signatureValid) errors.push("Ed25519 signature did NOT verify against the public key.");
    } catch (e) {
      errors.push(`Signature verification error: ${printable(e.message)}`);
    }
  } else {
    errors.push("No public key available to verify signature (provide pem/jwk or set fetchKey:true).");
  }

  // 3) Merkle inclusion (optional — only if the seal has been anchored).
  if (receipt.anchor && receipt.anchor.merkle_root && Array.isArray(receipt.anchor.proof)) {
    checks.inclusionValid = verifyMerkleProof(
      receipt.integrity_hash,
      receipt.anchor.proof,
      receipt.anchor.merkle_root
    );
    if (!checks.inclusionValid) errors.push("Merkle inclusion proof did NOT reproduce the checkpoint root.");
    // The root and proof come from the receipt itself. Nothing here fetches the external
    // witness, so a matching proof shows self-consistency, not when the seal was made.
    errors.push("Anchor root taken from the receipt; it was NOT checked against an external witness, so it does not prove when the seal was made.");
  }

  const ok =
    checks.hashValid &&
    checks.signatureValid &&
    checks.idBound !== false &&
    (checks.inclusionValid === null || checks.inclusionValid === true);

  return { ok, checks, errors };
}
