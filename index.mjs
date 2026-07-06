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

/** Deterministic JSON with recursively sorted object keys (arrays preserved). */
export function canonicalize(value) {
  return JSON.stringify(value, (_key, v) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      return Object.keys(v)
        .sort()
        .reduce((acc, k) => {
          acc[k] = v[k];
          return acc;
        }, {});
    }
    return v;
  });
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

/** Verify a Merkle inclusion proof produced by buildMerkleProof on the server. */
export function verifyMerkleProof(leafHex, proof, rootHex) {
  let acc = Buffer.from(leafHex, "hex");
  for (const node of proof) {
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

/** Fetch the JWKS and return the JWK matching the receipt's key id (or the first). */
export async function fetchJwk(jwksUrl, keyId) {
  const res = await fetch(jwksUrl);
  if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
  const body = await res.json();
  const keys = Array.isArray(body.keys) ? body.keys : [];
  if (keys.length === 0) throw new Error("JWKS contains no keys.");
  return keys.find((k) => k.kid === keyId) ?? keys[0];
}

/**
 * Verify a full receipt. Pass either { jwk } / { pem } directly, or set
 * fetchKey:true to pull the key from receipt.signature.jwks_url.
 *
 * Returns { ok, checks: { hashValid, signatureValid, inclusionValid|null }, errors }.
 */
export async function verifyReceipt(receipt, options = {}) {
  const errors = [];
  const checks = { hashValid: false, signatureValid: false, inclusionValid: null };

  if (!receipt || typeof receipt !== "object" || !receipt.sealed_payload) {
    return { ok: false, checks, errors: ["Receipt missing sealed_payload."] };
  }

  // 1) Hash integrity.
  const recomputed = computeIntegrityHash(receipt.sealed_payload);
  checks.hashValid = recomputed === receipt.integrity_hash;
  if (!checks.hashValid) {
    errors.push(`integrity_hash mismatch: recomputed ${recomputed} != receipt ${receipt.integrity_hash}`);
  }

  // 2) Signature.
  let key = null;
  if (options.pem) key = { pem: options.pem };
  else if (options.jwk) key = { jwk: options.jwk };
  else if (options.fetchKey && receipt.signature?.jwks_url) {
    try {
      const jwk = await fetchJwk(receipt.signature.jwks_url, receipt.signature.key_id);
      key = { jwk };
    } catch (e) {
      errors.push(`JWKS error: ${e.message}`);
    }
  }

  if (!receipt.signature?.value) {
    errors.push("Receipt is UNSIGNED (no signature value).");
  } else if (key) {
    try {
      checks.signatureValid = verifySignature(receipt.integrity_hash, receipt.signature.value, key);
      if (!checks.signatureValid) errors.push("Ed25519 signature did NOT verify against the public key.");
    } catch (e) {
      errors.push(`Signature verification error: ${e.message}`);
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
  }

  const ok =
    checks.hashValid &&
    checks.signatureValid &&
    (checks.inclusionValid === null || checks.inclusionValid === true);

  return { ok, checks, errors };
}
