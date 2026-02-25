// ─────────────────────────────────────────────────────────────────
// crypto.js — HMAC-SHA256 Token Engine (THE SECURITY CORE)
// ─────────────────────────────────────────────────────────────────
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const HMAC_SECRET = process.env.HMAC_SECRET || 'dev-secret-change-in-production-please';
// Token is valid for 60s on the backend, but the QR rotates every 30s on the frontend.
// The extra 30s buffer ensures students who scan near the end of the visible QR cycle
// still have plenty of time to fill the form and submit before the backend rejects it.
const TOKEN_EXPIRY_MS = parseInt(process.env.TOKEN_EXPIRY_MS || '60000');

/**
 * Generate a signed, time-bound, single-use token
 * Token structure: base64(JSON({ sessionId, timestamp, nonce, sig }))
 *
 * The SECRET KEY lives ONLY here on the server. Never sent to client.
 */
function generateToken(sessionId) {
  const timestamp = Date.now();
  const nonce = uuidv4().replace(/-/g, ''); // 32-char random hex
  const tokenId = `${sessionId}|${timestamp}|${nonce}`;

  // HMAC-SHA256: sign the payload with the secret
  const sig = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(tokenId)
    .digest('base64');

  const payload = { sessionId, timestamp, nonce, sig };
  const token = Buffer.from(JSON.stringify(payload)).toString('base64');

  return { token, tokenId, expiresAt: timestamp + TOKEN_EXPIRY_MS };
}

/**
 * Verify a token — all 4 checks must pass:
 * 1. Valid base64 + JSON structure
 * 2. HMAC signature matches (proves not tampered)
 * 3. Not expired (timestamp within window)
 * 4. Not used before (checked by caller against usedTokens)
 */
function verifyToken(tokenStr) {
  let payload;

  // Check 1: parseable
  try {
    payload = JSON.parse(Buffer.from(tokenStr, 'base64').toString('utf8'));
  } catch (e) {
    return { valid: false, reason: 'MALFORMED_TOKEN' };
  }

  const { sessionId, timestamp, nonce, sig } = payload;
  if (!sessionId || !timestamp || !nonce || !sig) {
    return { valid: false, reason: 'MISSING_FIELDS' };
  }

  // Check 2: HMAC signature
  const tokenId = `${sessionId}|${timestamp}|${nonce}`;
  const expectedSig = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(tokenId)
    .digest('base64');

  // Constant-time comparison to prevent timing attacks
  const sigBuffer = Buffer.from(sig);
  const expectedBuffer = Buffer.from(expectedSig);
  if (sigBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }

  // Check 3: expiry
  const age = Date.now() - timestamp;
  if (age > TOKEN_EXPIRY_MS) {
    return { valid: false, reason: `TOKEN_EXPIRED (age: ${Math.round(age / 1000)}s, max: ${TOKEN_EXPIRY_MS / 1000}s)` };
  }

  return { valid: true, sessionId, tokenId, expiresAt: timestamp + TOKEN_EXPIRY_MS };
}

/**
 * Verify only the HMAC signature of a token — NO expiry check.
 * Used by /scan when the token was already validated + claimed by /claim.
 * The 30s window applies to *opening* the link (claim), not to *submitting* the form.
 */
function verifyTokenSignatureOnly(tokenStr) {
  let payload;

  try {
    payload = JSON.parse(Buffer.from(tokenStr, 'base64').toString('utf8'));
  } catch (e) {
    return { valid: false, reason: 'MALFORMED_TOKEN' };
  }

  const { sessionId, timestamp, nonce, sig } = payload;
  if (!sessionId || !timestamp || !nonce || !sig) {
    return { valid: false, reason: 'MISSING_FIELDS' };
  }

  const tokenId = `${sessionId}|${timestamp}|${nonce}`;
  const expectedSig = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(tokenId)
    .digest('base64');

  const sigBuffer = Buffer.from(sig);
  const expectedBuffer = Buffer.from(expectedSig);
  if (sigBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }

  return { valid: true, sessionId, tokenId, expiresAt: timestamp + TOKEN_EXPIRY_MS };
}

module.exports = { generateToken, verifyToken, verifyTokenSignatureOnly, TOKEN_EXPIRY_MS };
