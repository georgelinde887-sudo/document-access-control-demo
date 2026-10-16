const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { TokenManager } = require('../src/token-manager');

describe('Document Access Control Engine Tests', () => {
  const secret = 'super-secure-production-secret-key-32chars';

  test('generates valid HMAC signed URL and successfully consumes it', () => {
    const tm = new TokenManager(secret);
    const { token, tokenId } = tm.generateSignedUrl('https://share.acme.com', 'doc_99', {
      expiresInSeconds: 300,
      recipientEmail: 'partner@benchmark.com',
      maxViews: 2
    });

    const res1 = tm.verifyAndConsumeToken(token);
    assert.equal(res1.valid, true);
    assert.equal(res1.tokenId, tokenId);
    assert.equal(res1.documentId, 'doc_99');
    assert.equal(res1.recipientEmail, 'partner@benchmark.com');
    assert.equal(res1.viewNumber, 1);
    assert.equal(res1.remainingViews, 1);
  });

  test('enforces max view counts and rejects subsequent visits', () => {
    const tm = new TokenManager(secret);
    const { token } = tm.generateSignedUrl('https://share.acme.com', 'doc_1', {
      maxViews: 1
    });

    const res1 = tm.verifyAndConsumeToken(token);
    assert.equal(res1.valid, true);

    const res2 = tm.verifyAndConsumeToken(token);
    assert.equal(res2.valid, false);
    assert.ok(res2.reason.includes('Maximum view limit'));
  });

  test('rejects tampered token signatures', () => {
    const tm = new TokenManager(secret);
    const { token } = tm.generateSignedUrl('https://share.acme.com', 'doc_1');

    const [payloadB64, sig] = token.split('.');
    // Tamper with payload
    const tamperedPayload = Buffer.from(JSON.stringify({ doc: 'tampered' })).toString('base64url');
    const tamperedToken = `${tamperedPayload}.${sig}`;

    const res = tm.verifyAndConsumeToken(tamperedToken);
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'Invalid cryptographic signature');
  });

  test('rejects expired tokens', () => {
    const tm = new TokenManager(secret);
    // Expire immediately (-10 seconds)
    const { token } = tm.generateSignedUrl('https://share.acme.com', 'doc_1', {
      expiresInSeconds: -10
    });

    const res = tm.verifyAndConsumeToken(token);
    assert.equal(res.valid, false);
    assert.ok(res.reason.includes('Token expired'));
  });

  test('immediately revokes token upon emergency kill-switch', () => {
    const tm = new TokenManager(secret);
    const { token, tokenId } = tm.generateSignedUrl('https://share.acme.com', 'doc_1');

    const res1 = tm.verifyAndConsumeToken(token);
    assert.equal(res1.valid, true);

    // Sender hits kill switch
    tm.revokeToken(tokenId);

    const res2 = tm.verifyAndConsumeToken(token);
    assert.equal(res2.valid, false);
    assert.ok(res2.reason.includes('Token has been explicitly revoked'));
  });

  test('immediately revokes entire document regardless of token', () => {
    const tm = new TokenManager(secret);
    const link1 = tm.generateSignedUrl('https://share.acme.com', 'pitch_deck_series_a');
    const link2 = tm.generateSignedUrl('https://share.acme.com', 'pitch_deck_series_a');

    tm.revokeDocument('pitch_deck_series_a');

    assert.equal(tm.verifyAndConsumeToken(link1.token).valid, false);
    assert.equal(tm.verifyAndConsumeToken(link2.token).valid, false);
  });
});
