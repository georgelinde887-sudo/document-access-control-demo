const crypto = require('node:crypto');

class TokenManager {
  constructor(secretKey) {
    if (!secretKey || typeof secretKey !== 'string' || secretKey.length < 16) {
      throw new Error('Secret key must be a string of at least 16 characters');
    }
    this.secretKey = secretKey;
    this.revokedTokens = new Set();
    this.revokedDocuments = new Set();
    this.viewCounts = new Map(); // tokenId -> count
  }

  generateSignedUrl(baseUrl, documentId, options = {}) {
    const {
      expiresInSeconds = 3600,
      recipientEmail = '',
      maxViews = 5
    } = options;

    const tokenId = 'tok_' + crypto.randomBytes(8).toString('hex');
    const expiresAt = Math.floor(Date.now() / 1000) + expiresInSeconds;

    const payload = {
      tokenId,
      documentId,
      expiresAt,
      maxViews,
      recipientEmail: recipientEmail.trim().toLowerCase()
    };

    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto
      .createHmac('sha256', this.secretKey)
      .update(payloadB64)
      .digest('base64url');

    const token = `${payloadB64}.${signature}`;
    const cleanBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    return {
      url: `${cleanBase}/view?token=${token}`,
      token,
      tokenId,
      expiresAt: new Date(expiresAt * 1000).toISOString(),
      maxViews
    };
  }

  verifyAndConsumeToken(tokenString) {
    if (!tokenString || typeof tokenString !== 'string') {
      return { valid: false, reason: 'Missing token' };
    }

    const parts = tokenString.split('.');
    if (parts.length !== 2) {
      return { valid: false, reason: 'Malformed token structure' };
    }

    const [payloadB64, signature] = parts;
    const expectedSig = crypto
      .createHmac('sha256', this.secretKey)
      .update(payloadB64)
      .digest('base64url');

    // Constant-time comparison to prevent timing attacks
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return { valid: false, reason: 'Invalid cryptographic signature' };
    }

    let payload;
    try {
      payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    } catch {
      return { valid: false, reason: 'Unparseable token payload' };
    }

    const { tokenId, documentId, expiresAt, maxViews, recipientEmail } = payload;

    // Check document-level revocation kill-switch
    if (this.revokedDocuments.has(documentId)) {
      return { valid: false, reason: 'Document access has been revoked globally by sender' };
    }

    // Check token-level revocation kill-switch
    if (this.revokedTokens.has(tokenId)) {
      return { valid: false, reason: 'Token has been explicitly revoked' };
    }

    // Check expiration timestamp
    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec > expiresAt) {
      return { valid: false, reason: `Token expired at ${new Date(expiresAt * 1000).toISOString()}` };
    }

    // Check view count limits
    const currentViews = this.viewCounts.get(tokenId) || 0;
    if (maxViews && currentViews >= maxViews) {
      return { valid: false, reason: `Maximum view limit (${maxViews}) exceeded` };
    }

    // Consume view
    const newCount = currentViews + 1;
    this.viewCounts.set(tokenId, newCount);

    return {
      valid: true,
      tokenId,
      documentId,
      recipientEmail,
      viewNumber: newCount,
      remainingViews: maxViews ? Math.max(0, maxViews - newCount) : null,
      expiresAt: new Date(expiresAt * 1000).toISOString()
    };
  }

  revokeToken(tokenId) {
    this.revokedTokens.add(tokenId);
    return true;
  }

  revokeDocument(documentId) {
    this.revokedDocuments.add(documentId);
    return true;
  }

  isTokenRevoked(tokenId) {
    return this.revokedTokens.has(tokenId);
  }
}

module.exports = { TokenManager };
