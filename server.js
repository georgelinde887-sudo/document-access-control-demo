const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const url = require('node:url');
const { TokenManager } = require('./src/token-manager');

const PORT = process.env.PORT || 8083;
const SECRET = process.env.DEMO_SECRET || 'development-demo-secret-key-32chars-minimum!';
const tokenManager = new TokenManager(SECRET);
const activeTokens = [];

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Static Assets
  if (pathname === '/' || pathname === '/index.html') {
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // API: Create Signed Link
  if (req.method === 'POST' && pathname === '/api/links/create') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const host = req.headers.host || `localhost:${PORT}`;
        const baseUrl = `http://${host}`;

        const linkInfo = tokenManager.generateSignedUrl(baseUrl, data.documentId || 'series-a-deck.pdf', {
          expiresInSeconds: Number(data.expiresInSeconds) || 3600,
          recipientEmail: data.recipientEmail || 'investor@fund.com',
          maxViews: Number(data.maxViews) || 3
        });

        activeTokens.push({
          ...linkInfo,
          documentId: data.documentId || 'series-a-deck.pdf',
          recipientEmail: data.recipientEmail || 'investor@fund.com',
          createdAt: new Date().toISOString()
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(linkInfo));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API: List Active Links
  if (req.method === 'GET' && pathname === '/api/links/active') {
    const list = activeTokens.map(t => ({
      tokenId: t.tokenId,
      documentId: t.documentId,
      recipientEmail: t.recipientEmail,
      url: t.url,
      expiresAt: t.expiresAt,
      maxViews: t.maxViews,
      viewsConsumed: tokenManager.viewCounts.get(t.tokenId) || 0,
      isRevoked: tokenManager.isTokenRevoked(t.tokenId)
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(list));
  }

  // API: Revoke Token
  if (req.method === 'POST' && pathname === '/api/links/revoke') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { tokenId } = JSON.parse(body);
        tokenManager.revokeToken(tokenId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, revokedTokenId: tokenId }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // Secure View Endpoint
  if (pathname === '/view') {
    const token = parsedUrl.query.token;
    const verification = tokenManager.verifyAndConsumeToken(token);

    if (!verification.valid) {
      res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>Access Denied — 403 Forbidden</title></head>
        <body style="background: #090d16; color: #f87171; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center;">
          <div style="background: #111827; border: 1px solid #ef4444; border-radius: 12px; padding: 40px; max-width: 480px;">
            <h1 style="font-size: 24px; margin-bottom: 12px;">Access Denied (403)</h1>
            <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">${verification.reason}</p>
            <div style="margin-top: 24px;">
              <a href="/" style="color: #60a5fa; text-decoration: none; font-size: 13px; font-weight: 600;">&larr; Back to Access Control Dashboard</a>
            </div>
          </div>
        </body>
        </html>
      `);
    }

    // Granted: Render Document with Dynamic Watermark
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Confidential Document Viewer — ${verification.documentId}</title>
        <style>
          body { background: #0b0f19; color: #fff; font-family: sans-serif; margin: 0; padding: 24px; }
          .container { max-width: 800px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 32px; position: relative; overflow: hidden; }
          .watermark-overlay {
            position: absolute; inset: 0; pointer-events: none;
            display: flex; align-items: center; justify-content: center;
            opacity: 0.12; font-size: 26px; font-weight: 800; color: #ef4444;
            transform: rotate(-30deg); user-select: none; text-align: center;
          }
          .header { border-bottom: 1px solid #1f2937; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }
          .badge { background: rgba(16, 185, 129, 0.2); color: #10b981; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="watermark-overlay">
            CONFIDENTIAL — ${verification.recipientEmail}<br>
            VIEW #${verification.viewNumber} &bull; ${new Date().toISOString()}
          </div>
          <div class="header">
            <div>
              <h2 style="font-size: 20px; margin-bottom: 4px;">Document: ${verification.documentId}</h2>
              <span style="font-size: 12px; color: #94a3b8;">Issued to: ${verification.recipientEmail}</span>
            </div>
            <div style="text-align: right;">
              <span class="badge">HMAC Verified</span>
              <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Remaining views: ${verification.remainingViews}</div>
            </div>
          </div>
          <div style="line-height: 1.8; color: #cbd5e1; font-size: 14px;">
            <h3>Series A Operating Forecast & Unit Economics</h3>
            <p>This document contains non-public financial performance metrics for Acme Corp. Gross margin expanded from 68% in 2024 to 79% in 2026. Net churn remains negative at -14% annually.</p>
            <p>Every view of this link is authenticated and tracked. Any unauthorized dissemination will breach signed confidentiality covenants.</p>
          </div>
        </div>
      </body>
      </html>
    `);
  }

  res.writeHead(404);
  res.end('Not Found');
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Document Access Control Server running at http://localhost:${PORT}`);
  });
}

module.exports = { server, tokenManager };
