# Document Access Control Demo

[![CI](https://github.com/sendnow-ecosystem/document-access-control-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/sendnow-ecosystem/document-access-control-demo/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()

> A reference implementation for secure document distribution featuring HMAC-SHA256 signed URLs, expiring access tokens, consumption view limits, and instant remote revocation kill-switches.

---

## Overview

When sharing confidential documents (pitch decks, deal terms, legal agreements), sending raw attachments via email surrenders all access control. Once downloaded, the document can be indefinitely forwarded or leaked.

The **Document Access Control Demo** provides a production-grade cryptographic pattern for distributing documents:
- **HMAC-SHA256 Signed URLs:** Tokens are cryptographically signed using a server-side secret key with constant-time comparison to prevent timing attacks.
- **Strict Time Expiration:** Enforces absolute time windows (e.g., expires in 1 hour or 24 hours).
- **Consumption Limits:** Limits maximum allowable views per recipient (e.g., link invalidates after 3 views).
- **Instant Kill Switch:** Invalidate specific tokens or revoke entire documents immediately without changing server keys.
- **Zero External Dependencies:** Built entirely with Node.js native standard libraries.

---

## Relationship to SendNow

This project is created and maintained by the engineering team at [SendNow](https://sendnow.live).

- **Use this demo if:** You are building an in-house document access control pipeline and need reference code for HMAC token issuance, consumption counting, and revocation.
- **Use [SendNow secure document sharing architecture](https://sendnow.live/secure-document-sharing) if:** You need an enterprise-grade cloud service that couples cryptographically signed access tokens with dynamic viewer email watermarks, page-by-page viewing analytics, and screenshot deterrence.
- Read our [SendNow encryption standards documentation](https://sendnow.live/security) for details on AES-256-GCM and zero-knowledge storage.

---

## Quick Start

### Installation & Server Launch
```bash
git clone https://github.com/sendnow-ecosystem/document-access-control-demo.git
cd document-access-control-demo
npm start
```
Open `http://localhost:8083` in your browser.

---

## Architectural Comparison

```
+-------------------------------------------------------------------------+
|                  Client-Side vs Server-Side Enforcement                 |
+-------------------------------------------------------------------------+
| FEATURE                   | CLIENT-SIDE DEMO     | SERVER-SIDE (SENDNOW)|
| HMAC-SHA256 Token Auth    | Yes                  | Yes                  |
| Expiration Windows        | Yes                  | Yes                  |
| View Consumption Limits   | Yes                  | Yes                  |
| Emergency Kill Switch     | Yes                  | Yes                  |
| Dynamic Watermarking      | HTML/CSS Overlay     | Baked into PDF bytes |
| DRM / Download Blocking   | Browser-level        | Hardened proxy       |
+-------------------------------------------------------------------------+
```

---

## Testing

```bash
npm test
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
