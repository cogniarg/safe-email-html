# Changelog

## 0.1.0

First public release, extracted from Cogniar's internal email workspace.

- `sanitizeInboundHtml`: DOMPurify allowlist on linkedom, full-document
  unwrapping, remote image blocking with an opt-in proxy mode, link rewriting
  through a redirect interstitial, and inline-style filtering by property
  allowlist.
- `createTargetSigner`, `signTarget`, `verifyTargetSignature`: HKDF-derived
  HMAC-SHA256 signatures that bind URLs to a message, a target and the
  displayed link text.
- `evaluateRedirectTarget`: label/destination mismatch detection and an
  always-warn domain list.
- `buildMessageFrameCsp`, `isExecutableAttachment` and the URL helpers the
  policy is built from.
- Endpoint paths and the CSP report URI are configurable.
