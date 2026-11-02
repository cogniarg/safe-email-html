# Changelog

## 0.2.0

Security release. Brings the library in line with Cogniar's email workspace,
which fixed these after 0.1.x was extracted. Upgrade from 0.1.x.

- **Every external link is now confirmed.** In 0.1.x `evaluateRedirectTarget`
  returned `allow`, a direct redirect, unless the link text named a different
  host. Hidden text defeats that check: `bank.com<span
  style="display:none">.evil.example</span>` linking to
  `bank.com.evil.example` reads as `bank.com` and was let through. The label
  scan is gone, and every http(s) link gets a confirmation page.
- **Removes a quadratic host scan** over the sender-controlled link text that
  took about 7 seconds for a 64,000-character label.
- **Signs at most 20 distinct remote images per render**
  (`MAX_PROXIED_REMOTE_IMAGES`), reusing the URL for repeats.
- Images inside links load like any other once the reader opts in.
- Inline styles may use negative margins again. The documentation no longer
  claims sender CSS can't overlap a link; it can, which is why every link is
  confirmed.
- Documents how to authorize the image proxy from the signed URL (the
  sandboxed frame sends no session cookie) and how to harden it.

Breaking changes:

- `evaluateRedirectTarget(to: string)` takes the destination only and
  returns `{ kind: "confirm", destination }` or `{ kind: "refused", reason }`.
  The `allow` and `warn` kinds, `RedirectWarnReason` and `alwaysWarnDomains`
  are removed.
- `boundDisplayedLinkText(text)` drops its second argument and only
  truncates. Links signed by 0.1.x with a re-appended host no longer verify;
  re-rendering the body signs them again.
- `extractDisplayedHosts` is removed.

## 0.1.1

- Package metadata identifies contributors by GitHub profile instead of
  email address. No code changes.
- 0.1.0 was unpublished: its `package.json` listed a personal email address.

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
