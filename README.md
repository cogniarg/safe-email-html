# safe-email-html

Render untrusted inbound email HTML without letting the sender run code, track
the reader, or disguise where a link goes.

```ts
import { sanitizeInboundHtml } from "safe-email-html"

const { html, hasRemoteImages } = await sanitizeInboundHtml({
  html: inboundBody,
  messageId: "msg_123",
})
```

Extracted from [Cogniar](https://cogni.ar)'s internal email workspace, where
it renders every inbound message on Cloudflare Workers. It needs no DOM, uses
only Web Crypto, and runs on Node.js 20+, Bun, Deno and Workers.

## What it does

An email body is HTML written by whoever sent it. Rendering it as-is lets the
sender run scripts in your app, learn when and where it was opened through
remote images, and phish with links whose text says `https://mybank.com` but
which point somewhere else. This library handles all three, in layers:

- **Sanitizes** with a strict DOMPurify allowlist. Scripts, event handlers,
  forms, iframes, SVG and `<style>` blocks are dropped, and inline styles are
  filtered down to presentational properties, so senders can't overlay a link
  with fake content.
- **Blocks remote images** by default (no tracking pixels on open), with an
  opt-in mode that routes them through your image proxy.
- **Routes every link through a signed interstitial.** The signature binds the
  link to the message, the exact destination and the visible label, so
  `evaluateRedirectTarget` can warn when a label claims a different host than
  the real destination, and the label can't be stripped to silence it.
- **Gives you a strict CSP** for the sandboxed iframe the body renders in, so
  anything that slips past sanitizing still can't run or phone home.

[docs/threat-model.md](docs/threat-model.md) explains each defense, why it
exists, what your app still has to do, and the known limitations.

## Install

```sh
npm install safe-email-html
```

## Usage

A full integration has three parts:

1. **A body route** that sanitizes the message, signs every link, and serves
   the result with the frame CSP.
2. **A redirect route** that verifies the signature and decides whether to
   send the reader straight through or show a warning.
3. **A sandboxed iframe** in your UI that loads the body route.

[examples/fetch-handler.ts](examples/fetch-handler.ts) is a complete, tested
version using only the Fetch API. The core of it:

```ts
import {
  boundDisplayedLinkText,
  buildMessageFrameCsp,
  buildRedirectUrl,
  createTargetSigner,
  evaluateRedirectTarget,
  parseDomainList,
  sanitizeInboundHtml,
  verifyTargetSignature,
} from "safe-email-html"

// 1. Body route: GET /messages/:id/body
const sign = await createTargetSigner(env.LINK_SIGNING_SECRET)
const { html } = await sanitizeInboundHtml({
  html: message.html,
  messageId: message.id,
  buildRedirectLinkUrl: async ({ url, displayedText }) => {
    const sig = await sign({
      purpose: "redirect",
      messageId: message.id,
      target: url,
      context: boundDisplayedLinkText(displayedText, url),
    })
    return `${buildRedirectUrl({ to: url, messageId: message.id, displayedText })}&sig=${sig}`
  },
})

return new Response(`<!DOCTYPE html><meta charset="utf-8">${html}`, {
  headers: {
    "content-type": "text/html; charset=utf-8",
    "content-security-policy": buildMessageFrameCsp(),
    "x-content-type-options": "nosniff",
  },
})

// 2. Redirect route: GET /api/redirect?to=…&messageId=…&text=…&sig=…
const valid = await verifyTargetSignature({
  purpose: "redirect",
  messageId: params.get("messageId") ?? "",
  target: params.get("to") ?? "",
  context: params.get("text") ?? "",
  secret: env.LINK_SIGNING_SECRET,
  signature: params.get("sig"),
})
if (!valid) return new Response("Invalid link signature.", { status: 403 })

const decision = evaluateRedirectTarget({
  to: params.get("to") ?? "",
  displayedText: params.get("text"),
  alwaysWarnDomains: parseDomainList("mybank.com, acme.example"),
})
// decision.kind is "allow" (302 to decision.destination),
// "warn" (show claimed label vs. real destination), or "refused" (400).
```

```html
<!-- 3. In your UI. No allow-scripts, no allow-same-origin. -->
<iframe
  src="/messages/msg_123/body"
  sandbox="allow-popups allow-popups-to-escape-sandbox"
></iframe>
```

Always check that the signed-in reader may read the message, in both routes.
A valid signature only proves your server emitted the URL.

### Remote images

Images are blocked by default. The original URL is kept in
`data-original-src`, and `hasRemoteImages` tells you whether to offer a
"load images" button. To load them, pass `remoteImages: "proxied"` and a
`buildRemoteImageUrl` that signs with `purpose: "img-proxy"`. Your proxy
should verify the signature, fetch without cookies, enforce size and content
type limits, and never forward the reader's IP. The default path is
`/api/img-proxy`, and `buildImgProxyUrl({ url, messageId, path })` builds it.

### Attachments

`isExecutableAttachment({ contentType, filename })` flags files that deserve
a confirmation step before download. It checks both the MIME type and the
extension, because senders often label executables as
`application/octet-stream`.

## API

| Export | Purpose |
|---|---|
| `sanitizeInboundHtml(input)` | Sanitize and rewrite a body. Returns `{ html, hasRemoteImages }`. |
| `createTargetSigner(secret)` | Derive the key once and return a signing function. |
| `signTarget(input)` / `verifyTargetSignature(input)` | One-off signing and constant-time verification. |
| `evaluateRedirectTarget(input)` | Decide `allow`, `warn` (with reasons) or `refused` for a clicked link. |
| `boundDisplayedLinkText(text, to?)` | The exact label string to bind into a redirect signature. |
| `buildRedirectUrl` / `buildImgProxyUrl` | Build interstitial and proxy URLs. Paths are configurable. |
| `buildMessageFrameCsp()` / `buildMessageFrameCspReportOnly(uri?)` | CSP for the frame document. |
| `isExecutableAttachment(input)` | Whether an attachment needs a download confirmation. |
| `parseDomainList`, `hostMatchesDomain`, `canonicalizeHost`, `extractDisplayedHosts`, `isRemoteUrl`, `stripUrlControlCharacters` | The URL helpers the policy is built from. |

Every export has TSDoc comments with the reasoning behind its rules.

## Development

```sh
pnpm install
pnpm run typecheck
pnpm run lint
pnpm run test
pnpm run build
```

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). Copyright 2026 Cogniar.
