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
only Web Crypto, and runs on Node.js 22+, Bun, Deno and Workers.

## What it does

An email body is HTML written by whoever sent it. Rendering it as-is lets the
sender run scripts in your app, learn when and where it was opened through
remote images, and phish with links whose text says `https://mybank.com` but
which point somewhere else. This library handles all three, in layers:

- **Sanitizes** with a strict DOMPurify allowlist. Scripts, event handlers,
  forms, iframes, SVG and `<style>` blocks are dropped, and inline styles are
  filtered down to presentational properties, so sender CSS can't load
  anything from a URL.
- **Blocks remote images** by default (no tracking pixels on open), with an
  opt-in mode that routes them through your image proxy.
- **Confirms every link on your server.** Each link points to a signed
  confirmation page headed by the real destination host. The signature binds
  the link to the message, the exact destination and the link text, so none
  of them can be swapped. The label never decides anything: hidden text and
  CSS make what the reader sees unknowable on the server.
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
2. **A redirect route** that verifies the signature and shows a confirmation
   page headed by the destination host.
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
      context: boundDisplayedLinkText(displayedText),
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

const decision = evaluateRedirectTarget(params.get("to") ?? "")
// decision.kind is "confirm" (show a page headed by decision.destination.host,
// with a link to continue) or "refused" (400). HTML-escape what you show.
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
`buildRemoteImageUrl` that signs with `purpose: "img-proxy"`. At most 20
distinct images are signed per render.

The sandboxed frame has an opaque origin, so its image requests carry no
`SameSite=Lax` session cookie. Bind the reader and an expiry into the
signature's `context` and authorize the proxy from that, not from the
session. The proxy must also follow redirects manually, refuse private
addresses, serve only PNG, JPEG, GIF and WebP identified by their bytes, and
put a deadline on the fetch. [The threat model](docs/threat-model.md) has the
full list. The default path is `/api/img-proxy`, and
`buildImgProxyUrl({ url, messageId, path })` builds it.

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
| `evaluateRedirectTarget(to)` | `confirm` (with the parsed destination) or `refused` for a clicked link. |
| `boundDisplayedLinkText(text)` | The exact link text to bind into a redirect signature. |
| `buildRedirectUrl` / `buildImgProxyUrl` | Build confirmation-page and proxy URLs. Paths are configurable. |
| `buildMessageFrameCsp()` / `buildMessageFrameCspReportOnly(uri?)` | CSP for the frame document. |
| `isExecutableAttachment(input)` | Whether an attachment needs a download confirmation. |
| `parseDomainList`, `hostMatchesDomain`, `hostMatchesAnyDomain`, `canonicalizeHost`, `isRemoteUrl`, `stripUrlControlCharacters` | The URL helpers the policy is built from. |

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
