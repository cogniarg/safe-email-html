# Threat model

`safe-email-html` assumes the **sender controls every byte of the email body**
and wants one of three things from the person reading it:

1. **Run code** in the reader's session: steal cookies or tokens, act as them.
2. **Learn about them**: confirm the address is read, learn their IP, track
   when and where they open the message.
3. **Trick them**: make a link look like it goes somewhere it doesn't, or get
   them to type credentials into a fake form.

It defends with three independent layers, so a gap in one is caught by the
next. Two of those layers live in your app, and the library gives you the
pieces to build them.

| Layer | What it does | Provided by |
|---|---|---|
| 1. Sanitize | Allowlist DOM filtering, then rewriting of every image, link and inline style | `sanitizeInboundHtml` |
| 2. Mediate | Signed link confirmation page and image proxy, so no remote request leaves without passing your server | `createTargetSigner`, `verifyTargetSignature`, `evaluateRedirectTarget` + your endpoints |
| 3. Contain | Sandboxed iframe plus a strict CSP on the rendered document | `buildMessageFrameCsp` + your frame |

## Layer 1: sanitize

**Allowlist, not blocklist.** DOMPurify runs with an explicit list of ~60
tags and ~25 attributes that legitimate email markup uses. Scripts, event
handlers, `javascript:` URIs, `<iframe>`, `<object>`, `<embed>`, `<base>`,
forms and inputs, SVG and MathML never survive. Disallowed containers are
dropped **with their content** (`KEEP_CONTENT: false`), so a phishing form
doesn't leak through as bare text.

**`<style>` blocks are dropped; inline styles are filtered.** Selectors and
`::before { content: "…" }` are far harder to filter than inline `style=""`
declarations, and inline styles are how senders style email for client
compatibility anyway. Each inline declaration is checked against an
allowlist of presentational properties:

- **Allowed:** colors, backgrounds, fonts, borders, margins, padding, sizing,
  table layout, and `display`/`opacity`/`visibility`, which the
  hidden-preheader idiom depends on.
- **Rejected by property:** `position`, `transform`, `z-index`, `inset`,
  `float` and anything else off the list.
- **Rejected by value:** `url()`, `image-set()`, `cross-fade()`,
  `expression()`, and CSS comments and backslash escapes, which could smuggle
  the others past the check.

The filter does not try to stop sender CSS from making a link look like
something else. Hidden text, negative margins, `letter-spacing` and
`line-height` can all make the visible label differ from the anchor's text,
and no server-side filter can know what the browser will paint. That is why
every link is confirmed (Layer 2) instead of judged by its label.

**Images are blanked by default.** Remote `src` values become `about:blank`,
with the original kept in `data-original-src`, so opening a message makes no
network request. Schemeless sources are blanked too, because they resolve
against your own body route and would fire authenticated same-origin
requests. `data:` images are blanked too, and the frame CSP would refuse
them anyway. When the reader opts in, remote images go through your image
proxy instead, including images inside links: every link is confirmed, so an
image's pixels can't decide where a click goes.

**Every remote link goes through the confirmation page.** That includes
scheme-relative `//host` and slashless `http:host` forms, which browsers
treat as absolute. URLs are normalized the way a WHATWG URL parser would see
them (C0 controls and tabs/newlines stripped) before any decision, so a
control-character prefix can't sneak a remote link past the check. Relative
links are removed, because they would re-enter your body route with
attacker-chosen query parameters. Only `mailto:` and `tel:` navigate directly.
Every link gets `target="_blank" rel="noopener noreferrer"`.

**Work is bounded.** Input is capped at `MAX_SANITIZED_HTML_CHARS` (1M
characters). At most `MAX_REWRITTEN_REMOTE_LINKS` (512) links are signed per
render, and the rest stay visible but inert, so one message can't turn a
render into unbounded crypto work. When images are on, at most
`MAX_PROXIED_REMOTE_IMAGES` (20) distinct images are signed; repeats reuse
their URL and the rest stay blank, which also bounds the upstream fetches one
open can make your proxy do.

## Layer 2: mediate

**Signatures bind each URL to one message and one exact target.** The
signer HMACs a length-prefixed tuple of version, purpose, message ID, target
and context. Your endpoints refuse anything unsigned, so they can't be used as
an open redirector or an authenticated fetcher with a caller-chosen URL.
Length-prefixing keeps field boundaries unambiguous: `("ab", "c")` and
`("a", "bc")` sign differently.

**The displayed link text is bound into the redirect signature.** The
confirmation page shows it, so stripping or swapping the `text` parameter
invalidates the link. It is capped at 200 characters.

**`evaluateRedirectTarget(to)` decides what a click does:**

- `refused`: unparsable URLs and anything that isn't `http(s)`.
- `confirm`: everything else. Show a page headed by
  `decision.destination.host` and let the reader continue or go back.

Nothing about the label is consulted. Earlier versions let a link through
without confirmation when its label didn't name a different host, but the
server can't know what the browser shows: a hidden span turns a visible
`bank.com` into the text `bank.com.evil.example`, which matches a link to
`bank.com.evil.example`. The host scan was also quadratic in the label's
length. Both are gone. The page can still show the link text, as
information, never as what the reader saw: it includes CSS-hidden parts.

The URL parser lowercases and IDNA-encodes the host, so a Cyrillic
`раураl.com` is shown as `xn--l-7sba6dbr.com`, and userinfo
(`bank.com@evil.example`) doesn't appear in `host` at all.

**Image URLs need their own authorization.** The frame's sandbox gives it an
opaque origin, so the browser treats its image requests as cross-site and
withholds a `SameSite=Lax` session cookie. A proxy that authorizes by session
returns 401 for every image. Don't fix it with `SameSite=None` or
`allow-same-origin`, which weaken your whole app. Bind the reader and an
expiry into the image signature's `context` instead, for example
`` `${expiry}:${readerId}` ``, send `exp` and the reader id as query
parameters, and have the proxy verify the signature, reject expired grants,
then check that this reader may read the message. Rounding the expiry to a
window (say 15 minutes) keeps a message's image URLs stable, and cacheable,
within it. A leaked URL loads that one image as that reader until it lapses.

## Layer 3: contain

`buildMessageFrameCsp()` returns the policy for the document you serve inside
the iframe:

```
default-src 'none'; img-src 'self'; style-src 'unsafe-inline';
connect-src 'none'; script-src 'none'; form-action 'none';
base-uri 'none'; frame-ancestors 'self'
```

There are no scripts, and the only network access is same-origin images (your
proxy). `img-src` deliberately excludes `data:`, so an image Layer 1 misses
can't load without passing your proxy. Serve the frame with `sandbox="allow-popups
allow-popups-to-escape-sandbox"` (no `allow-scripts`, no `allow-same-origin`),
so links open in a normal tab and nothing in the frame can touch your app.

## What your app still has to do

The library is pure functions, and it can't enforce what happens around them:

- **Serve the sanitized HTML only inside the sandboxed iframe, with the CSP
  header.** Don't inject it into your app's DOM.
- **Sign every rewritten URL** with `createTargetSigner`, and **verify it** in
  the endpoints with `verifyTargetSignature` before doing anything else. The
  default URL builders emit unsigned URLs, which are only safe for tests.
- **Authorize the reader** in every endpoint. A valid signature proves the
  library emitted the URL, not that this user may read this message. For the
  image proxy, authorize from the signed grant described in Layer 2, since
  the frame's requests carry no session cookie.
- **Confirm every link** on your redirect page, headed by the destination's
  host, and HTML-escape everything you put on it.
- **Harden the image proxy:**
  - Fetch without cookies, and never forward the reader's IP or headers.
  - Follow redirects manually and check every hop against your domain
    blocklist and private, loopback and link-local addresses, so the proxy
    can't be pointed at your internal network.
  - Serve only PNG, JPEG, GIF and WebP, identified by their leading bytes
    rather than the upstream `Content-Type`. Never serve SVG.
  - Cap the body size, put one deadline (say 10 seconds) over every redirect
    hop and the body read, and cancel every upstream body you discard.
  - Respond with `X-Content-Type-Options: nosniff` and
    `Content-Security-Policy: default-src 'none'`.
- **Serve attachments** with `Content-Disposition: attachment` and
  `nosniff`, and use `isExecutableAttachment` to require confirmation for
  executables (it checks both the MIME type and the extension, since senders
  mislabel executables as `application/octet-stream`).
- **Keep the secret secret.** Anyone who has it can sign arbitrary targets.

## Known limitations

- **No `<style>` support.** Media queries and dark-mode variants are lost.
  Senders inline their visual design for client compatibility, so most mail
  renders as intended. Adding it safely would need a real CSS parser with
  selector and pseudo-element allowlists.
- **One extra click per external link.** That is the cost of not trusting
  the label.
- **No confusable-character detection.** IDNA encoding shows `раураl.com`
  as punycode on the confirmation page, but the library doesn't flag
  look-alike domains such as `paypa1.com` by themselves.
- **linkedom is not a spec HTML parser.** It is fast and needs no DOM, but it
  differs from browsers in places. The library compensates where it matters:
  it unwraps full documents itself, refuses to run if DOMPurify reports the
  environment as unsupported (DOMPurify would otherwise silently return the
  input unchanged), and restores the prototype accessors DOMPurify needs for
  its DOM-clobbering protection. Layer 3 exists because parser differentials
  are a real class of bug.
