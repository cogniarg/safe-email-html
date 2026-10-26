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
| 2. Mediate | Signed redirect interstitial and image proxy, so no remote request leaves without passing your server | `createTargetSigner`, `verifyTargetSignature`, `evaluateRedirectTarget` + your endpoints |
| 3. Contain | Sandboxed iframe plus a strict CSP on the rendered document | `buildMessageFrameCsp` + your frame |

## Layer 1: sanitize

**Allowlist, not blocklist.** DOMPurify runs with an explicit list of ~60
tags and ~25 attributes that legitimate email markup uses. Scripts, event
handlers, `javascript:` URIs, `<iframe>`, `<object>`, `<embed>`, `<base>`,
forms and inputs, SVG and MathML never survive. Disallowed containers are
dropped **with their content** (`KEEP_CONTENT: false`), so a phishing form
doesn't leak through as bare text.

**`<style>` blocks are dropped; inline styles are filtered.** Stylesheet
rules can use selectors and `::before { content: "…" }` to paint text that is
not in the DOM. That text would never be checked against the link's real
destination. Inline `style=""` can't do that, and it is how senders style
email for client compatibility anyway. Each inline declaration is checked
against an allowlist of presentational properties:

- **Allowed:** colors, backgrounds, fonts, borders, padding, sizing, table
  layout, and `display`/`opacity`/`visibility`. Hiding content can't forge a
  label: visible text is always a subset of the text bound into the link
  signature. The hidden-preheader idiom depends on these.
- **Rejected by property:** anything that can move content over other content
  (`position`, `transform`, `z-index`, `inset`, `float`) and anything unknown.
- **Rejected by value:** `url()`, `image-set()`, `cross-fade()`,
  `expression()`, CSS comments and backslash escapes (which could smuggle the
  others past the check), and negative margins (the one allowlisted way to
  pull content over a link).

**Images are blanked by default.** Remote `src` values become `about:blank`,
with the original kept in `data-original-src`, so opening a message makes no
network request. Schemeless sources are blanked too, because they resolve
against your own body route and would fire authenticated same-origin
requests. `data:` images are blanked because a `data:` SVG can paint a fake
link label. When the reader opts in, remote images go through your image
proxy instead. Images inside links stay blocked even then: a loaded image
could paint a label (say, a picture of `mybank.com`) that never enters the
signed link text, while a blocked one shows its `alt` text, which is signed.

**Every remote link goes through the interstitial.** That includes
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
render into unbounded crypto work.

## Layer 2: mediate

**Signatures bind each URL to one message and one exact target.** The
signer HMACs a length-prefixed tuple of version, purpose, message ID, target
and context. Your endpoints refuse anything unsigned, so they can't be used as
an open redirector or an authenticated fetcher with a caller-chosen URL.
Length-prefixing keeps field boundaries unambiguous: `("ab", "c")` and
`("a", "bc")` sign differently.

**The displayed link text is bound into the redirect signature.** The warning
decision depends on what the label claims, so stripping or swapping the
`text` parameter invalidates the link instead of silently suppressing the
warning.

**`evaluateRedirectTarget` decides what a click does:**

- `refused`: unparsable URLs and anything that isn't `http(s)`.
- `warn` with `text_host_mismatch`: **any** host claimed in the label fails to
  look like the destination. Every host is checked, not just the first, so a
  matching decoy can't cover for a spoofed one. Hosts used as URL userinfo
  (`mybank.com@evil.example`) are compared too.
- `warn` with `always_warn_domain`: the destination is on a list you
  configure, such as banks, common phishing targets or your own internal
  hosts.
- `allow`: everything else.

"Looks like" means equal after removing `www.`, or the destination is a
subdomain of the label (`example.com` → `mail.example.com`). The reverse is
treated as phishing: a label of `mybank.com.evil.example` linking to
`evil.example` still warns. Hostnames are lowercased, stripped of trailing dots
and IDNA-normalized, so `раураl.com` (Cyrillic) is compared as its punycode
form, not as `paypal.com`.

**Label truncation can't hide a claim.** Labels are capped at 200 characters
for the URL. Hosts that the cut would drop are re-appended, with mismatching
hosts first, so a long hidden prefix can't push a spoofed `https://mybank.com`
out of view of the check.

## Layer 3: contain

`buildMessageFrameCsp()` returns the policy for the document you serve inside
the iframe:

```
default-src 'none'; img-src 'self'; style-src 'unsafe-inline';
connect-src 'none'; script-src 'none'; form-action 'none';
base-uri 'none'; frame-ancestors 'self'
```

There are no scripts, and the only network access is same-origin images (your
proxy). `img-src` deliberately excludes `data:`. That backstops every current
and future "paint a fake label with CSS or an image" trick that Layer 1 might
miss. Serve the frame with `sandbox="allow-popups
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
  library emitted the URL, not that this user may read this message.
- **Harden the image proxy:** fetch without cookies, enforce size limits and
  image content types, set `X-Content-Type-Options: nosniff`, and apply your
  domain blocklist. Never forward the reader's IP or headers.
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
- **The label check only fires on URL-shaped labels.** "Click here" pointing
  anywhere is allowed, because there is no claim to contradict. Use the
  always-warn list for destinations that deserve a warning regardless, or
  confirm every external link if your threat model needs it.
- **No confusable-character detection.** IDNA normalization stops
  `раураl.com` from being compared as `paypal.com`, but the library doesn't
  flag look-alike domains such as `paypa1.com` by themselves.
- **linkedom is not a spec HTML parser.** It is fast and needs no DOM, but it
  differs from browsers in places. The library compensates where it matters:
  it unwraps full documents itself, refuses to run if DOMPurify reports the
  environment as unsupported (DOMPurify would otherwise silently return the
  input unchanged), and restores the prototype accessors DOMPurify needs for
  its DOM-clobbering protection. Layer 3 exists because parser differentials
  are a real class of bug.
