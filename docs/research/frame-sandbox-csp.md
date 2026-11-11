# What the message frame's sandbox and CSP contain

Research for [#12](https://github.com/cogniarg/safe-email-html/issues/12) on
map [#11](https://github.com/cogniarg/safe-email-html/issues/11). The question
is what sanitized output can still do inside the message frame when the browser
parses it into a different DOM than the one the sanitizer checked. "Raw link"
below means a link that only exists in the browser's DOM, so Layer 1 never
rewrote it through the confirmation page.

## Configuration studied

- The iframe attribute from the README: `sandbox="allow-popups allow-popups-to-escape-sandbox"`.
- The header from `buildMessageFrameCsp()` in `src/url-policy.ts`:
  `default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; connect-src 'none'; script-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'`.
- The example body route in `examples/fetch-handler.ts` also sends
  `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`.

[Parsing that sandbox attribute][parse-sandbox] sets every sandboxing flag
except three. `allow-popups` clears the sandboxed auxiliary navigation flag and
the sandboxed custom protocols navigation flag. `allow-popups-to-escape-sandbox`
clears the sandbox-propagates-to-auxiliary-browsing-contexts flag. The flags
that stay set and matter here are navigation, top-level navigation with and
without user activation, origin (the document gets an opaque origin), forms,
scripts, automatic features and downloads.

All sources were retrieved on 2026-11-02:

- HTML Living Standard, last updated 30 October 2026.
- CSP Level 3, Editor's Draft of 27 October 2026.
- Referrer Policy, Editor's Draft of 20 March 2026.
- Fetch Living Standard and the SVG 2 Editor's Draft, linking chapter.
- Chromium at [`9150554b`][cr] (the GitHub mirror of `chromium/src` main),
  Firefox at [`7a315fc8`][gk], WebKit at [`8692e28a`][wk].

Nothing here comes from running a browser. Every claim comes from spec text or
from the source at those commits.

## Summary

| Markup or action | Contained? | By | Source |
| --- | --- | --- | --- |
| `<script>`, event-handler attributes | Yes | Scripts flag and `script-src 'none'` | [Sandboxing][sandboxing], [CSP fallback list][csp-fallback] |
| `javascript:` link, same frame or popup | Yes | Scripts flag; CSP inline check on navigations | [javascript: URL navigation][js-url], [CSP navigation check][csp-nav], [Chromium `frame_loader.cc` L897-929][cr-js] |
| `<meta http-equiv="refresh">` | Yes | Automatic features flag | [Declarative refresh][refresh], [Chromium][cr-refresh], [Firefox][gk-refresh], [WebKit][wk-refresh] |
| Form submission | Yes | Forms flag and `form-action 'none'` | [Form submission][form-submit], [form-action][csp-form-action] |
| Form fields rendered and typed into | No | Nothing, but the values cannot leave the frame | Follows from the row above |
| Raw link with `target=_blank` or a new target name, clicked | No | Nothing. `allow-popups` and `allow-popups-to-escape-sandbox` permit it | [Choosing a navigable][choose-nav] |
| Raw link with no target or `_self`, clicked | No | Nothing in Layer 3. Only the embedding page's `frame-src`, in Chromium and WebKit | [Allowed to navigate][allowed-nav], [Chromium][cr-csp-nav], [WebKit][wk-policy] |
| Raw link with `_top` or `_parent` | Yes, when the iframe's parent is the top-level page | Top-level navigation flags | [Allowed to navigate][allowed-nav], [Chromium `local_frame.cc` L2215-2273][cr-cannav-sandbox] |
| Custom-scheme link, clicked | No | `allow-popups` clears the custom protocols flag | [Custom protocols flag][custom-proto], [Chromium][cr-flags], [Firefox][gk-extproto] |
| `<base href>` | Yes | `base-uri 'none'` | [Frozen base URL][frozen-base], [base-uri][csp-base-uri] |
| `<base target>` | Not applicable | `base-uri` ignores `target`. It retargets raw links, which can set a target anyway | [Get an element's target][elem-target] |
| `<link rel=preconnect>` | No | No CSP directive and no sandbox flag applies | [preconnect][preconnect], [Chromium][cr-preconnect], [Chrome][cr-hints] |
| `<link rel=dns-prefetch>` | No | Same as preconnect | [dns-prefetch][dns-prefetch], [Chromium][cr-dns] |
| `<link rel=prefetch>`, `prerender` | Yes | `default-src 'none'` | [Effective directive][csp-effective], [Chromium][cr-csp-map] |
| External stylesheets, `@import`, `@font-face`, `preload` of styles, fonts, scripts or fetches | Yes | `style-src` has no host source; the others resolve to `'none'` | [Effective directive][csp-effective], [CSP fallback list][csp-fallback] |
| `<style>` element, unfiltered `style` attribute | No | `style-src 'unsafe-inline'` allows both | [CSP fallback list][csp-fallback] |
| `<img>`, `srcset`, `<picture>`, CSS `url()` images, SVG `<image>`, `preload as=image` | Partly | `img-src 'self'` allows any path on the app's origin, not only the proxy | [Effective directive][csp-effective], [self-origin][csp-self] |
| `<object>`, `<embed>` | Yes | `object-src` falls back to `default-src 'none'` | [Effective directive][csp-effective] |
| `<iframe src>`, `data:` frames | Yes | `frame-src` falls back to `default-src 'none'`; the message frame is the embedder | [Chromium `navigation_request.cc` L8405-8423][cr-csp-nav] |
| `<iframe srcdoc>` | Loads, gains nothing | Inherits the frame's CSP and its sandbox flags | [Policy container][policy-container], [Creation sandboxing flags][creation-flags], [Chromium L8433][cr-about] |
| `ping` attribute | Yes | `connect-src 'none'` | [Hyperlink auditing][ping], [Chromium][cr-csp-ping] |
| Downloads started in the frame | Yes | Downloads flag | [Downloads flag][downloads-flag] |
| Popup that keeps an opener (`rel=opener`, named target) | Partly | Chromium and WebKit refuse navigations through the opener; `postMessage` still works | [Chromium][cr-cannav-barth], [WebKit][wk-cannav] |
| `<meta name=referrer>` | Not applicable | Opaque-origin documents send no referrer | [Determine request's referrer][referrer], [Chromium][cr-referrer] |
| `<meta http-equiv=content-security-policy>`, `set-cookie` | Yes | A meta policy only adds restrictions; `set-cookie` is ignored | [Meta CSP][meta-csp], [Meta set-cookie][meta-set-cookie] |
| Body route opened as a top-level page | No at the time of writing; yes since [#33][issue-33] | The sandbox is an iframe attribute; the CSP had no `sandbox` directive until #33 added one | [iframe sandbox][iframe-sandbox], [CSP sandbox][csp-sandbox] |

## 1. Declarative self-navigation

`<meta http-equiv="refresh">` does not fire. The
[shared declarative refresh steps][refresh] navigate only if "meta is given,
document's active sandboxing flag set does not have the sandboxed automatic
features browsing context flag set". Only `allow-scripts` clears that flag
([parse a sandboxing directive][parse-sandbox]). All three engines implement
it:

- Chromium returns early with "Refused to execute the redirect specified via
  `<meta http-equiv='refresh' ...>`" in
  [`Document::MaybeHandleHttpRefresh`][cr-refresh].
- Firefox ignores the pragma in [`Document::ProcessMETATag`][gk-refresh].
- WebKit drops the scheduled redirect with "Unable to do meta refresh due to
  sandboxing" in [`ScheduledRedirect::fire`][wk-refresh].

The HTTP `Refresh` header is not covered by that check, but the server sets the
headers, so the sender cannot add one.

No other markup navigates the frame without a click:

- Form submission returns early under the sandboxed forms flag
  ([form submission algorithm][form-submit]). `form-action 'none'` blocks it
  again, and Chromium checks `form-action` against the initiator's policy
  ([`NavigationRequest::CheckCSPDirectives`][cr-csp-nav], L8389-8403).
  Implicit submission with Enter takes the same path.
- `<link rel=prefetch>` and `prerender` are fetches, not navigations. CSP sends
  requests whose initiator is "prefetch" or "prerender" to `default-src`
  ([effective directive][csp-effective]), and Chromium maps `PREFETCH` to
  `default-src` ([`content_security_policy.cc` L865-866][cr-csp-map]).
- `<base target>` changes where links without a `target` open, but starts no
  navigation by itself.
- SVG `href` and `target` on `<a>` are animatable ([SVG 2 `a`][svg-a]), so SMIL
  can change a link's destination after parsing. A click is still needed.
- `<iframe>`, `<object>` and `<embed>` create nested content, covered under
  section 3.

What the CSP covers and what it doesn't:

- `navigate-to` is not in CSP3. The editors removed it in
  [w3c/webappsec-csp#564][navigate-to] (September 2022) because no engine had
  shipped it. The current draft's navigation directives are `form-action` and
  `frame-ancestors`, and neither restricts where a link click goes.
- `base-uri` governs only the URL in `<base href>`. The check runs in
  [set the frozen base URL][frozen-base] through
  [Is base allowed for document?][csp-base-uri]. It does not look at
  `<base target>`.
- `frame-src`, `object-src` and the other fetch directives fall back to
  `default-src` ([fallback list][csp-fallback]). They decide what the frame
  embeds, not where the frame itself goes, with one engine detail covered in
  section 2.

## 2. Links the sanitizer never saw

A raw link resolves its target through
[get an element's target][elem-target] and the
[rules for choosing a navigable][choose-nav]. What happens on a click depends
on that target.

**`target=_blank` or a name that matches no existing navigable.** The browser
creates a new top-level traversable. The sandboxed auxiliary navigation flag is
clear, so the popup is allowed. The propagation flag is clear too, so the
popup's sandboxing flag set stays empty and the popup is an ordinary tab. It
loads the raw URL directly, with no confirmation page. The popup-blocker clause
in the same algorithm applies when the frame's window lacks transient
activation. The frame cannot run script, so in practice only a real click opens
a popup. The click's activation is consumed.

For `_blank`, [get an element's noopener][noopener] returns true unless the
link has `rel=opener`, so the popup has no opener. Chromium implements this in
[`AnchorElementUtils::HandleRelAttribute`][cr-noopener]. A named target, or
`rel=opener`, keeps the opener. That popup then holds a WindowProxy to the
message frame and, through `opener.top`, to the app's window. The spec's
[allowed by sandboxing to navigate][allowed-nav] check does not stop the
unsandboxed popup from navigating either one. Chromium
([`LocalFrame::CanNavigate`][cr-cannav-barth]) and WebKit
([`Document::canNavigateInternal`][wk-cannav]) still refuse. Both let a
document navigate another frame only if it is same-origin with that frame or
one of its ancestors. A top-level frame is also open to the document it
opened, and to documents same-origin with that frame's opener or the opener's
ancestors. The message frame is not top-level, and the app's window neither
opened the popup nor has an opener. `postMessage` to `opener.top` is not a navigation and is allowed.
Chromium severs the opener entirely when the app's top-level page sends
`Cross-Origin-Opener-Policy: same-origin` and the opening frame is
cross-origin to it ([`CoopSuppressOpener`][cr-coop]). The rules for choosing a
navigable contain a similar step, with a note that it applies to nested
documents that are cross-origin with the top-level document.

**No target, `_self`, or an SVG `<a>` with its default `_self`.** The frame
navigates itself. [Allowed by sandboxing to navigate][allowed-nav] returns true
when the source is the target, and so does Chromium's `CanNavigate`. The new
document takes its policy container from the response
([determine navigation params policy container][policy-container]), so it runs
under the destination server's CSP, not the library's. The iframe's sandbox
flags stay in force, because the
[creation sandboxing flags][creation-flags] come from the `<iframe>` element on
every navigation. The new page therefore still has no script, no form
submission and an opaque origin. It can load remote images, stylesheets and
fonts, which gives the sender the reader's IP address and the time of the
click. It can also draw a fake app screen inside the message pane.

The library's frame CSP cannot stop this. Chromium checks `frame-src` for every
navigation of a child frame against the parent's policy, whoever started it
([`NavigationRequest::CheckCSPDirectives`][cr-csp-nav], L8405-8423). WebKit
checks the owner element's document ([`PolicyChecker.cpp`][wk-policy], L87-102
and L182-188). So only the embedding page's own `frame-src`, `child-src` or
`default-src` limits where the message frame can go. Read literally, the spec
sets a navigation request's policy container to the initiator's
([create navigation params by fetching][nav-fetch]). Fetch then checks that
container ([main fetch][main-fetch], [should request be blocked][csp-block]).
By that reading the frame's own `default-src 'none'` would block a
self-navigation. Neither engine does this.
[w3c/webappsec-csp#509][csp-509], open since 2021, proposes narrowing
`frame-src` to the parent-set `src` attribute. If that lands, the embedding
page's `frame-src` stops covering this case.

**`_top` and `_parent`.** When the message iframe sits directly in the
top-level app page, both resolve to the top-level traversable. The sandboxed
top-level navigation flags (with and without user activation) refuse it
([allowed by sandboxing to navigate][allowed-nav]). Chromium refuses ancestors
and the top-level frame in
[`LocalFrame::CanNavigate` L2215-2273][cr-cannav-sandbox].

**`javascript:` URLs.** These never run. In the same frame, the sandboxed
scripts flag disables scripting, and
[navigate to a javascript: URL][js-url] runs the CSP navigation check, whose
inline check resolves to `script-src` ([CSP navigation check][csp-nav]). With
`'none'`, that check fails. For a popup target, the same check uses the
initiator's policy container, which is still the frame's CSP. Chromium also
drops the URL whenever the initiating window cannot execute script
([`FrameLoader::StartNavigation` L897-929][cr-js]). It also requires the
initiator to be same-origin with the target for `javascript:` URLs
([`CanNavigate` L2205-2213][cr-cannav-js]).

**Custom schemes.** `allow-popups` clears the
[sandboxed custom protocols navigation flag][custom-proto]. A raw
`<a href="someapp:...">` click can therefore hand off to an external
application, after whatever prompt the browser shows. Chromium clears the flag
for `allow-popups` ([`web_sandbox_flags.cc` L33][cr-flags]). Firefox stops
blocking external protocols once auxiliary navigation is allowed
([`ExternalProtocolIsBlockedBySandbox`][gk-extproto], L1052). Layer 1 only lets
`mailto:` and `tel:` through, so the sandbox adds nothing here.

**Referrer.** [Determine request's referrer][referrer] returns no referrer for
a document with an opaque origin, before any policy applies. Chromium follows
this ([`LocalDOMWindow::OutgoingReferrerUrl`][cr-referrer]). A raw link
therefore does not leak the body route URL. A raw `<meta name=referrer>`, which
the spec lets override the header ([meta referrer][meta-referrer]), changes
nothing.

## 3. Stripped markup that still works

**`<base>`.** `<base href>` is refused by `base-uri 'none'`, and the base URL
falls back to the document's own ([set the frozen base URL][frozen-base]).
Without that directive, one `<base href>` would resolve every rewritten link
and proxied image, which are root-relative paths, against the sender's host.
`<base target>` is not a URL and `base-uri` does not see it. It only changes
links that lack a `target`, and Layer 1 sets `target="_blank"` on every link it
keeps. The spec turns a target name that contains a tab or newline and a `<` into
`_blank`, which stops a dangling `target` attribute from carrying page text
into the window name ([get an element's target][elem-target]).

**`<form>`.** The sandbox and `form-action 'none'` block submission
independently. The form still renders, so a sender can show fake credential
fields. Typed values stay in the frame. No script can read them, no submission
can send them, and CSS attribute selectors match only the `value` attribute,
not what the reader types.

**`<link>`.**

- `rel=stylesheet` is refused. `style-src 'unsafe-inline'` has no host source,
  and external stylesheets resolve to it through `style-src-elem`.
- `rel=preload` follows its `as` destination. Images may load from the app's
  origin, and styles, fonts, scripts and fetches are refused.
- `rel=prefetch` and `prerender` are refused by `default-src 'none'`.
- `rel=preconnect` is not contained. The spec algorithm
  [preconnect][preconnect] obtains a connection, "DNS+TCP+TLS for HTTPS
  origins", with no CSP step, because no fetch takes place. Chromium's
  [`PreloadHelper::PreconnectIfNeeded`][cr-preconnect] checks only that the
  scheme is HTTP(S), and Chrome's browser-side
  [`NetworkHintsHandlerImpl::Preconnect`][cr-hints] opens the socket without a
  CSP or sandbox check. The sender's server sees the reader's IP address and
  the time the message was opened, with no click needed.
- `rel=dns-prefetch` is not contained either. [dns-prefetch][dns-prefetch]
  resolves the origin with no CSP step, and Chromium's
  [`PreloadHelper::DnsPrefetchIfNeeded`][cr-dns] gates it only on a
  frame-wide setting. `X-DNS-Prefetch-Control: off` sets a per-document flag
  ([`Document::ParseDNSPrefetchControlHeader`][cr-dns-doc]) that this path does
  not read. The sender's DNS server learns that the message was opened and
  when, from the resolver's address rather than the reader's.

**`<object>` and `<embed>`.** The destinations `object` and `embed` map to
`object-src` ([effective directive][csp-effective]), which falls back to
`default-src 'none'`. Fallback content inside `<object>` renders as ordinary
markup.

**`<iframe>`.** `<iframe src>` and `data:` frames are refused. Chromium checks
`frame-src` against the parent's policy, and the parent of a nested frame is
the message frame with `default-src 'none'`.

`<iframe srcdoc>` loads. Chromium skips CSP checks for `about:` URLs
([L8433][cr-about]), and the spec fetches nothing for srcdoc. The srcdoc
document gets a clone of the message frame's policy container
([determine navigation params policy container][policy-container]). Its
sandbox flags are the union of its own `sandbox` attribute and the message
frame's active flags ([creation sandboxing flags][creation-flags]). It
therefore has the same CSP and at least the same sandbox. Its markup is a
second, unsanitized parse, but it gains no capability the message frame
lacks. A raw link inside it that navigates the srcdoc frame itself is checked
against the message frame's `frame-src`, which is `'none'`. A raw link with a
popup target still opens a popup, as in gap 1.

**SVG `<a>`.** `href` and the deprecated `xlink:href` make a link, `target`
defaults to `_self`, and both attributes are animatable ([SVG 2 `a`][svg-a]).
It behaves like an HTML raw link (section 2), and with no `target` it
navigates the frame. SVG `<a>` also has `ping`, `rel` and `referrerpolicy`.
`ping` is refused (see below).

**CSS.** `style-src 'unsafe-inline'` allows `<style>` elements and every
`style` attribute, because `style-src-elem` and `style-src-attr` fall back to
`style-src` ([fallback list][csp-fallback]). Layer 1's property filter does not
run on markup it never saw. Sender CSS can use `position: fixed` to stretch a
transparent raw link over the whole frame, so any click in the message opens
it. The overlay cannot reach outside the iframe's viewport. CSS network access
is limited the same way as images. `url()` images go to `img-src 'self'`.
`@import`, `@font-face` and `image-set()` with remote URLs are refused. CSS
exfiltration through attribute selectors can only reach the app's own origin.

**Images.** `img-src 'self'` matches the response URL's origin even though the
document's origin is opaque ([self-origin][csp-self]). `<img>`, `srcset`,
`<picture>`, `<input type=image>`, SVG `<image>`, `preload as=image` and CSS
images can request any path on the app's origin, not only the proxy. The
proxy refuses unsigned URLs. Other GET routes receive requests from an opaque
origin, which the threat model's Layer 2 note says do not carry a
`SameSite=Lax` session cookie.

**`ping`.** A ping is a request with an empty destination
([hyperlink auditing][ping]), which CSP sends to `connect-src`
([effective directive][csp-effective]). Chromium maps `PING` to `connect-src`
([`content_security_policy.cc` L824-829][cr-csp-ping]). `connect-src 'none'`
refuses it.

**`<meta>`.** `http-equiv=refresh` is covered in section 1. A
`content-security-policy` meta only adds an enforced policy and only counts
as a child of `<head>` ([meta CSP][meta-csp]). `set-cookie` "has no effect"
([meta set-cookie][meta-set-cookie]). `name=referrer` is covered in section 2.

**Downloads.** The sandboxed downloads flag stops the frame from starting a
download, whether from a download link or from a navigation answered with an
attachment ([downloads flag][downloads-flag]). Popups are unsandboxed and can
download.

## Gaps in Layer 3

Each gap is stated so the threat model can cite it by number. In all of them,
Layer 3 means the sandbox attribute above plus `buildMessageFrameCsp()`.

1. **A raw link with `target=_blank` or a new target name opens its raw
   destination in an ordinary, unsandboxed tab when clicked.** No confirmation
   page is shown. `allow-popups` and `allow-popups-to-escape-sandbox` permit
   this by design. See section 2.
2. **A raw link without a popup target navigates the message frame itself when
   clicked.** The new document runs under its own server's CSP, so it can load
   remote resources, which exposes the reader's IP address. It keeps the sandbox, so
   it has no script and cannot submit forms. The frame CSP cannot prevent this
   in Chromium or WebKit, because both check `frame-src` against the embedding
   page. Only the embedding page's own CSP can, and the library does not ship
   or document one. See section 2.
3. **`<link rel=preconnect>` and `<link rel=dns-prefetch>` contact any host
   without a click.** CSP has no directive for them and no sandbox flag covers
   them. Preconnect exposes the reader's IP address and open time. DNS prefetch
   exposes the open time through the resolver. See section 3.
4. **Raw `<style>` elements and `style` attributes apply in full.**
   `style-src 'unsafe-inline'` permits them, and Layer 1's property filter
   never saw them. They can lay a raw link over the whole frame, which makes
   gaps 1 and 2 trigger on any click. Their network reach is limited to
   same-origin images.
5. **Raw custom-scheme links can launch external applications when clicked.**
   `allow-popups` clears the custom protocols flag in the spec, Chromium and
   Firefox.
6. **The sandbox does not travel with the response.** If the body route is
   loaded as a top-level page, for example from a raw same-origin link such as
   `<a href="" target="_blank">` or from the browser's "open frame in new tab",
   it runs on the app's origin with no sandbox. A raw meta refresh then fires,
   raw links without a target navigate the tab, and same-origin image requests
   carry the session cookie. The CSP still blocks scripts, forms and remote fetches, but
   not preconnect (gap 3). The HTML spec warns about this case under
   [the iframe `sandbox` attribute][iframe-sandbox]. A CSP
   [`sandbox` directive][csp-sandbox] with the same keywords would apply the
   flags to every load of the response. CSP ignores that directive in a
   `Content-Security-Policy-Report-Only` header, so it has to go in the
   enforced one.

   *Update:* [#33][issue-33] added
   `sandbox allow-popups allow-popups-to-escape-sandbox` to the enforced
   policy from `buildMessageFrameCsp()`, which closes this gap, and removes
   an empty `href`, so Layer 1 no longer emits the `<a href="">` example
   above. The report-only policy leaves the directive out. The rest of this
   note describes the policy as it was when it was written.
7. **`img-src 'self'` admits every path on the app's origin, not only the
   image proxy.** A raw `<img>` or CSS image can send GET requests to any app
   route. Per the Layer 2 note, they carry no `SameSite=Lax` cookie.
8. **A popup opened with `rel=opener` or a named target keeps a reference to
   the message frame and the app's window.** Chromium and WebKit refuse
   navigations through it, but the spec's sandbox check alone would not.
   `postMessage` to the app's window works in all cases. A
   `Cross-Origin-Opener-Policy: same-origin` header on the app page removes the
   reference in Chromium.

The Layer 3 sentence in `docs/threat-model.md` says links "open in a normal
tab and nothing in the frame can touch your app". Gaps 2, 6 and 7 qualify it.
Raw links without a target stay in the frame. The body route itself is
unsandboxed when opened top-level. Same-origin image requests reach the app.
Containment holds for script execution, form submission, `<base href>`, meta
refresh, nested frames and objects, and every subresource fetch except
same-origin images.

## Not verified

- Firefox: whether the embedding page's `frame-src` governs a navigation the
  child frame starts itself. `CSPService::ConsultCSP` uses the load's policy
  container, but I did not trace how the parent process builds it for
  child-initiated loads.
- Firefox: whether a popup can navigate its opener when the opener is a
  cross-origin subframe, or `opener.top`. Chromium and WebKit refuse both.
- Firefox and WebKit: implicit `noopener` for `target=_blank`. The spec and
  Chromium were checked.
- Whether any engine applies implicit `noopener` to SVG `<a>`. The HTML rule
  names only HTML `a`, `area` and `form`.
- Firefox and WebKit: whether they perform preconnect and DNS prefetch from a
  sandboxed, opaque-origin document, and whether any setting gates them on
  HTTPS pages.
- WebKit: custom-scheme handoff from a frame with `allow-popups`.
- Firefox and WebKit: the opaque-origin "no referrer" rule. The spec and
  Chromium were checked.
- Whether SMIL animation runs in a document sandboxed without `allow-scripts`.
  No engine source was read for this.
- Firefox and WebKit: whether `frame-src` applies to `about:srcdoc`. Chromium
  skips it. Either way the srcdoc document inherits the CSP and the sandbox.
- Which cookies, if any, the opaque-origin frame sends on same-origin requests
  and navigations beyond `SameSite=Lax`. Examples are `SameSite=None` and
  third-party cookie blocking. Chromium has an `allow-same-site-none-cookies`
  sandbox keyword that bears on this.
- [Allowed by sandboxing to navigate][allowed-nav] returns true for a non-top
  ancestor, while Chromium and WebKit refuse it. This matters only if the app
  nests the message iframe inside another iframe.
- My reading that the spec checks `frame-src` against the initiator's policy
  container. It comes from the HTML, Fetch and CSP text cited in section 2. No
  spec editor has confirmed it, and #509 does not state it.
- Browser prompts shown before an external-protocol handoff.

[sandboxing]: https://html.spec.whatwg.org/multipage/browsers.html#sandboxing
[parse-sandbox]: https://html.spec.whatwg.org/multipage/browsers.html#parse-a-sandboxing-directive
[custom-proto]: https://html.spec.whatwg.org/multipage/browsers.html#sandboxed-custom-protocols-navigation-browsing-context-flag
[downloads-flag]: https://html.spec.whatwg.org/multipage/browsers.html#sandboxed-downloads-browsing-context-flag
[creation-flags]: https://html.spec.whatwg.org/multipage/browsers.html#determining-the-creation-sandboxing-flags
[policy-container]: https://html.spec.whatwg.org/multipage/browsers.html#determining-navigation-params-policy-container
[refresh]: https://html.spec.whatwg.org/multipage/semantics.html#shared-declarative-refresh-steps
[meta-referrer]: https://html.spec.whatwg.org/multipage/semantics.html#meta-referrer
[meta-csp]: https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-content-security-policy
[meta-set-cookie]: https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-set-cookie
[elem-target]: https://html.spec.whatwg.org/multipage/semantics.html#get-an-element's-target
[frozen-base]: https://html.spec.whatwg.org/multipage/semantics.html#set-the-frozen-base-url
[allowed-nav]: https://html.spec.whatwg.org/multipage/browsing-the-web.html#allowed-to-navigate
[js-url]: https://html.spec.whatwg.org/multipage/browsing-the-web.html#navigate-to-a-javascript:-url
[nav-fetch]: https://html.spec.whatwg.org/multipage/browsing-the-web.html#create-navigation-params-by-fetching
[choose-nav]: https://html.spec.whatwg.org/multipage/document-sequences.html#the-rules-for-choosing-a-navigable
[noopener]: https://html.spec.whatwg.org/multipage/links.html#get-an-element's-noopener
[ping]: https://html.spec.whatwg.org/multipage/links.html#hyperlink-auditing
[dns-prefetch]: https://html.spec.whatwg.org/multipage/links.html#link-type-dns-prefetch
[preconnect]: https://html.spec.whatwg.org/multipage/links.html#link-type-preconnect
[form-submit]: https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#concept-form-submit
[iframe-sandbox]: https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox
[csp-effective]: https://w3c.github.io/webappsec-csp/#effective-directive-for-a-request
[csp-fallback]: https://w3c.github.io/webappsec-csp/#directive-fallback-list
[csp-nav]: https://w3c.github.io/webappsec-csp/#should-block-navigation-request
[csp-block]: https://w3c.github.io/webappsec-csp/#should-block-request
[csp-base-uri]: https://w3c.github.io/webappsec-csp/#directive-base-uri
[csp-form-action]: https://w3c.github.io/webappsec-csp/#directive-form-action
[issue-33]: https://github.com/cogniarg/safe-email-html/issues/33
[csp-sandbox]: https://w3c.github.io/webappsec-csp/#directive-sandbox
[csp-self]: https://w3c.github.io/webappsec-csp/#parse-response-csp
[navigate-to]: https://github.com/w3c/webappsec-csp/pull/564
[csp-509]: https://github.com/w3c/webappsec-csp/issues/509
[referrer]: https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer
[main-fetch]: https://fetch.spec.whatwg.org/#main-fetch
[svg-a]: https://svgwg.org/svg2-draft/linking.html#AElement
[cr]: https://github.com/chromium/chromium/tree/9150554b4f2404daf15995440690694542360aac
[cr-refresh]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/dom/document.cc#L5392-L5403
[cr-dns-doc]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/dom/document.cc#L8626-L8652
[cr-cannav-js]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/frame/local_frame.cc#L2205-L2213
[cr-cannav-sandbox]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/frame/local_frame.cc#L2215-L2273
[cr-cannav-barth]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/frame/local_frame.cc#L2329-L2393
[cr-referrer]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/frame/local_dom_window.cc#L583-L592
[cr-js]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/loader/frame_loader.cc#L897-L929
[cr-dns]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/loader/preload_helper.cc#L314-L347
[cr-preconnect]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/loader/preload_helper.cc#L349-L393
[cr-noopener]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/html/anchor_element_utils.cc#L171-L192
[cr-csp-ping]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/frame/csp/content_security_policy.cc#L820-L829
[cr-csp-map]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/third_party/blink/renderer/core/frame/csp/content_security_policy.cc#L865-L866
[cr-csp-nav]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/content/browser/renderer_host/navigation_request.cc#L8375-L8426
[cr-about]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/content/browser/renderer_host/navigation_request.cc#L8433-L8435
[cr-coop]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/content/browser/renderer_host/render_frame_host_impl.cc#L1130-L1144
[cr-flags]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/services/network/public/cpp/web_sandbox_flags.cc#L33-L38
[cr-hints]: https://github.com/chromium/chromium/blob/9150554b4f2404daf15995440690694542360aac/chrome/browser/predictors/network_hints_handler_impl.cc#L117-L144
[gk]: https://github.com/mozilla-firefox/firefox/tree/7a315fc898bbd3e61ba7dd220a8fb1d0721a1eb7
[gk-refresh]: https://github.com/mozilla-firefox/firefox/blob/7a315fc898bbd3e61ba7dd220a8fb1d0721a1eb7/dom/base/Document.cpp#L12326-L12336
[gk-extproto]: https://github.com/mozilla-firefox/firefox/blob/7a315fc898bbd3e61ba7dd220a8fb1d0721a1eb7/uriloader/exthandler/nsExternalHelperAppService.cpp#L1039-L1070
[wk]: https://github.com/WebKit/WebKit/tree/8692e28aac603a00bbe32d7a6eef96d797b72af5
[wk-refresh]: https://github.com/WebKit/WebKit/blob/8692e28aac603a00bbe32d7a6eef96d797b72af5/Source/WebCore/loader/NavigationScheduler.cpp#L205-L215
[wk-policy]: https://github.com/WebKit/WebKit/blob/8692e28aac603a00bbe32d7a6eef96d797b72af5/Source/WebCore/loader/PolicyChecker.cpp#L87-L102
[wk-cannav]: https://github.com/WebKit/WebKit/blob/8692e28aac603a00bbe32d7a6eef96d797b72af5/Source/WebCore/dom/Document.cpp#L5293-L5378
