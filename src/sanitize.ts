import createDOMPurify from "dompurify"
import { parseHTML } from "linkedom"

import {
  buildImgProxyUrl,
  buildRedirectUrl,
  isRemoteUrl,
  stripUrlControlCharacters,
} from "./url-policy.js"

// Minimal structural types for the linkedom values this module touches.
// linkedom's published types resolve differently depending on whether the
// consuming tsconfig loads the DOM lib (server runtimes usually do not,
// browser builds do), so relying on them breaks one side or the other.
interface SanitizerElement {
  getAttribute(name: string): string | null
  setAttribute(name: string, value: string): void
  removeAttribute(name: string): void
  querySelectorAll(selector: string): Iterable<SanitizerElement>
  textContent: string | null
}

interface SanitizerContainerElement {
  getAttribute(name: string): string | null
  setAttribute(name: string, value: string): void
  innerHTML: string
  outerHTML: string
}

interface SanitizerDocument {
  body: SanitizerContainerElement
  createElement(tagName: string): SanitizerContainerElement
  querySelectorAll(selector: string): Iterable<SanitizerElement>
}

interface SanitizerRealm {
  document: SanitizerDocument & { implementation?: unknown }
  window: Record<string, unknown> & {
    document: SanitizerDocument & { implementation?: unknown }
  }
}

function parseSanitizerHtml(html: string): SanitizerRealm {
  return parseHTML(html) as unknown as SanitizerRealm
}

/**
 * Builds a linkedom window that DOMPurify can operate on.
 *
 * DOMPurify hardens itself against DOM clobbering by capturing property
 * getters/methods from `Element.prototype`/`Node.prototype` at setup time
 * and calling them against every node it visits. linkedom, however, defines
 * most node properties per instance, not on prototypes, so those captures
 * come back empty and DOMPurify fail-closes on the first node it tries to
 * remove. The delegating prototype members installed here only forward to
 * each instance's own property, restoring the contract DOMPurify expects
 * without changing linkedom behavior (anything already reachable through
 * the prototype chain is left untouched).
 */
function createSanitizerWindow(): SanitizerRealm["window"] {
  const { window } = parseSanitizerHtml(
    "<!DOCTYPE html><html><head></head><body></body></html>"
  )
  const globals: Record<string, unknown> = window
  const elementPrototype = (globals.Element as { prototype: object }).prototype
  const nodePrototype = (globals.Node as { prototype: object }).prototype

  globals.NodeFilter ??= {
    SHOW_ALL: 0xffffffff,
    SHOW_ELEMENT: 0x1,
    SHOW_TEXT: 0x4,
    SHOW_CDATA_SECTION: 0x8,
    SHOW_PROCESSING_INSTRUCTION: 0x40,
    SHOW_COMMENT: 0x80,
    FILTER_ACCEPT: 1,
    FILTER_REJECT: 2,
    FILTER_SKIP: 3,
  }

  window.document.implementation ??= {
    createHTMLDocument: () =>
      parseSanitizerHtml(
        "<!DOCTYPE html><html><head></head><body></body></html>"
      ).document,
  }

  for (const name of [
    "parentNode",
    "nextSibling",
    "childNodes",
    "attributes",
    "shadowRoot",
  ]) {
    delegateInstanceAccessor(elementPrototype, name)
  }

  for (const name of ["cloneNode", "remove"]) {
    delegateInstanceMethod(elementPrototype, name)
  }

  for (const name of ["nodeType", "nodeName", "ownerDocument"]) {
    delegateInstanceAccessor(nodePrototype, name)
  }

  return window
}

function delegateInstanceAccessor(prototype: object, name: string): void {
  if (name in prototype) {
    return
  }

  Object.defineProperty(prototype, name, {
    configurable: true,
    get(this: object) {
      const own = Object.getOwnPropertyDescriptor(this, name)

      if (!own) {
        return undefined
      }

      return own.get ? own.get.call(this) : own.value
    },
    set(this: object, value: unknown) {
      // Constructors assign these as plain own properties; mirror that so
      // the prototype accessor never blocks linkedom's own writes.
      Object.defineProperty(this, name, {
        configurable: true,
        enumerable: true,
        writable: true,
        value,
      })
    },
  })
}

function delegateInstanceMethod(prototype: object, name: string): void {
  if (name in prototype) {
    return
  }

  Object.defineProperty(prototype, name, {
    configurable: true,
    writable: true,
    value(this: object, ...args: unknown[]) {
      const own = Object.getOwnPropertyDescriptor(this, name)
      const method = own?.value as
        | ((...methodArgs: unknown[]) => unknown)
        | undefined

      return method?.apply(this, args)
    },
  })
}

/**
 * Sanitizes attacker-controlled inbound email HTML for rendering inside a
 * sandboxed iframe (see docs/threat-model.md).
 *
 * Defense layers, in order:
 * 1. DOMPurify with an explicit tag/attribute allowlist (scripts, event
 *    handlers, javascript: URIs, <object>/<embed>/<base>/forms/svg/mathml
 *    never survive). <style> is dropped too: stylesheet rules can spoof
 *    the visible link label via pseudo-element content, and inline
 *    style="" attributes cannot. Styling email bodies via inline styles is
 *    what senders already do for client compatibility.
 * 2. A rewrite pass over the sanitized DOM: remote images are disabled (or
 *    routed through the image proxy when the reader opted in), every
 *    http(s) link is routed through the redirect interstitial, and inline
 *    styles are filtered down to a presentational property allowlist so
 *    sender CSS cannot overlay the clickable pixels of a rewritten link or
 *    paint pixels from a URL.
 * 3. The iframe sandbox and the strict CSP served with the rendered
 *    document (see url-policy.ts) backstop anything that slips through.
 */

/**
 * Upper bound on the HTML fed to the sanitizer. Inbound bodies beyond this
 * are truncated first: sanitization is CPU-bound work running inside a
 * request handler, and no legitimate email needs more.
 */
export const MAX_SANITIZED_HTML_CHARS = 1_000_000

/**
 * Upper bound on signed external links emitted by one message render. Links
 * beyond the limit remain visible but inert, keeping attacker-controlled
 * HTML from turning one render into unbounded cryptographic work.
 */
export const MAX_REWRITTEN_REMOTE_LINKS = 512

/** Whether remote images render via the proxy or stay disabled. */
export type RemoteImageMode = "blocked" | "proxied"

export interface SanitizeInboundHtmlInput {
  html: string
  messageId: string
  remoteImages?: RemoteImageMode
  /**
   * Builds the src used for an opted-in remote image. Pass a signer here
   * (see `createTargetSigner`) so image-proxy URLs are bound to this message
   * and this exact image URL, and have the proxy reject anything unsigned.
   * Defaults to the unsigned URL shape, which is only safe for callers that
   * inspect output without serving it.
   */
  buildRemoteImageUrl?: (url: string) => Promise<string> | string
  /**
   * Builds the href used for a rewritten remote link. Pass a signer here
   * (see `createTargetSigner`) so redirect URLs are bound to this message,
   * this exact destination and the displayed link text, and have the
   * redirect endpoint reject anything unsigned. Defaults to the unsigned URL
   * shape, which is only safe for callers that inspect output without
   * serving it.
   */
  buildRedirectLinkUrl?: (input: {
    url: string
    displayedText: string
  }) => Promise<string> | string
}

export interface SanitizedInboundHtml {
  html: string
  /** True when the original body referenced at least one remote image. */
  hasRemoteImages: boolean
}

const ALLOWED_TAGS = [
  "#text",
  "a",
  "abbr",
  "address",
  "b",
  "bdi",
  "bdo",
  "blockquote",
  "br",
  "caption",
  "center",
  "cite",
  "code",
  "col",
  "colgroup",
  "dd",
  "del",
  "div",
  "dl",
  "dt",
  "em",
  "figcaption",
  "figure",
  "font",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "hr",
  "i",
  "img",
  "ins",
  "kbd",
  "li",
  "mark",
  "ol",
  "p",
  "pre",
  "q",
  "s",
  "samp",
  "small",
  "span",
  "strike",
  "strong",
  "sub",
  "sup",
  "table",
  "tbody",
  "td",
  "tfoot",
  "th",
  "thead",
  "time",
  "tr",
  "u",
  "ul",
  "wbr",
]

const ALLOWED_ATTR = [
  "align",
  "alt",
  "bgcolor",
  "border",
  "cellpadding",
  "cellspacing",
  "class",
  "color",
  "colspan",
  "dir",
  "face",
  "height",
  "href",
  "id",
  "lang",
  "rowspan",
  "size",
  "src",
  "start",
  "style",
  "title",
  "type",
  "valign",
  "width",
]

export async function sanitizeInboundHtml({
  html,
  messageId,
  remoteImages = "blocked",
  buildRemoteImageUrl = (url) => buildImgProxyUrl({ url, messageId }),
  buildRedirectLinkUrl = ({ url, displayedText }) =>
    buildRedirectUrl({ to: url, messageId, displayedText }),
}: SanitizeInboundHtmlInput): Promise<SanitizedInboundHtml> {
  const boundedHtml = extractDocumentBody(
    html.slice(0, MAX_SANITIZED_HTML_CHARS)
  )
  const purifier = createDOMPurify(
    createSanitizerWindow() as unknown as Parameters<typeof createDOMPurify>[0]
  )

  // DOMPurify silently becomes a no-op factory when the environment lacks
  // the DOM features it needs. That failure mode would render raw
  // attacker HTML, so refuse loudly instead.
  if (!purifier.isSupported) {
    throw new Error(
      "DOMPurify reports the sanitizer DOM environment is unsupported."
    )
  }

  // linkedom's DOMParser does not relocate stray content into <body> the
  // way a spec HTML parser does; feeding it a complete document keeps the
  // parsed body (which DOMPurify sanitizes and serializes) populated.
  const sanitized = purifier.sanitize(
    `<html><head></head><body>${boundedHtml}</body></html>`,
    {
      ALLOWED_TAGS,
      ALLOWED_ATTR,
      ALLOW_DATA_ATTR: false,
      ALLOW_ARIA_ATTR: false,
      ALLOW_UNKNOWN_PROTOCOLS: false,
      // Disallowed containers are dropped together with their content. The
      // content-preserving path is where phishing form bodies would leak
      // through as bare text, and DOMPurify's child-rescue cloning is also
      // the one code path linkedom cannot execute (it crashes cloning
      // detached subtrees). Every tag legitimate email markup uses is in
      // ALLOWED_TAGS, so content loss only hits markup we mean to drop.
      KEEP_CONTENT: false,
    }
  )

  const { document } = parseSanitizerHtml(
    `<!DOCTYPE html><html><head></head><body>${sanitized}</body></html>`
  )

  const hasRemoteImages = await rewriteImages(
    document,
    remoteImages,
    buildRemoteImageUrl
  )
  await rewriteLinks(document, buildRedirectLinkUrl)
  filterInlineStyles(document)

  return {
    html: document.body.innerHTML,
    hasRemoteImages,
  }
}

async function rewriteImages(
  document: SanitizerDocument,
  remoteImages: RemoteImageMode,
  buildRemoteImageUrl: (url: string) => Promise<string> | string
): Promise<boolean> {
  let hasRemoteImages = false
  const linkedImages = new Set(document.querySelectorAll("a img"))

  for (const image of document.querySelectorAll("img")) {
    const source = image.getAttribute("src")

    if (!source || !isRemoteUrl(source)) {
      // Every non-remote src is blanked. Schemeless srcs (including the
      // empty string) resolve against the body route itself, so a message
      // could fan out authenticated same-origin requests on every open;
      // data: URIs can paint a trusted-looking link label that never
      // entered the signed redirect text. The frame CSP's img-src excludes
      // data: as the backstop.
      if (source !== null) {
        image.setAttribute("src", "about:blank")
      }

      continue
    }

    hasRemoteImages = true
    const absoluteSource = absolutizeRemoteUrl(source)

    image.setAttribute("data-original-src", absoluteSource)
    image.setAttribute(
      "src",
      remoteImages === "proxied" && !linkedImages.has(image)
        ? await buildRemoteImageUrl(absoluteSource)
        : "about:blank"
    )
  }

  return hasRemoteImages
}

async function rewriteLinks(
  document: SanitizerDocument,
  buildRedirectLinkUrl: (input: {
    url: string
    displayedText: string
  }) => Promise<string> | string
): Promise<void> {
  let rewrittenRemoteLinks = 0

  for (const anchor of document.querySelectorAll("a")) {
    const href = anchor.getAttribute("href")

    if (href && isRemoteUrl(href)) {
      // Everything navigable to a remote authority — including scheme-relative
      // `//host/...` URLs, which the browser resolves to https — goes through
      // the interstitial.
      if (rewrittenRemoteLinks >= MAX_REWRITTEN_REMOTE_LINKS) {
        anchor.removeAttribute("href")
      } else {
        anchor.setAttribute(
          "href",
          await buildRedirectLinkUrl({
            url: absolutizeRemoteUrl(href),
            displayedText: displayedLinkLabel(anchor),
          })
        )
        rewrittenRemoteLinks += 1
      }
    } else if (href && !isAllowedDirectLink(href)) {
      // Only the explicitly non-web mail and telephone schemes may navigate
      // directly. Relative references could re-enter this route, while other
      // external schemes such as ftp: would bypass the signed interstitial.
      anchor.removeAttribute("href")
    }

    // Sandboxed frames cannot navigate the top-level page; links must open
    // as popups that escape the sandbox into a normal browsing context.
    anchor.setAttribute("target", "_blank")
    anchor.setAttribute("rel", "noopener noreferrer")
  }
}

/**
 * The label a reader actually sees on a link. With remote images blocked,
 * an image-only anchor renders its alt text, so a spoofed
 * `alt="https://mybank.com"` is exactly as visible as text content and must
 * be bound into the signed redirect text the same way.
 */
function displayedLinkLabel(anchor: SanitizerElement): string {
  const parts = [anchor.textContent ?? ""]

  for (const image of anchor.querySelectorAll("img")) {
    parts.push(image.getAttribute("alt") ?? "")
  }

  return parts.filter((part) => part.trim().length > 0).join(" ")
}

/**
 * Real inbound email is almost always a complete HTML document. linkedom
 * parses a document nested inside the sanitizer's own <body> as a literal
 * <html> child (a spec parser would relocate the content instead), and
 * DOMPurify with KEEP_CONTENT: false then drops that disallowed element
 * together with the entire mail. Unwrap the document up front: keep the
 * <body> content, and carry the body's own presentational attributes over
 * on a wrapper <div> so background/font declarations survive. The wrapper
 * goes through the same sanitization as everything else afterwards.
 */
function extractDocumentBody(html: string): string {
  if (!/<(?:html|body)[\s>]/i.test(html)) {
    return html
  }

  const { document } = parseSanitizerHtml(html)
  const body = document.body

  // A parse that stranded the content outside <body> would blank the mail;
  // fall back to the original input and let DOMPurify decide.
  if (!body || body.innerHTML.trim() === "") {
    return html
  }

  const style = body.getAttribute("style")
  const bgcolor = body.getAttribute("bgcolor")
  // bgcolor first: it is a presentational hint, so the style attribute's
  // own declarations must win the last-declaration-wins tiebreak.
  const wrapperStyle = [
    ...(bgcolor === null ? [] : [`background-color: ${bgcolor}`]),
    ...(style === null ? [] : [style]),
  ].join("; ")

  if (wrapperStyle === "") {
    return body.innerHTML
  }

  const wrapper = document.createElement("div")
  wrapper.setAttribute("style", wrapperStyle)
  wrapper.innerHTML = body.innerHTML

  return wrapper.outerHTML
}

/**
 * Inline style properties allowed to survive sanitization.
 * Purely presentational: nothing here can reposition content over other
 * elements (no position/transform/z-index/inset/float), so sender CSS
 * cannot overlay the clickable pixels of a rewritten link with pixels that
 * disagree with the signed label. Hiding content (display, opacity,
 * visibility) is allowed — visible text is always a subset of the signed
 * textContent, so hiding cannot forge a label claim — and it is what the
 * standard hidden-preheader idiom relies on.
 */
const ALLOWED_STYLE_PROPERTIES = new Set([
  "background",
  "background-color",
  "border",
  "border-bottom",
  "border-bottom-color",
  "border-bottom-style",
  "border-bottom-width",
  "border-collapse",
  "border-color",
  "border-left",
  "border-left-color",
  "border-left-style",
  "border-left-width",
  "border-radius",
  "border-right",
  "border-right-color",
  "border-right-style",
  "border-right-width",
  "border-spacing",
  "border-style",
  "border-top",
  "border-top-color",
  "border-top-style",
  "border-top-width",
  "border-width",
  "box-shadow",
  "box-sizing",
  "caption-side",
  "color",
  "cursor",
  "direction",
  "display",
  "font",
  "font-family",
  "font-size",
  "font-style",
  "font-variant",
  "font-weight",
  "height",
  "letter-spacing",
  "line-height",
  "list-style",
  "list-style-position",
  "list-style-type",
  "margin",
  "margin-bottom",
  "margin-left",
  "margin-right",
  "margin-top",
  "max-height",
  "max-width",
  "min-height",
  "min-width",
  "opacity",
  "overflow",
  "overflow-wrap",
  "padding",
  "padding-bottom",
  "padding-left",
  "padding-right",
  "padding-top",
  "table-layout",
  "text-align",
  "text-decoration",
  "text-decoration-color",
  "text-decoration-line",
  "text-decoration-style",
  "text-transform",
  "vertical-align",
  "visibility",
  "white-space",
  "width",
  "word-break",
  "word-wrap",
])

/**
 * Rejected anywhere in a declaration value. url()/image-set()/cross-fade()
 * paint sender-controlled pixels — a data: SVG can spoof a link label past
 * the signed textContent, and a remote background would bypass the image
 * proxy. Comments and backslash escapes could smuggle those functions past
 * this check (a comment split inside `url(` or a `\75rl(...)` identifier
 * escape), so they are rejected outright. The frame CSP's img-src (self
 * only, no data:) backstops whatever CSS image syntax this misses.
 */
const FORBIDDEN_STYLE_VALUE =
  /url\s*\(|image-set|cross-fade|expression|\/\*|[\\<>]/i

/**
 * Filters one style attribute down to the allowlisted declarations, or
 * `null` when nothing survives. Negative margins are rejected because they
 * are the one allowlisted mechanism that could pull sender content over a
 * rewritten link's clickable area.
 */
function sanitizeStyleAttribute(css: string): string | null {
  const kept: Array<string> = []

  for (const declaration of css.split(";")) {
    const colon = declaration.indexOf(":")

    if (colon === -1) {
      continue
    }

    const property = declaration.slice(0, colon).trim().toLowerCase()
    const value = declaration.slice(colon + 1).trim()

    if (
      value === "" ||
      !ALLOWED_STYLE_PROPERTIES.has(property) ||
      FORBIDDEN_STYLE_VALUE.test(value) ||
      (property.startsWith("margin") && value.includes("-"))
    ) {
      continue
    }

    kept.push(`${property}: ${value}`)
  }

  return kept.length > 0 ? kept.join("; ") : null
}

function filterInlineStyles(document: SanitizerDocument): void {
  for (const styled of document.querySelectorAll("[style]")) {
    const filtered = sanitizeStyleAttribute(styled.getAttribute("style") ?? "")

    if (filtered === null) {
      styled.removeAttribute("style")
    } else {
      styled.setAttribute("style", filtered)
    }
  }
}

function isAllowedDirectLink(href: string): boolean {
  return /^(?:mailto|tel):/i.test(stripUrlControlCharacters(href))
}

function absolutizeRemoteUrl(url: string): string {
  // Strip the same characters a browser's URL parser would, so the URL we
  // rewrite (and sign) is the one the browser would have navigated.
  const trimmed = stripUrlControlCharacters(url)

  if (trimmed.startsWith("//")) {
    return `https:${trimmed}`
  }

  // Slashless `http:host/path` is still an absolute remote URL to a spec
  // URL parser; normalize to the canonical `http://host/path` form so
  // policy checks and signatures see what the browser would fetch.
  if (/^https?:(?!\/\/)/i.test(trimmed)) {
    try {
      return new URL(trimmed).href
    } catch {
      return trimmed
    }
  }

  return trimmed
}
