/**
 * URL policy for rendering attacker-controlled inbound email content.
 *
 * Centralizes every decision about which URLs the safe-render pipeline may
 * touch: which image hosts are proxied or refused, which link destinations
 * may be confirmed and followed, and which attachment types need an explicit
 * confirmation before download. Keeping the policy pure and side-effect free
 * lets both the sanitizer and your server routes share one implementation.
 */

/** Default path of the redirect interstitial that rewritten links point to. */
export const DEFAULT_REDIRECT_PATH = "/api/redirect"
/** Default path of the image proxy that opted-in remote images point to. */
export const DEFAULT_IMG_PROXY_PATH = "/api/img-proxy"
/** Default `report-uri` of the report-only frame CSP. */
export const DEFAULT_CSP_REPORT_PATH = "/api/csp-report"

/** Bound on the displayed link text forwarded to the redirect endpoint. */
export const MAX_DISPLAYED_LINK_TEXT_CHARS = 200

// Anything the browser can resolve to a remote authority: full http(s)
// URLs, scheme-relative `//host` URLs, and slashless `http:host/path`
// forms, which a spec URL parser still treats as absolute remote URLs.
const REMOTE_URL_PATTERN = /^(?:https?:|\/\/)/i

/**
 * Removes the characters a WHATWG URL parser strips before parsing:
 * leading/trailing C0 controls and spaces, plus every internal tab and
 * newline. Policy decisions must see the same URL the browser would
 * navigate, or a control-prefixed href bypasses the remote-URL checks.
 */
export function stripUrlControlCharacters(value: string): string {
  return (
    value
      // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping controls is the point
      .replace(/^[\u0000-\u0020]+/, "")
      // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping controls is the point
      .replace(/[\u0000-\u0020]+$/, "")
      // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping controls is the point
      .replace(/[\u0009\u000a\u000d]/g, "")
  )
}

export function isRemoteUrl(value: string): boolean {
  return REMOTE_URL_PATTERN.test(stripUrlControlCharacters(value))
}

/**
 * Normalizes the displayed link text forwarded to the redirect endpoint,
 * plainly truncated: the interstitial only shows it, and no decision reads
 * it. Exported so signers can bind the exact string that ends up in the
 * `text` query parameter.
 */
export function boundDisplayedLinkText(displayedText: string): string {
  const sliced = displayedText
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_DISPLAYED_LINK_TEXT_CHARS)

  // slice() cuts by UTF-16 code unit, so the bound can fall between the two
  // halves of a surrogate pair and leave a lone high surrogate. The body
  // route signs this exact string, but URLSearchParams later coerces a lone
  // surrogate to U+FFFD; dropping the dangling half keeps the signed and the
  // serialized text identical so the rewritten link does not 403.
  return /[\uD800-\uDBFF]$/.test(sliced) ? sliced.slice(0, -1) : sliced
}

export function buildRedirectUrl({
  to,
  messageId,
  displayedText,
  path = DEFAULT_REDIRECT_PATH,
}: {
  to: string
  messageId: string
  displayedText: string
  path?: string
}): string {
  const params = new URLSearchParams({
    to,
    messageId,
  })
  const boundedText = boundDisplayedLinkText(displayedText)

  if (boundedText) {
    params.set("text", boundedText)
  }

  return `${path}?${params.toString()}`
}

export function buildImgProxyUrl({
  url,
  messageId,
  path = DEFAULT_IMG_PROXY_PATH,
}: {
  url: string
  messageId: string
  path?: string
}): string {
  const params = new URLSearchParams({ url, messageId })

  return `${path}?${params.toString()}`
}

/**
 * Parses a comma-separated domain list (for example from an environment
 * variable) into a normalized set, such as the image-proxy blocklist.
 */
export function parseDomainList(value?: string): Set<string> {
  return new Set(
    (value ?? "")
      .split(",")
      .map((domain) =>
        domain
          .trim()
          .toLowerCase()
          .replace(/^\*?\.?/, "")
      )
      .filter((domain) => domain.length > 0)
  )
}

/**
 * Lowercases a hostname and strips trailing dots: DNS and browsers treat
 * the fully-qualified `example.com.` as `example.com`, so policy matches
 * must too or a trailing dot bypasses every domain list.
 */
export function canonicalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.+$/, "")
}

/** A host matches a domain entry exactly or as any-depth subdomain. */
export function hostMatchesDomain(host: string, domain: string): boolean {
  const normalizedHost = canonicalizeHost(host)

  return normalizedHost === domain || normalizedHost.endsWith(`.${domain}`)
}

export function hostMatchesAnyDomain(
  host: string,
  domains: ReadonlySet<string>
): boolean {
  for (const domain of domains) {
    if (hostMatchesDomain(host, domain)) {
      return true
    }
  }

  return false
}

export type RedirectDecision =
  | { kind: "refused"; reason: "invalid_url" | "unsupported_scheme" }
  | { kind: "confirm"; destination: URL }

/**
 * Decides how the redirect endpoint treats a link click coming out of an
 * inbound message. Only http(s) destinations are navigable, and every one
 * is confirmed first. Nothing about the link text is consulted: hidden
 * spans and CSS make the visible label unknowable on the server, so no
 * reading of it may skip the confirmation.
 */
export function evaluateRedirectTarget(to: string): RedirectDecision {
  let destination: URL

  try {
    destination = new URL(to)
  } catch {
    return { kind: "refused", reason: "invalid_url" }
  }

  if (destination.protocol !== "http:" && destination.protocol !== "https:") {
    return { kind: "refused", reason: "unsupported_scheme" }
  }

  return { kind: "confirm", destination }
}

const EXECUTABLE_CONTENT_TYPES = new Set([
  "application/x-msdownload",
  "application/x-msdos-program",
  "application/x-msi",
  "application/x-bat",
  "application/x-sh",
  "application/x-shellscript",
  "application/x-executable",
  "application/x-elf",
  "application/x-mach-binary",
  "application/x-ms-shortcut",
  "application/x-apple-diskimage",
  "application/vnd.microsoft.portable-executable",
  "application/vnd.android.package-archive",
  "application/java-archive",
  "application/hta",
])

const EXECUTABLE_FILENAME_EXTENSIONS = new Set([
  "exe",
  "msi",
  "bat",
  "cmd",
  "com",
  "scr",
  "pif",
  "cpl",
  "hta",
  "jar",
  "js",
  "jse",
  "vbs",
  "vbe",
  "ws",
  "wsf",
  "wsh",
  "ps1",
  "psm1",
  "reg",
  "sh",
  "apk",
  "dmg",
  "app",
  "lnk",
])

/**
 * Flags attachments that need an explicit confirmation before download.
 * Checks both the stored MIME type and the filename extension because
 * senders routinely mislabel executables as octet-stream.
 */
export function isExecutableAttachment({
  contentType,
  filename,
}: {
  contentType: string | null
  filename: string | null
}): boolean {
  const normalizedType = contentType?.split(";")[0]?.trim().toLowerCase()

  if (normalizedType && EXECUTABLE_CONTENT_TYPES.has(normalizedType)) {
    return true
  }

  // Windows strips trailing dots/spaces when saving, so "invoice.exe." is
  // opened as "invoice.exe"; normalize the same way before extracting.
  const extension = filename
    ?.replace(/[. ]+$/, "")
    .split(".")
    .pop()
    ?.trim()
    .toLowerCase()

  return (
    extension !== undefined && EXECUTABLE_FILENAME_EXTENSIONS.has(extension)
  )
}

/**
 * Strict Content-Security-Policy for the sandboxed message body document.
 * No scripts of any kind, no network access except same-origin images (the
 * proxy), inline styles only. data: images are excluded on purpose: a
 * sender-supplied data: SVG can paint a trusted-looking link label that
 * never entered the signed redirect text, and no heuristic over the DOM can
 * see what an image renders. Excluding them here fail-closes every current
 * and future "paint a fake label with CSS/images" vector at the platform
 * layer.
 *
 * The `sandbox` directive carries the same keywords the iframe's `sandbox`
 * attribute must have, so the body is sandboxed even when it is loaded
 * outside the frame, for example opened as a top-level page. Inside the
 * frame, the document's flags are the union of both, so identical keywords
 * change nothing. See docs/adr/0002-fixed-sandbox-flags-in-the-frame-csp.md.
 */
export function buildMessageFrameCsp(): string {
  return [...messageFrameDirectives(), MESSAGE_FRAME_SANDBOX].join("; ")
}

/**
 * The enforced policy without `sandbox`, which CSP ignores in a
 * Content-Security-Policy-Report-Only header, plus `report-uri`.
 */
export function buildMessageFrameCspReportOnly(
  reportUri: string = DEFAULT_CSP_REPORT_PATH
): string {
  return [...messageFrameDirectives(), `report-uri ${reportUri}`].join("; ")
}

const MESSAGE_FRAME_SANDBOX =
  "sandbox allow-popups allow-popups-to-escape-sandbox"

function messageFrameDirectives(): Array<string> {
  return [
    "default-src 'none'",
    "img-src 'self'",
    "style-src 'unsafe-inline'",
    "connect-src 'none'",
    "script-src 'none'",
    "form-action 'none'",
    "base-uri 'none'",
    "frame-ancestors 'self'",
  ]
}
