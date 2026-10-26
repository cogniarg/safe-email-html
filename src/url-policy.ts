/**
 * URL policy for rendering attacker-controlled inbound email content.
 *
 * Centralizes every decision about which URLs the safe-render pipeline may
 * touch: which image hosts are proxied or refused, which link destinations
 * require a phishing warning, and which attachment types need an explicit
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

/**
 * How many hosts dropped by the display-text cap are re-appended so the
 * mismatch check still sees them. Bounds the signed text against a label
 * stuffed with hundreds of URL-shaped strings.
 */
const MAX_PRESERVED_DISPLAYED_HOSTS = 5

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
 * Normalizes the displayed link text forwarded to the redirect endpoint.
 * Exported so signers can bind the exact string that ends up in the `text`
 * query parameter.
 */
export function boundDisplayedLinkText(
  displayedText: string,
  to?: string
): string {
  const normalized = displayedText.replace(/\s+/g, " ").trim()
  const sliced = normalized.slice(0, MAX_DISPLAYED_LINK_TEXT_CHARS)

  // slice() cuts by UTF-16 code unit, so the bound can fall between the two
  // halves of a surrogate pair and leave a lone high surrogate. The body
  // route signs this exact string, but URLSearchParams later coerces a lone
  // surrogate to U+FFFD; dropping the dangling half keeps the signed and the
  // serialized text identical so the rewritten link does not 403.
  const bounded = /[\uD800-\uDBFF]$/.test(sliced) ? sliced.slice(0, -1) : sliced

  if (bounded.length === normalized.length) {
    return bounded
  }

  // The cap must not hide URL-shaped claims: a long (e.g. display:none)
  // prefix would otherwise push a visible `https://mybank.com` past the
  // bound, and the redirect endpoint would evaluate a label with no claimed
  // host. Re-append the hosts the cut dropped so every claim stays bound
  // into the signed text. Hosts that do NOT look like the destination — the
  // ones that trigger the mismatch warning — are preserved first, so a
  // sender cannot overflow the cap with destination-matching decoys to
  // push the one spoofed host off the list.
  const destinationHost = safeParseHostname(to)
  const kept = new Set(extractDisplayedHosts(bounded))
  const lost = [...new Set(extractDisplayedHosts(normalized))]
    .filter((host) => !kept.has(host))
    .sort(
      (a, b) =>
        Number(destinationHost !== null && hostsLookAlike(a, destinationHost)) -
        Number(destinationHost !== null && hostsLookAlike(b, destinationHost))
    )
    .slice(0, MAX_PRESERVED_DISPLAYED_HOSTS)

  return lost.length > 0 ? `${bounded} ${lost.join(" ")}` : bounded
}

/** Hostname of a URL string, or null when absent or unparsable. */
function safeParseHostname(url: string | undefined): string | null {
  if (!url) {
    return null
  }

  try {
    return new URL(url).hostname
  } catch {
    return null
  }
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
  const boundedText = boundDisplayedLinkText(displayedText, to)

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
 * variable) into a normalized set. Used for both the image-proxy blocklist and the
 * always-warn redirect list.
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
  | { kind: "warn"; destination: URL; reasons: RedirectWarnReason[] }
  | { kind: "allow"; destination: URL }

export type RedirectWarnReason = "text_host_mismatch" | "always_warn_domain"

/**
 * Decides how the redirect endpoint should treat a link click coming out of
 * an inbound message. Only http(s) destinations are ever navigable; a
 * warning interstitial is required when the visible link text claims a
 * different host than the real destination, or when the destination is on
 * the configured always-warn list (banks, common phishing targets, your own
 * internal hosts).
 */
export function evaluateRedirectTarget({
  to,
  displayedText,
  alwaysWarnDomains,
}: {
  to: string
  displayedText: string | null
  alwaysWarnDomains: ReadonlySet<string>
}): RedirectDecision {
  let destination: URL

  try {
    destination = new URL(to)
  } catch {
    return { kind: "refused", reason: "invalid_url" }
  }

  if (destination.protocol !== "http:" && destination.protocol !== "https:") {
    return { kind: "refused", reason: "unsupported_scheme" }
  }

  const reasons: RedirectWarnReason[] = []
  const displayedHosts = extractDisplayedHosts(displayedText)

  // Warn if any host visible in the link text — including one hidden behind
  // CSS or placed before an `@` userinfo delimiter — fails to look like the
  // real destination. Checking every candidate, not just the first, stops an
  // attacker from prefixing a matching host to suppress the warning while the
  // user still reads a trusted-looking label.
  if (
    displayedHosts.some((host) => !hostsLookAlike(host, destination.hostname))
  ) {
    reasons.push("text_host_mismatch")
  }

  if (hostMatchesAnyDomain(destination.hostname, alwaysWarnDomains)) {
    reasons.push("always_warn_domain")
  }

  return reasons.length > 0
    ? { kind: "warn", destination, reasons }
    : { kind: "allow", destination }
}

/**
 * Pulls every host out of link text that looks like a URL or a bare domain,
 * which is the classic phishing shape ("https://mybank.com" pointing at
 * attacker.example). Plain prose yields an empty list: there is nothing to
 * compare. The `@` in the lookahead captures a host used as URL userinfo
 * (`trusted.com@evil.example`), so a trusted-looking label before the `@` is
 * compared instead of silently skipped.
 */
export function extractDisplayedHosts(text: string | null): string[] {
  if (!text) {
    return []
  }

  const hosts: string[] = []

  for (const match of text.matchAll(
    /(?:https?:\/\/)?(?:[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]*[\p{L}\p{N}\p{M}])?\.)+(?:[\p{L}]{2,}|xn--[a-z0-9-]{2,})\.?(?=[/:@?#,;!.)\]}>'"\s]|$)/giu
  )) {
    const host = normalizeDisplayedHost(match[0])

    if (host !== null) {
      hosts.push(host)
    }
  }

  return hosts
}

function normalizeDisplayedHost(candidate: string): string | null {
  const value = /^https?:\/\//i.test(candidate)
    ? candidate
    : `https://${candidate}`

  try {
    return canonicalizeHost(new URL(value).hostname)
  } catch {
    return null
  }
}

function hostsLookAlike(
  displayedHost: string,
  destinationHost: string
): boolean {
  // `www.` is the one prefix labels and destinations use interchangeably.
  const normalizedDestination = canonicalizeHost(destinationHost).replace(
    /^www\./,
    ""
  )
  const normalizedDisplayed = canonicalizeHost(displayedHost).replace(
    /^www\./,
    ""
  )

  // The destination may sit under the displayed host (label `example.com`
  // linking to `mail.example.com`): the reader sees the parent domain,
  // so nothing is hidden. The reverse is a phishing shape — a label like
  // `mybank.com.evil.example.com` IS a subdomain of the destination
  // `evil.example.com` but reads as mybank — and must keep the warning.
  return (
    normalizedDisplayed === normalizedDestination ||
    hostMatchesDomain(normalizedDestination, normalizedDisplayed)
  )
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
 */
export function buildMessageFrameCsp(): string {
  return [
    "default-src 'none'",
    "img-src 'self'",
    "style-src 'unsafe-inline'",
    "connect-src 'none'",
    "script-src 'none'",
    "form-action 'none'",
    "base-uri 'none'",
    "frame-ancestors 'self'",
  ].join("; ")
}

export function buildMessageFrameCspReportOnly(
  reportUri: string = DEFAULT_CSP_REPORT_PATH
): string {
  return `${buildMessageFrameCsp()}; report-uri ${reportUri}`
}
