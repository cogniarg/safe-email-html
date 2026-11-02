/**
 * Parser-differential check for sanitized output (see docs/threat-model.md).
 *
 * The sanitizer parses with linkedom, but a browser reads its output with a
 * spec HTML parser. This re-parses each output with parse5, the way the
 * frame document is parsed, checks the allowlist invariants on that tree,
 * and parses parse5's own serialization again: a tree that changes between
 * the two parses is the mutation-XSS shape the threat model warns about.
 */
import { isDeepStrictEqual } from "node:util"
import {
  type DefaultTreeAdapterTypes,
  parse,
  html as parse5Html,
  serialize,
} from "parse5"

import {
  boundDisplayedLinkText,
  buildImgProxyUrl,
  buildRedirectUrl,
  createTargetSigner,
  DEFAULT_IMG_PROXY_PATH,
  DEFAULT_REDIRECT_PATH,
  type RemoteImageMode,
  sanitizeInboundHtml,
} from "../src/index.js"
import {
  ALLOWED_ATTR,
  ALLOWED_STYLE_PROPERTIES,
  ALLOWED_TAGS,
} from "../src/sanitize.js"

type Node = DefaultTreeAdapterTypes.Node
type Element = DefaultTreeAdapterTypes.Element

export const SECRET = "test-secret-with-enough-entropy"

/** Where an integrator serves the frame document; relative URLs resolve here. */
const FRAME_URL = new URL("https://app.example/messages/msg/body")

/** Elements the document parse creates around the body, never the sender. */
const DOCUMENT_ELEMENTS = new Set(["html", "head", "body"])

/** Attributes the rewrite pass adds after the allowlist ran. */
const REWRITE_ATTRIBUTES = new Map<string, (value: string) => boolean>([
  ["a target", (value) => value === "_blank"],
  ["a rel", (value) => value === "noopener noreferrer"],
  ["img data-original-src", () => true],
])

/** The frame is sandboxed without scripts, so `<noscript>` parses as markup. */
const FRAME_PARSE = { scriptingEnabled: false }

/** The schemes the sanitizer lets navigate without the redirect. */
const DIRECT_LINK_PROTOCOLS = new Set(["mailto:", "tel:"])

/**
 * Renders a body the way the README recommends, every link and image
 * signed, through the package entry point, and checks the output.
 */
export async function renderChecked(
  html: string,
  {
    messageId = "msg_42",
    remoteImages = "blocked",
  }: { messageId?: string; remoteImages?: RemoteImageMode } = {}
) {
  const sign = await createTargetSigner(SECRET)
  const result = await sanitizeInboundHtml({
    html,
    messageId,
    remoteImages,
    buildRemoteImageUrl: async (url) => {
      const signature = await sign({
        purpose: "img-proxy",
        messageId,
        target: url,
      })

      return `${buildImgProxyUrl({ url, messageId })}&sig=${signature}`
    },
    buildRedirectLinkUrl: async ({ url, displayedText }) => {
      const signature = await sign({
        purpose: "redirect",
        messageId,
        target: url,
        context: boundDisplayedLinkText(displayedText),
      })

      return `${buildRedirectUrl({ to: url, messageId, displayedText })}&sig=${signature}`
    },
  })

  checkSanitizedHtml(result.html, remoteImages)

  return result
}

/**
 * Throws unless `sanitized` (a `sanitizeInboundHtml` output) keeps every
 * allowlist invariant under a spec parse, and parses to the same tree again.
 */
export function checkSanitizedHtml(
  sanitized: string,
  remoteImages: RemoteImageMode
): void {
  // The example body route serves `<!DOCTYPE html><meta charset>` + output;
  // the charset declaration does not change how a string parses.
  const first = parse(`<!DOCTYPE html>${sanitized}`, FRAME_PARSE)
  const reserialized = serialize(first)
  const violations = [...descendants(first)].flatMap((node) =>
    nodeViolations(node, remoteImages)
  )

  if (
    !isDeepStrictEqual(
      snapshot(first),
      snapshot(parse(reserialized, FRAME_PARSE))
    )
  ) {
    violations.push(`the tree changes when reparsed: ${reserialized}`)
  }

  if (violations.length > 0) {
    throw new Error(
      `Sanitized output breaks an invariant:\n- ${violations.join("\n- ")}\nOutput: ${sanitized}`
    )
  }
}

function nodeViolations(
  node: Node,
  remoteImages: RemoteImageMode
): Array<string> {
  if (!("tagName" in node)) {
    return node.nodeName === "#text" || node.nodeName === "#documentType"
      ? []
      : [`${node.nodeName} is not allowlisted`]
  }

  const tag = node.tagName
  const violations: Array<string> = []

  if (node.namespaceURI !== parse5Html.NS.HTML) {
    violations.push(`<${tag}> is in the ${node.namespaceURI} namespace`)
  }

  if (DOCUMENT_ELEMENTS.has(tag)) {
    for (const { name } of node.attrs) {
      violations.push(`<${tag} ${name}> reaches the document element`)
    }

    return violations
  }

  if (!ALLOWED_TAGS.includes(tag)) {
    violations.push(`<${tag}> is not allowlisted`)
  }

  for (const { name, value } of node.attrs) {
    violations.push(...attributeViolations(node, name, value, remoteImages))
  }

  return violations
}

function attributeViolations(
  { tagName: tag }: Element,
  name: string,
  value: string,
  remoteImages: RemoteImageMode
): Array<string> {
  const isExpectedRewrite = REWRITE_ATTRIBUTES.get(`${tag} ${name}`)

  if (/^on/i.test(name)) {
    return [`<${tag} ${name}> is an event handler`]
  }

  if (isExpectedRewrite) {
    return isExpectedRewrite(value)
      ? []
      : [`<${tag} ${name}="${value}"> is unexpected`]
  }

  if (!ALLOWED_ATTR.includes(name)) {
    return [`<${tag} ${name}> is not allowlisted`]
  }

  if (name === "href" && !isSignedRedirectOrDirectLink(value)) {
    return [`<${tag} href="${value}"> is not a signed redirect`]
  }

  if (name === "src" && !isAllowedImageSource(value, remoteImages)) {
    return [`<${tag} src="${value}"> is not allowed for ${remoteImages} images`]
  }

  if (name === "style") {
    // ponytail: splits on ";" like the sanitizer does, so it cannot catch a
    // CSS-parser differential; swap in a CSS tokenizer if one is suspected.
    return value
      .split(";")
      .flatMap((declaration) => {
        const colon = declaration.indexOf(":")

        // A declaration without a colon is invalid CSS and ignored.
        return colon === -1
          ? []
          : [declaration.slice(0, colon).trim().toLowerCase()]
      })
      .filter(
        (property) => property !== "" && !ALLOWED_STYLE_PROPERTIES.has(property)
      )
      .map((property) => `<${tag} style> sets ${property}`)
  }

  return []
}

function isSignedRedirectOrDirectLink(href: string): boolean {
  const url = resolveInFrame(href)

  return (
    (url !== null && DIRECT_LINK_PROTOCOLS.has(url.protocol)) ||
    isSignedRoute(url, DEFAULT_REDIRECT_PATH)
  )
}

function isAllowedImageSource(
  src: string,
  remoteImages: RemoteImageMode
): boolean {
  return (
    src === "about:blank" ||
    (remoteImages === "proxied" &&
      isSignedRoute(resolveInFrame(src), DEFAULT_IMG_PROXY_PATH))
  )
}

function isSignedRoute(url: URL | null, path: string): boolean {
  return (
    url !== null &&
    url.origin === FRAME_URL.origin &&
    url.pathname === path &&
    Boolean(url.searchParams.get("sig"))
  )
}

/** Resolves a URL the way the browser does inside the frame document. */
function resolveInFrame(value: string): URL | null {
  try {
    return new URL(value, FRAME_URL)
  } catch {
    return null
  }
}

function* descendants(node: Node): Generator<Node> {
  for (const child of "childNodes" in node ? node.childNodes : []) {
    yield child
    yield* descendants(child)
  }
}

/** A plain-data copy of a parse5 tree, comparable with deep equality. */
function snapshot(node: Node): unknown {
  return [
    node.nodeName,
    "namespaceURI" in node ? node.namespaceURI : null,
    "attrs" in node ? node.attrs.map(({ name, value }) => [name, value]) : [],
    "value" in node ? node.value : "data" in node ? node.data : null,
    "childNodes" in node ? node.childNodes.map(snapshot) : [],
  ]
}
