/**
 * A complete integration using only the Fetch API, so it runs unchanged on
 * Cloudflare Workers, Bun, Deno and Node.js 22+ (behind any router).
 *
 *   GET /messages/:id/body   the sanitized body, served into a sandboxed iframe
 *   GET /api/redirect        the signed link confirmation page
 *
 * Authorization and message storage are yours: `loadMessageHtml` stands in
 * for them. Check that the signed-in reader may read the message in BOTH
 * routes; a valid signature only proves this code emitted the URL.
 */
import {
  boundDisplayedLinkText,
  buildMessageFrameCsp,
  buildRedirectUrl,
  createTargetSigner,
  evaluateRedirectTarget,
  sanitizeInboundHtml,
  verifyTargetSignature,
} from "../src/index.js"

export interface Options {
  secret: string
  loadMessageHtml: (messageId: string) => Promise<string | null>
}

export function createHandler(options: Options) {
  async function renderBody(messageId: string): Promise<Response> {
    const html = await options.loadMessageHtml(messageId)

    if (html === null) {
      return new Response("Not found", { status: 404 })
    }

    const sign = await createTargetSigner(options.secret)
    const sanitized = await sanitizeInboundHtml({
      html,
      messageId,
      buildRedirectLinkUrl: async ({ url, displayedText }) => {
        const signature = await sign({
          purpose: "redirect",
          messageId,
          target: url,
          // Bind the exact label the URL carries, so the text the
          // confirmation page shows can't be stripped or swapped.
          context: boundDisplayedLinkText(displayedText),
        })

        return `${buildRedirectUrl({ to: url, messageId, displayedText })}&sig=${signature}`
      },
    })

    return new Response(
      `<!DOCTYPE html><meta charset="utf-8">${sanitized.html}`,
      {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": buildMessageFrameCsp(),
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
        },
      }
    )
  }

  async function redirect(url: URL): Promise<Response> {
    const to = url.searchParams.get("to") ?? ""
    const messageId = url.searchParams.get("messageId") ?? ""
    const displayedText = url.searchParams.get("text")
    const valid = await verifyTargetSignature({
      purpose: "redirect",
      messageId,
      target: to,
      context: displayedText ?? "",
      secret: options.secret,
      signature: url.searchParams.get("sig"),
    })

    if (!valid) {
      return new Response("Invalid link signature.", { status: 403 })
    }

    const decision = evaluateRedirectTarget(to)

    if (decision.kind === "refused") {
      return new Response("This link cannot be opened.", { status: 400 })
    }

    // Every link is confirmed, headed by the real host. The link text
    // includes CSS-hidden parts, so show it as information, never as what
    // the reader saw.
    const host = escapeHtml(decision.destination.host)
    const href = escapeHtml(decision.destination.href)
    const label = displayedText
      ? `<p>Link text in the email: <bdi>${escapeHtml(displayedText)}</bdi></p>`
      : ""

    return new Response(
      `<!DOCTYPE html><meta charset="utf-8"><h1>This link opens ${host}</h1>${label}<a rel="noopener noreferrer" href="${href}">Continue to ${host}</a>`,
      {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": "default-src 'none'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "cache-control": "private, no-store",
        },
      }
    )
  }

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url)
    const body = /^\/messages\/([^/]+)\/body$/.exec(url.pathname)

    if (body?.[1]) {
      return renderBody(decodeURIComponent(body[1]))
    }

    if (url.pathname === "/api/redirect") {
      return redirect(url)
    }

    return new Response("Not found", { status: 404 })
  }
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}
