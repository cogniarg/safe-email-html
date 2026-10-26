/**
 * A complete integration using only the Fetch API, so it runs unchanged on
 * Cloudflare Workers, Bun, Deno and Node.js 20+ (behind any router).
 *
 *   GET /messages/:id/body   the sanitized body, served into a sandboxed iframe
 *   GET /api/redirect        the signed link interstitial
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
  parseDomainList,
  sanitizeInboundHtml,
  verifyTargetSignature,
} from "../src/index.js"

export interface Options {
  secret: string
  loadMessageHtml: (messageId: string) => Promise<string | null>
  /** Destinations that always get a warning, e.g. "mybank.com, acme.example" */
  alwaysWarnDomains?: string
}

export function createHandler(options: Options) {
  const alwaysWarnDomains = parseDomainList(options.alwaysWarnDomains)

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
          // Bind the exact label the URL carries, so the warning decision
          // can't be changed by stripping or swapping it.
          context: boundDisplayedLinkText(displayedText, url),
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

    const decision = evaluateRedirectTarget({
      to,
      displayedText,
      alwaysWarnDomains,
    })

    switch (decision.kind) {
      case "refused":
        return new Response("This link cannot be opened.", { status: 400 })
      case "allow":
        return Response.redirect(decision.destination.href, 302)
      case "warn":
        // Render your own interstitial: show the claimed label next to the
        // real destination and let the reader decide.
        return new Response(
          JSON.stringify({
            destination: decision.destination.href,
            claimed: displayedText,
            reasons: decision.reasons,
          }),
          { headers: { "content-type": "application/json" } }
        )
    }
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
