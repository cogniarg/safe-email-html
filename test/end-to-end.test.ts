import { describe, expect, it } from "vitest"

import {
  boundDisplayedLinkText,
  buildRedirectUrl,
  createTargetSigner,
  evaluateRedirectTarget,
  parseDomainList,
  sanitizeInboundHtml,
  verifyTargetSignature,
} from "../src/index.js"

const SECRET = "test-secret-with-enough-entropy"
const MESSAGE_ID = "msg_42"

/** Renders a body the way the README recommends: every link signed. */
async function render(html: string) {
  const sign = await createTargetSigner(SECRET)

  return sanitizeInboundHtml({
    html,
    messageId: MESSAGE_ID,
    buildRedirectLinkUrl: async ({ url, displayedText }) => {
      const signature = await sign({
        purpose: "redirect",
        messageId: MESSAGE_ID,
        target: url,
        context: boundDisplayedLinkText(displayedText, url),
      })

      return `${buildRedirectUrl({ to: url, messageId: MESSAGE_ID, displayedText })}&sig=${signature}`
    },
  })
}

/** What a redirect endpoint does with a click on a rewritten link. */
async function click(href: string) {
  const params = new URL(href.replaceAll("&amp;", "&"), "https://app.example")
    .searchParams
  const to = params.get("to") ?? ""
  const displayedText = params.get("text")
  const valid = await verifyTargetSignature({
    purpose: "redirect",
    messageId: params.get("messageId") ?? "",
    target: to,
    context: displayedText ?? "",
    secret: SECRET,
    signature: params.get("sig"),
  })

  return valid
    ? evaluateRedirectTarget({
        to,
        displayedText,
        alwaysWarnDomains: parseDomainList("mybank.com"),
      })
    : ("forged" as const)
}

function firstHref(html: string): string {
  const href = /href="([^"]+)"/.exec(html)?.[1]

  if (!href) {
    throw new Error("no link in rendered html")
  }

  return href
}

describe("sanitize, sign, click", () => {
  it("lets an honest link straight through", async () => {
    const { html } = await render(
      '<a href="https://example.com/docs">example.com/docs</a>'
    )

    expect(await click(firstHref(html))).toMatchObject({ kind: "allow" })
  })

  it("warns on a link whose label claims another host", async () => {
    const { html } = await render(
      '<a href="https://evil.example/login">https://mybank.com/login</a>'
    )

    expect(await click(firstHref(html))).toMatchObject({
      kind: "warn",
      reasons: ["text_host_mismatch"],
    })
  })

  it("detects a label swapped after signing", async () => {
    const { html } = await render(
      '<a href="https://evil.example/login">https://mybank.com/login</a>'
    )
    // An attacker who strips the label to suppress the warning breaks the
    // signature, because the label is bound into it.
    const tampered = firstHref(html).replace(/&(?:amp;)?text=[^&]*/, "")

    expect(tampered).not.toBe(firstHref(html))
    expect(await click(tampered)).toBe("forged")
  })

  it("refuses a destination swapped after signing", async () => {
    const { html } = await render(
      '<a href="https://example.com/docs">example.com/docs</a>'
    )
    const tampered = firstHref(html).replace(
      encodeURIComponent("https://example.com/docs"),
      encodeURIComponent("https://evil.example/docs")
    )

    expect(tampered).not.toBe(firstHref(html))
    expect(await click(tampered)).toBe("forged")
  })
})
