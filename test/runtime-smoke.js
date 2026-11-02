// Smoke test for the built package on runtimes the Vitest suite doesn't run
// on. Bun and Deno call `smoke()`; workerd loads this file as a Worker.
import { createTargetSigner, sanitizeInboundHtml } from "../dist/index.js"

export async function smoke() {
  // Signing exercises Web Crypto (HKDF, HMAC) on the runtime under test.
  const sign = await createTargetSigner("smoke-test-secret")
  const { html } = await sanitizeInboundHtml({
    html: '<p onclick="x()">hi <a href="https://example.com/">link</a></p><script>bad()</script>',
    messageId: "m",
    buildRedirectLinkUrl: async ({ url }) =>
      `/r?sig=${await sign({ purpose: "redirect", messageId: "m", target: url, context: "" })}`,
  })

  if (html.includes("<script") || html.includes("onclick")) {
    throw new Error(`script or event handler kept: ${html}`)
  }
  if (!/href="\/r\?sig=[\w-]+"/.test(html)) {
    throw new Error(`link not rewritten: ${html}`)
  }

  return html
}

export default {
  async fetch() {
    return new Response(await smoke())
  },
}
