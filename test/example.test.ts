import { describe, expect, it } from "vitest"

import { createHandler } from "../examples/fetch-handler.js"

const messages: Record<string, string> = {
  honest:
    '<p>Docs: <a href="https://example.com/docs">example.com/docs</a></p>',
  phish:
    '<p onclick="steal()">Your account is locked.</p>' +
    '<a href="https://evil.example/login">https://mybank.com/login</a>',
}

const handle = createHandler({
  secret: "test-secret-with-enough-entropy",
  loadMessageHtml: async (id) => messages[id] ?? null,
  alwaysWarnDomains: "acme.example",
})

async function bodyOf(id: string) {
  return handle(new Request(`https://app.example/messages/${id}/body`))
}

async function follow(response: Response) {
  const href = /href="([^"]+)"/.exec(await response.text())?.[1] ?? ""

  return handle(new Request(new URL(href, "https://app.example")))
}

describe("examples/fetch-handler", () => {
  it("serves sanitized bodies with the frame CSP", async () => {
    const response = await bodyOf("phish")
    const html = await response.clone().text()

    expect(response.headers.get("content-security-policy")).toContain(
      "script-src 'none'"
    )
    expect(html).not.toContain("onclick")
    expect(html).toContain("/api/redirect?to=")
  })

  it("redirects honest links", async () => {
    const response = await follow(await bodyOf("honest"))

    expect(response.status).toBe(302)
    expect(response.headers.get("location")).toBe("https://example.com/docs")
  })

  it("warns on spoofed links", async () => {
    const response = await follow(await bodyOf("phish"))

    expect(await response.json()).toEqual({
      destination: "https://evil.example/login",
      claimed: "https://mybank.com/login",
      reasons: ["text_host_mismatch"],
    })
  })

  it("rejects forged redirect links", async () => {
    const response = await handle(
      new Request(
        "https://app.example/api/redirect?to=https%3A%2F%2Fevil.example&messageId=honest&sig=00"
      )
    )

    expect(response.status).toBe(403)
  })

  it("404s unknown messages", async () => {
    expect((await bodyOf("missing")).status).toBe(404)
  })
})
