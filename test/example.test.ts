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
    expect(response.headers.get("content-security-policy")).toContain(
      "sandbox allow-popups allow-popups-to-escape-sandbox"
    )
    expect(html).not.toContain("onclick")
    expect(html).toContain("/api/redirect?to=")
  })

  it("confirms every link, headed by the real host", async () => {
    const honest = await (await follow(await bodyOf("honest"))).text()
    const phish = await (await follow(await bodyOf("phish"))).text()

    expect(honest).toContain("<h1>This link opens example.com</h1>")
    expect(honest).toContain('href="https://example.com/docs"')
    expect(phish).toContain("<h1>This link opens evil.example</h1>")
    expect(phish).toContain("<bdi>https://mybank.com/login</bdi>")
  })

  it("escapes the link text on the confirmation page", async () => {
    messages.markup = '<a href="https://example.com">&lt;img src=x&gt;</a>'
    const page = await (await follow(await bodyOf("markup"))).text()

    expect(page).toContain("<bdi>&lt;img src=x&gt;</bdi>")
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
