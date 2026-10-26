import { describe, expect, it } from "vitest"

import {
  createTargetSigner,
  signTarget,
  verifyTargetSignature,
} from "../src/link-signing.js"

const SECRET = "test-secret-with-enough-entropy"

const input = {
  purpose: "redirect" as const,
  messageId: "msg_1",
  target: "https://example.com/path",
  context: "example.com/path",
}

describe("link signing", () => {
  it("produces a stable 256-bit hex signature", async () => {
    const first = await signTarget({ ...input, secret: SECRET })
    const second = await signTarget({ ...input, secret: SECRET })

    expect(first).toMatch(/^[0-9a-f]{64}$/)
    expect(second).toBe(first)
  })

  it("verifies its own signatures", async () => {
    const signature = await signTarget({ ...input, secret: SECRET })

    expect(
      await verifyTargetSignature({ ...input, secret: SECRET, signature })
    ).toBe(true)
  })

  it("rejects missing signatures", async () => {
    expect(
      await verifyTargetSignature({ ...input, secret: SECRET, signature: null })
    ).toBe(false)
  })

  it.each([
    ["purpose", { purpose: "img-proxy" as const }],
    ["message", { messageId: "msg_2" }],
    ["target", { target: "https://evil.example/path" }],
    ["context", { context: "mybank.com" }],
  ])("rejects a signature replayed with a different %s", async (_, change) => {
    const signature = await signTarget({ ...input, secret: SECRET })

    expect(
      await verifyTargetSignature({
        ...input,
        ...change,
        secret: SECRET,
        signature,
      })
    ).toBe(false)
  })

  it("rejects signatures made with another secret", async () => {
    const signature = await signTarget({ ...input, secret: "other-secret" })

    expect(
      await verifyTargetSignature({ ...input, secret: SECRET, signature })
    ).toBe(false)
  })

  it("keeps field boundaries unambiguous", async () => {
    // Without length-prefixing, moving characters between adjacent fields
    // would produce the same concatenated payload.
    const sign = await createTargetSigner(SECRET)
    const a = await sign({ ...input, messageId: "ab", target: "c" })
    const b = await sign({ ...input, messageId: "a", target: "bc" })

    expect(a).not.toBe(b)
  })
})
