import { describe, expect, it } from "vitest"

import {
  boundDisplayedLinkText,
  buildMessageFrameCsp,
  buildMessageFrameCspReportOnly,
  buildRedirectUrl,
  evaluateRedirectTarget,
  hostMatchesAnyDomain,
  isExecutableAttachment,
  isRemoteUrl,
  MAX_DISPLAYED_LINK_TEXT_CHARS,
  parseDomainList,
} from "../src/url-policy.js"

describe("isRemoteUrl", () => {
  it("matches full, scheme-relative, and slashless remote URLs", () => {
    expect(isRemoteUrl("https://example.com/x")).toBe(true)
    expect(isRemoteUrl("HTTP://example.com")).toBe(true)
    expect(isRemoteUrl("//example.com/x")).toBe(true)
    expect(isRemoteUrl("http:example.com/x")).toBe(true)
    expect(isRemoteUrl(" https:example.com ")).toBe(true)
  })

  it("does not match local or non-http(s) URLs", () => {
    expect(isRemoteUrl("/api/redirect?to=x")).toBe(false)
    expect(isRemoteUrl("mailto:jane@acme.example")).toBe(false)
    expect(isRemoteUrl("data:image/gif;base64,R0lGOD")).toBe(false)
    expect(isRemoteUrl("relative/path.png")).toBe(false)
  })

  it("sees through the characters a URL parser strips before parsing", () => {
    const soh = String.fromCharCode(0x01)
    const unitSeparator = String.fromCharCode(0x1f)
    const tab = String.fromCharCode(0x09)

    expect(isRemoteUrl(`${soh}https://evil.example/login`)).toBe(true)
    expect(isRemoteUrl(`${unitSeparator}//evil.example/x`)).toBe(true)
    expect(isRemoteUrl(`ht${tab}tps://evil.example/x`)).toBe(true)
  })
})

describe("evaluateRedirectTarget", () => {
  it("refuses non-http(s) and unparsable destinations", () => {
    expect(evaluateRedirectTarget("javascript:alert(1)")).toEqual({
      kind: "refused",
      reason: "unsupported_scheme",
    })
    expect(evaluateRedirectTarget("ftp://example.com/file")).toEqual({
      kind: "refused",
      reason: "unsupported_scheme",
    })
    expect(evaluateRedirectTarget("not a url")).toEqual({
      kind: "refused",
      reason: "invalid_url",
    })
  })

  it("confirms every http(s) destination with its canonical URL", () => {
    for (const [to, host] of [
      ["https://example.com/docs", "example.com"],
      ["http://EXAMPLE.com:8080/x", "example.com:8080"],
      ["https://bank.com@evil.example/login", "evil.example"],
      ["https://раураl.com/login", "xn--l-7sba6dbr.com"],
    ] as const) {
      const decision = evaluateRedirectTarget(to)

      expect(decision.kind).toBe("confirm")
      expect(decision.kind === "confirm" && decision.destination.host).toBe(
        host
      )
    }
  })
})

describe("hostMatchesAnyDomain", () => {
  it("treats trailing-dot hosts as their canonical host", () => {
    const blocked = parseDomainList("acme.example")

    expect(hostMatchesAnyDomain("intranet.acme.example.", blocked)).toBe(true)
    expect(hostMatchesAnyDomain("acme.example.evil.test", blocked)).toBe(false)
  })
})

describe("buildRedirectUrl", () => {
  it("bounds the forwarded displayed text", () => {
    const url = buildRedirectUrl({
      to: "https://example.com",
      messageId: "msg_1",
      displayedText: "x".repeat(MAX_DISPLAYED_LINK_TEXT_CHARS + 500),
    })
    const text = new URL(url, "https://mail.acme.example").searchParams.get(
      "text"
    )

    expect(text).toHaveLength(MAX_DISPLAYED_LINK_TEXT_CHARS)
  })

  it("honors a custom interstitial path", () => {
    expect(
      buildRedirectUrl({
        to: "https://example.com",
        messageId: "msg_1",
        displayedText: "",
        path: "/r",
      })
    ).toBe("/r?to=https%3A%2F%2Fexample.com&messageId=msg_1")
  })
})

describe("boundDisplayedLinkText", () => {
  it("does not split a surrogate pair at the length bound", () => {
    // 199 ASCII chars then an emoji: the emoji's high surrogate lands at the
    // last kept index and its low surrogate falls past the cap, so a naive
    // slice would leave a lone high surrogate.
    const text = `${"a".repeat(MAX_DISPLAYED_LINK_TEXT_CHARS - 1)}\u{1f600}`
    const bounded = boundDisplayedLinkText(text)

    expect(bounded).toBe("a".repeat(MAX_DISPLAYED_LINK_TEXT_CHARS - 1))
    // A lone surrogate would be coerced to U+FFFD here, so a clean round-trip
    // proves the signed text and the serialized `text` param stay identical.
    expect(new URLSearchParams({ text: bounded }).get("text")).toBe(bounded)
  })
})

describe("parseDomainList", () => {
  it("normalizes entries and drops blanks", () => {
    expect(
      parseDomainList(" Example.COM , *.acme.example ,, .bank.io ")
    ).toEqual(new Set(["example.com", "acme.example", "bank.io"]))
    expect(parseDomainList(undefined)).toEqual(new Set())
  })
})

describe("isExecutableAttachment", () => {
  it("flags executable MIME types", () => {
    expect(
      isExecutableAttachment({
        contentType: "application/x-msdownload",
        filename: "invoice.pdf",
      })
    ).toBe(true)
  })

  it("flags executable filename extensions even when mislabeled", () => {
    expect(
      isExecutableAttachment({
        contentType: "application/octet-stream",
        filename: "totally-a-document.EXE",
      })
    ).toBe(true)
    expect(
      isExecutableAttachment({
        contentType: "application/octet-stream; name=x",
        filename: "run.ps1",
      })
    ).toBe(true)
  })

  it("flags executables hiding behind trailing dots", () => {
    expect(
      isExecutableAttachment({
        contentType: "application/octet-stream",
        filename: "invoice.exe.",
      })
    ).toBe(true)
  })

  it("does not flag ordinary documents", () => {
    expect(
      isExecutableAttachment({
        contentType: "application/pdf",
        filename: "invoice.pdf",
      })
    ).toBe(false)
    expect(isExecutableAttachment({ contentType: null, filename: null })).toBe(
      false
    )
  })
})

describe("message frame CSP", () => {
  it("forbids scripts and network access", () => {
    const csp = buildMessageFrameCsp()

    expect(csp).toContain("script-src 'none'")
    expect(csp).toContain("connect-src 'none'")
    expect(csp).toContain("default-src 'none'")
    // No data: — a sender-supplied data: SVG could paint a spoofed link
    // label that never entered the signed redirect text.
    expect(csp).toContain("img-src 'self';")
    expect(csp).toContain("style-src 'unsafe-inline'")
    expect(csp).toContain("base-uri 'none'")
  })

  it("sandboxes every load of the body with the iframe's own flags", () => {
    // Without the directive, opening the body route as a top-level page
    // runs it on the app's origin with no sandbox. The keywords match the
    // documented iframe attribute, and an embedded frame gets the union of
    // both flag sets, so a correctly embedded frame is unchanged.
    expect(buildMessageFrameCsp().split("; ")).toContain(
      "sandbox allow-popups allow-popups-to-escape-sandbox"
    )
  })

  it("leaves sandbox out of the report-only variant, which ignores it", () => {
    // CSP3 ignores `sandbox` in a Report-Only header. Every other directive
    // stays identical to the enforced policy.
    const enforced = buildMessageFrameCsp().split("; ")
    const reportOnly = buildMessageFrameCspReportOnly("/csp").split("; ")

    expect(reportOnly.some((d) => d.startsWith("sandbox"))).toBe(false)
    expect(reportOnly).toEqual([
      ...enforced.filter((d) => !d.startsWith("sandbox")),
      "report-uri /csp",
    ])
  })

  it("adds the report endpoint to the report-only variant", () => {
    expect(buildMessageFrameCspReportOnly()).toContain(
      "report-uri /api/csp-report"
    )
    expect(buildMessageFrameCspReportOnly("/csp")).toContain("report-uri /csp")
  })
})
