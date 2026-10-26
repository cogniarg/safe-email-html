import { describe, expect, it } from "vitest"

import {
  boundDisplayedLinkText,
  buildMessageFrameCsp,
  buildMessageFrameCspReportOnly,
  buildRedirectUrl,
  evaluateRedirectTarget,
  extractDisplayedHosts,
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
  const noWarnList = new Set<string>()

  it("refuses non-http(s) destinations", () => {
    expect(
      evaluateRedirectTarget({
        to: "javascript:alert(1)",
        displayedText: null,
        alwaysWarnDomains: noWarnList,
      })
    ).toEqual({ kind: "refused", reason: "unsupported_scheme" })
    expect(
      evaluateRedirectTarget({
        to: "not a url",
        displayedText: null,
        alwaysWarnDomains: noWarnList,
      })
    ).toEqual({ kind: "refused", reason: "invalid_url" })
  })

  it("allows plain links whose text is not URL-shaped", () => {
    const decision = evaluateRedirectTarget({
      to: "https://example.com/docs",
      displayedText: "read the docs",
      alwaysWarnDomains: noWarnList,
    })

    expect(decision.kind).toBe("allow")
  })

  it("warns when displayed text claims a different host", () => {
    const decision = evaluateRedirectTarget({
      to: "https://evil.example/login",
      displayedText: "https://mybank.com",
      alwaysWarnDomains: noWarnList,
    })

    expect(decision).toMatchObject({
      kind: "warn",
      reasons: ["text_host_mismatch"],
    })
  })

  it("warns when the displayed host is followed directly by a query or fragment", () => {
    for (const displayedText of [
      "https://mybank.com?reset",
      "https://mybank.com#login",
    ]) {
      expect(
        evaluateRedirectTarget({
          to: "https://evil.example/login",
          displayedText,
          alwaysWarnDomains: noWarnList,
        })
      ).toMatchObject({ kind: "warn", reasons: ["text_host_mismatch"] })
    }
  })

  it("warns when the displayed host is wrapped in ordinary punctuation", () => {
    for (const displayedText of [
      "(https://mybank.com)",
      "go to https://mybank.com, then log in",
      "https://mybank.com...",
    ]) {
      expect(
        evaluateRedirectTarget({
          to: "https://evil.example/login",
          displayedText,
          alwaysWarnDomains: noWarnList,
        })
      ).toMatchObject({ kind: "warn", reasons: ["text_host_mismatch"] })
    }
  })

  it("warns when the displayed label is a subdomain of the destination", () => {
    expect(
      evaluateRedirectTarget({
        to: "https://evil.example.com/login",
        displayedText: "https://mybank.com.evil.example.com/login",
        alwaysWarnDomains: noWarnList,
      })
    ).toMatchObject({ kind: "warn", reasons: ["text_host_mismatch"] })
  })

  it("treats www and the apex as the same displayed host", () => {
    expect(
      evaluateRedirectTarget({
        to: "https://example.com/path",
        displayedText: "https://www.example.com/path",
        alwaysWarnDomains: noWarnList,
      }).kind
    ).toBe("allow")
  })

  it("does not warn when displayed text matches the destination host", () => {
    const decision = evaluateRedirectTarget({
      to: "https://www.example.com/path",
      displayedText: "example.com/path",
      alwaysWarnDomains: noWarnList,
    })

    expect(decision.kind).toBe("allow")
  })

  it("warns for destinations on the always-warn list, including subdomains", () => {
    const alwaysWarnDomains = parseDomainList("acme.example, mybank.com")

    expect(
      evaluateRedirectTarget({
        to: "https://intranet.acme.example/reset",
        displayedText: "intranet.acme.example/reset",
        alwaysWarnDomains,
      })
    ).toMatchObject({ kind: "warn", reasons: ["always_warn_domain"] })
  })

  it("stacks warning reasons", () => {
    const decision = evaluateRedirectTarget({
      to: "https://evil.example/",
      displayedText: "https://mybank.com",
      alwaysWarnDomains: parseDomainList("evil.example"),
    })

    expect(decision).toMatchObject({
      kind: "warn",
      reasons: ["text_host_mismatch", "always_warn_domain"],
    })
  })

  it("warns when a hidden host precedes a mismatching visible host", () => {
    // anchor.textContent for
    // <a href="https://evil.example">
    //   <span style="display:none">evil.example </span>https://mybank.com
    // </a>: the hidden host matches the destination, but the label the user
    // reads (mybank.com) does not, so the warning must still fire.
    const decision = evaluateRedirectTarget({
      to: "https://evil.example/",
      displayedText: "evil.example https://mybank.com",
      alwaysWarnDomains: noWarnList,
    })

    expect(decision).toMatchObject({
      kind: "warn",
      reasons: ["text_host_mismatch"],
    })
  })

  it("warns when displayed text uses userinfo to spoof the host", () => {
    const decision = evaluateRedirectTarget({
      to: "https://evil.example/login",
      displayedText: "https://mybank.com@evil.example/login",
      alwaysWarnDomains: noWarnList,
    })

    expect(decision).toMatchObject({
      kind: "warn",
      reasons: ["text_host_mismatch"],
    })
  })

  it("warns when displayed text claims a Unicode hostname", () => {
    const decision = evaluateRedirectTarget({
      to: "https://evil.example/login",
      displayedText: "https://раураl.com/login",
      alwaysWarnDomains: noWarnList,
    })

    expect(decision).toMatchObject({
      kind: "warn",
      reasons: ["text_host_mismatch"],
    })
  })
})

describe("host canonicalization", () => {
  it("treats trailing-dot destinations as their canonical host", () => {
    expect(
      evaluateRedirectTarget({
        to: "https://intranet.acme.example./reset",
        displayedText: null,
        alwaysWarnDomains: parseDomainList("acme.example"),
      })
    ).toMatchObject({ kind: "warn", reasons: ["always_warn_domain"] })
  })

  it("does not flag matching displayed text with a trailing dot", () => {
    expect(
      evaluateRedirectTarget({
        to: "https://example.com/path",
        displayedText: "example.com./path",
        alwaysWarnDomains: new Set(),
      }).kind
    ).toBe("allow")
  })

  it("still warns when trailing-dot displayed text claims another host", () => {
    expect(
      evaluateRedirectTarget({
        to: "https://evil.example/login",
        displayedText: "https://mybank.com./login",
        alwaysWarnDomains: new Set(),
      })
    ).toMatchObject({ kind: "warn", reasons: ["text_host_mismatch"] })
  })
})

describe("extractDisplayedHosts", () => {
  it("extracts hosts from URL-shaped and bare-domain text", () => {
    expect(extractDisplayedHosts("https://mybank.com/login")).toEqual([
      "mybank.com",
    ])
    expect(extractDisplayedHosts("visit mybank.com now")).toEqual([
      "mybank.com",
    ])
    expect(extractDisplayedHosts("click here")).toEqual([])
    expect(extractDisplayedHosts(null)).toEqual([])
  })

  it("returns every host claimed in the text, in order", () => {
    expect(
      extractDisplayedHosts("trusted.example@evil.example or mybank.com")
    ).toEqual(["trusted.example", "evil.example", "mybank.com"])
  })

  it("normalizes Unicode host labels through IDNA", () => {
    expect(extractDisplayedHosts("https://раураl.com/login")).toEqual([
      "xn--l-7sba6dbr.com",
    ])
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

  it("re-appends hosts the length cap would hide from the mismatch check", () => {
    const text = `${"hidden padding ".repeat(20)}https://mybank.com/reset`
    const bounded = boundDisplayedLinkText(text)

    expect(text.indexOf("mybank.com")).toBeGreaterThan(
      MAX_DISPLAYED_LINK_TEXT_CHARS
    )
    expect(bounded).toContain("mybank.com")
  })

  it("preserves mismatching hosts ahead of destination-matching decoys", () => {
    // Five parent-domain decoys all look like the deep destination, so a
    // count-based cap alone would drop the one spoofed host.
    const decoys = [
      "b.c.d.e.evil.example",
      "c.d.e.evil.example",
      "d.e.evil.example",
      "e.evil.example",
      "evil.example",
    ].join(" ")
    const text = `${"x".repeat(220)} ${decoys} https://mybank.com`
    const bounded = boundDisplayedLinkText(
      text,
      "https://a.b.c.d.e.evil.example/login"
    )

    expect(bounded).toContain("mybank.com")
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

  it("adds the report endpoint to the report-only variant", () => {
    expect(buildMessageFrameCspReportOnly()).toContain(
      "report-uri /api/csp-report"
    )
    expect(buildMessageFrameCspReportOnly("/csp")).toContain("report-uri /csp")
  })
})
