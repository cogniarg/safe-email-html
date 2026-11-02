import { describe, expect, it } from "vitest"

import * as entryPoint from "../src/index.js"
import { checkSanitizedHtml } from "./parser-differential.js"

const SIGNED_HREF =
  "/api/redirect?to=https%3A%2F%2Fexample.com%2F&amp;messageId=m&amp;sig=abc"

describe("checkSanitizedHtml", () => {
  it("accepts a signed link, a styled block and a blanked image", () => {
    expect(() =>
      checkSanitizedHtml(
        `<p style="color: red; margin: 0">` +
          `<a href="${SIGNED_HREF}" target="_blank" rel="noopener noreferrer">docs</a>` +
          '<a href="mailto:jane@acme.example">mail</a>' +
          '<img data-original-src="https://cdn.example/x.png" src="about:blank">' +
          "</p>",
        "blocked"
      )
    ).not.toThrow()
  })

  it("accepts proxied images only when remote images are proxied", () => {
    const proxied =
      '<img src="/api/img-proxy?url=https%3A%2F%2Fcdn.example%2Fx&amp;sig=abc">'

    expect(() => checkSanitizedHtml(proxied, "proxied")).not.toThrow()
    expect(() => checkSanitizedHtml(proxied, "blocked")).toThrow(
      /- <img src=.*> is not allowed for blocked images/
    )
  })

  it.each([
    [
      "a raw onclick",
      '<p onclick="alert(1)">x</p>',
      "<p onclick> is an event handler",
    ],
    [
      "an unsigned href",
      '<a href="/api/redirect?to=https%3A%2F%2Fevil.example">x</a>',
      '<a href="/api/redirect?to=https%3A%2F%2Fevil.example"> is not a signed redirect',
    ],
    [
      "a direct remote href",
      '<a href="https://evil.example">x</a>',
      '<a href="https://evil.example"> is not a signed redirect',
    ],
    [
      "a forbidden element",
      "<form><p>x</p></form>",
      "<form> is not allowlisted",
    ],
    [
      "a non-allowlisted style property",
      '<p style="color: red; position: fixed">x</p>',
      "<p style> sets position",
    ],
    ["a comment", "<p>x</p><!-- y -->", "#comment is not allowlisted"],
    [
      "attributes a document parse merges onto <body>",
      '<p>x</p><body onload="alert(1)">',
      "<body onload> reaches the document element",
    ],
    [
      "foreign content",
      "<p><svg><a>x</a></svg></p>",
      "<svg> is in the http://www.w3.org/2000/svg namespace",
    ],
    [
      "a tree that changes when reparsed",
      "<a><table><a>x</a></table></a>",
      "the tree changes when reparsed",
    ],
  ])("rejects %s", (_, html, violation) => {
    // Match the violation line, not the output echoed after it.
    expect(() => checkSanitizedHtml(html, "blocked")).toThrow(`- ${violation}`)
  })

  it("ignores a style declaration without a colon, as CSS does", () => {
    expect(() =>
      checkSanitizedHtml('<p style="color: red; foo">x</p>', "blocked")
    ).not.toThrow()
  })

  it("reads allowlists the package entry point does not export", () => {
    expect(
      Object.keys(entryPoint).filter((name) => name.startsWith("ALLOWED_"))
    ).toEqual([])
  })
})
