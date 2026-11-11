# Fixed sandbox flags in the frame CSP

`buildMessageFrameCsp()` ends with `sandbox allow-popups allow-popups-to-escape-sandbox`, a fixed value the host cannot change. Before this, the message body was sandboxed only by the iframe's `sandbox` attribute, so opening the body route as a top-level page ran it on the app's origin with no sandbox ([research, gap 6](../research/frame-sandbox-csp.md#gaps-in-layer-3)). The flags are the ones the README already tells integrators to put on the iframe, so the library owns that contract and the directive restates it. Inside the iframe, the document's sandboxing flags are the union of the iframe's flags and the CSP's (HTML, "beginning navigation": *finalSandboxFlags*), so identical keywords change nothing for a correctly embedded frame, and an iframe with extra allowances such as `allow-scripts` is still held to these. See [#33](https://github.com/cogniarg/safe-email-html/issues/33).

`buildMessageFrameCspReportOnly()` leaves the directive out, because CSP3 ignores `sandbox` in a `Content-Security-Policy-Report-Only` header. Its other directives stay identical to the enforced policy.

## Considered Options

- **Flags passed in by the host.** The host owns the iframe attribute, so it could pass the matching keywords. Nobody has asked for different flags, a parameter would let a host weaken the body's sandbox by mistake, and a host that wants different flags can still edit the header string.
- **No directive, document the risk.** Leaves the body unsandboxed whenever it is loaded outside the frame, which the library cannot prevent.

## Consequences

- A host that relies on extra iframe allowances in the body document (for example `allow-same-origin`) loses them. That configuration was already unsupported by the threat model.
- A body opened as a top-level page now has an opaque origin, so its same-origin image requests carry no `SameSite=Lax` cookie, as they already didn't inside the frame.
