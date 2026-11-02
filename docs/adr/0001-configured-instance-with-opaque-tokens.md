# Configured instance with opaque tokens, no unsigned mode

From 0.3.0 the public interface is one synchronous `createSafeEmail(config)` that returns `render`, `openLink`, `openImage` and `frameHeaders`. Every mediated URL carries a single opaque `?t=` token instead of readable query parameters, and the secret is required. In 0.2.x, callers signed and verified by hand: sign and verify had to agree on context rules that lived in the caller, the unsigned default URL builders were one omission away from production, and the image grant existed only as a doc comment. The instance keeps all of that behind one seam, and the token means callers can't verify one field and then act on another. See [Public interface for 0.3.0](https://github.com/cogniarg/safe-email-html/issues/13).

## Considered Options

- **Plain functions sharing a config value.** About as deep as the instance, with no construction step. We took its opaque token and kept the instance, so the config and the derived key are set once.
- **A fetch router with injected ports** (`(Request) => Response`). Deepest for the common case, but the library would own the link confirmation HTML and the image fetch policy, and refusing private addresses needs DNS that Workers can't do portably. It could ship as an example built on the instance, not as the core.
- **Positional link references, resolved by rendering again** (`?m=…&n=3`, no signature). Removes signing for links, but a link URL would depend on sanitizer output staying stable across releases, and images would still need a secret.

## Consequences

- An image proxy the app doesn't control (imgproxy, Camo) plugs in through `config.images.proxy`. It enforces only what its own signature covers, so the image grant's reader and expiry may not be enforced.
- `secret` can widen to `string | string[]` for key rotation without breaking callers.
