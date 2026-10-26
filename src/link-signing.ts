/**
 * HMAC signing that binds rewritten URLs (image proxy, redirect
 * interstitial) to one message and one exact target. The sanitizer signs
 * the URLs it emits into a rendered body; the endpoints refuse anything
 * else, so neither can be driven as a general authenticated
 * fetcher/redirector with a caller-chosen target.
 *
 * The HMAC key is derived from your secret via HKDF, so every server
 * instance computes the same key with no storage and no generation race,
 * and the derived subkey never exposes the secret itself. Uses only Web
 * Crypto, so it runs unchanged on Node.js 20+, Bun, Deno and Cloudflare
 * Workers.
 */

export type TargetPurpose = "img-proxy" | "redirect"

export interface TargetSignatureInput {
  /**
   * Extra data bound into the signature beyond the target itself, e.g. the
   * displayed link text whose value the warning interstitial depends on.
   */
  context?: string
  purpose: TargetPurpose
  messageId: string
  target: string
}

const encoder = new TextEncoder()

/**
 * Derives the signing key once and returns a function that signs targets
 * with it. Prefer this over {@link signTarget} when signing every link in a
 * message, so the key derivation runs once per render.
 */
export async function createTargetSigner(
  secret: string
): Promise<(input: TargetSignatureInput) => Promise<string>> {
  const key = await deriveKey(secret)

  return async ({ context = "", messageId, purpose, target }) =>
    hmacHex(key, payload(purpose, messageId, target, context))
}

export async function signTarget({
  secret,
  ...input
}: TargetSignatureInput & { secret: string }): Promise<string> {
  const sign = await createTargetSigner(secret)

  return sign(input)
}

export async function verifyTargetSignature({
  signature,
  ...input
}: TargetSignatureInput & {
  secret: string
  signature: string | null
}): Promise<boolean> {
  if (!signature) {
    return false
  }

  return timingSafeEqualHex(await signTarget(input), signature)
}

function payload(
  purpose: TargetPurpose,
  messageId: string,
  target: string,
  context: string
): string {
  // Length-prefixing every field makes boundaries unambiguous no matter
  // what characters the fields contain, so distinct field tuples always
  // produce distinct payloads.
  return ["v1", purpose, messageId, target, context]
    .map((field) => `${field.length}:${field}`)
    .join("")
}

async function deriveKey(secret: string): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    "HKDF",
    false,
    ["deriveKey"]
  )

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode("safe-email-html/link-signing/v1"),
      info: encoder.encode("hmac-sha256"),
    },
    baseKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]
  )
}

async function hmacHex(key: CryptoKey, message: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(message)
  )

  return [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
}

function timingSafeEqualHex(expected: string, actual: string): boolean {
  if (expected.length !== actual.length) {
    return false
  }

  let mismatch = 0

  for (let index = 0; index < expected.length; index += 1) {
    mismatch |= expected.charCodeAt(index) ^ actual.charCodeAt(index)
  }

  return mismatch === 0
}
