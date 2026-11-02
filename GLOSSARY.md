# safe-email-html

Rendering untrusted inbound email HTML so a reader can view it without the sender reaching the reader's session, network or attention unmediated.

## Language

**Message body**:
The sanitized HTML document rendered from one inbound message, served alone into a sandboxed frame.
_Avoid_: Sanitized output, email HTML

**Reader**:
The signed-in person viewing a message body.
_Avoid_: User, viewer, recipient

**Mediated URL**:
A URL the library rewrites into a message body so that following it passes through the app's server, which refuses any it did not emit.
_Avoid_: Signed URL, rewritten link

**Link confirmation**:
The page a reader sees after clicking a link in a message body, naming the real destination host before they continue.
_Avoid_: Interstitial, confirmation page, warning page

**Redirect**:
The route that serves the link confirmation for a mediated link URL.
_Avoid_: Using it for the confirmation page itself

**Image grant**:
The authorization carried by a mediated image URL: one reader, one message, one image, until an expiry.
_Avoid_: Image token, proxy signature
