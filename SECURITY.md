# Security policy

`safe-email-html` exists to stop attacks, so a bypass is the most important
kind of bug it can have.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead:
on this repository, go to **Security → Report a vulnerability**. Only you and
the maintainers can see the report.

Please include:

- the input HTML (or the smallest version that still reproduces it),
- what you expected the output to be, and what it actually was,
- the runtime and version (for example Node.js 22 or Cloudflare Workers).

You'll get an acknowledgement within 3 business days. Confirmed issues are
fixed in a patch release with credit to the reporter, unless you'd rather
stay anonymous.

## Scope

In scope: anything that gets script execution, a network request, or a
spoofed link past the defenses described in
[docs/threat-model.md](docs/threat-model.md), when the library is integrated
as that document describes.

Out of scope: problems that need the integrator to skip a step the threat
model lists as their responsibility, such as serving the output outside the
sandboxed iframe or not verifying signatures.
