# Security Policy

Tracexy captures network traffic and installs a privileged helper to do it. Both are worth
attacking, so security reports are taken seriously.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous release | Security fixes only |
| Older releases | No |

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Use [GitHub Security Advisories](https://github.com/RockxyApp/Tracexy/security/advisories) — go to
the Security tab and click "Report a vulnerability."

Include:

- What the vulnerability is, and roughly how bad you think it is
- Steps to reproduce, or a proof of concept
- Which versions you tested
- Anything you already know about mitigations

Please give us a reasonable window to ship a fix before disclosing publicly. We'll keep you posted
on progress and credit you in the release notes unless you'd rather we didn't.

## Areas worth your attention

If you are looking for somewhere to start:

- **The privileged helper** (`TracexyCaptureHelper/`) and the XPC surface between it and the app.
  Both sides validate the other's code signature; holes in that validation are the highest-value
  finding in this codebase.
- **Packet decoding** (`Tracexy/Core/Protocol/`). Every byte read there comes from a hostile source.
  A crafted frame or capture file that causes a crash, an out-of-bounds read, or unbounded
  allocation is a real bug — `PacketBuffer` is supposed to make that impossible.
- **Capture file parsing** (`Tracexy/Core/Capture/`). Same reasoning: a `.pcap` handed to you by
  someone else is untrusted input.

## Out of scope

- Requiring an admin password to install the privileged helper. That is the design.
- The app being able to see network traffic on the machine it is running on. That is the product.
