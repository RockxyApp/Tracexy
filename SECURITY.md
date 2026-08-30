# Security Policy

Tracexy captures network traffic and installs a privileged helper to do it.
Both are worth attacking, so security reports are taken seriously.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous release | Security fixes only |
| Older releases | No |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Use [GitHub Security Advisories](https://github.com/RockxyApp/Tracexy/security/advisories):
go to the Security tab and click "Report a vulnerability."

Include:

- a clear vulnerability description;
- impact and affected trust boundary;
- steps to reproduce or a proof of concept;
- affected Tracexy version, commit, macOS version, and hardware architecture if
  relevant;
- whether live capture, saved capture parsing, helper installation, export, or
  update handling is involved;
- crash logs, sanitized diagnostics, or minimal fixtures when safe to share;
- mitigation ideas, if you have them; and
- whether you want public credit.

Please give us a reasonable window to ship a fix before disclosing publicly.
We will keep you posted on progress and credit you in release notes unless you
prefer to remain anonymous.

## What to Expect

- Acknowledgment after maintainers receive the report.
- Initial severity assessment after reproduction or source review.
- A coordinated fix plan for valid issues.
- Credit in the advisory or release notes when requested and safe.

## In Scope

If you are looking for somewhere to start:

- **The privileged helper** (`TracexyCaptureHelper/`) and the XPC surface between it and the app.
  Both sides validate the other's code signature; holes in that validation are the highest-value
  finding in this codebase.
- **Packet decoding** (`Tracexy/Core/Protocol/`). Every byte read there comes from a hostile source.
  A crafted frame or capture file that causes a crash, an out-of-bounds read, or unbounded
  allocation is a real bug — `PacketBuffer` is supposed to make that impossible.
- **Capture file parsing** (`Tracexy/Core/Capture/`). Same reasoning: a `.pcap` handed to you by
  someone else is untrusted input.
- **Live capture spooling and locators.** Payload locators must remain
  reset-scoped, bounded, identity-checked, and unavailable for active-live
  growing-spool Follow Stream reads.
- **Export and privacy controls.** Protected `.tracexysession` export must omit
  raw frames and sensitive decoded metadata according to Privacy settings. Raw
  pcap/pcapng export must remain explicit and evidence-preserving.
- **History and automation.** Stored history and read-only automation exports
  must stay bounded and must not add raw packet payloads, executable targets,
  listeners, providers, or external data paths.
- **Update and signing behavior.** Signed update checks must stay separate from
  capture data, and helper/app signature mismatches must fail closed.

## Out of Scope

- Requiring an admin password to install the privileged helper. That is the design.
- The app being able to see network traffic on the machine it is running on. That is the product.
- Reports that only show that raw pcap/pcapng exports contain sensitive traffic;
  that is the nature of raw capture formats.
- Denial-of-service testing against third-party systems.
- Social engineering, phishing, or physical attacks against users or
  maintainers.
- Vulnerabilities in third-party dependencies by themselves. Report them
  upstream and notify Tracexy maintainers so the dependency fix can be tracked.

## Research Rules

Good-faith testing is welcome. Please:

- test only systems, captures, and accounts you are authorized to use;
- keep proof-of-concept captures minimal and sanitized;
- do not access, modify, or publish another person's data;
- do not persist credentials, private keys, or real packet captures in a public
  issue or pull request; and
- stop testing and report promptly if you discover a path to privilege
  escalation, arbitrary command execution, data exfiltration, or persistent
  compromise.

## Security Architecture

The main security model is documented in
[Privacy & security](docs/privacy-and-security.md). The highest-value
boundaries are:

- **App to helper:** a narrow XPC protocol with code-signing validation on both
  sides.
- **Untrusted bytes:** bounds-checked packet and capture-file parsing.
- **Local-first data:** captures, sessions, and history stay local unless the
  user explicitly exports them.
- **No hidden analysis transport:** the current automation core is read-only and
  transport-neutral; there is no MCP server, listener, provider, or AI data
  path in the public app today.

## Disclosure Policy

We follow coordinated disclosure. Maintainers will not pursue legal action
against researchers acting in good faith under this policy. Public disclosure
before a fix may put users at risk, especially for helper, parser, or export
issues.
