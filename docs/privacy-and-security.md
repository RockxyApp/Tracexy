# Privacy & security

Tracexy captures network traffic and installs a privileged helper to do it. Both deserve care, so this
page states plainly what the app does and does not do today.

## Privacy posture

- **Local-first.** Captured traffic stays on your Mac. Tracexy does not upload it to any server. The
  "Keep all data on this Mac" preference reflects this default posture.
- **Capture stays under user control.** By default, live capture begins when you press **Start**. If
  you explicitly enable **Settings → Capture → Auto-start capture on launch**, Tracexy starts capture
  after launch setup completes. The gate on capturing is the one-time operating-system approval of
  the privileged helper (System Settings → Login Items) — there is no separate per-capture consent
  dialog, and this documentation does not claim one.
- **Exports are sensitive — redact them yourself.** Exporting or sharing a capture writes the raw
  captured frame bytes. A `.pcap` is a recording of everything that crossed the wire, including things
  you may have forgotten were in it. Treat every export as sensitive and redact before sharing.

### Redaction preferences vs. enforcement

Settings → Privacy offers redaction and retention **preferences** — redact payload bodies, strip
credentials and tokens, mask IP addresses, auto-clear. These persist your choices, but the
end-to-end pipeline that would **enforce** them on export is **not implemented yet**. In other words:
turning on "redact bodies" records the intent, but today's export path does not yet act on it. Until
that lands, do your own redaction before sharing a capture, and don't rely on these toggles to sanitize
output.

## The privileged helper and trust boundary

Live capture runs in a separate, signed privileged binary (`TracexyCaptureHelper/`) that communicates
with the app over XPC. This boundary is the highest-value part of the codebase to get right.

- **Typed, narrow XPC surface.** The helper exposes only a small, typed protocol: report helper info,
  start capture on an interface, stop capture, and fetch buffered frames. It does not expose arbitrary
  command execution, shell, or file access. Frames are drained as typed `NSSecureCoding` objects
  (`FrameBatchMessage`/`CapturedFrameMessage`) with the secure-coding class allow-list configured on
  both endpoints; the app validates every field defensively and rejects malformed metadata rather than
  trusting it. This is protocol **v2** — an older v1 helper is classified incompatible and Start is
  gated with an update prompt, never silently downgraded to an untyped drain.
- **Bidirectional code-sign validation.** The helper validates every connecting caller (signing-team
  match with a certificate-chain fallback, plus a bundle-identity allowlist checked against the
  connection's audit token to resist PID races) before accepting it. Independently, the app validates
  the installed helper's signature before trusting it, so a signing mismatch surfaces as a diagnostic
  rather than being silently "fixed." That comparison targets the helper launchd actually executes — the
  binary embedded in the app bundle (`Contents/Library/HelperTools`) that SMAppService runs in place —
  not a legacy `/Library/PrivilegedHelperTools` artifact, which Tracexy never installs.
- **Bounded behavior.** The helper only captures and buffers frames. Its frame buffer is capped by a
  named bounded-buffer policy that counts every eviction, so a drop is reported (in the drain batch and,
  in the UI, as its own capture-stage figure — distinct from `pcap_stats` kernel/interface drops, and
  never folded into them) rather than hidden. Capture teardown is
  race-free: the caller requests stop and waits while the worker thread alone closes the pcap handle.
  The typed stop reply atomically returns the worker's final flush and final accounting, avoiding both
  silent tail loss and a stop→fetch race with the next capture generation.
  The helper stops capturing when the owning app disconnects — it does not run unbounded or unattended.

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Use GitHub Security Advisories on the
[Tracexy repository](https://github.com/RockxyApp/Tracexy/security/advisories), and see
[SECURITY.md](../SECURITY.md) for what to include and which areas — the helper/XPC surface, packet
decoding, and capture-file parsing — are most worth your attention.
