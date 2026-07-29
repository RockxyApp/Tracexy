# Tracexy documentation

Tracexy is a native macOS network intelligence app. It captures traffic passively and presents it as
**conversations** — DNS, TCP, TLS, HTTP — grouped into sessions and correlated into higher-level
actions, rather than a flat packet list.

This documentation describes what is actually in the source today, and clearly marks what is planned.

## Contents

| Doc | What it covers |
|---|---|
| [Getting started](getting-started.md) | Requirements, signing setup, build/test commands, capture vs. saved files |
| [Usage](usage.md) | Live capture, opening `.pcap`/`.pcapng`, sessions, correlation, focus sets, inspector |
| [Architecture](architecture.md) | The capture → protocol → session → UI pipeline, repository map, boundaries |
| [Protocol support](protocol-support.md) | The accurate, per-layer decode matrix and its limits |
| [Privacy & security](privacy-and-security.md) | Local-first posture, the privileged helper, and the trust boundary |

## Status at a glance

**Implemented:** live libpcap capture through a signed helper, PCAP read/write and PCAPNG read,
interface discovery, a bounds-checked packet decoder (L2–L4 plus DNS/TLS/HTTP-1/QUIC summaries),
five-tuple session grouping, action correlation with confidence levels, per-process attribution where
macOS reports it, and a native SwiftUI/AppKit interface with workspaces, filtering, focus sets, and an
inspector.

**Partial:** application-layer decode is naming-level only — DNS records, TLS handshake metadata, the
HTTP/1 request line, QUIC identification. Session building is a batch rebuild, not a stateful engine.

**Planned / not yet implemented:** a decoder registry with dispatch-table handoff, a stateful
connection table with TCP reassembly, an analysis/security engine, persistent SQLite storage, an
MCP/AI bridge, and an enforced export-redaction pipeline. Do not treat these as present.

When the source and these docs disagree, the source is correct — please open an issue or a fix.
