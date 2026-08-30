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
| [Competitor comparison](comparison.md) | Source-backed comparison with packet-analysis alternatives |

## Status at a glance

**Implemented:** live libpcap capture through a signed helper, PCAP/PCAPNG read/write and disk-backed
live-save, interface discovery, a bounds-checked packet decoder, incremental five-tuple sessions, a
bounded TCP connection/evidence table, selected evidence-linked findings, deterministic replay,
protected session export, terminal-summary SQLite History, and a native SwiftUI/AppKit investigation
workspace with typed queries and explicit bounded Follow Stream.

**Partial:** application-layer decode remains metadata-focused — DNS records, TLS handshake and record
metadata, HTTP/1 request-line and Host header recognition, QUIC long-header metadata, and STUN
attributes. TCP prefix recovery is bounded to initial TLS/HTTP/DNS metadata; the connection table
does not provide a general always-on stream/record analyzer.
Protected `.tracexysession` export enforces the Privacy settings by omitting raw frames and sensitive
decoded metadata. Raw pcap/pcapng remains evidence-preserving and is never presented as redacted.

**Planned / not yet implemented:** a decoder registry with dispatch-table handoff, general TCP
stream/record reassembly, deeper protocol/security policy, raw capture persistence, automatic History
retention, an MCP/AI bridge, and packet-rewriting redaction for raw capture formats. The existing
read-only automation core has no executable or network transport. Do not treat these as present.

When the source and these docs disagree, the source is correct — please open an issue or a fix.
