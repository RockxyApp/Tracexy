# Tracexy Competitor Comparison

Last reviewed: 2026-08-30. Source release: Tracexy 0.5.0, build 10.

This matrix is the repository-owned comparison for Tracexy as a native,
session-first macOS Network Intelligence Platform. It mirrors the public
Tracexy website positioning and keeps current source facts separate from
roadmap work.

A requested TCP connection viewer is intentionally excluded. It is not part of
the current public Tracexy competitor set, and adding it here would create an
unsupported comparison claim.

## Method

- Tracexy claims come from this repository's README, documentation, and current
  version configuration.
- The competitor set comes from the public Tracexy alternatives matrix:
  Wireshark, tcpdump, TShark, Packet, and Cocoa Packet Analyzer.
- Closed products are not reverse engineered. If a claim is not public or not
  verified, the cell says `closed source or no public information`.
- This document does not include outbound competitor links. The public website
  intentionally avoids competitor links on comparison pages and treats
  unverified closed-source claims conservatively.
- Tracexy is not described as a Wireshark clone or replacement. It is a
  different workflow: app-aware Mac sessions and support-ready evidence first,
  packet detail underneath.

## Product Boundary

Tracexy is passive packet capture and local analysis. It can expose TLS
metadata and identify QUIC long headers, but it does not intercept TLS, decrypt
TLS or QUIC, or expose encrypted HTTP payloads. HTTPS request inspection,
modification, replay, and redaction belong to
[Rockxy](https://github.com/RockxyApp/Rockxy), not Tracexy.

App and process attribution is also conditional: it is a core Tracexy workflow
when macOS reports `pktap` process context or when local socket fallback can
resolve ownership. Missing ownership is shown as unknown rather than invented.

## Maintained Feature Matrix

| Decision point | Tracexy | Wireshark | tcpdump | TShark | Packet | Cocoa Packet Analyzer |
|---|---|---|---|---|---|---|
| Primary workflow | Native macOS, session-first packet evidence with app/process context | Deep protocol dissection and broad packet-analysis workflow | Small command-line capture primitive | Wireshark dissection and field output in a terminal | Friendly native Mac traffic view | Native Mac packet/trace analyzer |
| Platform posture | macOS 14+ native app | Multi-platform desktop app | Multi-platform CLI | Multi-platform CLI | macOS; current public requirements need vendor verification | macOS; current public requirements need vendor verification |
| Source/license posture | Public source under AGPL-3.0-or-later; separate commercial terms may exist for official distributions | Public open-source project | Public open-source command-line tool | Public open-source Wireshark command-line tool | closed source or no public information | closed source or no public information |
| Live capture | Live libpcap capture through a narrow privileged helper | Live interface capture | Live interface capture from terminal | Live capture from terminal | Native Mac live traffic workflow, depth requires vendor verification | Capture workflow requires vendor verification |
| Saved capture files | Opens and writes PCAP and PCAPNG; sniffs capture-file type | Broad capture-file open support | Reads and writes pcap-style captures | Reads capture files through Wireshark tooling | closed source or no public information | PCAP/trace workflow publicly positioned, exact format scope requires vendor verification |
| App/process attribution | Core workflow when macOS context is available; unknown stays unknown | Possible through capture context and platform metadata, not the central workflow | Depends on capture context and surrounding tools | Available only if fields/capture context expose it | Per-app usage is publicly positioned, implementation depth requires vendor verification | Not a central verified claim |
| Session grouping | Canonical five-tuple sessions, timing, byte counts, lifecycle and bounded evidence | Conversation analysis exists, but workflow begins from packets/protocol trees | Not a native session UI | Terminal output can be shaped by fields and filters | closed source or no public information | closed source or no public information |
| Current protocol coverage | Ethernet, loopback/tunnel, ARP, IPv4/IPv6, ICMP, TCP/UDP, DNS, TLS metadata, HTTP/1 recognition, STUN, conservative QUIC long-header metadata | Broad dissector ecosystem | Capture-oriented; analysis usually handled elsewhere | Wireshark dissectors in terminal form | Readable protocol breakdown is publicly positioned, exact depth requires vendor verification | Plugin-oriented protocol dissection is publicly positioned, exact depth requires vendor verification |
| Bounds and malformed input posture | Bounds-checked decoder; truncated/malformed frames must produce partial decode or controlled errors | Public project has mature dissector hardening, exact behavior varies by dissector | Capture tool boundary | Wireshark dissector boundary in CLI form | closed source or no public information | closed source or no public information |
| Filtering | Interface/source selection, BPF, protocol/app/domain filters, search, typed Investigation queries | Capture filters, display filters, field expressions | libpcap/tcpdump capture-filter syntax | Capture filters, display filters, field extraction | UI-driven filters require vendor verification | Trace filters require vendor verification |
| TLS and HTTPS payloads | TLS metadata only; no TLS interception, no decryption, no encrypted HTTP body visibility | Packet visibility depends on keys, capture point, and protocol conditions | Captures bytes; no HTTP interception workflow | Same packet-analysis boundary as Wireshark | Not positioned as an HTTPS interception proxy | Packet-analyzer boundary; no verified HTTPS interception claim |
| Follow stream / reassembly | Explicit bounded Follow Stream for saved or fully stopped sources; no active-live growing-spool reads; no general always-on stream analyzer | Mature stream-follow workflow | Not a native GUI workflow | Terminal-oriented stream/field analysis depends on command usage | closed source or no public information | closed source or no public information |
| Evidence handoff | Decoded fields, raw hex, capture exports, protected `.tracexysession` export, local History summaries | Packet/protocol artifacts and export formats | Capture artifacts for scripts and incident collection | Machine-readable terminal output | Visual/export scope requires vendor verification | Trace/export scope requires vendor verification |
| Privacy model | Local-first; no automatic upload of capture payloads; protected session export omits raw frames and sensitive decoded metadata | Local analysis by default unless the user chooses external flows | Local CLI capture by default | Local CLI analysis by default | closed source or no public information | closed source or no public information |
| Automation fit | Native desktop investigation plus a bounded read-only History automation core; no executable target or network transport today | GUI with supporting command-line tools | Strong for scripts and remote hosts | Strong for shell pipelines and CI-style output | Desktop-first; automation requires vendor verification | Desktop-first; automation requires vendor verification |
| Best aligned user | Mac developer/support/security workflow that needs app-aware packet evidence without decrypting traffic | Protocol engineer or analyst needing maximum dissector depth | Operator collecting traffic quickly on a terminal or remote system | Analyst automating Wireshark-style dissection | Mac user wanting a friendly traffic view | Mac user wanting a native packet/trace analyzer |

## Tracexy Current Features

These are current source claims:

| Area | Current capability |
|---|---|
| Capture | Live interface capture through the helper; interface discovery; snap length, promiscuous mode, and BPF settings; PCAP and PCAPNG read/write |
| Protocol | Bounds-checked packet buffer and direct decoder for current L2-L4 and selected application metadata |
| Sessions | Canonical five-tuple grouping, endpoint projections, timing/byte summaries, bounded connection evidence |
| Findings | Selected evidence-linked TCP and datagram findings; no general durable security-analysis engine |
| Follow Stream | On-demand bounded TCP follow for identity-checked saved or fully stopped sources |
| History | Local terminal capture/session summaries in SQLite; no raw packet persistence |
| Automation | Read-only bounded History projection to deterministic JSON or spreadsheet-safe CSV; no listener, provider, executable target, or MCP server |
| Exports | Raw PCAP/PCAPNG stays byte-preserving; protected `.tracexysession` export omits raw frames and sensitive decoded metadata |

## Not Current Claims

Do not present these as shipped:

- deep HTTP/2 decoding;
- deep HTTP/3 or QUIC frame/payload decoding;
- WebSocket decoding;
- TLS analysis or decrypted HTTPS payload visibility;
- general always-on TCP stream or record reassembly;
- user-visible connection/TLS evidence navigation beyond current views;
- automatic History retention cleanup;
- production replay UI/runner;
- CLI transport, TracexyMCP, or AI data transport; and
- packet-rewriting redaction for raw PCAP or PCAPNG.

## Source Ledger

- Tracexy source truth: `README.md`, `docs/README.md`,
  `docs/protocol-support.md`, `docs/privacy-and-security.md`,
  `Configuration/Versions.xcconfig`.
- Public website source truth reviewed:
  `tracexy/alternatives.html`, `tracexy/compare.html`,
  `wireshark-alternative.html`, `tracexy.html`,
  `scripts/check-tracexy-feature-truth.mjs`.
- Public pages that carry the same positioning:
  `https://rockxy.io/tracexy/alternatives`,
  `https://rockxy.io/tracexy/compare`,
  `https://rockxy.io/wireshark-alternative`.
