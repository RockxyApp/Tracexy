# Tracexy

A native macOS network intelligence app. Tracexy captures traffic passively and presents it as
**conversations** — DNS lookups, TCP connections, TLS handshakes, HTTP exchanges — instead of a
scrolling wall of frames.

It is not a packet-list-first tool. Packets and hex are still there, one click away in an inspector
tab, because sometimes the bytes are the answer. But the thing you land on is the session: who
talked to whom, over what, how long it took, and what went wrong.

> **Status:** early. The capture → decode → session foundation is real and tested; the deeper
> analysis, storage, and protocol coverage described in the roadmap are still being built. Expect
> rough edges, and expect the UI to move.

---

## What it does today

- **Live capture** through a signed privileged helper, or **open a `.pcap` / `.pcapng`** file.
- **Decoding** of Ethernet, IPv4/IPv6 (including options and extension headers), TCP (with
  options), UDP, and enough DNS/TLS/HTTP to name a conversation — SNI-resolved hosts, HTTP status,
  DNS answers.
- **Sessions, not packets.** Frames are grouped by canonical five-tuple into session summaries,
  and related sessions are correlated into higher-level *actions*.
- **A native Mac interface** — `NavigationSplitView`, real `Table`, real SF Symbols, both inspector
  layouts, workspace tabs. No web view anywhere in the UI.
- **Focus sets and noise control** — save a named filter, mute the hosts and protocols you are
  tired of seeing.
- **Per-process attribution** where macOS will tell us, so a session has a name attached and not
  just a port.

## Requirements

macOS 14 or later. Capture needs a one-time privileged helper install; opening saved capture files
does not.

## Building

You'll need Xcode 16+, plus [SwiftLint](https://github.com/realm/SwiftLint) and
[SwiftFormat](https://github.com/nicklockwood/SwiftFormat) if you intend to submit changes.

```bash
git clone https://github.com/RockxyApp/Tracexy.git
cd Tracexy
cp Configuration/Developer.xcconfig.template Configuration/Developer.xcconfig
```

Put your own Apple Developer Team ID in `Configuration/Developer.xcconfig` — it is gitignored, so
your signing identity never leaves your machine. Then:

```bash
xcodebuild -project Tracexy.xcodeproj -scheme Tracexy -destination 'platform=macOS' build
```

```bash
xcodebuild -project Tracexy.xcodeproj -scheme Tracexy -destination 'platform=macOS' test
```

## How it is put together

The pipeline is layered, and each layer is meant to be understandable without the one above it:

```
Capture  →  Protocol  →  Session  →  UI
```

| Layer | Where | What lives there |
|---|---|---|
| **Capture** | `Tracexy/Core/Capture` | libpcap through the privileged helper, PCAP/PCAPNG readers and writers, interface enumeration, capture statistics |
| **Protocol** | `Tracexy/Core/Protocol` | `PacketBuffer` (bounds-checked, zero-copy) and the packet decoder |
| **Session** | `Tracexy/Core/Session` | canonical `FiveTuple` grouping, session summaries, action correlation |
| **App** | `Tracexy/Models`, `Tracexy/ViewModels`, `Tracexy/Views` | workspace state, the coordinator, and SwiftUI surfaces |

Two rules matter more than the rest, and reviews will hold you to them:

- **`Core/` never touches the main actor and never allocates on the hot path.** Decoding reads
  through `PacketBuffer`, which is bounds-checked and *throws* on a short or malformed packet
  rather than trapping. A hostile capture file must not be able to crash the app.
- **`Core/` knows nothing about the UI.** It produces values. Anything that looks like presentation
  or policy belongs above it.

App-level capacity limits — how many workspace tabs, how many saved focus sets — are not constants
scattered through the code. They come from an `AppPolicy` (`Tracexy/Models/Settings/`) resolved once
at launch and injected down. A store that enforces a cap receives a number through its initializer
and never learns where the number came from, which keeps the limits in one readable place and out
of everything else.

The helper (`TracexyCaptureHelper/`) is a separate privileged binary talking to the app over XPC,
with code-signature validation in both directions. Changes there are not picked up by rebuilding
the app — you have to uninstall, rebuild, and reinstall.

## Privacy

Captured traffic is yours. Tracexy keeps it on your machine, never uploads it, and asks before it
starts capturing. If you export or share a capture, redact first — a `.pcap` is a recording of
everything, including the parts you forgot were in there.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through
[SECURITY.md](SECURITY.md) — please don't open a public issue for those.

## License

[GNU AGPL v3](LICENSE).
