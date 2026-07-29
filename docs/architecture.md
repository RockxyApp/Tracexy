# Architecture

Tracexy is a layered pipeline. Each layer produces typed values and knows nothing about the layer
above it:

```
Capture  →  Protocol  →  Session  →  UI
```

The design goal is that `Core/` code is understandable — and testable — without the UI, and that a
hostile capture file can never crash the app.

## The pipeline today

**Capture** (`Tracexy/Core/Capture`) acquires frames and reads/writes capture files. Live capture
runs through the privileged helper over libpcap; the app also reads classic PCAP and PCAPNG files and
writes PCAP. Interface discovery and capture statistics live here.

**Protocol** (`Tracexy/Core/Protocol`) turns raw bytes into a `DecodedPacket`. `PacketBuffer` is a
bounds-checked, zero-copy view over the frame: every read is offset-checked and **throws** on a short
or malformed packet rather than trapping, and a partial decode keeps whatever layers parsed cleanly.
`PacketDecoder` is a single-pass, stateless, per-frame decoder covering L2–L4 plus naming-level
DNS/TLS/HTTP-1/QUIC (see [protocol support](protocol-support.md)).

**Session** (`Tracexy/Core/Session`) groups frames into conversations. `FiveTuple` canonically orders
the two endpoints so both directions collapse into one session. `SessionBuilder` is a **batch**
function: it decodes a set of frames and produces `SessionSummary` values, each with a stable UUID
derived from its tuple so selection survives a rebuild. `ActivityBuilder` is a separate pure function
over already-built sessions that correlates them into higher-level **actions**, attaching typed
evidence and an explicit confidence tier (weak / strong / causal).

**UI** (`Tracexy/Models`, `Tracexy/ViewModels`, `Tracexy/Views`) is native SwiftUI/AppKit built around
`MainContentCoordinator`, workspace state, and an inspector. App-level capacity limits (workspace tabs,
saved focus sets) are resolved once from an `AppPolicy` at the composition root and injected downward,
keeping the limits in one place rather than scattered as constants.

## Repository map

```text
Tracexy/Core/Capture/     packet acquisition and capture-file IO (PCAP/PCAPNG)
Tracexy/Core/Protocol/    PacketBuffer, PacketDecoder, DecodedPacket/DecodedLayer
Tracexy/Core/Session/     FiveTuple grouping, SessionBuilder, Activity correlation
Tracexy/Core/Services/    helper client, signing diagnostics, process resolution
Tracexy/Models/           session and UI value/state types, AppPolicy
Tracexy/ViewModels/       MainContentCoordinator
Tracexy/Views/            Overview, Sessions, Inspector, Flow, Settings, Sidebar
Tracexy/Theme/            design tokens
Shared/                   app/helper identity, XPC protocol, caller validation
TracexyCaptureHelper/     privileged capture daemon (SMAppService + XPC)
TracexyTests/             unit and fuzz-style coverage
```

## Boundaries and the trust boundary

- **Capture, decode, and session computation belong off the main actor.** The UI should receive
  bounded batches. The ingestion exception documented below is transitional debt, not a pattern to
  copy.
- **`Core/` knows nothing about the UI.** It produces values; presentation and policy live above it.
- **The privileged helper is the trust boundary.** It is a separate signed binary that talks to the app
  over a narrow, typed XPC protocol (start/stop capture, fetch frames, report info — nothing else). The
  app and helper validate each other's code signatures in both directions before trusting a connection.
  See [privacy & security](privacy-and-security.md).

## Transitional debt

`MainContentCoordinator.ingest` currently rebuilds sessions by calling `SessionBuilder.build` over all
retained live frames while isolated to `@MainActor`. The capture callback is batched and the list
refresh is coalesced (~once per second), but decoding and rebuilding the retained frames is still
main-actor work. This is known debt — the computation should move off-main; treat it as a spot to fix,
not a pattern to copy.

## Planned / not yet implemented

These are design intent — do not write code, or read these docs, as if they exist:

- a **decoder registry** with dispatch-table handoff between protocols (replacing the current monolithic
  decoder);
- a **stateful connection table** with TCP **reassembly** (today's grouping is a batch rebuild, not a
  live stream tracker);
- an **analysis / security** engine deriving latency, errors, and findings;
- **persistent storage** (a SQLite session store with large-payload offload);
- an **MCP / AI** integration.
