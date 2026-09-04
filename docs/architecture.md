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
runs through the privileged helper over libpcap; the app also reads classic PCAP and PCAPNG files,
writes classic PCAP where required, and saves complete live captures as PCAPNG. Interface discovery
and capture statistics live here.

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

**Projects** are the isolation boundary above all of it. One coordinator serves every Project and holds
one `ProjectRuntimeState` bucket per Project, bounded by `AppPolicy.maxProjects`. A parked Project keeps
its *actual* `WorkspaceStore`, `SessionStore`, `LiveCaptureSpool` actor, capture Library folder and
`UserDefaults` suite — nothing is evicted and nothing is rebuilt from portable configuration, so
switching back restores its retained investigation; derived queries/evidence are refreshed and raw
Follow Stream is requested on demand. `ProjectDataProviding` resolves those per-Project
locations; `ProjectCatalog.legacyDataOwnerProjectID` names the one Project that owns the pre-Projects
History database and Captures folder, assigned once and never reassigned.

There is a single capture engine and helper backend, so a Project change that involves a running
capture is a lifecycle transition, not a swap: stop → helper's final drain → final fold → terminal
History write → *then* the store/spool/preferences references move. Switch, create, import,
delete-active and recovery all run that one path. Generation and request tokens are globally monotonic
and are never restored to an older counter; a restored Project's stopped-spool readiness marker is
rebased onto a fresh token while the spool's own opaque evidence locators are left untouched.

Final-drain waiters are tied to one owed operation, not elapsed time. An explicit destructive helper
reset finalizes that operation's accepted prefix as incomplete under its recorded engine epoch. A
fresh publication token retires old replies while preserving the frozen History identity and
timestamps. The outgoing Project remains active until a later explicit retry succeeds.

Accepted saves and session exports hold their source against Clear, Start, saved-file adoption,
import replacement and trash. A Project transition drains queued saves and rejects active exports,
including revalidation after a delayed Stop-and-Switch confirmation. Restoring a runtime restarts
interrupted initial History reads, but preserves loaded pages/cursors and does not trigger retention.

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
  bounded batches. Live decode/grouping runs in the `LiveSessionEngine` actor (below); the main actor
  only enriches and publishes coalesced snapshots.
- **`Core/` knows nothing about the UI.** It produces values; presentation and policy live above it.
- **The privileged helper is the trust boundary.** It is a separate signed binary that talks to the app
  over a narrow, typed XPC protocol (start/stop capture, fetch frames, report info — nothing else). The
  app and helper validate each other's code signatures in both directions before trusting a connection.
  See [privacy & security](privacy-and-security.md).

## The live session path

Both paths fold decoded packets through one shared `SessionAccumulator`. For opened savefiles,
`SessionBuilder.build` folds every frame and emits summaries in a single pass. For a **live** capture,
`MainContentCoordinator.ingest` no longer rebuilds every session on the main actor; it feeds each batch
to `LiveSessionEngine`, an **actor** that decodes each frame **exactly once** as it arrives, folds it
into the same accumulator, and produces a snapshot on demand — never by re-decoding or retaining
history. The accumulator keeps only the running state needed for each published summary (representative
packets, byte tallies, a few "firsts", and reported DNS answer values), rather than a decoded-packet
history. Because both paths run the identical fold, a live snapshot equals `SessionBuilder.build` over
the same frames in the same order.

The main actor keeps only two cheap jobs: a bounded raw-frame window for save/export
(`RetainedFrameBuffer`, capacity `retainedFrameLimit`, independent of session accumulation — evicting a
raw frame never drops a session), and app-side process attribution applied to the snapshot before it is
published on the next runloop turn. A capture-generation token guards every snapshot so a late result
from a superseded capture cannot overwrite newer UI state.

### Capture fidelity is reported in distinct stages

Loss is never a single blurred number, and the three stages are surfaced as three distinct UI figures —
never folded into one another:

- **Kernel/interface drops** from `pcap_stats` (`CaptureStatistics`, `nil` when unavailable — shown as
  *unknown*, never a fabricated clean figure), driving the Overview capture-health fidelity percent.
- **Helper staging-buffer eviction**, a separate cumulative count carried in each drain batch. It is
  real capture-source loss the kernel figure never sees, so it is shown as its own footer chip and, in
  the Overview capture-health card, warns even when the kernel reports 100% — a green fidelity must
  never imply a complete capture when the helper stage lost frames. Stop returns the worker's final
  flushed frames and final accounting in one typed reply, so teardown does not silently lose the tail
  or race a separate fetch against the next capture generation.
- **Local inspection-window eviction** (`RetainedFrameBuffer`), a UI memory bound. It is reported
  separately and is never presented as captured-packet loss: sessions remain accounted for while the
  complete accepted raw stream is written off-main to a disk-backed pcapng spool for save/export.

## Planned / not yet implemented

These are design intent — do not write code, or read these docs, as if they exist:

- a **decoder registry** with dispatch-table handoff between protocols (replacing the current monolithic
  decoder);
- general TCP **stream/record reassembly** beyond the bounded lifecycle/sequence connection table,
  first-record metadata probes, and explicit on-demand Follow Stream reader already in source;
- deeper **analysis / security** policy beyond the selected evidence-linked TCP and datagram findings;
- raw capture/evidence persistence beyond the implemented terminal-summary SQLite History store;
- an **MCP / AI** integration.
