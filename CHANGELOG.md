# Changelog

All notable changes to Tracexy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **File → Open… (⌘O)** opens a PCAP/PCAPNG where it is, recording a reference in the Project Library instead of copying; the Open panel previews format, size, records and start/elapsed before opening, and offers **Copy into Library**. **Import into Library… (⌥⌘O)** keeps the managed-copy path.
- Referenced captures show their availability in the Library; a moved or replaced file offers **Locate…** and **Reload** inline instead of an error.
- **File → Open Recent**, **Close Capture (⇧⌘W)**, **Reload (⌘R)** when the open file changed on disk, and **File Set → Next / Previous File** for `dumpcap`/`tcpdump` rotation sets.
- **File → Get Info (⌘I)**: a capture information window with format and variant, time span and order, PCAPNG section and interface metadata (names, descriptions, filters, statistics counters), block inventory (name resolution, decryption secrets by type and size, custom, unknown), on-demand SHA-256/SHA-1 with cancel, and a Copy action.
- A **Frames** facet in the bottom inspector lists the selected session's frames (number, relative time, direction, length, TCP flags, summary, comment marker) from a bounded on-demand rescan; a row loads that exact frame into Layers/Hex.
- **File → Export Frames…** writes a new PCAPNG or classic PCAP from a scope (whole capture, sessions in view, selected session, time range), optionally preserving PCAPNG section, interface and per-frame metadata and compressing with gzip; PCAP is disabled with the reason when the source cannot be represented.
- The Context dock shows **Captured on** (the file's interface names) for sessions of multi-interface PCAPNG captures; the Frames facet adds an **Interface** column for such captures, and the Library row of a rotation-set member offers a **File Set** menu listing the set.
- Overview reads an opened file's format, interfaces, fidelity and drop counters from the file itself: the recognised container rather than the extension, the declared interface names, and loss from the Interface Statistics Blocks the capturing tool wrote (**Not recorded** when a file carries none), with a **Get Info** action in the storage card.
- A Quick Look preview extension (Finder Space-bar, Open panel preview) and a Spotlight importer for `.pcap`/`.pcapng`, both sandboxed and built on the same readers as the app; the format readers moved to a shared `CaptureFormat/` layer.
- Tracexy now imports the canonical `com.tcpdump.pcap` / `org.tcpdump.pcapng` type identifiers instead of app-private ones, so it interoperates with Wireshark's declarations.
- The PCAPNG reader now reads section and interface options, Interface Statistics Blocks and per-frame comment presence within block bounds, and counts decryption-secrets, name-resolution, custom and unknown blocks; secrets are never read.
- Open a `.pcap`, `.cap`, `.pcapng` or `.ntar` file from Finder (Open With, Dock icon) or by dropping it on the main window; the file follows the Project's Open preference (in place by default).
- Decode 802.1Q / 802.1ad VLAN-tagged Ethernet frames so trunk- and mirror-port captures form sessions.
- Sort the Sessions table by any column from its header; the default remains stable capture order.

### Fixed

- Defer bottom-inspector collapse and expansion until AppKit finishes the current layout pass, avoiding a window-constraint crash during SwiftUI updates.
- Bound the transport payload by the IP-declared length so Ethernet padding and trailers are no longer counted as TCP sequence space, which produced false overlap and retransmission findings and leaked into Follow Stream.
- Stop decoding a transport header out of non-first IP fragments and out of IPv4 headers shorter than 20 bytes; those frames no longer invent endpoints or sessions.
- Record a TCP reset that arrives after an orderly close as a reset observation, so a session shown as an error also carries the matching finding and evidence.
- Classify a TCP keep-alive probe as a keep-alive rather than a retransmission.
- Measure DNS latency for answerless responses (NXDOMAIN, NODATA) by the header's response bit.
- Read the classic pcap link type from the low 16 bits of its header word, so files written with an FCS-length hint open with their sessions.
- Open one main window, not two, when relaunching after a force-quit or crash.
- Expose saved-capture rows, Focus Set rows, Flow Map regions and inspector layer/field rows to VoiceOver and UI automation as activatable controls.
- Stop a live capture and say why when the capture source stops delivering (the interface went away or was reconfigured), instead of showing it as still capturing; the helper carries the reason with its final frames.
- Stream a session export from the capture file instead of loading the whole capture into memory.
- Ask before quitting while a live capture is running, as the General setting promised.
- Apply the General → Units setting to every byte figure, and honor "Restore last workspace on launch" when it is turned off.
- Keep the Focus Set editor, Noise Control and Settings windows from reopening on their own after a relaunch, and always open the workspace window after a force-quit relaunch.
- Keep a replaced helper XPC connection from being discarded by the previous connection's late invalidation.

### Changed

- Orient a session captured mid-stream toward the service port when no SYN was captured, so the remote host rather than this Mac's ephemeral socket reads as the destination.

## [0.7.0] - 2026-09-08

### Added

- Organize investigations into isolated Projects, each with its own workspaces, saved captures, History, and capture and privacy settings.
- Import PCAP and PCAPNG captures into a chosen Project, including gzip-compressed files, TCP Viewer session archives, and Linux cooked captures.
- Query whole sessions with bounded Session Expressions, return from host, client, IP, or Findings drill-downs with filters intact, and import named BPF capture filters.
- Export and import configuration-only `.tracexyproject` files without packets, payloads, capture paths, findings, or History.

### Changed

- Keep Project transitions safe by waiting for accepted capture and save work, preserving the current investigation when a transition cannot complete.
- Reorganize the native toolbar so Project selection, capture source, and Start/Stop controls remain distinct and easier to follow.

## [0.6.0] - 2026-09-02

### Added

- Navigate retained connection and TLS evidence to the exact cited local frame.
- Open the selected session in an auxiliary Inspector window that follows the workspace selection.

### Fixed

- Enforce the selected automatic History retention at launch, after a capture is stored, and when the setting changes.
- Remove duplicated workspace chrome and correct session-control and footer alignment.

### Changed

- Refine session controls, status, and inspector layout for a clearer native Liquid Glass workspace.

## [0.5.0] - 2026-08-24

### Added

- Add local History for completed live and saved captures, with bounded session summaries stored without packet payloads.
- Add typed Investigation queries, evidence-linked findings, and bounded Follow Stream for stopped or saved TCP captures.
- Add Capture Readiness details for the active interface, capture settings, buffering, and observed frame loss.

### Changed

- Stream large saved captures off the main UI path and keep complete live-capture session summaries through disk-backed spooling.
- Refresh the native workspace and Settings with adaptive macOS materials, accessible opaque data surfaces, and responsive window chrome.
- Expand Protocols, Apps, and Domains when the first decoded session arrives while respecting later manual collapse.

## [0.4.1] - 2026-08-19

### Fixed

- Continue to the save panel after the user explicitly confirms an unprotected raw pcap/pcapng export.

## [0.4.0] - 2026-08-19

### Added

- Protect native session exports with Privacy settings, omitting raw packet bytes and sensitive decoded metadata by default; raw pcap/pcapng exports now require explicit confirmation while a protection is enabled.

### Fixed

- Strengthen privileged capture-helper authentication against process-identity races.
- Remove temporary capture files left by interrupted sessions without touching active captures or unrelated data.

## [0.3.0] - 2026-08-17

### Added

- Add a capture summary dashboard with traffic activity, protocol mix, top talkers, and evidence-based findings.
- Add native session search, decoded-evidence copy actions, source management, and reversible session removal.
- Add deeper STUN, TLS-record, and QUIC long-header inspection, plus segmented TCP/DNS/TLS/HTTP recovery.

### Changed

- Preserve packet timestamps, lengths, link types, and capture-loss accounting across live capture and export, with configurable snap length, promiscuous mode, and BPF filters.
- Keep sustained captures responsive with bounded disk spooling and incremental session updates.

## [0.2.0] - 2026-08-13

### Added

- Add Tracexy demo captures
- Add update badge and inspector detail tables
- Add session export actions

### Fixed

- Harden live frame ingestion

### Changed

- Refine session search and assistant dock
- Streamline security investigation

## [0.1.4] - 2026-08-06

### Changed

- Make force reset authorization-safe

## [0.1.3] - 2026-08-06

### Changed

- Recover service registration after app updates

## [0.1.2] - 2026-08-05

### Fixed

- Stabilize live session table updates

## [0.1.1] - 2026-07-31

### Fixed

- Harden lifecycle recovery

## [0.1.0] - 2026-07-31

### Added

- Capture → protocol → session foundation: privileged capture helper, PCAP/PCAPNG IO, direct packet decoding, batch session summaries, and native UI.
- App-level capacity limits are resolved from an injected `AppPolicy` at launch rather than hardcoded: workspace tabs, saved focus sets, and pinned hosts. Reaching a limit now explains itself instead of doing nothing.
- Settings now uses native toolbar tabs, consistent grouped cards, semantic Light/Dark surfaces, and tighter field and status layouts across every pane.
- Sparkle 2 provides signed Community updates through the public appcast, with one app-owned updater shared by the app menu and Settings, automatic-check/download preferences backed directly by Sparkle, and local builds kept manual-only.

### Fixed

- Improved the description shown for unencrypted HTTP traffic.

### Changed

- Helper compatibility now reads the bundled helper version, build, and protocol from the shared release version configuration instead of assuming they match the app version.
