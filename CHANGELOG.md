# Changelog

All notable changes to Tracexy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Ask about the selected session with a local AI Assistant: connect a model running on this Mac, review the exact JSON before the first send, stream the answer, and click a citation to open the frame it refers to.
- Share bounded, read-only capture history with an MCP client through a bundled command-line tool that never opens a network port, scoped to one Project you grant and revoke in Settings.
- Overview plots every accepted frame's wire bytes on the real capture clock, split into bytes sent by clients and received from servers, for live and opened captures alike, with exact hover readouts and scoped findings pinned at the instant of their first cited frame.
- Overview is now a capture report: compact Protocols, Sessions started, and Findings charts, plus native Top hosts and Top apps tables whose rows narrow the session list.
- Open a `.pcap`, `.cap`, `.pcapng` or `.ntar` file from Finder (Open With, Dock icon) or by dropping it on the main window; the file takes the same Library import path as ⌘O.
- Decode 802.1Q / 802.1ad VLAN-tagged Ethernet frames so trunk- and mirror-port captures form sessions.
- Sort the Sessions table by any column from its header; the default remains stable capture order.

### Fixed

- Keep Assistant disclosure toggles and the exact reviewed JSON in sync, and fail closed when evidence
  changes underneath an approval.
- Mark provider length cutoffs as incomplete, keep MCP activity names allowlisted, reject undeclared
  MCP arguments, and prevent the synthetic Assistant walkthrough from invoking capture-helper setup.
- Keep Assistant transcript chrome from covering answers or incomplete-state labels.
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

- Replace the placeholder MCP and AI Insights settings with the real MCP grant, activity trail, and local-model controls, and retire the unused preference keys behind them.
- Overview Protocols shows the share of session bytes by innermost protocol so bars sum to the scope, replacing overlapping per-layer session counts.
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
