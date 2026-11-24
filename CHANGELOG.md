# Changelog

All notable changes to Tracexy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

### Fixed

### Changed

## [0.10.0] - 2026-11-13

### Added

- Import a text hex dump from File → Import Hex Dump…, with an explicit offset base, byte grouping, regular-expression scopes for packet bytes, timestamps, direction and sequence numbers, a chosen link type, and optional generated Ethernet, IPv4/IPv6, UDP, TCP or SCTP headers around entered payload bytes.
- Export the frames you chose: an exact selected-frame capture, every frame matching an applied Frame Expression, and an opt-in that leaves ignored frames out of the written file.
- Export packet dissections as text summaries, details and captured bytes, as JSON with optional raw hex for exactly mapped fields, or as a summary CSV that can add up to four applied Project field columns.
- Print packet summaries, decoded dissections or captured-byte hex dumps for the sessions in view, one frame, marked frames, a numeric frame range, or every frame matching an applied Frame Expression.
- Filter All Frames with a bounded Frame Expression over typed frame facts, including capture direction, inner tunnel addresses, TCP control flags and raw sequence/acknowledgement values, IPv4 Identification, Don't Fragment, TTL and fragment offsets, IPv6 hop limits, DNS transaction IDs and the TC flag, and ICMP/ICMPv6 type and code.
- Build Frame Expressions straight from the decode tree: copy a field as a filter term, highlight matching frames temporarily, or prefill a supported predicate for review before you apply it.
- Colorize packets with ordered Project-local coloring rules, up to ten capture-local conversation color slots, and an import that accepts Wireshark JSONC and legacy `colorfilters` records whose filters fit Tracexy's grammar; unsupported rules are reported rather than silently dropped.
- Resolve addresses from more sources: name an address from an All Frames row, merge a bounded standard or Wireshark `hosts` file, and read PCAPNG Name Resolution Blocks when a capture carries them, with omitted records reported in Capture Info.
- Correct the time of a saved capture in memory with a whole-capture offset, one anchor, or two anchors for linear drift, with Undo; sessions, findings, timelines, All Frames and Follow views recompute from the same correction, and supported exports carry it with its provenance.
- Set capture-wide time references in All Frames that survive paging and display filters, add a Cumulative Bytes column that resets at each reference, and keep up to sixteen temporary references per scope.
- Compare up to four named Frame Expression series in the I/O Graph over one pass of a stable capture, with per-series match, unknown and untimed coverage, CSV and chart-image export, and a jump from a chart interval to a representative matching frame.
- Read more TCP evidence in Session Health: receiver-reported SACK ranges, RFC 2883 D-SACK ranges shown as the receiver's report rather than a cause, SACK-aware Goodput beside wire throughput, a conservative SACK-reported RTT line beside Karn-safe RTT, and typed window-update and zero-window probe observations.
- Navigate and search a capture more directly: Frame Expression Find, UTF-8 and UTF-16 string search, bounded Back/Forward selection history, First/Last on the current page, pinned rows that persist across paging, Mark and Ignore All Displayed, and a frame-scoped details tree for a frame with no folded session.
- Filter, expand, copy and keyboard-navigate decoded layer trees in both the Session Inspector and standalone frame details, including a visible-subtree copy that honors what is folded.
- Follow conversations with more honest export: attributed TCP source chunks with per-peer indexes, direction-scoped UDP transcripts, raw payload export when completeness checks pass, and disabled bidirectional actions with a stated reason when retained provenance cannot prove cross-direction order.
- Override decoding per Project with TCP/UDP port rules prefilled from the packet list or packet details for review, and pass invocation-local `--decode-as` rules to the read-only command line without touching Project settings.
- Stream frame tables from the command line with `tracexy frames`, including capture direction and repeated `--column Protocol:Field` for supported decoded fields.
- Read SCTP common headers, verification tags and bounded chunk headers, validate CRC32C when the declared packet boundary is fully captured, and import SCTP chunks or payload bytes from a hex dump.
- See SCTP traffic as sessions: flows fold on their endpoint pair with directional packets and bytes, an SCTP tab joins Conversations and Endpoints (`--tap conv,sctp`, `--tap endpoints,sctp`), an observed INIT chunk names the side that opened the association, and an observed ABORT marks the session as an error. Sessions are keyed on the endpoint pair, not the verification tag, and SCTP streams are still not reassembled. An SCTP pill joins the session filter pills, so a capture that mixes SCTP with other transports can be narrowed to it, and `sctp` is a Session Expression protocol term like `tcp` and `udp`, so Help ▸ Supported Protocols, expression completion and the `sctp` and `sctp port` display-filter imports all name it.
- Rescan one TCP conversation on a stable source for deeper graph evidence, and see SMB2, LDAP, Kerberos, ICMP and ICMPv6 service response times over the complete capture in the window and the command line.

### Fixed

- A Frame Expression typed in All Frames applies when you press Return, and the field shows its grammar in a tooltip again.
- Exported and printed packet dissections carry a saved capture's Time Shift, so their times match All Frames instead of the uncorrected source.
- Go to Packet on a pinned frame now says when that frame is outside the capture in view, instead of doing nothing. A frame named by Find before any page has been listed now lists the page that would hold it rather than being refused.
- The first frame on a later All Frames page shows its real time delta from the frame before it, taken from the same scan that built the page, instead of an unknown delta. A filtered page whose opening frame is hidden, and a time reference pinned from another page, still report unknown rather than borrowing that time.
- Split Capture and the capture file-set settings now name the menu that walks a file set correctly, File ▸ File Set ▸ Next File, in English and Vietnamese. The old text named an item that does not exist.
- Overview's Measure and Series chart choices are kept per Project instead of being shared by every Project on this Mac, including a Synthetic Project. Both reset to their defaults once, because they move to a Project-owned setting.
- The All Frames footer reads `Showing 37 of frames 200,001–400,000, 500,000 scanned` rather than repeating "of" twice, and it is now translated.
- The All Frames expression field and its Highlight button are no longer drawn hard against the window edge with their leading corners clipped.
- The All Frames footer no longer truncates its own commands to "Mark All Di…" and "Unignore D…" at the window's ordinary width: the bulk mark and ignore commands share a Marks menu, the export and print commands an Export menu, and each is unavailable when it has nothing to act on. The Relative TCP Seq/Ack toggle reads on one line again instead of three.
- The IP Statistics and Service Response Time choosers sit under the titlebar instead of floating down the middle of an otherwise empty window.
- The Packet Lengths, Resolved Addresses, Protocol Hierarchy and Message Counts footers stay on one line at any window width; a caption that used to stop mid-clause now states the fact and names the bound it counts to in its tooltip.
- Decode As shows its rule-limit and redecode notices on their own line, so its buttons stay reachable on one line when a draft, the rule limit and a pending redecode coincide. Overview's chart notices stack for the same reason.
- Manage Interfaces opens at the size it declares rather than clamped to its minimum with the interface columns already squeezed.

### Changed

- TCP acknowledgement, window and checksum values, IPv4 Identification and fragment flags, and DNS transaction ID and TC flags now appear in the packet inspector and can be filtered.
- All Frames pages through a stable capture with a stated retained-row limit, so Frame Expression match counts describe the whole capture while toolbar search stays page-local.
- Settings → Privacy now states that all data stays on this Mac and that no usage analytics are collected, in place of two checkboxes that could not change either: Tracexy has no upload path and ships no analytics collection.

## [0.9.2] - 2026-10-21

### Fixed

- The official macOS download includes Settings → License so purchased Pro keys can be activated.

## [0.9.1] - 2026-10-08

### Fixed

- When live capture has no sessions, show guidance for specialized Wi-Fi interfaces and active capture filters.

## [0.9.0] - 2026-10-08

### Added

- Open several named workspace tabs in one Project. Each keeps its own scope, filters, grouping and panels, and the Project restores them on reopen.
- Investigate sessions with richer expressions, reusable filter buttons and macros, imported display filters, address names, session tags and evidence-linked notes.
- Browse every retained frame, search its text or bytes, inspect decoded fields and packet bytes, validate checksums, add frame comments, and jump between a finding, session and cited frame.
- Follow TCP and UDP conversations with frame citations and visible capture gaps. Read HTTP/1 exchanges, cleartext HTTP/2 including h2c upgrades, and WebSocket messages; save supported streams and HTTP response bodies.
- See response-time measurements, TCP health charts, traffic and field plots, a session ladder, and a flow graph drawn from captured frames.
- Use new Statistics views for conversations, endpoints, protocol hierarchy, DNS, HTTP, IP, packet lengths, service response times, SIP calls and RTP streams, with scoped export where available.
- Find evidence-linked TCP, DNS, TLS and ICMP problems, including unanswered handshakes, flow-control issues and cleartext credentials, with explicit unknown states when evidence is incomplete.
- Decode fragmented IPv4 and IPv6 datagrams, GRE and VXLAN tunnels, and more local, enterprise and media protocols including mDNS, DHCP, NTP, SIP/RTP, SMB, LDAP, Kerberos and TFTP.
- Add a local MaxMind-format GeoIP database to a Project for optional endpoint and session location context; private and special addresses are not looked up.
- Manage capture interfaces, validate and save BPF filters, choose per-interface optimization, stop automatically by time or packet count, and rotate long live captures into bounded files.
- Merge or split capture files, open LZ4-compressed captures and named-pipe input, inspect file structure, and export selected frames with optional address masking, notes and comments.
- Export bounded HTTP, SMB, email, FTP and certificate objects, packet dissections and application PDUs from captured evidence.
- Use the command line to inspect captures, sessions, frames, statistics and supported objects, and let an explicitly granted read-only MCP client list findings from History.
- Use the native interface in Vietnamese.

### Fixed

- RTP Stream Analysis handles out-of-range timestamps without crashing, computes off the main thread, and keeps both directions on one graph time axis.
- SMB Export Objects finds files across real share and handle lifecycles. Save All continues past individual failures and gives colliding file names unique destinations.
- Switching Projects refreshes capture-backed report windows, and early-opened Endpoints and Inspector views load their location context.
- Large Project catalogs and captures no longer stall routine saves or investigation views; over-limit saved data stays readable and editable while new additions remain gated.
- Project imports, tab actions, filter buttons and macros enforce capacity at the final write and preserve stored values this version cannot read.
- Cleartext HTTP/2 and WebSocket filters match their sessions; HTTP/1 requests with binary bodies and HTTP/2 prefaces sharing a segment remain readable.
- Auxiliary window controls, narrow inspector layouts, session selection and cited-frame navigation remain usable across window and accessibility transitions.
- PCAPNG TLS key-log blocks and equal-count statistics rows display correctly.

### Changed

- Export Objects and Export PDUs scan many connections in grouped passes, reducing repeated reads of large captures.
- Quitting during live capture now stops capture cleanly and retains session History; captured packets still require an explicit save.
- Session, finding, inspector and status text uses clearer plain-language descriptions and keeps unknown or missing evidence explicit.

## [0.8.1] - 2026-09-22

### Fixed

- Preserve approved helper updates
- Restore idle exit timer delivery

## [0.8.0] - 2026-09-21

### Added

- Ask about a selected session with the local Assistant, review the exact data before sending, and open cited frames in the evidence inspector.
- Grant an MCP client bounded, read-only capture history for one Project, and revoke access in Settings.
- Explore capture activity, protocols, sessions, findings, hosts and apps from the Overview.
- Open captures in place from File, Finder or drag and drop; preview them before opening, keep recent files, and locate or reload moved and changed references. Import into Library remains available when a managed copy is wanted.
- Inspect capture format, time span, interfaces and recorded metadata in **File → Get Info**; browse the exact frames of a session in the bottom inspector.
- Export whole captures or selected frames, sessions and time ranges as PCAPNG or compatible PCAP, with optional gzip compression.
- Preview PCAP and PCAPNG files in Quick Look and find them with Spotlight.
- Browse rotated capture file sets, decode VLAN-tagged traffic, and sort the Sessions table by column.

### Fixed

- Keep Assistant review and disclosure in sync, reject stale approval, and label incomplete answers clearly.
- Enable MCP access once the active Project finishes loading, even if Settings was opened first.
- Keep local capture paths out of default Library, recovery and Get Info text; Reveal and Copy Path remain explicit actions.
- Avoid a bottom-inspector layout crash and unwanted extra windows after relaunch.
- Correct false TCP retransmission findings from packet padding, fragments and keep-alive probes; retain reset evidence when it follows an orderly close.
- Open classic PCAP files that declare an FCS hint, and calculate DNS response time even when the answer contains no records.
- Stop live capture with a clear reason when its source disappears, and ask before quitting during capture.
- Improve VoiceOver navigation, honor byte-unit and workspace-restoration settings, and stream large exports without loading the entire capture into memory.

### Changed

- Replace placeholder MCP and Assistant settings with scoped access and local connection controls.
- Overview Protocols shows session-byte share by innermost protocol so its bars sum to the scope.
- Orient sessions captured mid-stream toward the service port when no connection start was captured.

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
