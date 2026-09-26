# Changelog

All notable changes to Tracexy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Open several **workspace tabs** in a Project with **File ▸ New Tab** (⌥⌘T): each keeps its own view of the same traffic — sidebar, filters, grouping and panels. A tab strip appears in the window's titlebar, under the toolbar, once there is more than one; click a tab to show it, double-click or use its context menu to rename it, drag it to reorder (Live stays first), and close it with its close button, **File ▸ Close Tab** or **Close Other Tabs**. **Window ▸ Show Next Tab** (⌃Tab) and **Show Previous Tab** (⌃⇧Tab) cycle through them. When the tabs no longer fit, the strip scrolls, keeps the active tab in view and adds an **All Tabs** menu. VoiceOver reads each tab as a selectable tab with its own close button. Tabs, their names and the active tab are kept with the Project. Up to 8 per Project.
- Follow Stream says how large each hole in a TCP stream is: "N bytes missing in the capture" between runs, or "not retained" when a retention bound dropped bytes, so a gap can be sized like Wireshark's missing-bytes marker.
- Read **WebSocket** conversations in the **Stream** facet: after an HTTP/1.1 upgrade, every message in capture order with its sender, type, text (or first bytes), close code and size — client frames unmasked, fragments joined, and permessage-deflate messages decompressed — plus every frame with its opcode, flags and length, each opening the captured frame behind it.
- Read HTTP/2 that began as HTTP/1.1: a connection that switched with `Upgrade: h2c` is read as HTTP/2 in the **Stream** facet, with the upgraded request as stream 1 and the client's `HTTP2-Settings`, and the session counts as HTTP/2 for the HTTP/2 filter.
- Read cleartext **HTTP/2** in the **Stream** facet: a followed TCP stream that opens with the HTTP/2 preface lists its streams (method, path, final status, response time, data size, and resets with their error code) and, on request, each side's headers decompressed with HPACK; every frame is listed in capture order with its type, stream, length and what it said, and opens the captured frame behind it.
- See where public addresses are with **Statistics ▸ GeoIP Databases…**: add a MaxMind-format `.mmdb` file you already have (GeoLite2 City, Country or ASN, or DB-IP) to the Project, and Endpoints shows Country, City and AS, the Session Inspector gains a GeoIP layer, and `$geoip_country(DE)`, `$geoip_city(…)`, `$geoip_asn(…)` and `$geoip_org(…)` find sessions by location. Lookups read the file on this Mac; private and special addresses are never looked up.
- Keep one-click **filter buttons** and **macros** per Project with **View ▸ Expression Library**: buttons apply a Session Expression from a bar under the toolbar or the menu (`Group//Label` makes pull-downs), and macros (`$name`, `$name(a, b)`) name reusable pieces of an expression, with errors shown where you typed them. Up to 10 of each per Project.
- See the open capture's traffic over time in **Statistics ▸ I/O Graph**: packets per second and bytes per second on one time axis, a chosen interval (whole multiples of the slices the capture keeps), a readout of the interval under the pointer, and Save Chart As (PNG, PDF) or Save as CSV.
- Report a connection refused by the peer and a connection attempt left unanswered as evidence-linked findings, filterable with `finding == connectionRefused` and `finding == handshakeUnanswered`.
- Report DNS name errors, server failures/refusals, and retried queries that received no response as evidence-linked findings, filterable with `finding == dnsNameError`, `dnsServerFailure`, and `dnsUnanswered`.
- Report ICMP destination-unreachable, packet-too-big, and time-exceeded messages as evidence-linked findings, filterable with `finding == icmpUnreachable`, `icmpPacketTooBig`, and `icmpTimeExceeded`.
- Report TCP flow-control health — a zero receive window and its probes, a filled receive window, duplicate acknowledgements, and keep-alive probes — as evidence-linked findings, filterable with `finding == zeroWindow`, `windowFull`, `duplicateAck`, and `keepAlive`.
- Report a connection aborted after data, a half-close with the peer still sending, and a reused connection tuple as evidence-linked findings, filterable with `finding == abortAfterData`, `halfClose`, and `tupleReuse`.
- Report an ICMP error against the session it was about, not only the ICMP conversation that carried it: an error quoting a complete TCP/UDP header now also appears on that flow, filterable with `finding == icmpReportedUnreachable`, `icmpReportedPacketTooBig`, and `icmpReportedTimeExceeded`. The quoted flow's protocol and endpoints are shown in the Layers inspector.
- Show retained DNS and ICMP observations in the bottom **Evidence** facet and summarize them in Details, so a DNS or ICMP session no longer reads as having no retained evidence.
- Open the Session Expression editor from **View ▸ Investigate Sessions…** (Option-Command-I) instead of only from the command cluster's overflow menu.
- Report TLS handshake outcomes as evidence-linked findings — a fatal alert, a warning-level alert that is not an orderly close, a server selecting a version below TLS 1.2, more than one HelloRetryRequest, and a ClientHello with no reply observed — filterable with `finding == tlsFatalAlert`, `tlsWarningAlert`, `tlsDeprecatedVersion`, `tlsRepeatedRetryRequest`, and `tlsHandshakeUnanswered`. A plaintext alert now names its level and description in the evidence row; an encrypted alert stays opaque.
- Measure response times between cited frames: the Details dock gains a **Response Times** section per session — the connection attempt the peer answered, the whole observed handshake, the TLS hello exchange, the first reply after a request, and each DNS query and its answer — and Overview gains a **Response times** table with the count, fastest, median and slowest of each in the current scope, where opening a row selects the session carrying its slowest measurement.
- See a TCP conversation's shape: the Details dock gains a **TCP Health** section with four charts of the selected session — sequence progress against the peer's acknowledged edge, throughput per direction, the round trip from a segment to the acknowledgement covering it, and the receive window offered to each direction beside its unacknowledged bytes. Every point is a retained frame; hovering reads it exactly and clicking the plot opens it in the evidence inspector. A retransmitted segment is never timed, advertised windows are scaled only when both SYNs showed the shift, and a conversation longer than the retained run says which frames the charts cover.
- Follow a UDP conversation from the **Stream** facet: every datagram in capture order with its endpoints, size and timing, DNS messages read as question, response code and answers, and each DNS response paired with its query and the time it took.
- Find text inside a followed stream or conversation, with every match highlighted and counted, and open the exact frame behind any transcript run or datagram.
- See, save and copy the certificates each side of a TLS connection sent in the clear, read from the followed stream in the order sent; a TLS 1.3 handshake is reported as having encrypted its certificates rather than as missing one.
- Write notes about a session and about any finding on it in the Details dock. Notes are saved per Project as you type, stay with the capture they describe even when the file is moved or renamed, follow a live capture into its saved file, mark annotated sessions in the Sessions table, and travel in a Tracexy Session export.
- Write richer session expressions: `host`/`process matches "*.example.com"` wildcards, value sets such as `port in {80, 443}` and `finding in {reset, retransmission}`, and port ranges such as `destination.port in 8000..8080`.
- Get name suggestions while typing a session expression, reapply recent expressions, and keep named expressions per Project.
- Narrow the investigation from any session with **Investigate Sessions Like This** (same host, destination address or port, process, or protocol).
- Export the sessions in view from **File → Export Investigation**: sessions or findings as CSV, both as JSON with the scope that produced them, or a Markdown investigation report with findings, cited frames and your notes.
- Check a custom capture filter while you type it: Settings → Capture shows whether libpcap accepts the expression, or its reason if not, before any capture starts. Save named capture filters per Project and choose them again from **Saved Filters**.
- Recognize mDNS (Bonjour), DHCP and NTP: sessions carry their own protocol labels, DHCP messages show the address offered and the lease, NTP shows mode and stratum, and names that devices announce over mDNS label their addresses.
- Step between flagged sessions with **View → Next / Previous Session With a Finding** (Option-Command-Down / Up Arrow).
- Add Timeline, Server Name, Duration, Sent, Received, Latency and Protocols columns to the Sessions table from its header menu; shown columns and their order are kept per Project.
- Stop a live capture automatically after a set time or packet count (Settings → Capture → Stop automatically); the toolbar says why it stopped.
- Read plain HTTP/1 responses: the status, content type and length, server and redirect location appear in Layers and Frames; cookie and authentication values are never shown.
- Start and stop a capture from the new **Capture** menu (Command-E), and see every shortcut in **Help → Keyboard Shortcuts**.
- Name an address for the Project from a session's context menu (**Name Address**); the name shows wherever that address is the session's only name.
- See a session as a ladder diagram in the new **Ladder** facet: handshake, data, close, TLS and DNS steps as arrows between the two endpoints, each opening its frame.
- Unwrap GRE and VXLAN tunnels: sessions show the conversation inside the tunnel, labelled with the tunnel it used.
- Copy a session's host, destination address or port, process, or protocol as a session expression term from **Copy → As Session Expression**.
- See how many sessions have a known process in the status bar (for example **Process 82 of 138**) while capturing, so an empty Process cell reads as unknown rather than absent.
- Go forward again after **Back to Previous Scope** with **View → Forward to Next Scope** (Command-]).
- See each plain HTTP/1 request paired with its response in a followed stream: status, time to the first response byte, body size, and links to the frames that carried them.
- Save an HTTP/1 response body from a followed stream with **Save Body…**, de-chunked and otherwise exactly as sent.
- See the traffic of the sessions in view over time: when a search, filter or drill-down narrows the list, Overview's **Traffic over time** draws those sessions against all traffic on the same clock.
- See every name the capture's DNS and mDNS answers gave an address in **Statistics → Resolved Addresses**, with routes to that address's sessions and to the session whose answer taught the name.
- Reopen a capture file where you left it: its selected session and applied session expression come back, per Project, even for a moved or renamed copy.
- Show session start times in UTC or as seconds since the capture started with **View → Session Time**.
- Carry your notes into an exported PCAPNG, as capture comments and as a packet comment on each noted session's first frame that Wireshark shows, with **Include my notes and frame comments** in Export Frames.
- Merge two or more captures into one time-ordered PCAPNG with **File → Merge Captures…**; every frame keeps the name of the file it came from.
- See the sessions in view grouped by protocol path, with their share of sessions and bytes, in **Statistics → Protocol Hierarchy**.
- See every DNS name looked up in view, what came back and how fast, in **Statistics → DNS Lookups**.
- Report fast retransmissions (a segment re-sent where repeated duplicate acknowledgements asked) and spurious retransmissions (bytes re-sent after the peer had acknowledged them) as evidence-linked findings, filterable with `finding == fastRetransmission` and `spuriousRetransmission`.
- Plot packets or the average bit rate instead of bytes in the Overview's **Traffic over time**, and switch the small time chart to the retransmitted segments the findings in scope cite.
- Count plain HTTP requests by method, responses by status, and DHCP messages by type in **Statistics → Message Counts**, and find their sessions with the new `http.method`, `http.status` and `dhcp.message` expression fields.
- Split the open capture into a set of files every N frames or seconds, optionally shifting its times, with **File → Split Capture…**; the set opens at its first file and **Next File in Set** walks the rest.
- Keep each capture's findings in History, and let MCP clients read them with a new read-only `list_findings` tool (kind, severity and citation counts; sessions by ID only, never your notes). History is upgraded in place the next time a Project opens.
- Use Tracexy in Vietnamese: menus, windows, buttons, labels, help text and the "Showing … sessions" line follow the macOS language setting.
- Read a capture from the command line with the app's own analysis: `Tracexy summary|sessions|findings <file>` prints sessions and findings as text, CSV or JSON, filters them with a Session Expression, and can fail a CI step on findings (`--fail-on warning`).
- Save a long live capture as a set of files, a new one every 10 MB–1 GB or minute–hour, optionally keeping only the newest 5, 20 or 100, from **Settings → Capture → Save as a file set**; **File → Show File Set in Finder** reveals the set when the capture ends.
- Replace the MAC, IPv4 and IPv6 addresses in packet headers with consistent stand-ins when exporting frames (**Replace addresses**), with checksums recomputed; payloads are left as they are and the status says so.
- Import Wireshark display filters from a `dfilters` file as saved Session Expressions (**Investigate Sessions → Saved → Import Wireshark Display Filters…**); filters about single packets are listed with the reason they were not imported.
- Open LZ4-compressed captures, as Wireshark writes with `--compress lz4`; every LZ4 checksum is verified.
- Find hex bytes or text in a frame's hex dump, and copy the frame or the selected field's bytes as a hex dump, hex stream, printable text, C array, escaped string or Base64.
- Find slow or long sessions with `duration >= 5s`, `latency >= 200ms` and `start >= "…"` in the Session Expression; unknown timing counts as undecided rather than as a match or a miss.
- See whether DNS was encrypted: **Statistics → DNS Lookups → Encrypted DNS** lists DNS over TLS, QUIC and HTTPS resolvers beside the plain DNS sessions.
- Put color tags on sessions from their right-click menu, see them beside the host, and find them with `tag == red`; tags stay with the capture in the Project, like notes.
- See every finding in view at once from **Statistics ▸ Findings** (Option-Command-E), grouped by kind like Wireshark's Expert Information — severity, count, sessions and cited frames per kind — with a warnings-only filter, a search over summaries and hosts, a flat list, Copy, and a double-click that opens the session and its first cited frame or narrows to a kind's sessions.
- See traffic between address pairs in **Statistics ▸ Conversations** and per address in **Statistics ▸ Endpoints**, split into IPv4, IPv6, TCP and UDP like Wireshark's tabs: frames and bytes in each direction (Tx/Rx for endpoints), sessions, relative start, duration and bit rates, the name the capture or your Project gave an address, sorting, search, Copy as CSV, and a double-click that narrows the main window to that pair's or endpoint's sessions. Frame and byte totals match `tshark -z conv,ip` / `-z endpoints,ip` on the same file.
- Sessions now count the frames each side sent; File ▸ Export Investigation and the command line's session CSV/JSON gain `packets_up` / `packets_down`.
- The report windows — Findings, Conversations, Endpoints, Protocol Hierarchy, DNS Lookups, Message Counts, Resolved Addresses — live in a new **Statistics** menu.
- Report an acknowledgement of bytes the capture never saw its peer send — Wireshark's "ACKed segment that wasn't captured" — as a note, filterable with `finding == ackedUnseen` (and `tcp.analysis.ack_lost_segment` in imported Wireshark filters). It is claimed only once the peer's own sequence edge is known, so it points at the capture rather than the network.
- See which TCP stages each session's capture showed — Wireshark's `tcp.completeness` (SYN 1, SYN-ACK 2, ACK 4, data 8, FIN 16, RST 32) — in an optional **Completeness** column (`RFDASS` style, with the verdict in its help), and find sessions with `tcp.completeness == complete`, `incomplete` or a number; imported Wireshark filters on `tcp.completeness` translate too.
- See the frame lengths of the sessions in view in **Statistics ▸ Packet Lengths**, in Wireshark's ranges (0–19 … 5120 and greater) with count, average, minimum, maximum, rate and percent, a bar chart, and Copy as CSV. The counts match `tshark -z plen,tree` for every frame that belongs to a session.
- Choose how frame lists show time with **View ▸ Frame Time** — seconds since the session's first frame, since capture start or since the previous frame, local or UTC date and time, or epoch seconds — and mark a frame as time zero with **View ▸ Set Time Reference** (Command-T) or the Frames facet's context menu: it reads `*REF*` and later frames count from it, as in Wireshark.
- Decode captured bytes in **Show Packet Bytes**: from the Layers facet (**Show Bytes…**, the frame or the selected field) or an HTTP exchange in the Stream facet (**Show Body…**), undo Base64, gzip, zlib/HTTP deflate, raw deflate, percent-encoding, quoted-printable, ROT-13 or hex digits over any byte range, and read the result as text, pretty-printed JSON, a hex dump, a C array or an image; Copy and Save As write the decoded bytes. A body's Content-Encoding and Content-Type pick the first decoding and view, and decoding stops at 16 MiB.
- Print the Statistics windows from the command line: `tracexy stats <capture> --tap conv,ipv4|endpoints,tcp|plen|phs|expert|dns|http` (tshark's `-z` spellings accepted, several taps at once, optional `--expression`) as a text table, CSV or JSON.
- See every frame of a capture in **View ▸ All Frames** (Option-Command-A), Wireshark's packet list: number, time (in the View ▸ Frame Time format), source, destination, protocol, length and a Wireshark-style Info line (TCP flags, sequence, acknowledgement, window and length; TLS record types; DNS query or response with its name), limited by default to the frames of the sessions in view, with search, **Go to frame**, and a double-click that opens the frame's session and that exact frame in Layers. It lists up to 200,000 frames of a saved or stopped capture and says when there are more.
- Draw the capture as a sequence diagram in **Statistics ▸ Flow Graph**: one lane per address, one arrow per frame with its Wireshark-style Info, for the frames the All Frames list shows (sessions in view, search); double-click an arrow to open its session and frame, and Copy or Export the diagram as ASCII.
- Mark and ignore frames in **View ▸ All Frames** (right-click a frame), step between marks with **Previous Mark** / **Next Mark**, show or hide ignored frames, and export only the marked frames — **Export Marked…** opens File ▸ Export Frames with the new **Marked frames** scope.
- Comment on individual frames in **View ▸ All Frames** (**Add Frame Comment…** on a frame's right-click menu); the comments are written into those frames when you export frames as PCAPNG with **Include my notes and frame comments**, where Wireshark shows them as packet comments.
- Name a field on its own in a Session Expression to ask whether a session has it, as a bare field works in a Wireshark display filter: `finding` (any finding), `process`, `latency`, `sni`, `dns.query`, `dns.answer` — for example `sni and not finding`. Imported filters on `_ws.expert`, the TLS server name or DNS query/answer fields translate to them.
- Warn when a login secret crosses the wire unencrypted — an HTTP Basic `Authorization` header, an FTP or POP3 `PASS`, an IMAP `LOGIN`, or SMTP `AUTH PLAIN/LOGIN` on its standard port — as the finding "Credentials sent in cleartext" (`finding == cleartextCredentials`), citing the frame. Unlike Wireshark's Tools ▸ Credentials, Tracexy never reads out, stores or shows the user name or secret.
- Tell Tracexy how to read a port with **Capture ▸ Decode As…**, as in Wireshark: rules such as "UDP port 5300 decodes as DNS" (DNS, mDNS, NTP, DHCP, QUIC, STUN, TLS or HTTP/1, on the transports each runs over) are kept per Project, apply to every capture decoded afterwards, and **Decode Again** re-reads the open capture file with them.
- List every frame from the command line with `tracexy frames <capture>` — number, time, source, destination, protocol, length, Wireshark-style Info and session, as text, CSV or JSON, optionally only the frames of the sessions an `--expression` keeps (tshark's `-T fields` over these columns). The All Frames Info line now leads with the application summary (for example `GET /admin HTTP/1.1`) when there is one.
- All Frames marks the frames of the selected frame's session, with its first and last frames, as Wireshark's related-packet marks do.
- A capture opened at launch takes Wireshark's `-Y`/`--expression` and `-g`/`--frame` arguments (`open -a Tracexy capture.pcapng --args -Y "tcp" -g 42`).
- Fixed: going to a frame from All Frames, from a finding's "Open Session and Cited Frame", or from `-g` lost the cited frame when it also changed the selected session.
- File ▸ Open… takes an optional **Session Expression**, Wireshark's read filter in session form: the capture opens already narrowed to it, and an expression that does not parse keeps the panel open with the reason.
- **File ▸ Export Objects ▸ HTTP…** lists every HTTP/1 response body in the capture (frame, host, content type, size, file name) with Save… and Save All…; gzip and deflate bodies are decoded, and the saved bytes match `tshark --export-objects http`.
- Follow Stream shows each run's offset from the stream's first frame and gains **Filter Out This Stream**, which narrows the main window to every other session.
- Export Frames can **Include address names**: the names the capture's DNS/mDNS answers and your Project gave its addresses travel inside the PCAPNG as a Name Resolution Block, which Wireshark uses for its host names.
- Conversations and Endpoints gain an **Ethernet** tab (MAC address pairs), and the Session Expression gains `mac`, `source.mac` and `destination.mac` (Wireshark's `eth.addr`, `eth.src` and `eth.dst` translate to them), so an Ethernet row's Show Sessions narrows the main window.
- **Tools ▸ Firewall Rules…** writes a block or allow rule for the selected session in pf, iptables, nftables, ipfw, Cisco IOS or Windows Firewall syntax, matching its source, destination, destination port or the whole conversation; every pf rule it can write passes `pfctl -n`.
- The decode tree's layers now fold and unfold from their chevrons (which were drawn but did nothing), with Expand All and Collapse All on right-click; a folded protocol stays folded across packets, and clicking one of its bytes unfolds it.
- File ▸ Export Frames gains **Headers**, Wireshark's Strip Headers: write each frame from its innermost IP packet (raw IP) or from the Ethernet frame a VXLAN or GRE tunnel carries; frames without that inner packet are left out and counted. **Remove duplicate frames** and **Keep at most N bytes of each frame** match `editcap -d` and `editcap -s`.
- **View ▸ Zoom In / Zoom Out / Actual Size** (⌘+ / ⌘− / ⌘0) scale packet text in the hex dump, decode tree, Follow Stream transcripts and All Frames, per Project.
- Help menu: Tracexy User Guide (⌘?), Release Notes, Sample Captures, Show Captures Folder and Report an Issue, in place of the empty system Help item; Keyboard Shortcuts lists Restart Capture and the User Guide.
- Save statistics: Packet Lengths saves its chart as PNG or PDF and its table as CSV; Flow Graph saves the diagram as a paginated PDF (every frame) or a PNG; Conversations, Endpoints and Protocol Hierarchy gain Save as CSV, and Protocol Hierarchy also Copy as CSV.
- **Capture ▸ Restart Capture** (⇧⌘R) stops the running capture, lets it finish writing, and starts a new one with the same settings; **Capture ▸ Refresh Interfaces** reloads the toolbar's interface list so a newly attached adapter appears.
- Layers: the decode tree takes the keyboard — ↑/↓ move between rows, ← folds a layer or goes to its parent, → unfolds or enters it, ⌘→/⌘← unfold or fold everything.
- `tracexy glossary` lists expression terms, protocol keywords, finding kinds, statistics taps and Export Objects types (text or JSON), and `tracexy frames --column Protocol:Field` adds decode-tree fields as columns, like tshark's `-e`.
- `tracexy stats` accepts tshark's `ip_hosts,tree` … `ipv6_hop,tree`, `http_seq,tree`, `sip,stat` and `rtp,streams`, printing the IP Statistics, HTTP Request Sequences, SIP and RTP Streams windows' numbers; text tables keep a tree's indentation.
- Statistics ▸ RTP Streams ▸ **Stream Analysis…**: one stream packet by packet — delta, jitter, skew, bandwidth, marker and status — with its largest delta, jitter and skew, its loss, and its clock and frequency drift, and a graph of jitter, delta and skew over time, as Wireshark's RTP Stream Analysis.
- Statistics ▸ VoIP Calls ▸ **Flow Sequence**: the Flow Graph limited to one call — its SIP messages and the RTP streams its SDP offered, each drawn once with its payload and packet count.
- View ▸ All Frames: right-click ▸ **Conversation Filter** (Ethernet, IPv4/IPv6, TCP/UDP) filters the Sessions list to the frame's conversation, and **Tag** colors its session — Wireshark's Conversation Filter and Colorize Conversation.
- **Capture ▸ Enabled Protocols…** switches a protocol's recognition off per Project (its traffic stays plain TCP/UDP data, even under a Decode As rule), with Enable All and Decode Again — Wireshark's Enabled Protocols, in the Decode As window.
- **Statistics ▸ Service Response Time**: SMB2, LDAP and Kerberos request/reply timing per command or procedure (calls, min, max, average, sum), matching `tshark -z smb2,srt`, `ldap,srt` and `kerberos,srt`, and ICMP/ICMPv6 echo timing (requests, replies, loss, min/max/mean/median/standard deviation) matching `icmp,srt` and `icmpv6,srt`; also `tracexy stats --tap smb2,srt` and friends.
- **Apply as Column** (right-click a field in Layers) shows that field's value for every frame as a View ▸ All Frames column, up to four per Project; Remove Column takes it away.
- View ▸ All Frames: right-click ▸ **Copy** ▸ Summary as Text, …as CSV, …as YAML or …as HTML (Wireshark 4.6's packet-list copy formats; HTML pastes as a formatted table row).
- Recognize TFTP on UDP 69 (requests, blocks, errors, option acknowledgements; `tftp` in expressions and Decode As), and **File ▸ Export Objects ▸ TFTP** rebuilds each transferred file as `tshark --export-objects tftp` does — write-request uploads too, which Wireshark 4.6 misses.
- Recognize IP in IP (protocol 4) and 6in4 (protocol 41) tunnels, in IPv4 and IPv6: the inner flow becomes the session, as with GRE and VXLAN, and IP Statistics counts them as Wireshark does.
- **Apply as Filter** and **Prepare as Filter** on a decode-tree field or layer (right-click in Layers): addresses, ports, MACs, HTTP method/status/Host, TLS server name, DNS query, DHCP message type and protocols become the Session Expression that finds their sessions, joined to the current expression in Wireshark's six ways (Selected, Not Selected, …and/…or/…and not/…or not Selected).
- **File ▸ Export Objects** gains **Email (IMF)**, **FTP Data** and **X.509 Certificates** beside HTTP, in one window with a kind bar: SMTP messages as `.eml`, the files FTP RETR/STOR moved (tied to their PASV, EPSV, PORT or EPRT data connection) and TLS certificates as `.cer`, saved byte for byte as `tshark --export-objects imf|ftp-data|x509af` saves them; `tracexy objects --type` lists them too.
- **Statistics ▸ IP Statistics**: Wireshark's IPv4 and IPv6 Statistics trees — All Addresses, Protocol Types, Source and Destination Addresses, Destinations and Ports, and TTLs or Hop Limits — for IPv4 or IPv6, matching `tshark -z ip_hosts,tree` and its siblings row for row, with Copy and Save as CSV.
- **Help ▸ Supported Protocols**: every protocol Tracexy recognizes, what it reads from each, its expression keyword, and how many sessions of the open capture carry it, with Show Sessions.
- **Previous/Next Frame in Session** in View ▸ All Frames (⌃, / ⌃.), as Wireshark's Previous/Next Packet in Conversation.
- **Find in Frames** in View ▸ All Frames: Wireshark's Find Packet — a string, hex bytes or regular expression in each frame's bytes or decoded details, with Next (⌘G) and Previous and an "n of N" count.
- **File ▸ Export Packet Dissections…** and `tracexy frames --details`: every frame's layers and fields as plain text (tshark `-V` layout) or JSON, as Wireshark's Export Packet Dissections.
- **Shift times by N seconds** in File ▸ Export Frames… and `tracexy select --time-shift`, as `editcap -t` and Wireshark's Time Shift: correct a capture taken with a skewed clock.
- Command line: `tracexy info` (capinfos: the Get Info report with SHA-256/SHA-1), `tracexy select` (editcap: frames by number or by Session Expression, `--dedupe`, `--snaplen`, `--time-shift`, `--comment`) and `tracexy merge` (mergecap), the last two printing PCAPNG to standard output.
- **File ▸ Show File Structure** (Shift-Command-F): the capture file's own pcapng blocks or pcap records with offsets, lengths and key fields, as Wireshark's Reload as File Format/Capture; decryption secrets are never shown.
- **Statistics ▸ Plot…** (or right-click a numeric field in Layers ▸ Plot Over Time): a field's values over time as dots or a line, with a logarithmic scale and time from the first point, and a click on the plot goes to that frame — as Wireshark's Plots window.
- **Statistics ▸ Value Distribution…** (or right-click a field in Layers ▸ Show Value Distribution): every value one field took across the capture, with occurrences, percent and normalized Shannon entropy, as Wireshark's Distribution window.
- Capture from a named pipe carrying pcap or pcapng (**Capture ▸ Manage Interfaces ▸ Pipes**, or `--args -i /path/to.fifo -k`), read by Tracexy itself with no helper — the bridge for `ssh host "tcpdump -U -w -" > fifo`. Wireshark's `-i` and `-k` launch arguments also pick an interface and start capturing.
- **Statistics ▸ HTTP ▸ Request Sequences**: requests under the page that referred to them and redirect targets under the request they answered, to any depth, matching `tshark -z http_seq,tree`.
- **Statistics ▸ UDP Multicast Streams**: each source sending to a multicast group with its packet rate, average and peak rate, largest burst, buffer growth and burst/buffer alarms, computed as Wireshark's dialog of the same name, with its parameters editable.
- **Pin Session** (session context menu or Edit menu) keeps a session in a strip above the Sessions table whatever the filter shows, as Wireshark pins packets; clicking a pin inspects it without changing the filter.
- Recognize Kerberos (message type, and an error's code and realm) and LDAP (operation, message id and result code), matching tshark; principal names, bind names and credentials are never read.
- Recognize SMB (SMB2/3 command, status and ids), LLMNR and the NetBIOS Name Service, matching tshark's `smb2.*`, `llmnr` and `nbns.*` fields; LLMNR answers name hosts like mDNS.
- **View ▸ Name Resolution ▸ Resolve Network Addresses** shows names in the All Frames list — the Project's names, then the capture's own DNS answers, then named subnets — with no network lookups.
- **File ▸ Export PDUs…**: the application messages of the sessions in view — recognized datagrams and reassembled stream turns — written as Wireshark Upper PDU packets that Wireshark and tshark dissect directly.
- **Statistics ▸ VoIP Calls**: each SIP call with its From, To, start, duration, message count and outcome (in call, completed, rejected with its code, cancelled), as Wireshark's VoIP Calls.
- Recognize SIP and add **Statistics ▸ SIP**: messages, resent messages, status codes, request methods and call setup time, matching `tshark -z sip,stat`. Statistics ▸ DNS and ▸ SIP now share one outline window.
- **Statistics ▸ RTP Streams**: each RTP stream's payload, packets, loss, largest packet gap and jitter, computed as Wireshark's RTP Streams (matching `tshark -z rtp,streams`), with Show Sessions and CSV.
- Command line: `tracexy objects` lists a capture's HTTP objects and `--body <n>` prints one (as tshark's `--export-objects http`), and `tracexy follow` prints one TCP stream in the Follow Stream formats (raw matches tshark's `-z follow,tcp,raw`). Output goes to standard output only.
- Recognize SSH, FTP, SMTP, POP3, IMAP and SSDP: each gets its protocol label and expression keyword, and command and reply lines are named as Wireshark names them (matching tshark), while user names and passwords are never read out. They can also be chosen in Decode As.
- Show packet bytes as bits: the bytes pane's Hexadecimal / Bits choice (also View ▸ Show Bytes as Bits) writes eight bytes a row in binary, with byte-to-field linking unchanged.
- Name IPv4 subnets per Project (Statistics ▸ Resolved Addresses ▸ Name Subnet…), as Wireshark's `subnets` file: an unnamed address in a named block shows as `office.5`, and Endpoints can group each named block into one row. Names match `tshark -N n` with the same `subnets` file.
- **Capture ▸ Manage Interfaces…**: hide the system interfaces you never capture on (awdl, llw, utun, bridge…) from the capture menus, give an interface a friendly name and keep a comment, as Wireshark's Manage Interfaces does. The interface in use always stays listed.
- Session Expressions compare session measures with arithmetic, as Wireshark display filters do: `bytes.sent`, `bytes.received`, `frames`, `frames.sent` and `frames.received` join `bytes`, and a value can use `+ - * / %` with `{}` grouping, for example `bytes.received >= {10 * bytes.sent}`.
- **Statistics ▸ DNS**: Wireshark's DNS statistics tree for the frames in view (record types, classes, response codes, opcodes, sizes, name and section statistics, and request-to-response times), with Copy as CSV and Save as CSV. It matches `tshark -z dns,tree`, except that Response Stats counts each response once.
- **Statistics ▸ HTTP**: Wireshark's HTTP Requests (by host, then URI), Load Distribution (by server address and host) and Packet Counter (by method and status) trees for the frames in view, with Copy as CSV and Save as CSV. Counts match tshark's `http_req`, `http_srv` and `http` trees.
- View ▸ All Frames marks frames whose decoding stopped early, as Wireshark's Expert Info does: **[Malformed Packet]** for an invalid header and **[Packet size limited during capture]** for a frame the snapshot length cut inside a header, with the reason on hover and an **Only Decode Problems** filter; with View ▸ Validate Checksums on, frames with a wrong checksum join them. A UDP header cut short now keeps its ports in the decode tree.
- **View ▸ Validate Checksums** (off by default, per Project) checks the IPv4 header, TCP, UDP, ICMP and ICMPv6 checksums of the inspected frame and notes each verdict after the value: correct, incorrect with the expected value, partial (checksum offload), not present or unverified. The expected values and verdicts match Wireshark's with checksum validation on.
- **Mask IP addresses** now covers File ▸ Export Investigation (both CSVs, the JSON and the Markdown report), and the Save panel says when addresses will be masked. Address masking also catches an `address:port` written inside text, such as a note that says "proxy 10.0.0.5:3128", and keeps the port.
- Point at a byte in the Layers facet's hex dump to see which field owns it and its byte span; click a byte to select that field in the decode tree, which scrolls to it. The IPv4, TCP and UDP trees now list every fixed header field (DSCP, identification, flags, fragment offset, checksums, acknowledgement, header length, window, urgent pointer, UDP length) at Wireshark's byte offsets, and TCP flags cover both flag bytes.
- Save a followed TCP stream as Wireshark does: **Save Stream** in the Stream facet writes both directions or one as raw bytes, ASCII text, a hex dump, C arrays (`peer0_0`, `peer1_0`…) or YAML (peers and each turn with its frame, time and base64 data), or copies C arrays, YAML or the hex dump; a summary line counts each direction's frames and the stream's turns. Turns follow the frame that first carried each byte and match `tshark -z follow,tcp,raw`.

### Fixed

- Pasting a very long search or filter-rule value no longer stops a Project's tabs from saving: the fields stop at 512 characters, as stored.
- Saving Projects no longer re-writes and re-checks every Project on each change, so large catalogs save without pausing the window; each Project has room for all of its tabs and rules at their longest, and can always be exported.
- A save that keeps being refused for lack of room is reported once instead of after every pause in typing.
- **Close Other Tabs** asks first when the Project holds more tabs than can be added now, since those tabs could not all be opened again.
- The tab strip fades the edge that hides more tabs instead of cutting a tab through its title, and keeps the active tab clear of the fade.
- Importing a Project now respects the number of advanced Session Filter rules a workspace may add, as editing does; a Project whose workspace has more is refused with the limit named.
- The Filter Buttons and Macros editors no longer let a list that is already above its limit take in new entries by removing one and adding another; editing, reordering and removing always work.
- Filter buttons or macros this version cannot read are kept aside instead of being lost at the next save.
- A new Project waiting for a capture to finish is checked against the Project limit again before it is created.
- Cleartext HTTP/2 sessions whose connection preface shares a segment with the first frames are recognised as HTTP/2 again (the HTTP/2 filter and Protocol column missed them), and an HTTP/1 request line followed by a binary body in the same segment is no longer dropped.
- Projects, workspace tabs and advanced filter rules above the current limit (an imported or hand-edited catalog) are kept: a catalog holding more Projects or tabs than the current limit now loads and stays editable instead of failing to open, and saved filter rules and Focus Sets are no longer cut down when they are restored or applied. Only adding past the limit is refused, and the Projects window says so.
- File ▸ Get Info named a pcapng TLS key log block wrongly: the reader expected the wrong secrets-type code (`TLSK` is 0x544C534B).
- Statistics trees (DNS, HTTP, HTTP Request Sequences) now order rows with equal counts as Wireshark does, instead of alphabetically or by first appearance.
- The **HTTP/2** and **WebSocket** protocol filters could never match: sessions are now marked HTTP/2 from the cleartext connection preface or a TLS 1.2 ServerHello choosing ALPN `h2`, and WebSocket from an HTTP/1 Upgrade, as tshark reads the same frames.

- Opening or capturing traffic with tens of thousands of connections no longer stalls: past the connection, evicted-connection and event bounds, the oldest item is now found through a heap or an index instead of a scan (a 40,000-connection capture went from about 7.5 minutes to about 6 seconds, and 80,000 from 10 minutes to about 13 seconds).
- The inspector no longer overflows its column for a TCP session in a narrow window: the TCP Health chart picker becomes a pop-up menu when its segments do not fit.
- Statistics, All Frames, Decode As, Findings and the other auxiliary windows keep their Copy and Save buttons at the bottom edge when they have nothing to show, instead of under the empty-state message.

- A session selected from another window is scrolled to the middle of the Sessions table, clear of the inspector that opens with it, instead of to an edge where it could stay hidden.

- Returning to the Frames facet while a frame is cited no longer bounces straight back to Layers.

- The TCP finding cited on a segment that arrived beyond the expected sequence is now titled "TCP segment ahead of a sequence gap" instead of "out-of-order delivery": the frames show earlier bytes were not seen yet, not that they were reordered. `finding == outOfOrder` and imported `tcp.analysis.lost_segment` filters find it.
- Selecting a session from somewhere other than the table — Next/Previous Session With a Finding, a report window, Response times — now scrolls the Sessions table to that row instead of leaving it out of sight.
- Stop the app from crashing when VoiceOver or another accessibility client reads the Investigate Sessions editor in Expression mode.
- Keep the session count visible in the status bar when capture telemetry fills it; it moves to the leading edge instead of being squeezed out.

### Changed

- Status bar, inspector, History, finding and evidence text reads as plain phrases ("1 of 4 selected", "1 TLS session, 716 bytes", "NXDOMAIN response for example.com. 2 cited observations, bounded evidence.") instead of dot-separated fragments; protocol stacks read outer to inner with ›.
- Quitting during a live capture now stops it the same way Stop does, so its sessions are kept in History; the captured packets are still discarded unless you save the capture first.

- A reset that follows observed data now reports as "Connection aborted after data" instead of a generic TCP reset, and a retried SYN with no answer reports only as an unanswered handshake rather than also as a retransmission.

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
