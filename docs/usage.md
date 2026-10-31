# Usage

Tracexy is session-centric: the object you work with is a *conversation*, not a packet. Packets and
hex are demoted to an inspector tab, one click away when the bytes are the answer.

## Live capture

Choose the capture interface from the toolbar menu beside **Start/Stop**, on the right.
The compact label shows the interface's friendly name (for example, **Wi-Fi**); the menu,
tooltip, and accessibility value retain its BSD identifier (for example, **Wi-Fi (en0)**).
At narrow window widths the same menu becomes icon-only. Project selection remains separate
on the left. A vertical divider distinguishes interface selection from Start/Stop; a native gap
separates capture controls from Export and the inspectors. Export retains its button background
when disabled and becomes available when a session with retained capture frames is selected.

Live capture reads from a network interface through the signed privileged helper. By default, it
begins when you press **Start**. If you explicitly enable **Settings → Capture → Auto-start capture
on launch**, Tracexy starts capture after launch setup completes. Starting a capture clears the
previous live buffer and switches you to the live session list so traffic is visible as it arrives.
For ordinary internet traffic, choose the connected Wi-Fi or Ethernet interface. AWDL and
Low-Latency Wi-Fi are specialized sources that can report as running while showing no ordinary
internet sessions. If capture starts but the list stays empty, check the selected interface,
the BPF capture filter in **Settings → Capture**, and any search or session filters.

The helper streams raw frames to the app in batches; the app decodes them, groups them into sessions,
and refreshes the list a few times a second while capturing. The list is ordered oldest→newest and stays
stable as traffic arrives: sessions you are already looking at keep their positions and update in place
(their byte counts, duration, and status), while a genuinely new session appears at the bottom rather
than pushing the whole table down. **Settings → Capture → Stop automatically** ends a live capture by itself after a set time (1 minute
to 8 hours) or a set number of packets (10,000 to 1,000,000), whichever comes first, so a capture can be
left running unattended. Its sessions go to History exactly as when you press Stop, and the toolbar
shows the reason, for example "Stopped after 15 minutes". Clearing the list during a capture restarts
the packet count but not the time limit.

**Settings → Capture → Save as a file set** writes a long capture as a set of PCAPNG files: a new file
every 10 MB, 100 MB or 1 GB, and/or every minute, 10 minutes or hour, whichever comes first. The set goes
to its own folder, `Captures/File Sets/Capture <date and time>`, in the active Project, with names like
`capture_00001_20270115080000.pcapng` that **File → Next File in Set** walks. When the capture ends the
last file joins the set, the toolbar status says how many files were written, and **File → Show File Set
in Finder** reveals them. **Keep newest 5 / 20 / 100** deletes older files of that set as the capture runs
(nothing is ever deleted with **Keep every file**); a finding or evidence row that cites a deleted file says
the file was removed by the file-set limit rather than showing other bytes. Sessions and findings keep
covering the whole capture. **Follow** and **Frames** read the newest file; **Save Capture**, session export
and **Export Frames** use every file still kept, merged in capture order.

**Follow Live** in the Sessions command strip keeps the newest visible
session selected; selecting another row, navigating with the keyboard, scrolling the history, or turning
the control off yields that follow behavior. **Jump to Latest** is a one-time jump and never changes the
Follow Live setting. Both actions honor the current filters. The in-memory inspection window is bounded,
while accepted live frames are also written to a local disk-backed spool for complete save/export. If
the helper is not yet approved, Tracexy tells you to approve it in System Settings → Login Items and
press Start again. If the capture source stops on its own — the interface goes away or is
reconfigured — Tracexy settles the capture exactly as an explicit Stop would (final fold, History
entry, save eligibility) and shows the reason instead of leaving "Capturing" on with nothing arriving.
Quitting while a capture runs asks for confirmation unless you turn that off in
**Settings → General**.

The centered capture status in the toolbar opens **Capture Readiness**. It reports the selected
interface, helper or direct-capture path, BPF filter, packet snapshot and promiscuous settings, bounded
memory window, interface drops, helper drops, and frames outside the in-memory window. Unknown and
stopped values are labelled explicitly instead of being presented as zero. The popover also links
directly to Capture and Helper settings for recovery.

**Settings → Helper** shows registration, reachability, bundled metadata, installed metadata, and
the result of verifying the exact running helper executable. From there you can install, update,
uninstall, or recheck the helper. A normal protocol-v5 app update preserves the existing Login Items
approval: Tracexy requests an idle helper restart and verifies that a new launch is running the exact
signed bytes embedded in the app. The one-time protocol-v4 migration remains an explicit **Update**
because that older contract cannot request a safe maintenance restart.

If a registered helper stops answering, Tracexy times out the request, reports it as unreachable,
and ends an affected live capture instead of leaving the UI stuck. If an automatic executable refresh
was already requested, **Retry Safe Recovery** reconnects and verifies it without unregistering. For
other unreachable registration drift, **Repair Registration** explicitly unregisters and re-registers
this app's service (no admin password), which can require Login Items approval again. **Force Reset &
Reinstall** is the next, confirmed recovery action for stale
launchd/helper state: it asks for an administrator password, removes only Tracexy's own privileged
helper and launch daemon, and — only after that succeeds — unregisters and reinstalls the bundled
helper before re-probing it, so the result always reflects the real final status. If the administrator
prompt is cancelled, nothing is removed and no reinstall is attempted. If normal recovery still can't
clear the helper, Tracexy shows last-resort guidance to reset macOS Login & Background Items yourself.
Because that global reset affects Background Items for other apps too, Tracexy never runs it for you:
it displays the exact command (`sudo /usr/bin/sfltool resetbtm`) with a Copy Command action, and you
run it in Terminal, restart your Mac, then install the helper again from Settings.

## Opening saved captures

Open a `.pcap` (classic libpcap) or `.pcapng` file from disk — no helper or admin rights required.
Tracexy sniffs the file format and streams bounded frame reads through the same decode → session fold
off the main UI actor. The current workspace remains usable while byte progress is shown; sessions are
published once, only after the complete accepted input has been folded. A truncated final record keeps
complete earlier sessions and shows an explicit warning, while malformed or cancelled opens replace no
existing workspace state.

Only the recent raw-frame inspection window stays in memory. Session summaries cover the whole opened
file, and the Inspector reopens exactly one representative frame by validated file offset when a saved
session is selected. Opening another file, clearing, or starting live capture retires stale progress,
results, and selected-evidence reads.

**File → Open… (⌘O)** opens a capture *where it is*. Tracexy records a small reference in the
active Project's Library (a `.tracexyref` sidecar next to its managed copies) and reads the
file in place, so a multi-gigabyte capture is never copied. The Open panel previews the chosen
file before you commit — format, size, records, and start / elapsed — from a bounded scan, and
says "timed out at N records" rather than pretending to know the total of a very large file.
Its **Session Expression** field is Wireshark's read filter in session form: the capture opens already
narrowed to the sessions the expression finds (an expression that does not parse is shown in red and keeps
the panel open). Its **Copy into Library** checkbox switches to the managed-copy path; the choice is remembered
per Project. **File → Import into Library… (⌥⌘O)** and the sidebar's Import action always copy.
Opening a `.pcap`, `.cap`, `.pcapng` or `.ntar` file from Finder (**Open With → Tracexy**, or
dropping it on the Dock icon) and dropping a capture file anywhere on the main window follow the
Project's Open preference; Tracexy registers as an alternate viewer for those types and does not
claim them as the default. One capture is opened per drop — a multi-file drop is refused with a
message rather than opening only its first file — and a file opened before the app has finished
loading Projects opens once loading completes. Tracexy decides the format from the file's own
header, so a capture stored as `evidence.bin` or with no extension is accepted. Gzip and LZ4
PCAP/PCAPNG (LZ4 as Wireshark writes it with `--compress lz4`, or the `lz4` tool, including linked blocks;
every LZ4 checksum present is verified) and the capture payload in the observed TCP Viewer schema-1 `.tcpviewsession` archive are always
expanded into a managed capture, whichever way they were opened. Other compressed or session
formats — Zstandard, bzip2, xz — are refused with a concrete recovery message. Recognizing a header or archive is not a
guarantee that the whole capture parses, so the streaming open above still reports truncated or
malformed input. Importing never overwrites: a capture whose name is already taken is kept under
a unique name beside the existing one, and the original source on disk is never moved. Switching
Projects while a panel is open cancels the open rather than filing the capture into the new Project.

**File → Import Hex Dump…** brings packet bytes copied from a log or diagnostic into the active
Project. Choose the text file and its link-layer format (Ethernet, Raw IP, Linux cooked v1 or v2).
If each source packet contains a complete IPv4 or IPv6 packet but no link-layer bytes, choose
**Ethernet** and **Add synthetic Ethernet to complete IP packets**. Tracexy checks each IP
version and declared length, prepends a 14-byte Ethernet header with generated locally
administered MAC addresses, and keeps the original IP bytes and timestamps unchanged. The
managed filename includes `synthetic-ethernet` so the generated layer is apparent. An
incomplete IP packet or a different selected link type refuses the whole import. This option
does not create IP or transport headers from application payloads. To import bytes that are
only a UDP payload, choose **IPv4 + UDP from payload** or **IPv6 + UDP from payload** under
**Synthetic headers**, choose Ethernet or Raw IP frame format, and enter both IP addresses
and UDP ports. Tracexy generates the IP/UDP lengths and checksums; inbound direction swaps
the generated source and destination endpoints. The managed filename includes
`synthetic-udp`. The original payload bytes stay at the end of each generated packet.
This mode does not infer endpoints from application bytes or recreate a real captured
header; supply endpoints that describe the intended synthetic context.
For application bytes from a TCP stream, choose **IPv4 + TCP from payload** or
**IPv6 + TCP from payload** and enter the same explicit endpoint fields. Tracexy
generates IP/TCP checksums and starts synthetic sequence numbers at zero separately
for each direction, advancing them by each payload's byte length. Generated packets
carry payload bytes without fabricating a SYN, ACK, or handshake; connection lifecycle
and timing evidence from them should be read as synthetic context, not observed traffic.
The managed filename includes `synthetic-tcp`. TCP and UDP modes each accept Ethernet
or Raw IP output.
For existing SCTP chunk bytes, choose **IPv4/IPv6 + SCTP from chunks**, enter the
endpoint fields and a decimal verification tag. Tracexy checks chunk boundaries and
adds the SCTP common header, CRC32C, IP header and optional Ethernet header. For
application bytes, choose **IPv4/IPv6 + SCTP DATA from payload** and enter a decimal
payload protocol identifier (PPI). That mode adds one DATA chunk per input packet,
with synthetic per-direction TSNs starting at zero and a zero verification tag.
The generated headers do not establish an SCTP association or prove delivery;
Tracexy currently exposes bounded SCTP frame fields but does not fold SCTP sessions
or reassemble its streams. The managed filename includes `synthetic-sctp`.
Choose the source's **Offset format**: hexadecimal (default), decimal, octal, or **No offsets (one frame)**.
In the first three modes each row starts with an offset in that base; an offset of zero starts a new packet.
No-offset mode joins all non-comment byte rows into exactly one frame. It accepts whitespace-separated
hexadecimal byte tokens, with no offset tokens or ASCII columns. **Byte groups** defaults to
**Single bytes**, requiring exactly two hex digits per token. Select **Network order (1–4 bytes)**
for groups of 2, 4, 6 or 8 hex digits, or **Little endian (1–4 bytes)** to reverse the byte order
within each group; groups never reverse the order of whole lines. Offset modes also accept Tracexy's
own hex/ASCII rows. A gap, malformed byte or mismatched ASCII column refuses
the whole import. The input is limited to 32 MiB, each packet to 1 MiB, and all packet
bytes together to 16 MiB. Tracexy adds a managed PCAPNG under a unique name, leaves the text source
untouched, and does not invent capture timestamps. For dumps that put one UTC ISO 8601 line before each
packet's zero offset, select **Read UTC timestamp lines before each frame**. In no-offset mode, one
UTC line may instead precede the first byte row. For example,
`2026-10-24T10:30:01.250Z` on its own line precedes `000000 aa bb`. UTC timestamps can have
one to six fractional digits, matching the PCAPNG writer's microsecond precision. Every packet must have exactly
one timestamp; malformed, missing and orphan timestamps refuse the whole import. With the option off,
timestamp lines are refused and frames remain untimed. With UTC timestamps enabled, select
**Read I/O direction before each UTC timestamp** for optional `I` (inbound) or `O` (outbound)
before a timestamp, such as `I 2026-10-24T10:30:01.250Z`. The marker describes capture-interface
direction, not which endpoint began a conversation. A packet without a marker has unknown direction;
Tracexy writes known direction to PCAPNG packet flags and refuses direction markers without real
timestamps rather than inventing times. **View → All Frames** shows the interface-relative value
in its **I/O** column (`I`, `O`, or `—` when unknown). For a text log, select
**Extract packets with a regular expression** and choose **Regex match scope**. The default
**One packet per line** needs a whole-line pattern. **Across the file** searches for nonoverlapping
matches that can span lines; only whitespace and `#` comment lines may remain between matches,
so other unmatched text refuses the import. Each match needs a `(?<data>...)` group. The optional
`(?<time>...)` group accepts the same UTC ISO 8601 timestamps;
`(?<dir>...)` recognizes `I`/`i`/`<` as inbound and `O`/`o`/`>` as outbound, and requires a valid time
for known direction. Choose **Regex data encoding** independently of the offset-mode byte groups:
hexadecimal accepts pairs of digits with optional whitespace or colons, octal uses three digits per
byte, binary uses eight bits per byte, and Base64 requires canonical padding; each also accepts
interspersed whitespace. Incomplete bytes or invalid symbols refuse the whole import. A line may
also capture `(?<seqno>...)` as a positive decimal packet ID. It needs a real UTC
time and is stored as `epb_packetid` in PCAPNG; classic PCAP cannot carry it.
The one-line scope also refuses any unmatched nonblank, noncomment line. Regex mode ignores the
offset, byte-group and timestamp controls above it; matching has a soft roughly half-second deadline
per candidate and a 30-second import deadline. It does not synthesize protocol headers.

A referenced capture shows a clock badge while Tracexy checks its file in the background; it is
not treated as readable until the file identity is verified. The badge then becomes a link. Opening
the row performs its own background recheck. If the file is moved or replaced the
badge turns into a warning, and opening it shows an inline notice with **Locate…** (choose the
moved file; Tracexy accepts only a file with the same size and leading bytes) or **Reload**
(re-read the file now at that path). **Remove from Library** on a reference trashes only the
sidecar and never touches the file; **Copy into Library** turns a reference into a managed copy.
**File → Open Recent** lists recently opened captures by name with **Clear Menu**;
**File → Close Capture (⇧⌘W)** clears the workspace; **File → Reload (⌘R)** is enabled when
the open capture changed on disk. Captures written in rotation by `dumpcap` or `tcpdump`
(`name_00001_20260919120000.pcapng`, …) can be stepped through with **File → File Set →
Next File / Previous File**, always in place; a member's Library row also carries a **File Set**
menu that lists the set with the open file checked, so any member opens from there.

Copying runs off the UI thread with progress and **Cancel Import**. Source-changing actions
stay held until copying or cancellation cleanup finishes; switching Projects waits and keeps
the copy in its original Project. A complete copy published just before cancellation stays
in the Library but does not open automatically. See [Capture migration](capture-migration.md)
for Wireshark and other tools, conversion tradeoffs, supported artifacts, and recovery.

### Export Packet Dissections…

**File → Export Packet Dissections…** offers plain text, Summary CSV, or JSON. For plain text, select any combination
of packet summary lines, supported decoded details, and captured packet bytes. Details show the layers and fields in
**Layers**; bytes use a hex and printable-ASCII view of the actual captured frame. At least one text section must stay
selected. JSON writes one object per frame with number, UTC time, captured and on-the-wire length, session, and nested
layers. For text exports, when **Captured packet bytes** is selected, the default-off **Include timestamp preamble**
option adds each frame's UTC timestamp immediately before its hex dump (`unknown` when the frame has no timestamp).
JSON normally writes each field's name and decoded value. Its default-off **Include raw field bytes** option
adds a top-level `raw_field_bytes_included` marker; mapped fields also get `raw_hex`, `raw_byte_offset` and
`raw_byte_length` for an exact contiguous range of the captured frame. It includes the full backing byte for bitfields and
does not imply bit-mask extraction. Fields without
a contiguous mapping, outside the captured frame, or beyond the 4 KiB per-field / 32 KiB captured-byte per-frame bounds have
`raw_hex: null` and a `raw_hex_status` explaining why. Reassembled fields have no raw mapping. Summary CSV writes
original number, UTC time when known, source, destination, protocol, captured length and Info; capture-derived cells
are quoted and guarded against spreadsheet formulas. When the current Project has applied All Frames
field columns, CSV offers a default-off **Include applied field columns** option; checked columns are
inserted before Info in their configured order. Repeated field occurrences are comma-joined in one cell;
each decoded value is capped at 200 characters as in the All Frames projection, and each added CSV field
cell is capped at 8 KiB with an ellipsis for a longer joined value. These formats cover the frames of the
sessions in view, or the whole capture when nothing is filtered out. Text with captured bytes requires a separate raw
data acknowledgement, regardless of Privacy settings, since bytes can contain credentials and message content. JSON
raw field bytes require the same acknowledgement. Other exports confirm when Privacy protections are on because decoded
values can spell out unmasked addresses, names and URLs.
When ignored frames exist, the save panel offers **Exclude ignored frames**, unchecked by default; it snapshots the
current ignored frame numbers, applies the option only after the chosen packet scope matches, and reports how many
frames it omitted. The decoder still reads every source frame in order. The file appears only once it is complete;
if preparation fails, an existing file chosen in the save panel keeps its previous contents.

**File → Export Capture Frame Range Dissections…** accepts original capture frame numbers such as `5,10-15,20-`.
It scans the complete stable capture and exports only those frames in the same text, Summary CSV, or JSON formats.
This range is capture-wide even when session filters are active. Invalid ranges stop before the save panel; a
truncated capture stops the export without replacing a previous file.
In All Frames, right-click a row and choose **Export This Frame’s Dissection…** to export only that original
capture frame number in text, Summary CSV, or JSON. It also works for a frame that is not folded into a session;
the standard ignored-frame option, privacy confirmation, and atomic file publication still apply.
Choose **Export This Frame…** from the same menu to write that frame's captured bytes as a one-frame PCAP or
PCAPNG capture. The regular capture-export format, metadata, ignored-frame and privacy controls still apply;
the action does not export the current page or the selected session.
**File → Export Marked Packet Dissections…** exports exactly the frame numbers marked in All Frames across the
capture, regardless of session filters. The action is available once at least one frame is marked and uses the
same format picker and privacy confirmation.
**Export First to Last Marked Dissections…** includes every capture frame between the earliest and latest mark,
including unmarked frames between them. It also ignores session filters.
When a Frame Expression is applied in All Frames, **Export Matching Dissections…** scans the complete stable
capture and writes only frames where the expression evaluates true. Unknown frames are omitted and counted in the
result; the action is capture-wide and does not depend on the retained All Frames page or session visibility. It
uses the same text, CSV and JSON formats, spreadsheet protection, privacy confirmation and atomic file publication.
When a Frame Expression is applied, **All Frames → Print Matching Packet Views…** prints a summary, decoded
dissection, or captured bytes for every matching frame in the complete stable capture. Frames whose expression
result is unknown are excluded and counted in the outcome. This scope is capture-wide and does not use the current
session visibility or retained All Frames page; captured bytes still require the raw-byte acknowledgement.

**File → Print Packet Views → Custom Packet Views…** lets you combine summary lines, decoded details, and captured bytes
for the sessions in view. Choose at least one section; selected sections appear in that order for each frame.
When ignored frames exist, packet-view printing asks whether to **Exclude ignored frames**; the choice is off by default
and applies only to frames in the selected print scope. The decoder still reads every source frame in order, and the
print outcome reports omitted ignored frames.
**Packet Summaries…** prints compact source, destination, protocol and Info lines with original
frame numbers. **Packet Dissections…** prepares the supported decoded layers and fields for the sessions in view and
opens the macOS print panel after the stable source has been checked. It requires a saved capture or a fully
stopped live capture. Printing is limited to 8 MiB of decoded text and a bounded page-layout height; narrow
the sessions in view or use the file export for a larger result. Summary and dissection print layouts omit packet bytes, but can contain
unmasked addresses, names and URLs, so Privacy protections require a separate confirmation before preparing the print view.
**Packet Bytes…** prints a hex and printable-ASCII view of each captured frame. It always asks for a separate
raw-byte acknowledgement, since the print panel can send packet contents to a printer or save them as PDF.
The **Marked Packet Summaries…**, **Marked Packet Dissections…**, and **Marked Packet Bytes…** actions print only frames marked in
**View → All Frames**, retaining their capture frame numbers. The three **First to Last Marked…** actions include
every frame between the earliest and latest mark. Every print layout uses the same stable-source check and
8 MiB text limit. The three **Capture Frame Range…** actions accept original capture frame numbers such as
`5,10-15,20-`; their scope is capture-wide, even when the Sessions view is filtered. The range stays compact in
memory and is applied while scanning the stable source. Combined layouts that include captured bytes require the raw-byte acknowledgement.
In **View → All Frames**, a frame's context menu also offers **Print This Frame** as a summary, dissection, or
captured-byte view. This uses that frame's original capture number and the same source checks, text bound, and
privacy confirmations as the File menu actions.

### File structure

**File → Show File Structure** (Shift-Command-F, Wireshark's Reload as File Format/Capture shortcut) lists the
capture file itself, block by block: every pcapng block — Section Header, Interface Description, Enhanced
Packet, Name Resolution, Interface Statistics, Decryption Secrets, custom — or the pcap file header and each
packet record, with its byte offset, length and key fields (version and byte order, link type and snap length,
the frame number and captured/on-the-wire bytes). Decryption secrets are sized, never shown. Packet data is
skipped, not read, so a large file lists quickly; the first 200,000 blocks are listed and all successfully
walked blocks are counted, with a breakdown by block type in the footer's help. **Block Type** filters that retained list; the footer
shows the filtered count against the listed and total counts. An empty filtered list means no matching block
was found in the listed prefix, not that none exists later in a larger capture. Filtering runs off the main
thread and does not reopen or read packet data. A file that ends mid-block says where it stopped. The
blocks and lengths match `tshark -X read_format:"MIME Files Format"`.

### Finder previews and Spotlight

Tracexy ships a Quick Look preview and a Spotlight importer for `.pcap` / `.pcapng` files. Press
Space on a capture in Finder (or use the Open panel's preview column) to see its format, size,
record count, start / elapsed, the writing application and comment, and the interfaces it declares
— the same bounded scan the Open panel runs, never packet payload. Spotlight indexes the format,
record count, capture dates, duration, interface names and writing application so a capture can be
found by what it is; no address, host name or payload is indexed. Both run sandboxed inside the
app bundle and share the app's readers.

### Capture Info (⌘I)

**File → Get Info (⌘I)** opens a window with what the capture file says about itself: name,
location, kind (managed copy or opened in place), format and variant, size, first and last frame
time, elapsed span and time order; for PCAPNG, each section's hardware, OS, application and
comments, and a sortable table of interfaces with name, description, link type, snapshot length,
time resolution, capture filter, frame count and the received/dropped counters from Interface
Statistics Blocks; a statistics group (frames, bytes, average frame size and rate, sessions);
and an inventory of blocks Tracexy does not interpret — decryption secrets
(type and size only; the secrets are never read or used), custom and unknown blocks. PCAPNG
Name Resolution Blocks show retained mappings and any mappings or oversized blocks omitted by
the parser's memory bounds. **Compute
SHA-256 and SHA-1** hashes the file on demand with progress and Cancel, and refuses if the file
changed since it was opened. **Copy** puts every value on the clipboard as text. Strings written
by the tool that created the file (comments, names, filters, application) appear only in this
window; they never enter Sources, History, automation, MCP or the Assistant. For a PCAPNG with
several interfaces, the Context dock shows **Captured on** for the selected session.

### Frames

The bottom inspector's **Frames** facet lists every frame of the selected session in capture
order — number, time relative to the session's first frame, direction, length, TCP flags, the
capture interface when a PCAPNG declares more than one, a one-line summary and a comment marker —
rescanned on demand from the stable source (the open file, or a copy of the stopped live spool). Selecting a row loads that exact frame into Layers,
Payload and Hex through the same guarded path as finding citations. The list holds references
only, never bytes, and is bounded at 10,000 frames; the footer says when it is a prefix of a
larger session and when the source ends mid-record. **Rescan** re-reads the source; an active
live capture offers no Frames facet until it is stopped.

### Merge Captures…

**File → Merge Captures…** combines two or more PCAP or PCAPNG files — for example a client-side and a
server-side capture of the same problem — into one PCAPNG in capture-time order, then opens it. Each
source interface becomes its own interface in the merged file, described by the source file's name, so
every frame still says which file it came from (Wireshark shows it as the frame's interface
description). Frames with equal times keep the order the files were chosen in. A frame without a capture
time cannot be placed and stops the merge with nothing written; so does choosing one of the sources as
the destination. The sources are only read, and the merged file is published after every source is
verified unchanged. Frame comments in the sources are not carried over, and the status says so.

### Split Capture…

**File → Split Capture…** writes the open saved capture as a set of PCAPNG files — a new file every N
frames or every N seconds (measured from each file's first frame) — optionally shifting every frame's time
by a number of seconds, as `editcap -t` does. You choose a folder and a prefix; the files are named
`prefix_00001_YYYYMMDDHHMMSS.pcapng` from each file's first (shifted) frame, the naming **File → Next File in
Set** already walks, and the first one opens. Every file is written under a hidden temporary name and the
set is published only after the source is verified unchanged, so a refusal or failure leaves nothing
behind; an existing file of the same name is never replaced. Frames without a capture time cannot be
written and stop the split. Frame comments are not carried over, and the status says so.

### Export Frames…

**File → Export Frames…** (also in the toolbar Export menu, a session row's Export menu with the
session preselected, and the Library row of the open capture) writes a new capture file from a
scope: **Whole capture**, **Sessions in view** (filters, Focus Sets, Noise Control and removed
rows applied), **Selected session**, a **Time range** on the capture clock, or **Frames matching the
applied Frame Expression**. **Export Matching Frames…** in All Frames preselects that last scope.
It reevaluates the accepted expression from a streaming decode of the complete capture; the current
page's retained matches do not limit the export, and the Sessions in View and search controls do not
change this explicitly named scope. When ignored frames exist, **Exclude ignored frames** is available
as a separate, unchecked-by-default option for any export scope; it snapshots the currently ignored
capture ordinals and reports the number excluded from the selected scope. The decoder still processes
every source frame, so this output choice does not remove ignored frames from analysis. Unknown
expression results are excluded and counted in the export status. The Save panel's
Format pop-up offers PCAPNG (default) and classic PCAP; PCAP stays listed but disabled, with the
reason, when the source mixes link types or holds untimed frames. **Preserve capture metadata**
carries section hardware/OS/application and comments, interface names, descriptions and filters from a PCAPNG source. Metadata beyond the bounded section/interface inventory is reported as potentially unavailable; section comments and text clipped by their individual bounds are reported as omitted or truncated.
Complete PCAPNG per-frame option lists are copied verbatim only when the source is little-endian, the export
keeps the complete frame sequence, and the packet bytes are unchanged. For selected/subset frames and other byte
orders, independent packet comments are preserved; packet hashes are preserved only while the bytes stay
unchanged; packet IDs and direction flags are reconstructed from typed source facts. Unsupported or
sequence-dependent options are counted in the export status. Options tied to original bytes are not carried onto
changed packets after header stripping, address replacement or truncation. **Include my notes and frame
comments** (shown when the capture has notes or frame comments) writes the notes on the exported sessions into the PCAPNG
section as capture comments, each naming its session (and finding), which Wireshark shows under Capture
File Properties, and also puts each session's notes on that session's first exported frame as a packet
comment (Wireshark's `frame.comment`), beside any comment the frame already carried, and writes each frame
comment from View ▸ All Frames on its own frame. The panel's optional **Additional capture comment for this
export** is written first among the investigator's section comments in the new PCAPNG, before included
session/finding notes; it is limited to 16,000 UTF-8 bytes and is never saved to the source capture or Project.
A nonempty comment blocks saving as classic PCAP or with **Replace addresses**, since those outputs cannot
carry it safely. **Include address names** (shown when the capture's DNS or
mDNS answers, or you, named addresses) writes those names into the PCAPNG file as a Name Resolution Block, so
Wireshark shows the same host names without resolving them itself; **Replace addresses** writes a copy you can share more safely: every MAC, IPv4 and IPv6 address in
the packet headers (including ARP and the header an ICMP error quotes) is replaced by a consistent stand-in
— `10.x.y.z`, `fd00::…`, `02:00:00:…` — in first-seen order, so conversations still line up; broadcast,
multicast, loopback and unspecified addresses keep their meaning, and IP, TCP, UDP and ICMP checksums are
recomputed. **Payloads are not changed** — DNS answers, HTTP headers and TLS server names still carry what
they carried — and copied metadata and notes are left out. A frame whose headers cannot be parsed safely is
left out and counted in the status. **Headers** strips tunnel encapsulation as Wireshark's Strip Headers
does: **Strip to the inner IP packet** writes each frame from its innermost IPv4 or IPv6 header as raw IP,
and **Strip to the inner Ethernet frame** writes the Ethernet frame a VXLAN or GRE tunnel carries; frames
without that inner packet are left out and counted (addresses are replaced after stripping, so the inner
headers are the ones replaced). **Remove duplicate frames** leaves out a frame whose bytes match one of
the five frames before it exactly, and **Keep at most N bytes per frame** keeps only the first bytes of
each frame while recording its original length, as `editcap -d` and `editcap -s` do; both are counted in the
status. **Shift times by N seconds** moves every written frame's time, earlier with a negative number, as
`editcap -t` does. This is a fixed offset on the frames in the export; the open source capture is unchanged.
For a saved capture, **Edit → Time Shift…** applies a whole-capture offset, one frame/time anchor, or two anchors
for linear clock drift. The overlay includes ignored and filtered frames, and **Undo Time Shift** restores the
source timestamps. Sessions and time-based evidence are recomputed together. **Save Capture** or a corrected
PCAPNG export writes the shifted timestamps plus a bounded provenance comment into a new file; the original
file remains unchanged. The capture retains PCAPNG microsecond timestamp precision. **Compress with gzip** writes a `.gz`. The export streams from the source with progress and **Cancel Export**, is
published only after it completes and the source is verified unchanged, and reports anything it
could not carry (for example frame comments from a big-endian section). Exporting raw packet
formats while privacy protections are configured asks for the same acknowledgement as session
export.

To correct a capture clock, choose **Correct timestamps in exported copy** and set one frame to a known time
for a fixed offset, or two frames to correct linear clock drift. Tracexy reads the source times for those
1-based frame numbers, writes every frame to a new PCAPNG at microsecond precision, adds a section comment
describing the correction, and opens the copy so sessions, evidence, findings, timelines and History are
computed from the corrected file. Untimed frames remain untimed. The source file is not edited; correction
requires the full capture scope and cannot be combined with packet-removal, byte-transform, gzip or classic
PCAP options. History labels the result as corrected from its declared section comment. This creates a
corrected copy; in-memory Apply/Undo and fractional-second anchor entry are not provided.

Sessions, Overview and Flow name the active scope and show visible sessions against the
capture total. **Reset Session Filters** clears the current workspace’s filters and sidebar
protocol lens. Noise Control and sessions removed from view have separate recovery actions;
resetting a filter does not change those choices or another workspace.

### Export Investigation

**File → Export Investigation** writes what the Sessions list shows right now — after its pills,
search, sidebar scope, rules and session expression — as a file you choose:

- **Sessions as CSV…**: one row per session in view with its start time (UTC), duration, protocols,
  status, host, process, endpoints, bytes each way, latency, the titles of its findings and whether
  you wrote a note on it.
- **Findings as CSV…**: one row per finding on those sessions, with its severity, the session it was
  reported on and the frames it cites.
- **Sessions and Findings as JSON…**: both, plus the scope that produced them (how many sessions were
  in view of how many, and the session expression) and your notes.
- **Investigation Report…**: a Markdown document with the scope, a findings table with cited frames,
  your notes, and the sessions (the first 500; the CSV has all of them).

An unknown start time or duration is left empty (`null` in JSON), never written as zero. Text taken
from the capture that a spreadsheet could read as a formula is prefixed so it stays text. With
**Settings → Privacy → Mask IP addresses** on, every address in these files — hosts, endpoints, notes,
finding text and the expression — is written as `[masked-ip]`, keeping ports. Nothing is sent
anywhere; the file stays where you save it.

## Projects

A Project is a complete, isolated investigation. Use the Project selector in the main toolbar,
immediately beside the sidebar controls, or the **Project** menu to switch, create, rename, and manage
Projects.

Each Project owns, separately from every other Project:

- its captured sessions, investigation snapshot, findings, evidence, retained frames, capture
  statistics, errors, warnings, and throughput chart;
- its workspace tabs — names, filters, grouping, navigation, inspector layout, selected session, and
  structured query drafts and results;
- its saved-capture Library folder and its local History database, including History selection,
  paging, Clear, and retention;
- its capture settings (interface, filter mode and BPF, snap length, promiscuous mode, retention
  size, auto-start), its privacy settings (payload redaction, credential stripping, IP masking,
  History Auto-clear), and its pins, Focus Sets, muted noise, hidden sources, and default view.

Appearance, byte units, quit confirmation, workspace restoration, the selected Settings tab, the
"Local only" posture, analytics, updates, and the privileged helper stay application-wide. The
Settings window shows the Project name beside the panes it edits, and it reopens against the new
Project when you switch, so an editor left open cannot apply one Project's draft to another.

Switching Projects preserves the investigation within an app session. Going A → B → A restores A's
sessions, snapshot, findings, evidence, retained frames, selected session, query drafts and results,
saved source references, capture statistics and chart, removed-session state, and History selection
exactly as they were. Starting, clearing, filtering, or changing settings in B never affects A.
In-flight derived work is cancelled at the boundary; evidence projections and accepted queries are
rebuilt from the restored snapshot. Interrupted initial History reads restart in the restored
Project; already-loaded pages and their paging position are preserved. An on-demand Follow Stream
request can be run again.

If a capture is running when you change Projects, Tracexy asks first. **Cancel** leaves the running
capture and its Project completely untouched. **Stop and Switch** stops the capture and waits for the
helper's final packets, the final session fold, and the terminal History entry *before* the Project
changes. If the helper does not confirm that final drain, Tracexy stays where it is, says so, and
offers a retry — a timeout never counts as a confirmed drain. Capture cannot be started while a
Project change or a final drain is in progress, and auto-start applies only at launch, never on a
switch. If you explicitly reset the helper while its final reply is unavailable, Tracexy preserves
the accepted packet prefix, marks its terminal History entry **incomplete**, and stays in the
outgoing Project. Retry the Project change after recovery has settled; the missing tail is not
reported as recovered.

An accepted **Save Capture** or session export holds its capture source until it finishes or fails.
During that time Start, Clear, opening another capture, importing, and Library trash are
refused so they cannot change the bytes being saved or exported. Stop remains available. Project
changes wait for accepted saves; finish or cancel an export before changing Projects.
Import and Trash explain when the capture source is busy rather than reporting a filesystem
permission problem. Save/export failures remain visible even if you stopped the capture while
the operation was running. If a resumed History read fails, it offers retry instead of leaving
the selected-session pane loading indefinitely.
The destination is prepared and the catalog saved before activation. A failed save keeps the old
Project and investigation active. Deleting an inactive Project does not stop the active capture.

**Project → Manage Projects…** opens the same management sheet used by the toolbar control. Its sidebar
lists local Projects and their workspace counts; the detail area can open, rename, import, export, or
delete the selected Project. Deleting a Project removes it from the catalog and releases it from the
app, discarding its unsaved in-memory sessions and evidence. Its saved captures and local History are
**not** deleted — they remain on disk — but they are no longer reachable from Tracexy.

**Export Project Configuration…** writes a configuration-only `.tracexyproject` file. It can include
user-authored filter text, so review it before sharing, but it never includes packets, payloads, capture
paths, session selection, findings, or History. Import always creates a new local Project with fresh
identities and never replaces an existing Project. Project files and the local catalog are size-bounded
and validated before adoption.

### What survives quitting

Durable configuration, per-Project History, and managed saved captures survive relaunch. **Sessions
held only in memory do not**: Tracexy does not checkpoint an unsaved live capture, so a Project's
current sessions and retained frames exist for the life of the app session only. Use **Save Capture**
before quitting if you need them later.

Data written before Project isolation existed — the original History database and Captures folder —
is attached to exactly one Project the first time the catalog is loaded, and that ownership is
recorded and never reassigned. Nothing is copied, moved, or deleted. If the catalog has to be
repaired, that data stays on disk and is deliberately left unattached rather than handed to a newly
created Project.
Catalog reload is a startup-recovery action. If an investigation is already open, save unsaved captures
and relaunch before reloading. Explicit catalog reset warns about discarding in-memory investigations;
it prepares the replacement before changing the catalog, and preserves saved files and History on disk.

## Local History

**History** keeps bounded terminal capture summaries in a local SQLite database. A live capture appears
only after it has stopped and its final accepted session fold is ready; an opened saved capture appears
only after the open has completed successfully. History never presents an active-capture dot, live rate,
or guessed total. Its footer reports only the capture and session summaries currently persisted.

Each entry records its local start/end time, whether it came from live capture or a saved file, whether
the result was complete, and bounded session metadata such as process, normalized display host,
endpoints, protocol stack, status, duration and byte totals. The display host can be derived from a DNS
name or TLS SNI, as in the live Sessions table. History does not store capture-file paths, packet bytes,
decoded trees, dedicated DNS/SNI evidence, findings or evidence locators. Address masking follows the
Privacy setting at write time.

Use **Refresh** to reload the newest summaries. **Clear…** requires confirmation and removes only the
local History database rows; it does not clear the current capture or delete saved capture files.

**Settings → Privacy → Auto-clear** can keep History forever or remove entries whose capture end time
is older than 15 minutes, 1 hour, or 24 hours. Cleanup runs at launch, after a completed live or saved
capture is accepted into History, and immediately when the setting changes; there is no background
timer. An entry ending exactly at the cutoff is retained. This policy affects only local History rows,
so an older saved capture can disappear from History while remaining open in the current workspace and
unchanged on disk.

## Sidebar sources

The **Sources** groups in Browse are derived from the current capture. Secondary-click an app,
domain, or IP row to open its sessions, copy its identity, pin an address, or **Remove from Sources**.
Removing a source hides only that sidebar row and persists the presentation preference; it never
deletes captured sessions or packet evidence. Secondary-click the Apps, Domains, or IP Addresses
category to restore every hidden row in that category.

At launch, **Protocols**, **Apps**, and **Domains** remain compact until the first decoded session
arrives, then open automatically so live capture data is visible without extra clicks. This happens
only once for the current data lifetime: manually collapsing a group afterwards is respected while
more sessions arrive. Clearing or starting another live capture resets the session list and re-arms
the behavior.

## Overview

**Overview** is the first destination under **Monitor**, followed by **Sessions** and **Flow Map**. It
summarizes the current capture without replacing the session workflow: capture identity, frames,
sessions, traffic, duration, activity, storage, top talkers, protocol mix, observed sources, and a
compact findings severity summary are kept in one native dashboard. Overview never duplicates the
finding evidence list; its analysis summary links to the existing filtered Sessions workflow.

Overview is a capture report. The headline row shows frames, sessions, traffic, duration, and
fidelity. **Traffic over time** plots every accepted frame's wire bytes on the real capture clock for
live and opened captures alike, split into bytes **sent by clients** and **received from servers**
when the session direction remains stable. If later evidence changes client/server orientation,
the chart shows exact total bytes only and explains why. Slices start at one second and widen only
when a long capture would otherwise exceed the bounded bucket count; the caption states the current slice
width. Hovering a column reads its exact figures. Findings in the current scope are pinned along the
top of the plot at the instant of their first cited frame; a bounded number are placed and the footer
says when it is a subset. Frames that carry no capture time count in the totals and are named in a
notice, never drawn. When a search, filter, drill-down or session expression narrows the sessions in
view, the chart draws their bytes as **In view** over the capture-wide **All** line on the same slices,
scaled to the sessions in view so a small scope stays readable; the all-traffic line may run past the
top, and hovering still reads both values exactly. Per-session slices are bounded; if a very large capture
exceeds that bound, the footer says the in-view line may read low. The **Bytes / Packets / Bits/s**
control switches what the chart plots: wire bytes, frames, or the average bit rate of each slice (a
slice's bytes × 8 over its width, never a peak); the chips beside it follow, with Bits/s giving the
average across the timed span.

Beneath it, three compact charts summarize the scope: **Protocols** partitions session bytes by each
session's innermost protocol (bars sum to the scope; click a bar to narrow to that protocol),
**Sessions started** counts new conversations per slice on the same clock (when the scope has
retransmission findings, its **Retransmissions** control plots instead the re-sent segments those findings
cite, and says how many more were not retained), and **Findings** shows the
severity split with a route to review those sessions. **Top hosts** and **Top apps** are native tables
of sessions, sent, received, and total bytes with an in-row share bar (client-sent and
server-received against the leading row); double-click a row (or use its context menu) to narrow
the session list to exactly that host or app. Sessions with no attributed process are never listed as an
app. **Sources** counts observed apps, domains, and addresses and opens the Flow Map.

**Response times** is a native table of the intervals Tracexy could measure between two cited frames
in the current scope: how long the peer took to answer a connection attempt, how long the whole
observed handshake took, how long a TLS ClientHello waited for its ServerHello, how long a request
waited for the first reply, and how long a DNS query waited for its answer. Each row gives the count
in scope with the fastest, median and slowest of them; the median of an even count is the lower of
the two middle values, never an average. Double-click a row (or use its context menu) to select the
session carrying its slowest measurement. Nothing here is graded fast or slow — a passive capture
cannot support a target — and a capture with no timed pair of frames shows no table at all.

**Capture health** shows live kernel/interface loss, helper-buffer drops, and the bounded in-memory
inspection window. Window trimming does not remove accumulated sessions or frames from the disk-backed
live spool and is never reported as capture-source loss. For an opened file, Overview shows the
container the reader recognised, its declared interfaces, and loss counters only when Interface
Statistics Blocks record them. Missing counters read **Not recorded**; counters from only some
interfaces are labelled partial. These figures cannot reconstruct traffic missed before the file was
written. **Get Info** opens the capture information window. Frames outside the inspection window
remain in the source file and decoded session/activity totals.

## Sessions

Frames are grouped by their canonical **five-tuple** (protocol + the two endpoints, direction-
normalized) so both directions of a conversation land in one session. The session's **client** is
the endpoint that sent the captured SYN. When no SYN was captured — the capture began mid-stream —
a session first seen from a service port (an IANA system port, or a common registered service port
such as 3306 or 8443) toward an ephemeral port is oriented toward the service, so the remote host
rather than this Mac's ephemeral socket reads as the destination. Two ephemeral or two service ports
keep the first-observed direction. Each session summary carries:

- endpoints and a resolved **host** (from TLS SNI or a DNS name where available, otherwise the peer IP);
- the **protocol stack** (outer→inner, e.g. TCP · TLS);
- **byte counts** up and down, packet timing, and duration;
- a **status** (OK / Warning / Error) that drives its color and icon — a TCP reset observed at any
  point, including after an orderly close, marks the session as an error and is recorded as a reset
  observation in its evidence;
- a concise **info line** derived from the real decode — a DNS query and its answer, a TLS host, or the
  innermost layer's summary — never placeholder text.

Connectionless traffic (ARP, ICMP/ICMPv6) is keyed on the IP pair (port 0) so it still surfaces as a
session rather than disappearing.

Click a column header to sort the flat table by that column; click again to reverse it. The default
order stays the stable capture order (oldest→newest, rows updating in place); a sort you choose is
kept while you keep working in that window.

The first rounded control shelf keeps a stable icon cluster beside search: **Follow Live**, **Jump to
Latest**, a divider, **Clear Capture Data**, and **More Session Actions**. The order does not change at
narrower widths; the cluster and search controls stack when needed. Domain and less-frequent actions —
**Investigate**, **Advanced Filters**, **New Focus Set**, **Save Capture**, **Noise Control**, and
restoring removed sessions — use labelled sections inside the More menu. Every icon-only command keeps
an explicit help label and accessibility name. Both rounded shelves span the workspace while their
commands and protocol filters stay anchored to the sidebar edge. The bottom status bar is intentionally
read-only: only the visible/selected session summary is centered; source, loss, retention, and memory
telemetry remains trailing. When the telemetry leaves no room to center it, the summary moves to the
leading edge rather than disappearing. It does not mutate the capture or filters.

Select a session to enable the toolbar's **Export** menu beside the independent **Start** and inspector
controls. The same menu is available from the session row's **Export** submenu. **Export Session**
writes a versioned `.tracexysession` document. With the default Privacy settings, the protected document
keeps session and frame metadata but omits captured packet bytes, DNS-derived strings, and the free-form
summary; optional IP masking replaces literal addresses with a fixed placeholder. Turning every export
protection off preserves the original version-1 document with packet frames. **Export as pcap** writes a
classic capture when all matching frames share one link type; **Export as pcapng** preserves mixed
per-frame link types. Those raw formats always preserve captured bytes and require a per-export warning
acknowledgement while any privacy protection is enabled. Export is always an explicit local save-panel
action. Live export reads the complete local pcapng spool; saved-capture export re-reads the source file,
so the bounded in-memory inspection window does not silently truncate an export.

Secondary-click any flat session row, disclosed action member, inferred action, host group, or process
group to **Remove from View**. Removing a row hides its session identity and derived values from
Sessions, Overview, Flow Map, Sources, Findings, related-session cards, and UI totals for the current
capture. It is intentionally reversible and does not rewrite packet evidence or silently redact a
saved/exported capture. Use **List Options → Restore Removed Sessions** to bring every removed row back;
starting, opening, or clearing a capture also resets this presentation state.

Choose **Pin Session** from a session's context menu or the **Edit** menu to keep it in a strip above
the table, as Wireshark pins packets. A pin stays in the strip whatever the search, filters or
expression show; a pinned session the list currently leaves out is marked with a crossed-out eye, and
clicking any pin inspects that session without changing the filter. Secondary-click a pin to unpin it,
or use **Unpin All**. Pins belong to the capture: removing a session from view takes its pin out of the
strip until it is restored, and starting, opening or clearing a capture clears them.

## Correlation into actions

The session list opens **flat by default** — one row per session, exactly as decoded, so a busy
capture shows every observed conversation rather than a handful of collapsed rows. Grouping into
higher-level actions is *inference layered on top of the raw sessions*, so it is **opt-in**: choose
**Action** from the **Group By** menu when you want the interpretation, and switch back to **None
(flat)** — always one click away — whenever the grouping looks wrong. **Host** and **Process**
grouping are also available; unlike Action they group on a recorded session attribute rather than
inferring a causal relationship.

When Action grouping is on, related sessions are correlated into a higher-level **action** — for
example a DNS lookup, the TCP connect to the address it returned, and the TLS handshake carrying that
hostname. Every action reports the strength of the evidence behind it: **causal** (a DNS answer named
the very address the next connection dialed within a 30-second window), **strong** (the same observed
process owns the sessions, or DNS name, TLS SNI, and host agree), or **weak** (sessions merely began
close together). Correlation on identifiers alone — the same process talking to the same name with no
observed causal step — is held to a tight bar: it needs a real observed process **and** an agreed
name, and only groups sessions that began within a couple of seconds of each other. When two
hostnames resolve to the same address (a shared CDN IP), the attribution is **contested**: Tracexy
lowers the confidence and shows the competing names rather than silently guessing.

## Focus sets and filtering

The control area above the session list has two rounded surfaces. The first combines the stable command
cluster with search; the second owns the **protocol/category pills**, which narrow by
protocol (DNS, TCP, UDP, TLS, HTTP, HTTP/2, QUIC, WebSocket, STUN — HTTP/2 where the switch is visible: the
cleartext connection preface, a `101` agreeing to `Upgrade: h2c`, or a TLS 1.2 ServerHello choosing ALPN
`h2` (TLS 1.3 encrypts that choice);
WebSocket where an HTTP/1 `Upgrade: websocket` is seen), by evidence-backed **Findings**,
and by exact status (**Errors**). Selected protocol pills combine with OR, selected
investigation pills combine with OR, and the two groups combine with AND — so choosing *TCP* and
*Errors* shows TCP sessions that failed. *Errors* means exactly an error; a warning is not swept in.
*Findings* includes exactly the sessions referenced by the typed Core analysis snapshots: a connection
refused by the peer (an observed SYN answered only by a reset from the other side), a connection
attempt left unanswered (a SYN retried at least once with no SYN+ACK observed), a connection aborted
after data (payload observed, then a reset), a half-close (a FIN in one direction with the peer sending new
bytes afterwards), a reused connection tuple (a conflicting SYN before any observed terminal),
observed TCP reset,
retransmission, a login secret sent unencrypted (an HTTP Basic `Authorization` header, an FTP or POP3 `PASS`,
an IMAP `LOGIN` or SMTP `AUTH PLAIN/LOGIN` on its standard port; `finding == cleartextCredentials` — only the
kind is kept, never the user name or secret), segment overlap, a segment that arrived ahead of a sequence gap (Wireshark's "previous
segment not captured": earlier bytes were not seen *yet* — lost on the wire, reordered, or missing from
the capture), an acknowledgement of bytes the capture never saw its peer send (Wireshark's "ACKed segment
that wasn't captured"; `finding == ackedUnseen`, reported only once the peer's own sequence edge is known,
so the capture-start and keep-alive cases Wireshark flags stay unclaimed), four TCP flow-control observations — a zero
receive window advertised or probed, a data segment that filled the peer's advertised window, repeated
duplicate acknowledgements, and keep-alive probes on an idle connection — two retransmission refinements
— a fast retransmission (a segment sent starting exactly where the peer's repeated duplicate
acknowledgements asked, reported once per repeated edge) and a spurious retransmission (bytes sent again
after the peer had already acknowledged them) — plus four UDP-DNS outcomes: a retained
message set its TC bit, a response said the name does not exist (NXDOMAIN), a response reported a
server failure or refusal (SERVFAIL/REFUSED), or a recursion-desired query id was sent at least twice
with no response observed in that flow; and three ICMP messages — destination unreachable,
fragmentation needed / packet too big, and time exceeded. An ICMP error is reported on the ICMP
conversation that carried it, and, when the message quoted a complete TCP or UDP header, reported
again on the session it named ("ICMP unreachable reported for this session", "ICMP path MTU limit
reported for this session", "ICMP time exceeded reported for this session"), citing the same ICMP
frames. The quotation is read only as flow identity — addresses, ports and transport — and a
quotation that was truncated, fragmented, of the wrong IP version or not TCP/UDP is not paired at
all, so a partial message never names the wrong session. Five TLS observations join them: a fatal
alert and a warning-level alert that is not an orderly close, a server that selected a version below
TLS 1.2 (SSL 3.0, TLS 1.0 or TLS 1.1, all deprecated by the standards that define them), more than
one HelloRetryRequest in one direction, and a ClientHello with no reply of any kind observed. An
alert's level and description are read only when the record carries them in the clear — an encrypted
alert stays opaque and produces no finding — and `close_notify` and `user_canceled` are an orderly
shutdown, never a finding. A ClientHello answered by an alert reports the alert, not an unanswered
handshake, and "unanswered" is stated only for a flow whose TLS evidence was complete. No SNI,
certificate, key or decrypted payload is read: certificate-chain and SNI/ALPN checks are deliberately
absent, and a selected cipher suite stays an observed fact in the evidence rows rather than a
verdict. "Unanswered" describes the capture window only — it never
claims that no answer existed — a refused open and an abort after data are each reported once, not
also as a generic reset, a retried SYN is reported as an unanswered handshake rather than also as a
retransmission when the retransmission cites nothing but those same SYN frames, and an
unanswered DNS query is never reported for flows whose retained evidence was bounded or for
mDNS/LLMNR traffic. A full receive window is reported only when both SYNs were observed, because the
window-scale factor is otherwise unknown and the edge would be a guess. Status, plaintext HTTP, an unanswered DNS query and latency do
not create findings on their own. Finding identity is stable, and Details reports bounded citation and
coverage information without claiming whole-capture completeness.

**Findings** lives only in this filter bar; it is not a separate sidebar destination. The table keeps
all of its columns, search, advanced rules, grouping, row context actions, selection, and inspector,
so large finding sets can be narrowed and investigated rather than opened one row at a time.

The **search cluster** in the first surface has an on/off checkbox, a field-scope menu (**All Fields**, Host, Client,
Protocol, Source, Destination, Summary — default All Fields), a search box with a clear button, an
**Add Field** button, and the **Group By** menu. All Fields searches the host, client process, protocol
labels, both endpoints, the info summary, and DNS answers. Turning the search off keeps the typed text
but stops it constraining the list. Press **Command-F** from any main surface to return to Sessions,
reveal this filter area if needed, enable search, and place the cursor in the existing search box.

For finer control, **Add Field** opens the advanced rule builder: rows of *field · operator · value*,
each independently on/off and joined to the previous row by AND or OR. Connectors evaluate strictly
left-to-right (no operator precedence), so a saved set always filters the same way. Operators are
Contains, Is, Starts With, Ends With, Does Not Contain, Is Not, and Regex; an invalid regex safely
matches nothing. A build allows up to a fixed number of advanced rules (12 by default); the add buttons
disable at that limit.

**Investigate** opens a separate capture-local typed query editor, from the command cluster's overflow
menu or from **View ▸ Investigate Sessions…** (**Option-Command-I**). **Rows** provides bounded native
controls for process, host, exact IP address, CIDR block, port range, protocol, status, finding kind,
start-time range, total bytes, or retained evidence. Choose **All** or **Any** across rows and
optionally negate an individual row.

**Expression** accepts a bounded Session Expression over whole sessions. It supports lower-case
protocol terms; `not`/`!`, `and`/`&&`, `or`/`||`, and parentheses; exact or CIDR endpoint matches;
exact ports and port ranges (`destination.port in 8000..8080`); quoted host/process `contains`
(substring) and `matches` (whole-value wildcard: `*` any run, `?` one character, e.g.
`host matches "*.example.com"`); byte comparisons; typed finding names; and value sets —
`ip in {address, cidr, …}`, `port in {80, 443, 8000..8080}`, `finding in {reset, retransmission}` — which
mean the same as joining the comparisons with `or`. For example: `http and destination.port == 80`.
Time fields take a unit (`ms`, `s`, `m`, `h`): `duration >= 5s`, `latency >= 200ms`,
`latency in 50ms..1s`; `start >= "2027-01-15T08:00:00Z"` or `start <= "2027-01-15 08:30:00"` (no zone
means local time). A session whose duration, measured latency or start is unknown is neither a match
nor a non-match: it is counted as undecided, even under `not`. Message fields: `http.method == GET`,
`http.status in 400..499`, `dhcp.message == Offer`. Ethernet addresses: `mac == 0a:00:27:00:00:01`,
`source.mac`, `destination.mac`, `mac in {…}` (colon-separated, any case) — the client's and server's MAC from the session's
representative frame (a session without an Ethernet header never matches); Wireshark's `eth.addr`,
`eth.src` and `eth.dst` translate to them. A field named on its own tests presence, as a bare
field does in Wireshark: `finding` (the session has any finding), `process` (an owning app is known),
`latency`, `sni`, `dns.query`, `dns.answer` — for example `sni and not finding`. `finding` alone follows the
finding rules: a session without one is undecided rather than a non-match when evidence was bounded.
Session measures compare with `==`, `>=` and `<=`: `bytes`, `bytes.sent` and `bytes.received` (sent by
the session's source, and what it got back), `frames`, `frames.sent` and `frames.received`. The value can be
whole-number arithmetic over numbers and measures, with `+`, `-`, `*`, `/` and `%` and `{}` for grouping, as
in a Wireshark display filter: `bytes.received >= {10 * bytes.sent}` finds lopsided downloads,
`bytes >= {64 * 1024}` is the same as `bytes >= 65536`. Put spaces around `/`, since `/` also writes a CIDR
prefix. Division rounds toward zero, and a division by zero or an overflow is not a match. A session saved
before frame counts were kept is undecided for the `frames` measures.
`matches` is a wildcard, not a regular expression, so no pattern can make an evaluation slow. This is
Tracexy session syntax, not a Wireshark display filter: packet fields such as `ip.addr` and `tcp.port`,
regular-expression operators, arithmetic outside a measure's value, and unsupported names are rejected with a position instead of being
reinterpreted.

While you type, the editor offers the names that can come next — a field, its operators, a finding
name, or `and`/`or` — and a click completes the word. **Recent** lists the expressions you applied in
this Project and **Saved** the ones you named with **Save…**; both are kept per Project and survive
relaunch. Right-click a session and choose **Investigate Sessions Like This** to narrow the current
expression by that session's host, destination address or port, process, or protocol. The same terms
are under **Copy ▸ As Session Expression**, for pasting into a saved expression or a note.

**Saved ▸ Import Wireshark Display Filters…** reads a Wireshark `dfilters` file and saves each filter that
has a session meaning as a Session Expression under its own name: addresses (`ip.addr`, `ip.src`,
`ipv6.dst`, CIDR and sets), ports (`tcp.port`, `udp.dstport`, ranges and sets, kept to their protocol),
protocol names (`ssl` becomes `tls`, `bootp` becomes `dhcp`), `http.request.method`, `http.response.code`,
the names a session is known by (`http.host`, the TLS server name, `dns.qry.name`), and the TCP, DNS, ICMP
and TLS conditions Tracexy reports as findings (`tcp.analysis.retransmission` becomes
`finding == retransmission`). A filter about single packets — `frame.len`, `tcp.window_size`, a URI — is
not imported, and the alert lists each with the reason; the ones read as findings are named so you can
check they mean what you want. Regular-expression matches are not translated.

**View ▸ Expression Library** keeps one-click **filter buttons** and **macros** per Project. A filter
button applies its Session Expression exactly as typing it and choosing Apply would; the buttons sit in a
bar under the toolbar and are also listed in the menu, so each is reachable from the keyboard. A label
written `Group//Label` puts the button in a pull-down named Group. **Add Filter Button…** starts from the
expression in use; **Edit Filter Buttons…** renames, reorders and removes them. A macro names a piece of
an expression: write `$name`, `$name(a, b)` or `${name:a;b}` in any Session Expression, and `$1` to `$9`
in the macro take the values in order. Macros may use other macros; a cycle, an unknown name or the wrong
number of values is reported at the place you typed it, and what you typed — not the expansion — is what
is accepted and remembered. A Project holds up to 10 filter buttons and 10 macros. A list that already
holds more (imported, say) is kept whole and stays editable; only adding more is refused.

Both modes retain their unfinished drafts when you switch. **Apply** validates the complete active
draft first; an invalid row or expression keeps its error visible and does not replace the previous
accepted query or result. Expression input is limited to 4,096 UTF-8 bytes, 256 tokens and eight
levels of nesting before the existing typed-query bounds are applied.

An accepted Investigation query composes with the existing pills, search, sidebar scopes, mute rules,
and advanced filters. Its removable chip reports the current matched count. Evidence-dependent queries
also report how many sessions are **incomplete**: those sessions are not counted as matches, and a
missing retained finding is never treated as proof that no finding exists. Investigation state belongs
only to the current capture/workspace. Clearing it, resetting filters, or replacing/clearing the capture
retires the query; it is not saved into a Focus Set.

Right-click a session and choose **Name Address** to give one of its addresses a name in this Project
(for example `192.0.2.5` as `NAS`). The name appears wherever that address is a session's only name —
as "NAS (192.0.2.5)" in the Host column and the Details title — and never replaces a name the capture
itself supplied through DNS, TLS or HTTP. Choose **Remove Name** in the same dialog to take it away.

Right-click the Sessions table header to show more columns — **Timeline** (when each session ran,
drawn against the sessions in view; an untimed session draws nothing), **Server Name**, **Duration**,
**Sent**, **Received**, **Latency** and the full **Protocols** stack — or hide ones you do not use, and
drag a header to reorder. Each column sorts by its own value, with sessions that lack it sorted last. The
choice is kept per Project.

Save a named rule set as a **focus set** to reapply later; applying one loads its rules into the active
workspace's advanced filter, clamped to the rule limit. Focus sets persist across launches. **Reset
Filters** clears the pills, the search text, sidebar host/process/IP scopes, the active Investigation
query, and the advanced rules, and hides the builder (it does not touch Noise Control).

Each **workspace tab** is an independent investigation over the same traffic, with its own filter,
selection, grouping, and inspector layout. **File ▸ New Tab** (⌥⌘T) opens one; once a Project has
more than one, a tab strip appears in the titlebar under the toolbar. Click a tab to show it,
double-click it (or use **Rename Tab…** in its context menu) to name it, drag it to change the order,
and close it with its close button, **File ▸ Close Tab**, or **Close Other Tabs**. When the tabs no
longer fit, scroll the strip or pick one from the **All Tabs** menu. **Window ▸ Show Next Tab** (⌃Tab) and **Show Previous Tab** (⌃⇧Tab)
cycle through them. The first tab, **Live**, always stays first. A Project keeps up to 8 tabs; tabs are
saved with the Project and come back on relaunch.

## Inspector

Selecting a session opens the bottom evidence inspector. It shows the decoded
protocol **layers** and fields for the representative packet, and a **hex** pane whose byte ranges line
up with those fields — click a field to highlight the bytes it came from. Right-click a layer or field
to copy its visible summary, name, value, or combined name/value text without retyping it. When a
session carries an application-layer exchange (HTTP, DNS, STUN), a requests facet is offered. A plain
HTTP/1 request shows its request line and Host; a response shows its status (for example `301 Moved
Permanently`), version, content type and length, encoding, server, cache control and redirect location,
read from the first 512 bytes. Cookie and authentication headers are only named as present, never shown. For an
opened capture, only the selected session's representative bytes are loaded; changing selection retires
the previous read and file replacement/truncation is rejected rather than displaying bytes from a stale
offset.

The selected-session strip keeps the current status, primary protocol, observed process or host, and
source-to-destination endpoints visible above the inspector facets. A correlated multi-session action
is labelled there with one non-wrapping **Whole action** badge; selection context never competes with
the facet tabs. Both rows span the inspector and keep identity and facet labels anchored to the sidebar
edge; fixed utilities remain trailing. Facet labels stay on one line, preserve their source order, and
move lower-priority facets into a More menu while keeping the active facet directly visible. Tracexy
does not manufacture a URL for transport, DNS, TLS, or other sessions that did not yield one as typed
evidence. The trailing window button opens the same selection-aware inspector in a resizable auxiliary
window; it follows the
row selected in the main workspace. On macOS 15 and later, this transient window is excluded from state
restoration so it does not reopen empty after relaunch. A read-only rounded footer
partitions the active facet, protocol stack, byte total, and duration without moving capture or filter
actions into the evidence area.

When retained TCP connection, direct-frame TLS or DNS/ICMP datagram observations exist, the **Evidence**
facet merges them on the capture's frame-order axis. A DNS row names the message shape, transaction id,
response code and counts; an ICMP row names the family, type and code, and the flow the message quoted
when the decoder retained one. Reused five-tuples remain separate connection incarnations, while TLS
records stay explicitly shared at session scope when the retained facts cannot attribute them to one
incarnation. Per-connection omissions, truncation, loss knowledge and bounds remain visible; global
capture omissions are labelled capture-level and are never assigned to the selected session. Selecting
a citation reads exactly that one frame from the current local saved file or live spool and opens its
decoded Layers view with a visible **Cited frame** scope. A missing locator, superseded live-spool source,
replaced or truncated file, or mismatched source fails visibly and never falls back to a representative packet.
Changing session, workspace, capture, or source clears the cited bytes. This finite single-frame read is
allowed during active live capture and is separate from Follow Stream's stable-source requirements.

Above the hex dump in Layers and in the raw evidence view, **Find bytes** highlights every place a pattern
occurs in that frame: hex byte pairs such as `16 03 01` (spaces, colons or dashes allowed) are a byte
sequence, anything else searches the query's UTF-8 bytes. Text search ignores ASCII case by default;
**Case Sensitive** compares those bytes exactly and does not change hex searches. Hex-only input such as
`CAFE` is interpreted as two hex bytes, not literal text. The count says when there are more than 256.
**Previous byte match** and **Next byte match** wrap through the retained hits, scroll the matching
dump row into view and distinguish the active hit; if more than 256 matches exist, later hits are not
retained or navigable. Changing the query, bytes or hex/bits style clears the active hit. **Copy Bytes** copies the frame — or, when a field is selected in the decode tree, just that field's
bytes — as a hex dump, a hex stream, printable text, a C array, an escaped string, Base64 or raw binary (`application/octet-stream`).

Right-click a layer and choose **Copy Visible Subtree** to copy its header, fields and expanded descendants as
indented text. Folded descendants contribute only their header, and copied content follows the displayed tree
projection; it does not restore fields hidden by a search. **Copy Layer Summary** remains available for just
the selected header.

Each layer in the decode tree folds shut with the chevron beside its name; right-click a layer for recursive
**Expand Subtree** and **Collapse Subtree** actions, or **Expand All** / **Collapse All** for the displayed tree.
Click a row and the keyboard moves through the tree as Wireshark's packet details do: **↑** and **↓** step through
the rows shown, **←** folds the selected layer or goes to the layer a field belongs to, **→** unfolds a layer or
enters it, **Return** toggles the selected layer, **⇧→** / **⇧←** expand/collapse the selected layer's whole subtree, and **⌘→** / **⌘←** unfold or fold
every layer. Command-arrow takes precedence when modifiers are combined. Repeated layers with the same title share
their folded state. A folded protocol stays folded as you move between
packets, as in Wireshark, and clicking a byte that belongs to a folded layer unfolds it. Right-click a field
whose value names sessions — an Ethernet or IP address, a TCP or UDP port, an HTTP method, status or Host, a TLS
server name, a DNS query, a DHCP message type — or a layer's name, and choose **Apply as Filter** to filter the
Sessions list by it, or **Prepare as Filter** to put it in the Investigate editor to change first. Each offers
Wireshark's six joins: **Selected**, **Not Selected**, and **…and**, **…or**, **…and not**, **…or not Selected**
with the expression already in the editor. **Apply as Column** on a field adds its value as a column of View ▸ All
Frames (up to four, kept per Project, placed before Info; a field that occurs twice in a frame shows both values,
comma-separated) and opens that window; choose it again, or right-click a frame ▸ **Remove Column**, to take it away. The decode tree and
the hex dump are linked both ways. Selecting a field or layer tints its bytes; pointing at
a byte in the Layers facet names the field it belongs to at the bottom of the dump, with its byte span, and
clicking a byte (hex or text column) selects that field and scrolls the tree to it. The innermost owner wins,
so a byte inside the TCP header names its TCP field, not the whole layer. Every byte of the fixed Ethernet,
IPv4, TCP and UDP headers has a named field at the same offsets Wireshark reports. The bytes pane's
**Hexadecimal / Bits** pop-up (or **View → Show Bytes as Bits**) writes each byte as eight binary digits,
eight bytes a row, as Wireshark's "…as Bits"; pointing and clicking work the same, and the choice is kept per
Project.

**View → Validate Checksums** (off by default, per Project, as in Wireshark) checks the IPv4 header
checksum and the TCP, UDP, SCTP, ICMP and ICMPv6 checksums of the frame in Layers against its bytes.
It writes the verdict after each Checksum value: `[correct]`, `[incorrect, should be 0x…]`, `[partial, likely
checksum offload]` when the field holds only the pseudo-header sum, `[not present]` for a zero UDP
checksum over IPv4, or `[unverified, not fully captured]`. Frames captured on the Mac that sent them often
show offloaded or incorrect checksums because the network card fills them in after capture; that is not
a network fault.

The **Ladder** facet draws the same retained evidence as a two-lane diagram: the session's endpoints as
lanes and one arrow per step between them, oldest at the top, with its offset from the first step — SYN,
SYN+ACK, the first data each way, FIN and RST, runs of retransmissions (counted, not repeated), TLS
handshake and alert records, and DNS and ICMP messages. Trouble (a reset, a retransmission run, a TLS
alert, a DNS error, an ICMP error) is drawn in orange. Clicking an arrow opens its frame in Layers. A long
session is drawn up to 80 steps and says how many later steps are not drawn.

For TCP sessions, the **Stream** facet offers an explicit **Follow Stream** action. Opening the facet
alone does not scan or retain application bytes. After activation, Tracexy locally rescans an
identity-checked saved capture, or an immutable temporary copy of a fully stopped live capture, and
shows the two canonical directions independently in Text or Hex form. Retransmissions do not duplicate
bytes; gaps, out-of-order segments, conflicting overlaps, capture/source truncation, and reader/display
bounds remain visible as separate limitations. Each direction is bounded by the reader and the UI
formats at most another 64 KiB; omitted counts stay explicit. A growing live spool is never scanned:
stop capture and let its final ingest finish first. Follow Stream sends and exports nothing, but the
local application data it reveals may contain credentials or personal information. Changing selection,
opening/starting/clearing a capture, or cancelling retires the selection-scoped result.

For UDP sessions the same facet offers **Follow Conversation**, which lists every datagram of the
conversation in capture order under the same stable-source rules: sender and receiver by endpoint, the
payload size (a datagram captured shorter than it was sent says so), its signed offset from the first
datagram when both timestamps are known (otherwise **Untimed** or **Offset unavailable**),
the capture-time delta from the immediately preceding retained datagram when both timestamps are known,
and its bytes in Text or Hex. A missing timestamp breaks the adjacent delta; a negative delta is kept for
non-monotonic captures. This delta is capture-clock spacing, not network latency. The payload ends where the UDP header says it ends, so Ethernet padding is
never shown as data. A DNS datagram is read instead of dumped in Text mode — the question, the response
code and the answer records — and each response is paired with the query it answers, with the time
between them; a retried or unanswered query stays visibly unpaired. The list keeps the first 4,096
datagrams in capture order and counts the rest exactly.

**Save Conversation as YAML** writes both directions or one direction from the retained datagrams. Every packet
record keeps its capture order, peer, per-peer index, frame ordinal, optional timestamp, retained and captured
payload lengths, per-message omitted bytes and Base64 payload, so consecutive datagrams remain separate and
empty payloads remain explicit. The conversation footer records omitted datagrams/bytes, source completeness
and observed limitations. A confirmation explains that Base64 contains the original application bytes; the YAML excludes
capture identity, source paths and frame locators. Output is bounded to 8 MiB and 4,096 datagrams.

**Save Raw Payload** writes one direction or both by concatenating UDP application payloads in capture order.
The binary output contains no UDP headers or datagram separators, so datagram boundaries are lost. Before saving,
Tracexy confirms that the output may contain sensitive data and explains the boundary loss. It refuses when the
source is truncated, datagrams or payload bytes were omitted or bounded, any selected payload is shorter than its
declared length, or the output would exceed 8 MiB; use YAML to inspect retained datagrams and their limitations.
Raw output covers only datagrams observed by the capture and cannot establish that the original network traffic
was captured completely.

**Transcript Direction** shows both directions or only one endpoint direction. It filters retained rows before
the display-byte budget, search count, and previous/next matching-datagram navigation, while the summary's scanned
and matched totals continue to cover the whole conversation. YAML and raw export keep their own direction choices.
The **Δ** shown on a row remains the capture-time difference from the immediately preceding retained datagram in
the complete conversation, so it can span a hidden opposite-direction row; it is not network latency.

**Find in transcript** highlights matches in drawn TCP/UDP content, including the HTTP/1, HTTP/2 and
WebSocket summaries. By default it ignores case and diacritics; turn on **Case Sensitive** to match
uppercase and lowercase exactly, without case or diacritic folding. The bounded match total counts the
TCP stream text or, for UDP, each displayed fragment separately; summary highlights use the same query
policy but do not add to that total. UDP matches cannot cross fragment boundaries. In Follow UDP,
**Previous matching datagram** and **Next matching datagram** move through retained rows with at least
one match (one stop per datagram, even if it contains several occurrences); navigation wraps at either
end and does not include omitted later datagrams. Each TCP run and each datagram carries a **Frame** link that opens that exact
frame in Layers through the same guarded cited-frame path as the Evidence facet.

Above the transcript a line counts each direction's frames and, when retained frame evidence proves the
interleaving, the stream's **turns** — consecutive source chunks from one side before the other spoke, in
capture order, as Wireshark's Follow Stream does. The source chunks keep their own frame and time attribution;
same-direction packets are not merged in YAML. **Save Stream** writes both directions or one of them as raw
bytes, ASCII text, a hex dump (the second side indented), C arrays (`peer0_0`, `peer1_0`, … each noting its
frame, or saying frame unavailable) or YAML (the two peers, then each attributed source chunk with its per-peer
index, frame, optional time and base64 data), and copies the C arrays, YAML or hex dump. If dropped provenance
or contradictory frame attribution makes cross-direction order unknown, both-direction Save/Copy/Print is refused
with a reason; saving one direction remains available in TCP sequence order and clearly marks unavailable frame
metadata. The turns agree with `tshark -z follow,tcp,raw` when chronology is known. Each run of bytes shows its
offset from the stream's first frame (`+0.020000 s`). In TCP and UDP Follow, **Filter Out This Stream** narrows the main window to every
session except this conversation, using the existing Session Expression rather than a packet display filter.

**Print Stream** prints the already-loaded snapshot in either direction or both, using ASCII, hex, C arrays or YAML.
Raw bytes print as a hex dump so binary data is not decoded lossily. Before opening macOS's print panel, Tracexy
asks you to confirm because the transcript may contain credentials or personal information and the panel can
send it to a printer or save it as PDF. The print document names the selected endpoints, retained and omitted
byte counts, source completeness, unknown-provenance byte count and observed stream limitations. Printing is refused when conservative
format-expansion estimates exceed 8 MiB; save the stream to a file instead. This is a print view of the retained
snapshot, not a claim that the conversation is complete.

When a followed TCP stream carries plain HTTP/1.0 or HTTP/1.1, the facet lists its **requests and the
responses that answered them**, paired in order as HTTP/1.1 requires: the method and target, the status,
the time from the frame that completed the request to the frame carrying the first byte of the response,
and the response body size. **Request** and **Response** open the frame that carried each message's first
byte. Body lengths follow Content-Length or chunked coding; interim `100 Continue` replies, `HEAD`, `204`
and `304` responses are handled without shifting the pairing. Reading stops, and says why, at a message the
retained bytes cut short, a response that runs until the connection closes, a protocol upgrade, a length
that can't be trusted, a gap in the stream, or after 256 requests. When the capture began between a request
and its response, that response is passed over rather than paired with the next request, and the list
says so. Nothing is decompressed or shown from bodies here; the transcript below
holds the bytes. **Save Body…** saves a response body that was read to its end, with chunked framing
removed and content coding such as gzip left exactly as sent (the offered name then ends in `.gz`); the
name comes from the request path, with an extension from the Content-Type when the path has none.

When a followed TCP stream opens with the **HTTP/2** connection preface (cleartext HTTP/2 with prior
knowledge), or began as HTTP/1.1 and switched with `Upgrade: h2c` — then the upgraded request is stream 1,
and the client's `HTTP2-Settings` header gives its settings — the facet lists its **streams**: the stream identifier, the method and path, the final status
(an interim `103` does not replace it), the time from the frame carrying the request headers to the frame
carrying the response headers, and the size of the response data. **Headers** shows each side's header list,
decompressed with HPACK exactly as sent, including Huffman-coded values and entries the connection indexed
earlier. A stream reset by either side names who reset it and the error code. **Request**, **Response** and
each frame's **Frame** link open the captured frame that carried it. The frames themselves — SETTINGS,
HEADERS, CONTINUATION, DATA, RST_STREAM, WINDOW_UPDATE, GOAWAY and the rest — are listed in capture order
with their stream, length and what they said, and agree with `tshark -Y http2`. Reading stops, and says why,
at bytes that end inside a frame, a frame that breaks HTTP/2 framing, a header block that cannot be
decompressed (later headers on that side depend on it), a gap in the stream, or after 50,000 frames per side;
the first 1,000 frames and 1,000 streams are listed. HTTP/2 inside encrypted TLS is not read.

When a followed TCP stream's HTTP/1.1 request is answered by `101 Switching Protocols` to **WebSocket**, the
facet lists the **messages** that follow, in capture order: which side sent each, Text, Binary, Close, Ping or
Pong, the text itself (or the first bytes in hex), the close code and reason, and the size. Client frames are
unmasked, fragmented messages are joined (a ping between fragments stays its own row), and when the server
accepted `permessage-deflate` compressed messages are decompressed with the context each side carries from one
message to the next. Every frame is listed behind a disclosure with its opcode, FIN, RSV1 and mask bits and
its length, and each row's **Frame** opens the captured frame; the values agree with `tshark -Y websocket`.
Reading stops, and says why, at bytes that end inside a frame, a frame that breaks WebSocket framing, or after
50,000 frames per side; a message is kept up to 256 KiB, and a compressed message that cannot be decompressed
leaves the later compressed messages from that side without content. WebSocket inside TLS (wss) is not read.

When a followed TCP stream is TLS, the facet lists the **certificates each side sent in the clear**, in
the order sent: the name, the issuer (or "Issued by itself" when the issuer and subject names match),
the validity dates and the subject alternative names, with the SHA-256 fingerprint in the tooltip. Each
certificate can be saved as DER or PEM or copied as PEM, and a chain can be saved as one PEM file —
exactly the bytes observed; no private key is involved. The certificates are read from the stream's
leading bytes only when it opens with a TLS record, and a certificate appears only when its DER parses
completely. When the handshake switched to encryption first — the normal case for TLS 1.3 and resumed
sessions — the facet says so rather than reporting a missing certificate. Nothing here judges trust,
expiry or whether the certificate matches the name asked for. Certificates are read on demand from the
local capture and are not retained in session evidence.

**Tunnels** are unwrapped: a GRE packet (IP protocol 47, carrying IPv4, IPv6 or transparent Ethernet)
or a VXLAN datagram (UDP 4789) is decoded down to the packet it carries, and the session is that inner
conversation, labelled GRE or VXLAN, with the outer header shown as its own layer (GRE key and sequence,
VXLAN network identifier). At most two tunnels are unwrapped; a deeper one, or a GRE payload type Tracexy
does not decode, stops at the tunnel layer. Select them with `gre` or `vxlan` in a session expression.
IP in IP (protocol 4) and 6in4 (protocol 41) carry the inner IPv4 or IPv6 packet with no header of their own:
the outer IP header stays as its own layer, reading "IPIP (4)" or "IPv6 (41)" as its protocol, and the session
is again the inner conversation.

**Local-network services** get their own protocol labels. **mDNS** (Bonjour, UDP 5353) is read with
the DNS decoder, so its question and answer records appear like DNS, and a device's own answers teach
Tracexy its local name (for example `printer.local`) the same way unicast DNS answers do. **DHCP** (UDP
67/68) names the message type — Discover, Offer, Request, ACK, NAK, Release, Inform — the address offered
or requested, the server, the lease time, the router and the DNS servers handed out; a message without
the DHCP magic cookie is labelled plain BOOTP. **NTP** (UDP 123) names the version, mode, stratum,
reference and transmit time of the 48-byte header. Each is recognized only when its fixed header is
present and well formed, and a truncated message keeps what was read without claiming more. They can
be selected in a session expression as `mdns`, `dhcp` and `ntp`.

**SSDP** (UPnP discovery, UDP 1900) names the method or status and the headers that say what a device
offers and where: `ST`, `NT`, `NTS`, `USN`, `LOCATION`, `SERVER`, `MAN`, `MX` — the traffic behind "why
can't this Mac see my TV or speaker". **SSH** names the version banner (`SSH-2.0-OpenSSH_9.6`) on any
port and labels the binary packets after it without reading them. **FTP** (21), **SMTP** (25, 587),
**POP3** (110) and **IMAP** (143) name each command and reply line with the fields Wireshark uses
(command, argument, reply code, `+OK`/`-ERR`, IMAP tag and status); lines that are not commands, such as a
message body, stay message data. A user name or password is never read out: the argument of `USER`,
`PASS`, `ACCT`, `APOP`, `AUTH`, `LOGIN` and `AUTHENTICATE` reads **Not shown** (the Cleartext Credentials
finding still says one crossed the wire). Select them with `ssdp`, `ssh`, `ftp`, `smtp`, `pop` and `imap`,
and use **Capture ▸ Decode As…** for a service on another port.

**SMB** (TCP 445 or 139) is read to its header in the packet list — for SMB2-family messages the command,
request or response, message, tree and session ids and, on a response, its NT status (`STATUS_LOGON_FAILURE`,
`STATUS_ACCESS_DENIED`, …), so a failed share connection names its reason. File names and data are read only
when you explicitly choose **File → Export Objects → SMB**. **LLMNR** (UDP 5355) is read like DNS and
its answers name hosts like mDNS answers do. The **NetBIOS Name Service** (UDP 137) names the query or response,
the name with its suffix (`FILESERVER<20>`, and in an answer the service it stands for) and the address a
response gives. Select them with `smb` (or `smb2`), `llmnr` and `nbns`.

**Kerberos** (UDP or TCP 88) names the message — AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ, AP-REP or KRB-ERROR —
and for an error its code (`KDC_ERR_PREAUTH_REQUIRED`, `KRB_AP_ERR_SKEW` for a clock problem, …) and realm.
**LDAP** (TCP 389, or 3268 for the global catalog) names the first message's id and operation (`bindRequest`,
`searchRequest`, …) and a reply's result code (`invalidCredentials`, `insufficientAccessRights`, …). Principal
names, bind names and credentials are never read. Select them with `kerberos` and `ldap`.

**STUN** is recognized by its RFC 5389 magic cookie on any port (it rides on ephemeral ICE ports, not
a well-known one), so the traffic a capture would otherwise show as bare UDP is surfaced with its
message type — Binding Request/Indication/Success/Error, or an honest hex value for other types —
along with the declared length, magic cookie, and transaction ID. This is header **metadata only**:
Tracexy does not track ICE state, follow TURN allocation state, or decrypt any payload.

**TLS** is recognized by its record header on any TCP port, so an encrypted connection captured
mid-stream is surfaced as TCP · TLS instead of bare TCP. Each recognized record reports its actual
content type — Handshake, Application Data, Alert, Change Cipher Spec, or Heartbeat — with the
record-layer version and record length. A ClientHello or ServerHello is enriched further with SNI,
ALPN, negotiated version, and cipher suite. A bounded 16 KiB, per-direction TCP prefix reassembler in
the session layer recovers this metadata when a first TLS record, HTTP header, or DNS-over-TCP message
is split across nearby segments; it handles gaps, overlap, retransmission, and sequence wrap without
retaining an unbounded stream. Tracexy still does **not** decrypt payloads, parse certificates, or offer
a general connection/reassembly engine. When a record remains incomplete, its captured and declared
lengths are labelled honestly, for example "4096 declared, 40 captured (fragment)". Encrypted TLS
records carry no plaintext exchange, so a TLS-only session offers no requests facet.

In the right-hand **Details** dock, **Response Times** lists the intervals this session's own frames bound: the
connection attempt the peer answered, the whole observed handshake, the TLS hello exchange, the first
reply after a request, and each DNS query and its answer. Every row carries the two frames that bound
it, so the number can always be checked against the capture. An interval is reported only when both
frames carry a capture time and nothing was dropped between them; otherwise the row is absent rather
than estimated. A TLS session's hello exchange supersedes the generic request-to-reply row when both
describe the same two frames. Capture-loss knowledge is stated once beneath the rows.

**TCP Health** follows the response times with four charts of the same conversation, one at a time:
**Sequence** plots each direction's observed payload byte interval as well as how far its sequence
space reached, against the edge its peer acknowledged,
**Throughput** plots both wire bytes sent per second and receiver-ACKed sequence bytes per second
for each direction. Goodput combines newly reported SACK ranges with cumulative ACK advancement,
counting overlapping ranges only once as the cumulative edge moves and excluding RFC 2883 D-SACK
block patterns from new-byte credit. **Round Trip** is the interval
from a segment to the acknowledgement that covered it, and **Window** is the receive window offered to each
direction beside the bytes it had sent but not yet seen acknowledged. Each direction is named by the
endpoint its frames came from, never "client" or "server". Every point is a frame that was retained:
ranges are shown as vertical payload or SACK intervals at the frame that carried them; sequence/window lines
connect observed points linearly without smoothing, averaging across a gap, or extrapolating. Hovering reads the nearest point exactly
rather than against the axis, and clicking the plot opens that frame in the evidence inspector. A
pending round-trip candidate is removed under [Karn's algorithm (RFC 6298 §3)](https://www.rfc-editor.org/rfc/rfc6298#section-3)
when a later observed sequence range overlaps it, because
the acknowledgement cannot say which transmission it covered; the chart states how many candidates
were excluded. A timed range starting below the observed high-water mark is conservatively not sampled
because a first out-of-order copy cannot always be distinguished from a retransmission. Advertised
The Round Trip chart keeps Karn-safe cumulative-ACK RTT separate from **SACK-reported RTT**. The latter
uses the first retained SACK block that exactly matches one non-overlapping captured payload range,
and cites both frames; repeated reports do not create extra samples. It describes receiver observation,
not application delivery, and is a conservative Tracexy measurement rather than a claim of Wireshark
algorithm parity. Windows are scaled only when both SYNs showed the
RFC 7323 shift; when no SYN was captured for one side, the chart says the values are raw and the real
window may be larger. Tracexy keeps a bounded run of each conversation's segments rather than the
whole capture, so a long conversation states once which frames the charts cover and how many later
segments were not retained. **Analyze Entire Conversation** rescans the complete stable source for the
selected TCP conversation, up to 65,536 decoded segments; active capture is unavailable, and an
incomplete source or an exceeded segment limit does not replace the retained-prefix charts with a partial
full-scan result. Full-scan charts draw at most 1,024 observed points per line, preserving capture-order
group endpoints and extrema, and state how many points are drawn out of the total. TCP SACK options show
the receiver-reported left and exclusive right edges in wire order, as ranges relative to the peer's
first observed sequence number when that base can be placed safely. Unplaceable ranges are counted.
The Goodput line reflects receiver-reported sequence space and does not prove application consumption.
The Sequence overlay gives [RFC 2883](https://www.rfc-editor.org/rfc/rfc2883.html) D-SACK ranges a distinct dashed style when the first block is wholly below
that ACK's cumulative edge, or wholly above it and contained by the second SACK block. The label and chart caveat identify
this as the receiver's report; Tracexy does not infer why the duplicate arrived or create a D-SACK finding.
A session with
no retained TCP segments — a UDP flow, for instance — shows no charts at all.

Below it the dock uses compact two-column tables for assessment, connection/TLS/datagram evidence
coverage, decoded layer facts, host baseline, related actions, findings, and grouping evidence. Its
connection/TLS sections summarize scope and link to the chronological Evidence facet rather than
duplicating the full event list. Technical values are selectable and monospaced; related-action rows
remain clickable, and evidence-backed finding citations can open their exact local frame.

**Capture → Start Capture** (Command-E) starts or stops a live capture from the keyboard, like the
toolbar button. Launched with a capture (`open -a Tracexy capture.pcapng --args -Y "tcp and port == 443" -g 42`), Tracexy
takes Wireshark's `-Y` (or `--expression`) to open the capture narrowed to that Session Expression and `-g` (or
`--frame`) to go to that frame, as a cited frame in Layers. `-i` (or `--interface`) chooses the capture interface —
a name such as `en0`, or a named pipe's path — and `-k` starts capturing once launch setup completes. Other
arguments are ignored.

**View → Zoom In** (Command-+), **Zoom Out** (Command-−) and **Actual Size** (Command-0) change the size of
packet text, as Wireshark's zoom does: the hex dump (pointing and clicking bytes still land on the right
byte), the decode tree, Follow Stream transcripts and the All Frames list. The size is kept per Project.
**Capture → Restart Capture** (Shift-Command-R, as Wireshark's Restart) stops the running
capture, waits for it to finish writing its last packets, and starts a new one with the same settings; the
new capture replaces what the list showed, as Stop then Start would. **Capture → Refresh Interfaces**
reads the interface list again, so an adapter added since the menu was built (a VPN, a USB or Thunderbolt
adapter) appears. **Capture → Manage Interfaces…** (also at the bottom of the toolbar's interface menu)
lists every interface on this Mac: clear **Show** to leave one out of the capture menus (the one you
capture on always stays listed), type a **Name** to show it by, such as "Office Wi-Fi", and keep a
**Comment**. These belong to the Mac, so every Project sees them. The **Pipes** tab lists named pipes as
capture sources, as Wireshark's does: make one with `mkfifo /tmp/remote.fifo`, add its path, choose it from the
interface menu's Pipes group and Start, then send a pcap or pcapng stream into it — for example
`ssh host "tcpdump -U -w - -i eth0" > /tmp/remote.fifo`. Tracexy reads the pipe itself, with no helper and no
privilege; the capture filter does not apply, so filter where the capture is taken. Capture stops when the writer
closes the pipe, or on Stop. `open -a Tracexy --args -i /tmp/remote.fifo -k` does the same from the command line
and adds the pipe to the list. **Help → Supported Protocols** lists every protocol Tracexy recognizes — its name, what is read from it, the Session
Expression keyword that finds it and how many sessions of the open capture carry it — and **Show Sessions** narrows the
main window to them, as Wireshark's View → Internals → Supported Protocols lists its dissectors.
**Help → Keyboard Shortcuts** lists every menu command that has a key. The Help menu
also opens this **User Guide** (Shift-Command-?), the **Release Notes**, Wireshark's public **Sample
Captures** page and **Report an Issue** in your browser, and **Show Captures Folder** reveals the active
Project's capture folder in Finder.

**View → Next Session With a Finding** (Option-Command-Down Arrow) and **Previous Session With a
Finding** (Option-Command-Up Arrow) select the next or previous flagged session among those in view, in
capture order, from anywhere in the window. They stop at the first and last flagged session rather than
wrapping around.

**Notes** closes the dock: a place to write what you concluded about the session, and — through
**Note a Finding** — about any finding on it. A note is saved as you type, in the active Project only,
and belongs to the capture it was written about: a saved file is recognized by its content, so the note
comes back when the same file is reopened, moved, renamed or copied, but never appears on a different
capture that happens to contain the same conversation. Notes written during a live capture follow it into
the Library file when the capture is saved. A session with a note shows a note mark beside its host in the
Sessions table. Clearing a note's text removes it. Each Project keeps at most 500 notes of up to 2,000
characters; a note is never removed to make room. A **Tracexy Session** export includes the notes on
that session exactly as written, and a protected export records that it carries them, because masking
and credential stripping apply to decoded evidence, not to your own words.

**Tag** in a session's right-click menu puts Finder-style color tags on it — red, orange, yellow, green,
blue, purple, gray — with whatever meaning you give them; **Clear Tags** removes them. Tags follow the
same rules as notes: kept in the active Project, tied to the capture by its content, carried from a live
capture to its saved file, and at most 2,000 tagged sessions per Project. Tagged sessions show colored dots
beside their host, and `tag == red` or `tag in {red, orange}` in the Session Expression finds them; the
list updates as soon as you tag another session.

A capture file also reopens where you left it: the session that was selected and the session expression
that was applied come back when the same file (recognized by content, like notes) is opened again in the
same Project. A session no longer in the file is simply not selected. The last 100 captures are
remembered; live captures are not, since a live run is never reopened as itself.

The adjacent **AI Assistant** tab is a working conversation over a model running on this Mac. See
[AI Assistant](#ai-assistant) below.

## AI Assistant

The Assistant answers questions about **the selected session only**, using a model running on this
Mac. It is local-only in this build: there is no account, no API key and no remote provider.

**Connect a local model.** Install a local model runner — an [Ollama](https://ollama.com) daemon on
its default `http://127.0.0.1:11434` needs no configuration — and open the AI Assistant tab. Tracexy
checks the endpoint once and shows what it found. To point at a different local runner, use
**Settings → MCP & Assistant → Local endpoint**. Only `127.0.0.1`, `::1` and `localhost` are accepted;
a remote address, a URL with a user name or password, or a redirect off this Mac is refused before
anything is sent. An endpoint that answers only the OpenAI-compatible API is labelled *local
OpenAI-compatible*, because Tracexy will not claim to know which server it is.

**Ask about a session.** Select a session, then type a question or pick one of the suggested openers.
Use the model picker beside the composer to choose among the models the endpoint advertises.

**Review what is sent.** On the first send — and again whenever the Project, selected session,
evidence publication, disclosure, endpoint or model changes — Tracexy shows the **Review Data** sheet before anything
leaves the app. It shows the literal JSON, the destination and model, the disclosure decision and the
coverage limits. **Included fields** are separate opt-ins for the process name, the display host, and
the source/destination endpoints; all three start off. The display host can contain a name derived
from DNS or TLS SNI. Packet bytes, payload bodies, URLs, file paths and credentials are never included.

**Read the answer honestly.** Answers stream as they arrive. **Stop** ends one, and whatever text had
arrived is kept and marked incomplete — Tracexy never presents a partial answer as a conclusion, and
the same label appears when a length or time limit is reached. **Retry** re-sends the last prompt, and
**New conversation** starts over. Changing Project, workspace, session, endpoint or model cancels an
answer in flight rather than letting it land under something it does not describe.

**Follow the evidence.** Citations such as `frame-1024` appear as buttons under an answer; clicking one
opens that exact frame in the evidence inspector, the same route a Findings row uses. A citation the
model invents is not clickable — it resolves to nothing rather than to the wrong frame.

Conversations are kept per Project workspace, in memory, for the life of the app session. Prompts and
answers are not written to disk.

## MCP for external clients

Tracexy bundles a free, read-only MCP command-line tool so an MCP client — an editor, an agent, a
notebook — can read bounded summaries from **one Project you authorize**. It speaks JSON-RPC over
stdin and stdout and **never opens a network port**.

Open **Settings → MCP & Assistant**. The pane names the current Project, the field families that will
be disclosed, and the maximum rows one request may read, then **Grant Access** issues the grant. The
pane shows `Contents/MacOS/TracexyMCP`, the command's location **inside the Tracexy app on your Mac**.
**Copy Client Configuration** creates ready-to-paste JSON for a client on that same Mac. Its `command`
contains the full path to your installation, which may include your macOS account name. Keep that JSON
in your local client settings rather than sharing it publicly. If you move the app, copy the
configuration again. The client needs no port, host or token.

A client sees exactly four read-only tools: `describe_scope`, `list_captures`, `list_sessions` and
`list_findings`. `list_findings` returns a capture's evidence-linked findings by the same kind names the
Session Expression uses (`retransmission`, `dnsNameError`, …) with their severity and citation counts, and
names each finding's session only by ID. Your notes are never exposed. History written before this
version records no findings until Tracexy opens that Project again and upgrades it.
There is no tool for packet bytes, capture files, file paths, raw frames, capture control or writes,
and a process or host filter is refused unless you disclosed that field.

**Recent activity** lists what clients called: the time, the tool, the outcome, the Project, and the
*names* of the filter fields used — never the values, and never anything read back.

Switching Projects or pressing **Revoke** invalidates the grant, so the next call from any connected
client fails closed. Re-issuing a grant also supersedes the old one; reconnect the client afterwards.

## Language

Tracexy follows the language order in **System Settings → General → Language & Region**, or the
per-app choice there. English and Vietnamese are included. The Vietnamese translation covers the
menus, windows, buttons, labels and help text that the interface declares as fixed copy; some
composed status lines and protocol terms stay in English, and protocol field names, Session
Expression words and exported file contents are never translated.

## Command line

The Tracexy app binary is also a read-only command, for scripts and CI:

```
Tracexy.app/Contents/MacOS/Tracexy summary  <capture> [--json]
Tracexy.app/Contents/MacOS/Tracexy sessions <capture> [--expression <text>] [--format csv|json]
Tracexy.app/Contents/MacOS/Tracexy findings <capture> [--expression <text>] [--format csv|json] [--fail-on note|warning]
Tracexy.app/Contents/MacOS/Tracexy stats    <capture> --tap <name> [--tap <name>…] [--expression <text>] [--format text|csv|json]
Tracexy.app/Contents/MacOS/Tracexy frames   <capture> [--expression <text>] [--format text|csv|json] [--details]
Tracexy.app/Contents/MacOS/Tracexy objects  <capture> [--expression <text>] [--format text|csv|json] [--body <n>]
Tracexy.app/Contents/MacOS/Tracexy follow   <capture> --expression <text> [--format ascii|hex|raw|c|yaml]
Tracexy.app/Contents/MacOS/Tracexy info     <capture> [--format text|json]
Tracexy.app/Contents/MacOS/Tracexy select   <capture> [--frames 1-100,250] [--expression <text>] [--dedupe] [--snaplen <n>] [--comment <text>] > out.pcapng
Tracexy.app/Contents/MacOS/Tracexy merge    <capture> <capture>… > merged.pcapng
```

It reads one PCAP or PCAPNG file with the same fold, findings, Session Expression and export code as
the window, and prints to standard output: `summary` gives frames, sessions and findings by title;
`sessions` and `findings` print the same CSV or JSON as **File → Export Investigation**, limited to the
sessions the `--expression` matches (for example `finding == retransmission and port == 443`). It never
captures, never writes a file and never touches a Project, History, Library or setting. `stats` prints the
Statistics windows — the counterparts of tshark's `-z` taps, and tshark's spellings are accepted:
`conv,ipv4|ipv6|tcp|udp` (Conversations; `conv,ip` too), `endpoints,…` (Endpoints), `plen` (Packet
Lengths), `phs` (Protocol Hierarchy; `io,phs` too), `expert` (Findings by kind), `dns` (DNS Lookups),
`http` (Message Counts), `ip_hosts`, `ptype`, `ip_srcdst`, `dests`, `ip_ttl` and their `ipv6_…` / `ipv6_hop` forms
(IP Statistics), `http_seq` (HTTP Request Sequences), `sip,stat` (SIP), `rtp,streams` (RTP Streams) and
`smb2,srt`, `ldap,srt`, `kerberos,srt`, `icmp,srt`, `icmpv6,srt` (Service Response Time) — as an aligned text table
by default (trees keep their indentation), or CSV (formula-guarded) or JSON; repeat
`--tap` for several, and `--expression` narrows the sessions first. `frames` prints the bounded View ▸ All Frames
list — number, time since the first frame, source, destination, protocol, capture-interface direction
(`inbound`, `outbound`, or `unknown`), length, Info and session id, plus any
decode-tree field named with `--column Protocol:Field` (for example `--column TCP:Window`, like tshark's `-e`) — for
frame in the capture, or only the frames of the sessions `--expression` keeps. The CLI spools these rows to a
temporary file, validates the complete stable capture, then prints text, CSV or JSON with bounded row memory.
Frame-derived statistics still use the 200,000-frame retained list and fail with an incomplete-coverage error if
that limit is exceeded, except SRT taps, which use bounded capture-wide reducers and can be combined with
session-only taps such as `conv,ipv4`. Other taps that need frame rows retain the 200,000-frame limit. A truncated
final capture record fails before a frame table is printed. `--details` (or `-V`) prints each frame's whole
decode tree instead, as text laid out like tshark `-V` or as JSON (one object per frame with its layers and fields,
times in UTC with microseconds) — the same output as **File → Export Packet Dissections…**. Add
`--frames 2,5-7` with `--details` to select original capture frame numbers; `--expression` can further narrow
those frames by session. Dissection export rejects a truncated final capture record and rechecks source identity
before reporting success. The app does not publish its staged file, and the CLI stages its output before writing
stdout, when this happens. `objects` lists the HTTP response bodies
(File ▸ Export Objects; tshark's `--export-objects`) with their frame, host, content type, size and
file name — or, with `--type imf`, `tftp`, `ftp-data` or `x509af`, the email messages, TFTP or FTP files or
certificates — and
`--body 2` prints the second one's bytes (an HTTP body gzip or deflate decoded), so
`tracexy objects capture.pcap --body 2 > page.html` saves it. `follow` prints the one TCP session the
`--expression` names (for example `port == 50000`) in the Follow Stream formats; `--format raw` gives the same
bytes as tshark's `-z follow,tcp,raw` when cross-direction order is known. The command reports an error instead
of fabricating an interleave when both directions lack proven chronology. Both write only to standard output.
`glossary` (no capture needed) lists every name a script can use — expression terms, protocol keywords, finding
kinds, statistics taps and Export Objects types — as text or `--format json`. `info` is capinfos: the **File → Get
Info** report — format, frames, first and last time, elapsed, each section and interface with its link type,
snapshot length and statistics — with the file's SHA-256 and SHA-1, as text or as JSON key/value pairs. `select` is
editcap's selection: the frames `--frames` lists (numbers and ranges, as `editcap -r`), or the frames of the
sessions `--expression` keeps, with `--dedupe` dropping a frame identical to one of the previous five (`editcap
-d`), `--snaplen` keeping at most that many bytes of each frame (`editcap -s`), `--time-shift` moving every
frame's time by that many seconds (`editcap -t`) and `--comment` adding a capture
comment (`editcap --capture-comment`, repeatable). `merge` is mergecap: every frame of two or more captures in time order, each interface kept apart. `select`
and `merge` print PCAPNG to standard output, so a file exists only where the shell redirects it. Exit status is 0
on success, 1 when the capture cannot be read, 2 for a usage or expression error (the expression is
checked before the file is read), and 3 when `--fail-on` finds a finding of that severity or worse. A
gzip- or LZ4-compressed capture is expanded into a temporary folder first, with the same limits as the app. **Settings → MCP & Assistant → Command Line** copies a
command that links it into your PATH as `tracexy`; Tracexy never installs it itself.

Decoding commands (`summary`, `sessions`, `findings`, `stats`, `frames`, `objects`, `follow` and `select`)
also accept repeatable `--decode-as udp:5300:dns` rules (or `tcp:port:protocol`) to interpret a
nonstandard service port for that command. Values must name a supported Tracexy protocol and
transport; ports are 1–65535, selectors must be unique, and at most 64 rules are accepted.
These rules apply only to that CLI invocation and are not saved to Project settings. The syntax
is Tracexy's own and does not implement TShark's `-d` grammar.

## Software updates

When the signed appcast reports a newer release, the center toolbar status shows a gray **New Updates**
capsule beside the capture state. The count represents newer appcast releases when that history is
available. Click the capsule to open the standard Sparkle update experience. The capsule stays visible
until the feed no longer reports a newer compatible release; closing the update window does not dismiss
it as though the update had disappeared.

## Process attribution

Where macOS reports it, a session carries the **owning app's name**. Tracexy reads this from the
`pktap` per-packet metadata header on captured frames — preferring the *delegating* app for traffic
carried by a system daemon, so a URLSession request is attributed to the app that made it rather than
to `nsurlsessiond` — and falls back to a local socket-to-process lookup. This is display-only
enrichment. When the owner cannot be resolved, the session simply has no process name; Tracexy shows it
as unknown rather than inventing one. The status bar says how far attribution reached — **Process 82 of
138** means 82 of the sessions in view carry an owning process. It is shown while capturing, and for a
capture file only when at least one session is attributed.

Throughout, Tracexy shows what it captured and nothing more: a host with no resolvable name shows its
IP, a session with no attributable process shows none, and an idle capture shows an empty list. Nothing
in the UI is fabricated when data is missing.

### Session time

**View ▸ Session Time** chooses how the Sessions table's first column shows when each session started:
**Time of Day** (local, the default), **Time of Day (UTC)** for lining up with server logs, or **Seconds
Since Capture Start**, counted from the capture's first timed frame. The column title follows the choice,
sorting is unchanged, and the choice is kept per Project. A capture with no timed frame keeps showing the
time of day rather than inventing an origin.

### Protocol hierarchy

**Statistics ▸ Protocol Hierarchy** groups the sessions in view by protocol path — TCP, then TLS or HTTP inside
it; UDP, then DNS or QUIC — with each row's sessions and bytes and their share of the scope. It counts
sessions, not packets: a session counts once toward every layer of its stack, so a parent row is at least
the sum of its children. **Show Sessions** (or a double-click) narrows the main window to the sessions
carrying every protocol on the row, as a drill-down Back to Previous Scope can return from.

### DNS lookups

**Statistics ▸ DNS Lookups** lists every name the sessions in view looked up over unicast DNS: how many lookups
there were, what came back (answered, no such name, server failure, unanswered — the last three from the
same evidence-linked findings the Findings list shows), and the median measured time from query to
answer. Names with a problem come first. **Show Sessions** (or a double-click) narrows the main window to
that name — its lookups and the sessions that used it. Multicast DNS names are listed in Resolved
Addresses instead.

The **Encrypted DNS** view of the same window answers "is my DNS encrypted?": it lists the resolvers the
sessions in view reached over DNS over TLS or DNS over QUIC (recognized by port 853) and over DNS over
HTTPS (recognized only when the server's name is a well-known public resolver such as `dns.google`,
`cloudflare-dns.com` or `dns.quad9.net` — a private resolver is not guessed), with their sessions and bytes,
and the footer sets them beside the plain DNS sessions. The looked-up names stay encrypted; only the
resolver is visible.

### Message counts

**Statistics ▸ Message Counts** counts the plain HTTP/1 requests by method, the HTTP/1 responses by status class
and code, and the DHCP messages by type in the sessions in view — the counters Wireshark calls HTTP and
DHCP packet counters. A message is counted once per captured frame whose first 512 bytes begin with its
request or status line (or carry the DHCP message type); a message that started mid-frame is not counted,
and each session keeps at most 16 kinds per table, with the footer saying when more were seen. Every row
names the Session Expression that finds its sessions (`http.method == GET`, `http.status in 400..499`,
`dhcp.message == Offer`); **Show Sessions** (or a double-click) narrows the main window with it, and the
context menu copies it. The same three fields work in **View ▸ Investigate Sessions…**.

### Decode As

Tracexy recognizes most protocols by content (TLS, HTTP/1, STUN) or by their standard port (DNS 53, mDNS
5353, NTP 123, DHCP 67/68, QUIC 443). **Capture ▸ Decode As…** adds rules for traffic on another port, as
Wireshark's Decode As does: choose TCP or UDP, a port, and one of the protocols offered for that transport. A
rule applies to frames to or from that port, ahead of Tracexy's own detection; a rule that cannot apply (port 0,
QUIC over TCP) is marked and ignored. In **View ▸ All Frames**, right-click a TCP or UDP packet and choose a
source or destination port under **Decode As…** to prefill a proposed rule. Review the port and protocol, then
choose **Apply Rule**; the proposal does not change decoding until applied. You can also right-click a TCP or UDP
layer in the packet-details tree. If that transport/port already has a rule, applying the proposal replaces it
instead of adding a shadowed duplicate.
Rules belong to the active Project and apply to captures decoded in the app after the change — live captures,
files you open, frame lists and Follow — and **Decode Again** re-reads the open capture file with them
(Wireshark's Redissect); the file itself is not changed. The command line is a separate, read-only invocation:
pass `--decode-as` explicitly when needed; it does not load or change Project rules.

**Capture ▸ Enabled Protocols…** (the second pane of the same window) switches recognition off, as Wireshark's
Enabled Protocols does: uncheck a protocol and its traffic stays plain TCP or UDP data wherever it appears — by
port, by content or by a Decode As rule — for a port another program uses for something else. **Enable All** turns
everything back on. The choice belongs to the Project, applies to captures decoded from then on, and **Decode
Again** re-reads the open file with it.

### All frames

**View ▸ All Frames** (**Option-Command-A**) lists every frame of the open capture file (or a stopped live
capture) the way Wireshark's packet list does: number, time, source, destination, protocol, length and an
Info line — TCP flags with sequence, acknowledgement, window and length (raw sequence numbers; Wireshark shows
them relative by default). **Relative TCP Seq/Ack** in the footer opts into an All Frames-only relative
projection, using each direction's first observed sequence as its origin; an ACK stays `?` until the reverse
direction has an observed origin. This display projection is bounded to 200,000 conversations and does not
change raw decoder facts or Frame Expression matching. TLS record types such as Client Hello or Application Data, DNS query or response
with its type and name, or the innermost layer's summary. IPv6 addresses are shown compressed. **Limit to
Sessions in View** (on by default) keeps only the frames of the sessions the main window shows — the
counterpart of Wireshark's displayed frames — and the search field matches Info, addresses and protocol. When no frames match, **Show Frames Outside Sessions in View** removes only this session scope; search, Frame Expression, ignored-frame and decode-problem filters still apply, so the action does not promise every capture frame will become visible.
The **Frame Expression** field filters individual listed frames using a small typed subset: `frame.len >= 128`
(original frame length), `frame.cap_len < 128` (captured byte length), and `frame.truncated` (original length
greater than captured length; this is a Tracexy-specific field), `ip.ttl <= 2`, `ipv6.hlim == 64`,
`ip.flags.mf`, `ip.flags.df`, and `ip.frag_offset > 0`. TTL and hop-limit predicates support five numeric comparisons
with values from 0 to 255; nested IP layers match when any corresponding decoded header meets the condition.
While editing, the draft is syntax-checked and reports **Draft syntax valid** or the parser's character position
and reason. This check does not evaluate frames or alter the active filter; choose **Apply** (or press Return)
to run the filter. Editing a bad draft leaves the prior applied result in place.
The IPv4 fragment offset uses bytes (0–65535); its comparison also matches any decoded IPv4 header.
`ip.flags.mf` matches when any decoded IPv4 header has the More Fragments flag set. `ip.flags.df` matches when
any decoded IPv4 header has Don’t Fragment set; write it as a bare predicate or `not ip.flags.df`. The two flags
are evaluated independently. A fragment that could hide an inner IPv4 header remains unknown if no matching
flag was observed; the DF bit alone does not establish an MTU problem or successful delivery. If decoding stops
before the fields can disprove a match, the result is unknown, including under negation. Both length fields support
`==`, `>`, `>=`, `<`, or `<=` and a decimal value from 0 to 4294967295. Other terms include `tcp.rst`,
`tcp.syn`, `tcp.flags.fin`, `tcp.flags.syn`, `tcp.flags.reset`, `tcp.flags.push`, `tcp.flags.ack`,
`tcp.flags.urg`, `tcp.flags.ece`, `tcp.flags.cwr`, `tcp.port == 443`,
`tcp.window_size_value == 0` (the observed unscaled 16-bit TCP header value),
`tcp.seq_raw == 1000` and `tcp.ack_raw == 2000` (the observed raw 32-bit TCP header values),
`tcp.srcport == 50000`, `tcp.dstport == 443`, `udp.port == 53`, `udp.srcport == 53`,
`udp.dstport == 5353`, `ip.addr == 192.0.2.10` (source or destination), `ip.src == 192.0.2.10`,
`ip.dst == 198.51.100.7`, and `ip.id == 4660` (the observed unsigned IPv4 Identification, compared as a
decimal value; it matches any decoded IPv4 header). A match does not establish reassembly or identify a
unique datagram. **Identification** in the IPv4 decode tree is shown in hexadecimal and offers Apply/Prepare
as Frame Filter only when the IP layer is unique; the action converts it to the decimal Frame Expression value.
An unresolved fragment whose payload may contain an inner IPv4 header remains unknown when no matching ID
was observed. IPv6 has no equivalent fixed-header Identification field. Other terms include `dns.response`,
`dns.rcode == 3` (the observed 4-bit DNS response code), and
`dns.id == 4660` (the observed unsigned 16-bit DNS transaction ID, including on a message whose later body
does not decode). A matching ID does not establish that two frames are one query/response transaction;
when a malformed/truncated decode or unresolved TCP/UDP fragment could hide DNS, the result stays unknown,
including under negation. DNS predicates describe decoded per-frame messages, not encrypted or reassembled
stream-only DNS. The decoded DNS, mDNS and LLMNR Transaction ID field offers **Apply as Frame Filter** and
**Prepare as Frame Filter** only when that DNS-family layer is unique.
The bare `dns.flags.truncated` predicate matches the observed DNS TC bit in query or response headers;
the decoded **Truncated (TC)** field offers the same Apply/Prepare actions. TC is independent of
`frame.truncated`, which means the captured frame bytes are shorter than the original frame. TC alone does
not prove packet loss, resolver failure, or successful TCP fallback.
Capture direction is available as `frame.capture_direction == inbound` or
`frame.capture_direction == outbound`. This is direction relative to the recording interface, not
client/server or endpoint direction. PCAPNG packet flags can provide it; classic PCAP or frames without
direction metadata evaluate as unknown. Unknown remains unknown under `not`, so an absent flag is never
assumed outbound. The same predicate applies in All Frames, Frame Find, I/O Graph comparisons, filtered
frame export and dissection export.
ICMP and ICMPv6 also support `icmp.type == 3`, `icmp.code == 3`, `icmpv6.type == 2`, and `icmpv6.code == 0`.
These compare only the observed outer ICMP header's raw 8-bit type/code; they do not classify the message or inspect quoted-flow fields.
The session inspector's decoded fields also offer **Apply as Frame Filter** and **Prepare as Frame Filter**
for supported IP addresses, IPv4 Identification / TTL / Don’t Fragment / More Fragments / fragment offset, IPv6 hop limit,
ICMP/ICMPv6 Type and Code, directional TCP/UDP source and destination ports, individual TCP FIN/SYN/RST/PSH/ACK/URG/ECE/CWR
bits, and the observed TCP window, sequence, and acknowledgement values. TCP flag rows use distinct labels such as
**Acknowledgment (ACK)** so they remain separate from the numeric **Ack** field. TCP actions require a unique TCP
layer. IP, ICMP and ICMPv6 field actions are offered only when the corresponding decoded protocol layer is unique,
avoiding ambiguous tunnel-layer selection.
When a field has a supported, unambiguous Frame Expression term, its context menu offers **Highlight Matching
Frames** and **Copy as Frame Filter**. Highlighting opens All Frames and applies the existing temporary,
page-local highlight without changing the Frame Expression draft or applied filter; **Clear Highlight** removes it.
Copy places the standalone term on the clipboard without changing either expression editor or opening All Frames.
**Apply as Frame Filter** and **Prepare as Frame Filter** open **All Frames** and use its packet-level expression;
they do not change the Session Expression. **Highlight Matching Frames** opens **All Frames** and applies the
temporary highlight only. **Copy as Frame Filter** only places the standalone term on the clipboard.
Directional port terms such as `tcp.srcport == 50000` retain which endpoint supplied the decoded field.
TCP raw sequence and acknowledgement fields support equality only with a decimal value from 0 to 4294967295. They match the wire header values; the acknowledgement field is available even when the ACK flag is clear. Repeated values alone do not establish retransmission. The TCP window value supports the same five numeric comparisons with a decimal value from 0 to 65535;
it does not infer a negotiated window scale from missing handshake packets. A raw zero value can also
appear on SYN, FIN or RST packets; use the evidence-linked `zeroWindow` finding for Tracexy's
flow-control evidence. Its events can include a receive-window update, zero-window advertisement, a probe, or an
acknowledgement that repeats the probe edge or advances by the single observed probe byte. This
does not infer acceptance of later bytes from repeated acknowledgements. If that one-byte ACK
also reopens the advertised window, the captured byte is accounted for before Tracexy evaluates
whether the ACK extends beyond observed sequence data.
Use **Saved Frame Filters** to reuse named expressions within this Project. Choosing one fills the draft;
it does not change the active result until you choose **Apply**. Manage Saved Frame Filters supports
adding, editing and removing bounded presets. They are local to the Project's preference suite and are
not included in `.tracexyproject` transfer. They use Tracexy's Frame Expression grammar, not Wireshark
display-filter syntax or macros.
**Recent Frame Expressions** keeps up to 12 distinct expressions accepted in the current capture
session in memory. Selecting one fills the draft and still requires **Apply**; malformed expressions
and cancelled or superseded evaluations are not recorded. The list clears when the capture or Project
changes and is never written to disk.
Choose **Highlight** to apply the draft as one temporary visual rule while keeping the packet list intact;
it is independent of the applied filter and the matching expression appears beside the controls. Matching
rows carry an orange dot in the frame-number column with an accessibility label. Unknown results remain
untinted and are counted for the retained page. **Clear Highlight** removes the rule. Highlights are
page-local, recalculated after a page rescan, and cleared when the capture or Project changes; they are not
saved into Project settings, captures, History, exports or `.tracexyproject` files. This temporary highlight remains independent of Project coloring rules. **Coloring Rules** stores up to 32
ordered rules in this Project. Each rule has a name, a Frame Expression, foreground and background colors, and an
enabled switch. The first rule that evaluates yes wins. An unknown higher-priority rule blocks lower-priority
colors so missing packet facts do not fabricate a match. Rules need at least 4.5:1 text/background contrast;
selected and ignored rows keep their native selection/ignored treatment. **Duplicate** creates a new draft row after
the source rule with a fresh identity, copied expression/colors/enabled state and an available name; it is disabled
at the 32-rule limit. Save persists the edited draft, while Cancel discards it. Rules are evaluated off the main thread
over retained frame rows and are not included in `.tracexyproject` transfer. **Import Wireshark Rules…** accepts
`coloring_rules.jsonc` and legacy `colorfilters` files up to 1 MiB / 256 rules. It appends supported rules to the
editable draft, preserving their order, colors and enabled state; existing names are kept and duplicates or
unsupported filters are reported with reasons. Review the imported rows and choose **Save** to persist them.
Import supports Tracexy's Frame Expression subset only; it does not import Wireshark profiles or provide
Wireshark display-filter compatibility. Right-click a frame with a known session and choose **Color This
Conversation** to assign the first free temporary color slot. Up to ten conversations can be distinguished at
once; choose **Clear Conversation Color** on that conversation to free its slot, or use **Conversation Colors →
Clear Conversation Colors** to clear all slots. Temporary conversation colors are capture-local, follow the stable
session identity across All Frames paging, and override persistent coloring rules. Selected and ignored rows retain
their native treatment. The palette uses dark text on light backgrounds; sessionless frames cannot receive a
conversation color. Slots clear when the capture changes and are not saved into Project settings or capture exports.
Combine terms with `and`, `or`, `not`, and parentheses, then choose **Apply**. **Clear** removes the
expression. A frame whose truncated or unsupported decode cannot establish the expression is excluded
from matches and counted as unknown; negation does not turn unknown into a match. An invalid expression
shows the error position and keeps the last applied filter. This is separate from Session Expressions,
which filter whole sessions; other packet field spellings and packet-filter macros are not supported.
Type a number and choose **Go** to select and scroll to that frame. For a capture larger than the retained
window, **Previous Page** and **Next Page** rescan the stable source to show another bounded range; Go loads
the range containing the requested frame. After **Apply**, Frame Expression scans the complete stable
capture: the footer counts all matches and unknown frames, while the table shows matches on the current
range. **Previous Matching Page** and **Next Matching Page** skip ranges without a match. The toolbar
search and **Limit to Sessions in View** narrow the currently listed range. **Find in Frames** (the magnifying-glass
toolbar button) opens Wireshark's Find Packet bar: find a **String**, **Hex** bytes (`16 03 01`, `160301` or
`16:03:01`) or a **Regex** in each frame's **Bytes**, or a string or regular expression in its **Details** — the
layers and fields as Layers shows them — with **Match Case** for strings and expressions. String searches in
Bytes default to UTF-8 and can instead search UTF-16 little-endian, big-endian, or all three encodings. Case-insensitive
UTF-16 search folds ASCII letters by 16-bit code unit; other code units match exactly. This setting does not change
Hex, Regex or Details searches. **Next** (Command-G) and
**Previous** step through matches across the stable capture, loading another page when needed and wrapping at
the source boundary. The bar shows the capture-wide match count. Each step rescans the source while retaining
only the adjacent match and count. If the capture ends in a truncated record, both Find and Frame Expression
label their counts as complete frames before the truncated tail. UTF-8 string, hex and regex byte searches use the
same captured bytes as tshark's `frame contains` and `frame matches`; UTF-16 string modes additionally search the
chosen two-byte encoding. Double-clicking a frame selects its
session in the main window and loads that exact frame in Layers; a frame that belongs to no session opens a
frame-scoped packet-details and byte window from its exact captured bytes. It does not create a session for that
frame. Each list range is rescanned from the stable source on demand, retaining up to
200,000 frames, with progress and Cancel; time follows **View ▸ Frame Time**.
**First on Page** and **Last on Page** select the first or last row currently shown by All Frames, including pinned
time-reference rows. On large captures these actions stay within the retained page; they do not search other pages.
**Back** and **Forward** step through up to 64 distinct frame selections in this capture, like a browser history.
Selecting a new frame after going back starts a new history branch. If a history target is hidden by the current
filters, All Frames reports that fact without changing the filters or moving the history position; targets on
another retained page are loaded before selection.

Selecting a frame in All Frames marks the other frames of its session, as Wireshark's related-packet marks do:
a link beside each, and where the session's first and last frames are. **Previous** and **Next Frame in Session**
(the chevrons in the toolbar, Control-comma and Control-period as in Wireshark's Go menu) step through that session's
frames in the list. **First Displayed Frame in Session** and **Last Displayed Frame in Session** select its earliest
or latest row in the current displayed result, including retained time-reference rows; paging and filters may hide
the capture-wide endpoints. **Mark Selected Frame** / **Unmark Selected Frame** and
**Ignore Selected Frame** / **Unignore Selected Frame** are also available in the toolbar for the selected
row while it remains visible in the main list, including sessionless frames. Right-click a frame in All Frames to
**Mark** or **Ignore** it, as Wireshark's context actions do: a marked
frame shows a bookmark, an ignored one is hidden (or, with **Show Ignored**, dimmed and struck through).
**Mark All Displayed** marks the rows currently shown after session scope, search, decode-problem,
Frame Expression and ignore filters, including pinned time-reference rows. Existing marks outside that visible result stay marked.
**Unmark All Displayed** clears marks only for those rows; **Ignore All Displayed** ignores only those shown rows;
**Unignore Displayed** clears ignore only for rows in the current All Frames result, including retained time-reference rows from another page; filtered rows stay ignored, and the separate pinned strip is not included. With **Show Ignored** off, hidden ignored rows are not included. **Unignore All** clears every ignored frame. **Previous Mark** and **Next Mark** step
between marks; **Export Marked…** opens File ▸ Export Frames with
the **Marked frames** scope chosen. Marks and ignores belong to the open capture and are cleared when another
one is opened; ignoring a frame hides it from the list, it does not change any finding. Right-click ▸
**View Source Comments…** reads the selected frame's existing PCAPNG packet comments on demand and read-only;
they remain separate from **Add Frame Comment…**, which writes your Tracexy note only into a later explicit PCAPNG export.
Comments are bounded to 16 values and 256 displayed bytes each; truncation, invalid UTF-8 and omitted values are identified.
Classic PCAP has no packet-comment options.
Right-click ▸
**Conversation Filter** ▸ Ethernet, IPv4 or IPv6, TCP or UDP filters the Sessions list to the frame's conversation at
that layer (its two MAC addresses, its two IP addresses, or its two endpoints), as Wireshark's Conversation Filter
does; **Tag** colors the frame's session, as Colorize Conversation does. Right-click ▸ **Copy**
puts a frame's columns on the clipboard as Wireshark's Copy ▸ Summary does: **Summary as Text** (tab-separated),
**…as CSV** (quoted), **…as YAML** (a list under a comment naming the frame's row and the capture) or **…as HTML**
(a table row that pastes formatted into Mail, Pages or Notes, with the text alongside for plain-text editors).
The nested **Bytes** menu copies the exact packet bytes as a hex dump, hex stream, printable text, C array,
escaped string, Base64 or raw `application/octet-stream`; bytes are re-read from the stable local source and are
never reconstructed from the displayed row.
**Name Address** offers only the row's valid IP endpoints and adds, edits or removes their aliases in the active Project's address book.
**Pin Row to Top** keeps up to 16 chosen frames in a separate strip above the list while you page or filter; click a pinned frame to select it, use its pin button to unpin it, or right-click a pinned row and choose **Unpin All Rows**. If the frame is excluded by the current filters, Tracexy reports that it is hidden; adjust the filters to reveal it. Navigation is unavailable while the frame list is scanning. Pins are capture-local and separate from marks and time references.

**Add Frame Comment…** (right-click a frame) writes a comment for that frame, shown with a filled bubble in
the Info column. When you export frames as PCAPNG with **Include my notes and frame comments**, each comment is written into its
frame as a packet comment, which Wireshark shows and filters on (`frame.comment`). Frame comments belong to
the open capture until then; they are cleared when another capture is opened.

A frame whose decoding stopped early is marked in the Info column with a warning sign and Wireshark's
suffix: **[Malformed Packet]** when a header is invalid (for example an IPv4 header length below 20 bytes),
or **[Packet size limited during capture]** when the capture's snapshot length cut the frame inside a
        header. With **View → Validate Checksums** on, a frame with a wrong IPv4, TCP, UDP, SCTP,
        ICMP or ICMPv6 checksum is
marked the same way and counted too (a partial, offloaded checksum is not). Hover the sign for the reason.
**Only Decode Problems** in the footer, shown when there are any, lists just those frames. A decode problem is about the capture, not the network, so it never becomes a
session finding.

### Export objects

**File → Export Objects** lists the files and messages the capture carried, one kind at a time, as Wireshark's
Export Objects does; pick the kind from the submenu or the bar at the top of the window. Each row gives the frame,
a host, the content type, the size and the file name it saves under.

- **HTTP** — every HTTP/1 response body: the frame the response began in, the request's host, and the request's
  last path component (with an extension from the content type when it has none). Bodies sent with gzip or
  deflate content coding are listed and saved decoded, as Wireshark's are; other codings are kept.
- **Email (IMF)** — every message an SMTP client sent after DATA, exactly as sent (dot-stuffing kept), named
  after its Subject with `.eml`, the From address as host, at the frame carrying the closing ".". Reading stops
  at STARTTLS.
- **FTP Data** — every file a RETR, STOR, STOU or APPE moved: the data connection the PASV or EPSV reply (or the
  PORT or EPRT command) set up, named by the command's argument, from the frame and sender of its first byte.
  Bytes come from the command's sending direction in TCP sequence order. Directory listings are not files and
  are left out, as in Wireshark. FTP control streams with unknown command/reply packet order are skipped and counted.
- **SMB** — complete files reconstructed on demand from clear SMB2-family CREATE, READ/WRITE and CLOSE traffic.
  The request/reply must match within one unambiguous TCP connection; byte ranges must cover the complete file
  from offset zero to a capture-observed final size. Files with gaps, conflicting bytes, truncated evidence,
  unsupported records or no trustworthy end-of-file witness are omitted. The Evidence column lists the exact
  contributing frames; choose a frame there to inspect it. SMB1, encrypted or compressed transforms, RDMA,
  compounds, named pipes and partial files are not exported. This is capture-observed coverage, not an atomic
  snapshot guarantee about later changes on the server.
- **TFTP** — every file a read or write request moved: the transfer between the requesting client port and the
  server (from whatever port it answers), blocks put in order at the size an option acknowledgement set (512 bytes
  otherwise), a repeated block ignored; a transfer with a missing block, or without its short last block, is left
  out, as in Wireshark. Named by the request's file name without its directories, at the frame of the last block.
  Wireshark 4.6 rebuilds only downloads; Tracexy rebuilds a write request's upload too.
- **X.509 Certificates** — every certificate a TLS handshake sent in the clear (TLS 1.3 sends them encrypted), as
  DER named by its serial number with `.cer`, the subject's common name as host.

**Save…** writes the selected object, **Save All…** writes every object in view into a folder you choose (a
repeated name becomes `name(1)`; a character a file name cannot hold, such as `/` or `:`, is written as `%2f`
or `%3a`, as tshark writes it), and a double-click selects the object's session. The saved files match
`tshark --export-objects http|imf|smb|tftp|ftp-data|x509af`. SMB files contain captured file data; save and share
them only when that disclosure is intended. Tracexy reads the streams of the open capture (or a stopped
live capture's copy) on demand, at most 200 streams, 2,000 objects and 256 MB; the footer says when a bound was
reached. Nothing is opened or run.

**File → Export PDUs…** writes the application messages of the sessions in view to a PCAPNG that Wireshark
dissects directly, as Wireshark's Export PDUs to File does at the application layer: each DNS, mDNS, SIP,
SSDP, NTP, DHCP, STUN or QUIC datagram's payload, and each reassembled turn of an HTTP, TLS, SMTP, FTP, IMAP,
POP3, SSH or SIP stream, one packet each (link type 252, Wireshark Upper PDU) tagged with its protocol and its
addresses and ports. The payload is unredacted, so a Project with privacy protections asks first, as Export
Frames does. TCP streams whose retained frame evidence cannot prove the order between directions are skipped and
counted. At most 200 TCP streams, 100,000 PDUs and 512 MB are read.

### Firewall rules

**Tools ▸ Firewall Rules…** writes a rule for the session selected in the main window, as Wireshark's
Firewall ACL Rules does: choose the firewall (Packet Filter `pf`, iptables, nftables, ipfw, a Cisco IOS
access list or Windows Firewall `netsh`), what to match (the source address, the destination address, the
destination port, or both addresses and the port), **Block** or **Allow**, and **Inbound** or **Outbound**.
IPv6 addresses get the IPv6 form (`ip6tables`, `inet6`, `ipv6 access-list`). **Copy Rule** copies the text;
Tracexy never applies it.

### HTTP statistics

**Statistics ▸ HTTP** shows Wireshark's four HTTP statistics trees over the frames the All Frames list reads
(the capture file is scanned once, on demand), limited to the sessions in view unless you turn that off:
**Requests** (by `Host`, then URI), **Load Distribution** (requests by server address and by `Host`, and
responses by server address as OK or Error), **Packet Counter** (requests by method, responses by status
class and code) and **Request Sequences** (each request's full URI under the page its `Referer` names, and
each redirect's resolved `Location` under the request it answered, to any depth — the order a browser walked a
site). Each row shows its count and its share of its parent; every row starts expanded. **Copy as CSV** and
**Save as CSV…** write the tree shown, indented by depth. The counts match `tshark -z http_req,tree`,
`-z http_srv,tree`, `-z http,tree` and `-z http_seq,tree`, including Wireshark's way of counting a sequence: a
page seen again is counted where it was last placed, and every page above a referer is counted once more per
request. HTTP/1 only: a request or response line must be in the first 512 bytes of a frame; the `Referer` and
`Location` values are read from the frame's own header block.

### DNS statistics

**Statistics ▸ DNS** shows Wireshark's DNS statistics tree over the same frames, on the same terms as
Statistics ▸ HTTP: queries and responses, query and answer record types, classes, response codes, opcodes,
message size, question-name length and label depth, the section counts of responses, and **Service Stats**:
request-to-response time in milliseconds (a response is paired with the first query of the same session
and transaction ID), responses no query asked for, and repeated responses. Measured rows show average,
minimum and maximum. **Copy as CSV** and **Save as CSV…** write the tree. The rows match
`tshark -z dns,tree` with one deliberate difference: **Response Stats** counts each response once, where
Wireshark 4 counts every answered response twice.

### SIP statistics

**SIP** (UDP or TCP 5060) is recognized by its start line: a request (`INVITE sip:bob@example.test SIP/2.0`) names
its method and Request-URI, a response its status code and reason, and both the Call-ID, From, To and CSeq headers
(compact forms too); an Authorization header is never read. Select it with `sip`. **Statistics ▸ SIP** shows
Wireshark's SIP Statistics over the frames in view: the messages, the resent ones (a request repeated while it
waits, or a final response repeated with the same code, per Call-ID and direction), the status codes and request
methods, and the call **setup time** from INVITE to the ACK of its answer, with average, minimum and maximum. The
counts match `tshark -z sip,stat`. **Statistics ▸ VoIP Calls** lists each call (a Call-ID that carried an INVITE)
with its start, duration, From, To, message count and where it got to — call setup, ringing, in call, completed,
rejected with the final code, or cancelled — as Wireshark's VoIP Calls; Show Sessions narrows to its signalling
session and Open First Frame shows its INVITE. **Flow Sequence** opens the Flow Graph drawing only that call: its SIP
messages, and each RTP stream sent to a media address its SDP offered (the `c=` address and `m=` port), drawn once
as "RTP (g711U), 150 packets" at its first packet, as Wireshark's call flow does. **Show All Frames** returns the
graph to every frame.

### RTP streams

**Statistics ▸ RTP Streams** lists the RTP streams in the frames in view — the audio and video of a VoIP
or WebRTC call — one row per source, destination and SSRC, with the payload (g711U, g711A, …), packets,
lost packets, the largest gap between packets and the mean and largest jitter. The numbers are computed as
Wireshark's RTP Streams computes them (RFC 3550 jitter from the payload type's clock; a dynamic payload
type has no known clock, so its jitter reads —), and a warning mark flags a stream whose sequence numbers or
timestamps skipped or went backwards. Show Sessions narrows the main window to the stream; Copy and Save as
CSV write every column. A UDP datagram is read as RTP only when no other decoder claimed it and its header
has RTP's shape, and the frames keep their UDP label everywhere else. **Stream Analysis…** (select a stream) shows it packet by packet, as
Wireshark's RTP Stream Analysis does: each packet's time since the previous in-order packet (Delta), the RFC 3550
jitter, the skew between the RTP timestamp's clock and the arrival clock, the bandwidth over the last second (IP and
UDP headers included), the marker bit and a status (wrong sequence number, incorrect timestamp, payload change,
comfort noise, marker missing?), under the stream's largest delta and where, largest and mean jitter, largest skew,
loss, and the clock drift and frequency drift Wireshark fits by least squares (a sender whose clock runs 1 % slow reads
about −10 ms per second of stream and −0.99 %). **Graph** plots jitter, delta and skew in milliseconds against time;
each series can be hidden independently. When RTP streams use the reversed endpoint pair, **Stream Analysis** offers
the reverse candidates in the same window so you can compare both directions and inspect either direction's packets.
The CSV includes source and destination for each packet. Double-click a packet to open its frame; save the table as CSV.

### UDP multicast streams

**Statistics ▸ UDP Multicast Streams** lists each source sending UDP to an IPv4 224.0.0.0/4 or IPv6 ff00::/8
group — IPTV, market data, mDNS, SSDP — with packets, packets per second, the average rate, the peak rate
of the largest burst, the largest burst inside the burst interval, and how large a receiver's buffer would
have grown if it drained at the empty speed. A burst or buffer alarm counts each time a stream crosses its
threshold. The numbers are computed as Wireshark's UDP Multicast Streams computes them, bytes being the UDP
length field; **Parameters** sets the burst interval (1–1,000 ms), both alarm thresholds and the per-stream and
total empty speeds, with Wireshark's defaults (100 ms, 50 packets, 10,000 bytes, 5,000 and 100,000 kbit/s).
The footer names the stream count and what all streams together peaked at. Show Sessions narrows the main
window to a stream; Copy and Save as CSV write Wireshark's columns.

### IP statistics

**Statistics ▸ IP Statistics** prints Wireshark's IPv4 and IPv6 Statistics trees for the frames in view. Pick
IPv4 or IPv6 and one of five trees: **All Addresses** (every source or destination address), **Protocol
Types** (TCP, UDP or NONE), **Source and Destination Addresses**, **Destinations and Ports** (each destination
under its protocol and port) and **TTLs** or **Hop Limits** (each source under the value it arrived with, and
each destination under that). Counts are IP headers as Wireshark counts them — a GRE, VXLAN, IP-in-IP or 6in4 packet counts
once per IP header, under its innermost addresses (so 6in4 lists IPv6 addresses in the IPv4 trees) — and rows with equal counts keep Wireshark's order, so the tree reads as `tshark -z ip_hosts,tree` and its siblings do. Turn
off **Limit to Sessions in View** to count the whole capture; Copy or save the tree as CSV.

### Service response time

**Statistics ▸ Service Response Time** times how long servers took to answer, as Wireshark's SRT tables do, for
**SMB2**, **LDAP**, **Kerberos**, **ICMP** and **ICMPv6**: each command or procedure with its paired replies (**Calls**) and their
minimum, maximum, mean and total time in seconds. Every service rescans the complete stable capture,
independent of the All Frames page; **Limit to Sessions in View** restricts them to the sessions currently shown.
Each SRT scan retains at most 200,000 unmatched requests or correlations. Echo scans also retain at most 200,000
exact duration samples for median calculation; if either echo ceiling is exceeded or a decoded echo frame lacks a
timestamp/session address, the scan fails visibly instead of reporting partial statistics. SMB2, LDAP and Kerberos
report unmatched-request omissions in the window and CSV.
Replies are paired inside their session as Wireshark
pairs them in one pass: an SMB2 reply with the request of its message ID once, waiting past an asynchronous
STATUS_PENDING interim reply (Cancel and Oplock Break are left out); every LDAP reply to a message ID — a search
counts each entry and its result — with that request; a Kerberos AS-REP or TGS-REP, or an error, with the most recent
tracked AS/TGS request. LDAP Search keeps its correlation through SearchResultDone. Unrelated Kerberos messages are
ignored, and a mismatched tracked KDC reply consumes the pending request. LDAP decoding currently recognizes only the
first message per segment, so the SRT scan does not reassemble multiple TCP PDUs.
The tables read as `tshark -z smb2,srt`, `ldap,srt` and `kerberos,srt` print them. **ICMP** and **ICMPv6** time
echo (ping) replies instead: the requests, the replies paired with them (once, by identifier, sequence and the
checksum a matching reply carries), the requests left unanswered as a loss percentage, and the reply times in
milliseconds — minimum, maximum, mean, median and sample standard deviation, with the frames of the fastest and
slowest reply — as `tshark -z icmp,srt` and `icmpv6,srt` print them. **Limit to Sessions in View** works as in the
other frame statistics; echo tables rescan the whole stable capture and copy or save the result as CSV.
`tracexy stats --tap smb2,srt` (or `ldap,srt`,
`kerberos,srt`, `icmp,srt`, `icmpv6,srt`) prints the same numbers.

### Value distribution

**Statistics ▸ Value Distribution…** counts every value one decode-tree field took across the capture — a DNS
query name, a TLS version, a TTL, a destination port — as Wireshark's Distribution window: each value with its
occurrences and share of all occurrences (a frame carrying the field twice counts twice), and in the footer the
normalized Shannon entropy of the whole, from 0 (one value dominates) to 1 (values evenly spread). Right-click
any field in **Layers** and choose **Show Value Distribution**, or pick one of the selected session's fields
from the window's **Field** menu. The capture is read again for the count, limited to the sessions in view
unless you turn that off; up to 50,000 distinct values are listed. Copy or save the table as CSV.

### Plot

**Statistics ▸ Plot…** draws one decode-tree field's numeric values over time, as Wireshark's Plots window:
a TTL, a window size, a length, a port — one point per occurrence at its frame's time. Right-click a numeric
field in **Layers** and choose **Plot Over Time**, or pick one of the selected session's fields from the
window's **Field** menu, which also switches the value axis to a logarithmic scale (values at or below zero are
then left out) and measures time from the first point instead of the capture's start. Draw **Dots** or a
**Line**. Pointing at the plot names the nearest frame, its value and time; clicking goes to that frame in the
main window. Values are read as Tracexy shows them — "1500 bytes" is 1,500, "0x0800" is 2,048 — and values that are
not numbers are counted, not drawn. Beyond 20,000 points every n-th point is drawn and the footer says so.
Copy or save the points as CSV (frame, time, value).

### Saving statistics

Statistics windows save what they show. **Packet Lengths** saves its chart with **Save Chart As → PNG
Image… or PDF Document…** and its table with **Save as CSV…**; **Flow Graph** saves the diagram with
**Save As → PDF Document…** (every frame, one page per 40 frames) or **PNG Image…** (the first 300 frames)
beside Export as ASCII; **Conversations**, **Endpoints**, **Protocol Hierarchy** (indented by depth) and
**HTTP** save their rows as CSV. Images are drawn in the light appearance on white, as a document prints.

### Flow graph

**Statistics ▸ Flow Graph** draws the frames of the All Frames list as Wireshark's flow graph: a lane per
address in the order addresses first appear, a horizontal arrow for each frame from its source lane to its
destination lane, the time since the first drawn frame on the left and the frame's Info on the right. It
follows the same **Limit to Sessions in View** switch and search as All Frames, draws at most 12 lanes and
5,000 arrows (the footer says how many frames were left out), and a double-click on an arrow opens its
session and that frame in Layers. **Copy as ASCII** and **Export as ASCII…** give the diagram as text, for a
ticket or a chat.

### Show Packet Bytes

**Show Bytes…** in the Layers facet (next to Copy Bytes) opens the frame's bytes — or the selected field's —
in the **Show Packet Bytes** window; **Show Body…** on an HTTP exchange in the Stream facet opens that
response's body. **Decode as** undoes one encoding: Base64 (padding optional), gzip, zlib (HTTP
`Content-Encoding: deflate`), raw deflate, percent-encoding, quoted-printable, ROT-13 or hex digits.
**Show as** reads the result as UTF-8, UTF-16 LE, UTF-16 BE, pretty-printed JSON (shown as text, with a note, when it does
not parse), a hex dump, a C array, or an image. UTF-16 odd trailing bytes and malformed surrogate pairs appear as U+FFFD.
The **Bytes** fields narrow the input to a range. For an
HTTP body the Content-Encoding and Content-Type choose the first decoding and view. A truncated compressed
stream shows what inflated; decoding stops at 16 MiB of output. **Copy** copies the rendering; **Save As…**
writes the decoded bytes exactly. **Save Rendering…** saves the current text/JSON/hex/C-array view as UTF-8
(`.json` for valid pretty JSON, `.txt` for text/UTF-16/hex or invalid-JSON fallback, `.c` for a C array), with an
8 MiB output limit. It is unavailable for image views and refuses oversized inputs instead of truncating.
For a selected frame's full protocol-details dump, narrowing the byte range switches to the range's own
rendering so Copy and Save Rendering match the bytes shown.
When the full frame-details tree is shown, **Filter Fields** searches layer titles and summaries, field names and
values by case-insensitive substring. A layer-title or summary match keeps that layer's complete subtree; a field
match keeps the matching ancestors and fields. **Clear field filter** restores the tree, and a no-results message
appears in the tree pane while the adjacent bytes pane remains available. The query resets when the inspected
frame changes. Clicking a byte opens the visible owning layer path and scrolls to its field. If **Filter Fields**
hides that owner, the query stays in place and the tree says the field is hidden; clear the query and click the byte
again to reveal it.
Click a layer or field row to focus this tree. It supports the same **↑** / **↓**, **←** / **→**, **⇧←** / **⇧→**
and **⌘←** / **⌘→** navigation described above; typing in **Filter Fields** keeps keyboard input in the search box.

### Frame time and time references

**View ▸ Frame Time** chooses how the Frames facet shows each frame's time: seconds since the session's
first listed frame (the default), since the first captured frame's timestamp, since the previous
displayed frame, or since the previous captured frame; the local or UTC date and time of day; or seconds
since 1970. **View ▸ Frame Time Precision** selects seconds, milliseconds or microseconds (the default)
for every numeric and fractional date display; values round to the nearest selected unit, with exact ties
rounded away from zero. This changes presentation only; it does not claim the capture clock had that
accuracy. Previous displayed uses the visible rows in the current list page;
when the preceding displayed row is outside that retained page or its time is unknown, the delta is an
em dash. Previous captured follows capture order across pages. Choose a frame (select it in the Frames
facet) and use **View ▸ Set Time Reference** (**Command-T**), or right-click a row, to mark a time
reference. In All Frames, references are capture-wide: pinned rows remain visible when paging or when
session, Frame Expression, ignored, decode-problem, or search filters would hide them. **Previous Time
Reference** and **Next Time Reference** navigate among them. In the Session Frames facet, references
remain session-scoped. Up to 16 references may be active across the capture; each reference row reads
`*REF*`. In either since-start format, later frames count from the latest preceding applicable reference
by capture order. Capture-wide references also apply in session tables; session-scoped references do not
affect All Frames. Frames before the first applicable reference keep the current format's normal origin.
References are temporary, in memory, and cleared when the capture or Project changes; they are not saved
with the capture or Project preferences. An untimed frame shows an em dash and cannot be marked as a
reference. When the limit is reached, remove a reference before adding another. The current format is
remembered per Project. **Cumulative Bytes** in All Frames is an optional capture-wide column: it sums
captured lengths (not on-the-wire lengths), includes the reference frame in the new total, and resets at
the latest capture-wide reference. References on other pages and frames hidden by session/expression
filters still affect the total; session-scoped references do not. It is calculated off the main thread and
updates when capture-wide references change.

### Packet lengths

**Statistics ▸ Packet Lengths** counts the frames of the sessions in view by their length on the wire, in
the ranges Wireshark's Packet Lengths statistic uses (0–19, 20–39, 40–79 … 2560–5119, 5120 and greater):
count, average, minimum and maximum length, frames per second over the span of those sessions, and each
range's share, above a bar chart of the same counts. Every session keeps its own fixed-size histogram, so
the report is exact for any scope; frames that belong to no session (IGMP membership reports, for example)
are not counted. **Copy as CSV** copies the table.

### I/O graph

**Statistics ▸ I/O Graph** plots the open capture's traffic over time as two graphs sharing one time axis:
packets per second and bytes per second, as Wireshark's I/O Graph opens with. It counts every timed frame
in the capture, whether or not it belongs to a session in view. **Interval** widens each point to a whole
multiple of the slices the capture keeps (1 second for about the first 17 minutes of a capture, doubling as it
grows), so every value is exact: the interval's total divided by its width — an average across the
interval, never a peak. Pointing at a graph reads out that interval. Frames without a capture time are
counted in the footer and plotted in no interval. **Save Chart As** saves both graphs as PNG or PDF, and
**Save as CSV…** writes each interval's frames, bytes and both rates.

Add up to four named **Frame Expression** series (for example `dns.response` and `tcp.flags.reset`) and
choose **Apply Comparison** to compare them across the complete saved capture or fully stopped live
capture. Every series uses the same bounded Tracexy grammar, time extent, interval and adaptive bucket
resolution, independent of All Frames paging, search or session scope. Each series has a distinct color,
symbol and line pattern. Drafts are applied atomically: invalid syntax leaves the previous comparison
visible. **Show All Traffic** returns to the normal unfiltered graph, including live updates, while keeping
the drafts for later. Starting a new live capture makes a comparison unavailable until it has stopped
and finalized; Tracexy does not display a partial scan.

In an applied comparison, choose a **Frame navigation series** and click a chart interval to select that
series' highest-ordinal timed match in **View ▸ All Frames**. **Frame interval** can also be changed with
the keyboard or VoiceOver, and each series exposes a **Show frame** action for that interval. All Frames
applies its current filters and reports when the cited frame is hidden; orphan frames remain available
through the existing All Frames row workflow. The request is rejected if the Project or capture source
changed after the graph scan.

The comparison retains the complete capture's time extent, including empty intervals before and after
matches. No-match intervals are zero. Series count independently, so overlapping expressions can count
the same frame more than once. Per-series coverage distinguishes matching, nonmatching, unknown and
untimed matching frames; unknown evaluations are excluded from that series' rates, and untimed matches
are never plotted. Saved-capture Time Shift is applied consistently. Changing **Interval** reprojects
the retained bounded aggregates without rescanning the capture. **Save as CSV…** includes every enabled
series' expression, interval values and coverage; **Save Chart As** includes the named series, expressions,
coverage and both rate charts. A capture with no timed frames can export coverage as CSV without invented
graph values. The comparison supports packet and byte rates; arbitrary field calculations, secondary
axes and moving averages are not included.

### TCP completeness

The Sessions table's optional **Completeness** column (right-click the header) shows which stages of a TCP
conversation the capture contained, in Wireshark's order R·F·D·A·S·S — reset, FIN, data, the ACK that
answered the SYN-ACK, SYN-ACK, SYN — with a dot for a stage not seen. Its help names the verdict
("Complete, with data" when the handshake and a FIN or reset were seen) and the number Wireshark uses for
`tcp.completeness` (SYN 1, SYN-ACK 2, ACK 4, data 8, FIN 16, RST 32). Find sessions with
`tcp.completeness == complete`, `== incomplete` or `== 31`. It describes the capture, not the endpoints: a
stage that happened before capture began is simply absent.

### Conversations and endpoints

**Statistics ▸ Conversations** lists the traffic between each pair of addresses in the sessions in view;
**Statistics ▸ Endpoints** lists each address on its own. A segmented control in the toolbar switches
between Ethernet (MAC addresses from each session's representative frame, ARP included), IPv4 and IPv6
(addresses only) and TCP and UDP (address and port), each labelled with its row count; Ethernet rows narrow
the main window with `mac == …`.
Conversations show frames and bytes in both directions — A is the side that started the first session
between the two — with the relative start (seconds from the capture's first timed frame), duration and mean
bit rate per direction. Endpoints show frames and bytes sent (Tx) and received (Rx), how many sessions
involve the address, when it was first seen, and the name a DNS or mDNS answer in this capture or your
Project gave it. Every figure is a sum of the sessions' own tallies, so frames that belong to no session —
IGMP membership reports, for example — are not counted, and ARP is not an IPv4 conversation. Sort by any
column, search by address, port or name, and copy a row or the whole table as CSV; a double-click (or **Show
Sessions**) narrows the main window with the row's Session Expression, such as `ip == 10.0.0.5 and ip ==
192.0.2.1`.

**Statistics ▸ GeoIP Databases…** (also in the Endpoints footer) adds a MaxMind-format database file you already
have — GeoLite2 City, Country or ASN, or a DB-IP file in the same `.mmdb` format — to the active Project.
Tracexy ships no database, never downloads one and never sends an address anywhere: it remembers where the
file is and reads it on this Mac. Endpoints then gains Country, City and AS columns, the Session Inspector a
GeoIP layer, and the Session Expression `$geoip_country(DE)`, `$geoip_city(Berlin)`, `$geoip_asn(3320)` and
`$geoip_org(Telekom)` macros. Private, unique-local, link-local, loopback and other special addresses are
never looked up. A Project uses one database. **Reload** reads the files again after an update.

### Findings

**Statistics ▸ Findings** (⌥⌘E) lists every typed finding in the sessions in view, grouped by kind the way
Wireshark's Expert Information groups by summary: each kind shows its severity, how many findings, in how
many sessions, and how many frames they cite, and expands to one row per session. **Warnings Only** hides
notes, the search field matches summaries, hosts and expression names, and **Group by Kind** switches to a
flat list. Double-clicking a kind (or **Show Sessions**) narrows the main window with `finding == <kind>`;
double-clicking a finding (or **Open Frame**) selects its session, scrolls the table to it and opens its
first cited frame in Layers. The context menu copies the rows as tab-separated text or the kind's Session
Expression. Nothing here adds analysis: every row is a finding the session already carries.

### Resolved addresses

**Statistics ▸ Resolved Addresses** lists names this capture's DNS and mDNS answers gave an address, names
embedded in the opened PCAPNG capture's Name Resolution Blocks (**Capture file**),
beside the names you gave addresses in this Project (**Named by you**). Each learned name shows where it
came from; DNS/mDNS rows include how many answers carried it. A warning mark says when answers gave the same address more
than one name, so a session to it may be labelled with another. **Show Sessions** (or a double-click)
narrows the main window to that address; **Show Answering Session** selects the DNS or mDNS session whose
answer gave the name, narrowing to its host when the current scope hides it (Back to Previous Scope
returns). The list is read from the sessions in the capture and keeps nothing of its own.

**Name Subnet…** names an IPv4 block for this Project, as Wireshark's `subnets` file does: name
`192.168.1.0/24` "office" and an address in it with no name of its own shows as `office.5`; for a /20,
`office.1.5` (the octets the mask does not fully cover). The most specific named block wins, and a name you
gave the address itself wins over any block. Subnets are listed here as **Subnet named by you**; Show Sessions
narrows to `ip in` the block, and the context menu or the Delete key renames or removes one. In
**Statistics ▸ Endpoints**, IPv4, **Group by Named Subnet** adds the addresses of each named block into one row
(a session between two of its addresses counts once); other addresses keep their own rows.

Choose **Import Hosts…** to select a standard or Wireshark `hosts` text file. Tracexy reads only that file
and adds names for addresses this Project does not already name; existing Project labels are left untouched.
Each line contributes its first hostname, extra aliases are counted and skipped, and the last repeated
address in the selected file supplies its imported hostname. The import is bounded to 256 KiB, 10,000 lines
and 500 addresses; names longer than 60 characters are shortened and counted. It reports malformed lines,
ignored aliases, duplicate addresses and any address-book limit reached. It does not search Wireshark
profile folders or perform external DNS lookups.

**View ▸ Name Resolution ▸ Resolve Network Addresses** (off by default, per Project, as in Wireshark) shows
names instead of addresses in the All Frames list: the name you gave an address, else the first name from the
capture's DNS/mDNS answers, else its PCAPNG Name Resolution Block, else its named subnet's form. Pointing at a name shows the address. Tracexy never
looks a name up on the network — only names the Project or the capture already hold are used, as tshark does
with `-N dn`.

### Return from a scope drill-down

After opening a host, client, IP address, or Findings scope, use **Back to Previous Scope** in the scope row or View menu (**Command-[**). **Forward to Next Scope** (**Command-]**) redoes a Back, with the session that was selected there, until you change the scope another way; a new drill-in starts a new path. Each workspace remembers up to eight drill-down origins, including the previous sidebar location and selected session. Returning keeps your current search text, advanced rules, Investigation query, Noise Control, and removed-session decisions. Reset Session Filters clears this return history. A source or Project generation change makes older entries unavailable.

When an exact frame citation opens Layers, **Clear Citation** returns to the inspector tab that preceded the first citation. Selecting another session or changing the source discards that return point. Follow Stream keeps the existing session and filters.

Selecting an IP in the sidebar matches the exact address in typed endpoints or DNS answers, including equivalent IPv6 spellings; it does not match parts of another IP address.

### Open sessions from Overview and Flow

Overview's host, app and protocol rows narrow the sessions already represented by
the summary. Existing search, category chips, advanced rules, Investigation query
and Noise Control remain active. A host or app row under a different host or app
scope is stale and does nothing rather than widening the list. Review Findings
intersects the current scope with typed finding membership, including when Errors
is already selected.

Flow groups typed destination addresses; equivalent IPv6 spellings share one row.
Show Sessions opens only sessions whose destination matches that row, while the
sidebar IP command also matches source addresses and DNS answers. Sessions without
a usable destination are counted as omitted from the address list. The map uses
the same groups and describes registry regions, not physical server locations or
the location of the machine that recorded an imported capture.

Open Sessions and Overview's Open Flow Map keep the current scope. Explicit
aggregate drill-downs support **Back to Previous Scope**. **Reset Session Filters**
clears aggregate narrowing; Project configuration saves the filter intent, without
captured data or navigation history.
