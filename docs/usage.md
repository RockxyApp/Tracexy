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

The helper streams raw frames to the app in batches; the app decodes them, groups them into sessions,
and refreshes the list a few times a second while capturing. The list is ordered oldest→newest and stays
stable as traffic arrives: sessions you are already looking at keep their positions and update in place
(their byte counts, duration, and status), while a genuinely new session appears at the bottom rather
than pushing the whole table down. **Follow Live** in the Sessions command strip keeps the newest visible
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
Its **Copy into Library** checkbox switches to the managed-copy path; the choice is remembered
per Project. **File → Import into Library… (⌥⌘O)** and the sidebar's Import action always copy.
Opening a `.pcap`, `.cap`, `.pcapng` or `.ntar` file from Finder (**Open With → Tracexy**, or
dropping it on the Dock icon) and dropping a capture file anywhere on the main window follow the
Project's Open preference; Tracexy registers as an alternate viewer for those types and does not
claim them as the default. One capture is opened per drop — a multi-file drop is refused with a
message rather than opening only its first file — and a file opened before the app has finished
loading Projects opens once loading completes. Tracexy decides the format from the file's own
header, so a capture stored as `evidence.bin` or with no extension is accepted. Gzip PCAP/PCAPNG
and the capture payload in the observed TCP Viewer schema-1 `.tcpviewsession` archive are always
expanded into a managed capture, whichever way they were opened. Other compressed or session
formats are refused with a concrete recovery message. Recognizing a header or archive is not a
guarantee that the whole capture parses, so the streaming open above still reports truncated or
malformed input. Importing never overwrites: a capture whose name is already taken is kept under
a unique name beside the existing one, and the original source on disk is never moved. Switching
Projects while a panel is open cancels the open rather than filing the capture into the new Project.

A referenced capture shows a link badge in the Library. If its file is moved or replaced the
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
and an inventory of blocks Tracexy does not interpret — name resolution, decryption secrets
(type and size only; the secrets are never read or used), custom and unknown blocks. **Compute
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

### Export Frames…

**File → Export Frames…** (also in the toolbar Export menu, a session row's Export menu with the
session preselected, and the Library row of the open capture) writes a new capture file from a
scope: **Whole capture**, **Sessions in view** (filters, Focus Sets, Noise Control and removed
rows applied), **Selected session**, or a **Time range** on the capture clock. The Save panel's
Format pop-up offers PCAPNG (default) and classic PCAP; PCAP stays listed but disabled, with the
reason, when the source mixes link types or holds untimed frames. **Preserve capture metadata**
carries section hardware/OS/application and comments, interface names, descriptions, filters and
each frame's own options (comments, flags, hashes) from a PCAPNG source; **Compress with gzip**
writes a `.gz`. The export streams from the source with progress and **Cancel Export**, is
published only after it completes and the source is verified unchanged, and reports anything it
could not carry (for example frame comments from a big-endian section). Exporting raw packet
formats while privacy protections are configured asks for the same acknowledgement as session
export.

Sessions, Overview and Flow name the active scope and show visible sessions against the
capture total. **Reset Session Filters** clears the current workspace’s filters and sidebar
protocol lens. Noise Control and sessions removed from view have separate recovery actions;
resetting a filter does not change those choices or another workspace.

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
notice, never drawn. The chart is capture-wide — session filters narrow the panels below it, not the
frames.

Beneath it, three compact charts summarize the scope: **Protocols** partitions session bytes by each
session's innermost protocol (bars sum to the scope; click a bar to narrow to that protocol),
**Sessions started** counts new conversations per slice on the same clock, and **Findings** shows the
severity split with a route to review those sessions. **Top hosts** and **Top apps** are native tables
of sessions, sent, received, and total bytes with an in-row share bar (client-sent and
server-received against the leading row); double-click a row (or use its context menu) to narrow
the session list to exactly that host or app. Sessions with no attributed process are never listed as an
app. **Sources** counts observed apps, domains, and addresses and opens the Flow Map.

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
telemetry remains trailing. It does not mutate the capture or filters.

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
protocol (DNS, TCP, UDP, TLS, HTTP, HTTP/2, QUIC, WebSocket, STUN), by evidence-backed **Findings**,
and by exact status (**Errors**). Selected protocol pills combine with OR, selected
investigation pills combine with OR, and the two groups combine with AND — so choosing *TCP* and
*Errors* shows TCP sessions that failed. *Errors* means exactly an error; a warning is not swept in.
*Findings* includes exactly the sessions referenced by the typed Core analysis snapshots: observed TCP
reset, retransmission, segment overlap or out-of-order delivery, plus the neutral observation that a
retained UDP-DNS message set its TC bit. Status, plaintext HTTP, an unanswered DNS query and latency do
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

**Investigate** opens a separate capture-local typed query editor. **Rows** provides bounded native
controls for process, host, exact IP address, CIDR block, port range, protocol, status, finding kind,
start-time range, total bytes, or retained evidence. Choose **All** or **Any** across rows and
optionally negate an individual row.

**Expression** accepts a bounded Session Expression over whole sessions. It supports lower-case
protocol terms; `not`/`!`, `and`/`&&`, `or`/`||`, and parentheses; exact or CIDR endpoint matches;
exact ports; quoted host/process contains matches; byte comparisons; and typed finding names. For
example: `http and destination.port == 80`. This is Tracexy session syntax, not a Wireshark display
filter: packet fields such as `ip.addr` and `tcp.port`, regex operators, and unsupported names are
rejected with a position instead of being reinterpreted.

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

Save a named rule set as a **focus set** to reapply later; applying one loads its rules into the active
workspace's advanced filter, clamped to the rule limit. Focus sets persist across launches. **Reset
Filters** clears the pills, the search text, sidebar host/process/IP scopes, the active Investigation
query, and the advanced rules, and hides the builder (it does not touch Noise Control). Each
**workspace tab** is an independent
investigation with its own filter, selection, and inspector layout.

## Inspector

Selecting a session opens the bottom evidence inspector. It shows the decoded
protocol **layers** and fields for the representative packet, and a **hex** pane whose byte ranges line
up with those fields — click a field to highlight the bytes it came from. Right-click a layer or field
to copy its visible summary, name, value, or combined name/value text without retyping it. When a
session carries an application-layer exchange (HTTP, DNS, STUN), a requests facet is offered. For an
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

When retained TCP connection or direct-frame TLS observations exist, the **Evidence** facet merges them
on the capture's frame-order axis. Reused five-tuples remain separate connection incarnations, while TLS
records stay explicitly shared at session scope when the retained facts cannot attribute them to one
incarnation. Per-connection omissions, truncation, loss knowledge and bounds remain visible; global
capture omissions are labelled capture-level and are never assigned to the selected session. Selecting
a citation reads exactly that one frame from the current local saved file or live spool and opens its
decoded Layers view with a visible **Cited frame** scope. A missing locator, superseded live-spool source,
replaced or truncated file, or mismatched source fails visibly and never falls back to a representative packet.
Changing session, workspace, capture, or source clears the cited bytes. This finite single-frame read is
allowed during active live capture and is separate from Follow Stream's stable-source requirements.

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

The right-hand **Details** dock uses compact two-column tables for assessment, connection/TLS evidence
coverage, decoded layer facts, host baseline, related actions, findings, and grouping evidence. Its
connection/TLS sections summarize scope and link to the chronological Evidence facet rather than
duplicating the full event list. Technical values are selectable and monospaced; related-action rows
remain clickable, and evidence-backed finding citations can open their exact local frame.

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

A client sees exactly three read-only tools: `describe_scope`, `list_captures` and `list_sessions`.
There is no tool for packet bytes, capture files, file paths, raw frames, capture control or writes,
and a process or host filter is refused unless you disclosed that field.

**Recent activity** lists what clients called: the time, the tool, the outcome, the Project, and the
*names* of the filter fields used — never the values, and never anything read back.

Switching Projects or pressing **Revoke** invalidates the grant, so the next call from any connected
client fails closed. Re-issuing a grant also supersedes the old one; reconnect the client afterwards.

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
as unknown rather than inventing one.

Throughout, Tracexy shows what it captured and nothing more: a host with no resolvable name shows its
IP, a session with no attributable process shows none, and an idle capture shows an empty list. Nothing
in the UI is fabricated when data is missing.

### Return from a scope drill-down

After opening a host, client, IP address, or Findings scope, use **Back to Previous Scope** in the scope row or View menu (**Command-[**). Each workspace remembers up to eight drill-down origins, including the previous sidebar location and selected session. Returning keeps your current search text, advanced rules, Investigation query, Noise Control, and removed-session decisions. Reset Session Filters clears this return history. A source or Project generation change makes older entries unavailable.

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
