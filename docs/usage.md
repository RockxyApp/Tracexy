# Usage

Tracexy is session-centric: the object you work with is a *conversation*, not a packet. Packets and
hex are demoted to an inspector tab, one click away when the bytes are the answer.

## Live capture

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
press Start again.

The centered capture status in the toolbar opens **Capture Readiness**. It reports the selected
interface, helper or direct-capture path, BPF filter, packet snapshot and promiscuous settings, bounded
memory window, interface drops, helper drops, and frames outside the in-memory window. Unknown and
stopped values are labelled explicitly instead of being presented as zero. The popover also links
directly to Capture and Helper settings for recovery.

**Settings → Helper** shows the registration, reachability, bundled version, and installed version.
From there you can install, update, uninstall, or recheck the helper. If a registered helper stops
answering, Tracexy times out the request, reports it as unreachable, and ends an affected live capture
instead of leaving the UI stuck. When the helper is unreachable, the first-line fix is **Repair
Registration** — a non-destructive step that re-submits the registration from the current app bundle
(no admin password) and then re-probes, which clears the launchd/Background-Items drift that can follow
an in-place update. **Force Reset & Reinstall** is the next, confirmed recovery action for stale
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

For a live capture, the activity chart shows measured throughput and the storage card distinguishes
kernel/interface loss, helper-buffer drops, and trimming of the bounded in-memory inspection window.
Window trimming does not remove accumulated sessions or frames from the disk-backed live spool, and is
never reported as capture-source loss.
For an opened file, Overview shows file provenance and activity derived from its real frame timestamps;
capture fidelity and original drop counters remain **Unknown** because a savefile cannot reconstruct
what was missed when it was recorded. Frames outside the local inspection window remain in the source
file and in the decoded session/activity totals; window eviction is not reported as capture loss.

## Sessions

Frames are grouped by their canonical **five-tuple** (protocol + the two endpoints, direction-
normalized) so both directions of a conversation land in one session. Each session summary carries:

- endpoints and a resolved **host** (from TLS SNI or a DNS name where available, otherwise the peer IP);
- the **protocol stack** (outer→inner, e.g. TCP · TLS);
- **byte counts** up and down, packet timing, and duration;
- a **status** (OK / Warning / Error) that drives its color and icon;
- a concise **info line** derived from the real decode — a DNS query and its answer, a TLS host, or the
  innermost layer's summary — never placeholder text.

Connectionless traffic (ARP, ICMP/ICMPv6) is keyed on the IP pair (port 0) so it still surfaces as a
session rather than disappearing.

The first rounded control shelf keeps a stable icon cluster beside search: **Follow Live**, **Jump to
Latest**, a divider, **Clear Capture Data**, and **More Session Actions**. The order does not change at
narrower widths; the cluster and search controls stack when needed. Domain and less-frequent actions —
**Investigate**, **Advanced Filters**, **New Focus Set**, **Save Capture**, **Noise Control**, and
restoring removed sessions — use labelled sections inside the More menu. Every icon-only command keeps
an explicit help label and accessibility name. The bottom status bar is intentionally read-only: it
reports the visible/selected session summary and source, loss, retention, and memory telemetry; it does
not mutate the capture or filters.

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

**Investigate** opens a separate capture-local typed query editor. Its bounded rows can match process,
host, exact IP address, CIDR block, port range, protocol, status, finding kind, start-time range, total
bytes, or retained evidence. Choose **All** or **Any** across rows and optionally negate an individual
row. **Apply** validates the complete draft first; an invalid row keeps its field-level error visible
and does not replace the previous accepted query or result.

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
the facet tabs. Facet labels stay on one line, preserve their source order, and move lower-priority
facets into a More menu while keeping the active facet directly visible. Tracexy does not manufacture a URL
for transport, DNS, TLS, or other sessions that did not yield one as typed evidence. The trailing
window button opens the same selection-aware inspector in a resizable auxiliary window; it follows the
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

The adjacent **AI Assistant** tab uses a conversation-style layout with a compact attached-session row,
an empty transcript, and a composer pinned to the bottom. The current build does not include an assistant
backend: history, new-conversation, prompt, and send controls remain unavailable, and the Read-only control
explains that no capture data or model request leaves the Mac.

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
