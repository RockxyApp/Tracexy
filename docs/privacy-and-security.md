# Privacy & security

Tracexy captures network traffic and installs a privileged helper to do it. Both deserve care, so this
page states plainly what the app does and does not do today.

## Privacy posture

- **Local-first.** Captured traffic stays on your Mac. Tracexy does not upload it to any server. The
  "Keep all data on this Mac" preference reflects this default posture.
- **Capture stays under user control.** By default, live capture begins when you press **Start**. If
  you explicitly enable **Settings → Capture → Auto-start capture on launch**, Tracexy starts capture
  after launch setup completes. The gate on capturing is the one-time operating-system approval of
  the privileged helper (System Settings → Login Items) — there is no separate per-capture consent
  dialog, and this documentation does not claim one.
- **Raw exports are sensitive.** A `.pcap` or `.pcapng` is a recording of captured packet bytes,
  including data you may have forgotten was present. Tracexy does not claim to rewrite or redact these
  evidence-preserving formats. When a Privacy protection is enabled, every raw export requires explicit
  acknowledgement before the save panel opens.

### Project isolation

Each Project keeps its capture sessions, saved-capture Library folder, local History database, and
capture/privacy preferences separate from every other Project. Privacy protections and History
Auto-clear are therefore *per Project*: enabling IP masking or a short retention window in one
investigation does not silently change what another exports or retains. A new Project starts from the
shipped protective defaults and never inherits another Project's values.

Isolation is arranged by scoping storage, never by copying or deleting user data. Data written before
Project isolation existed keeps its original location and is attached to exactly one Project the first
time the catalog is loaded; that ownership is persisted before any capture, History write, or Library
scan is allowed and is never reassigned — not when the owning Project is deleted, and not when the
catalog is repaired. Repair deliberately leaves that data unattached rather than handing one person's
capture history to a freshly created Project.

Deleting a Project removes it from the catalog and discards its unsaved in-memory sessions and
evidence. Its saved captures and History remain on disk and are not deleted; they simply stop being
reachable from the app. Configuration-only `.tracexyproject`
exports are unchanged: they never carry packets, payloads, paths, selection, findings, or History.

Sessions held only in memory are not checkpointed. They survive Project switches for the life of the
app session and are lost on quit unless saved — Tracexy does not claim otherwise.

### Protected session export

Settings → Privacy controls the native `.tracexysession` export path. Redacting payloads, stripping
credentials, or masking addresses produces a version-2 protected document that contains session and
frame metadata but no raw packet bytes. Credential stripping also removes DNS query/answer strings and
the free-form decoded summary; IP masking replaces literal IPv4/IPv6 addresses in exported summary
fields with a fixed placeholder. The document records the applied protections as machine-readable
metadata. A version-1 document with packet bytes is produced only when every protection is disabled.

These controls do not sanitize raw pcap/pcapng files. Use the warning as a hard trust boundary: export
those formats only when you intend to handle the result as sensitive evidence. The **Auto-clear**
choice applies only to bounded summaries in the local History database. Tracexy enforces it at launch,
after accepting a terminal capture into History, and when the choice changes; it never deletes raw
pcap/pcapng files, the live spool, exports, or the current workspace.

### The MCP boundary

MCP is free, and it is **off until you grant it**. Nothing is exposed by default.

Tracexy bundles a read-only command-line tool at `Tracexy.app/Contents/MacOS/TracexyMCP`. It speaks
JSON-RPC over stdin and stdout to a client you start. **It never opens a network port**, so nothing on
your network or on this Mac can connect to it, and there is no listener to secure.

What a client can ask for is deliberately small: the scope description, one page of stored captures,
and one page of a capture's session summaries. There is no tool for packet bytes, capture files, file
paths, raw frames, capture control, arbitrary SQL, or writes of any kind. Filtering is applied to the
one examined page, and a process or host filter is refused unless you disclosed that field — so a
filter can never be used to guess a value you kept private.

Access is one grant you issue in **Settings → MCP & Assistant**. The grant names exactly one Project,
that Project's History database, which field families are disclosed, and how many rows one request may
read. It contains no token, credential, capture path, evidence locator or packet byte, is written
owner-only and replaced atomically, and it expires. The tool re-reads and re-validates it on every
call and refuses to answer when it is absent, malformed, expired, superseded, or names a different
Project — so switching Projects or pressing **Revoke** stops the next call, not the next session. The
History database is opened read-only, so an older database is refused rather than migrated.

The same pane shows a bounded local activity trail: the time, the tool, the outcome, the Project, and
the *names* of the filter fields a request used. It deliberately cannot record a filter value, a host,
a process name, an endpoint, a path, or anything a client read back. Revoking deletes it.

### The AI Assistant

The Assistant is local-only in this build. It talks to a model endpoint on this Mac that you choose,
and it sends no API key, bearer token, cookie or identifying header — there is nothing to leak,
because there is no credential anywhere in the path. Only `127.0.0.1`, `::1` and `localhost` are
accepted; `localhost` is canonicalized to `127.0.0.1`. A remote address, a URL carrying a user name
or password, an unsupported scheme, and any redirect that leaves this Mac are refused before a
request is made.

What is sent is one bounded evidence brief for the **selected session only**. It cannot contain packet
bytes, payload bodies, URLs, certificates, file paths, database paths, evidence locators,
capture-source tokens or credentials — those fields do not exist in it. Process, display host and
endpoint disclosure are separate opt-ins that start **off**. The display host can contain a name
derived from DNS or TLS SNI when the Host option is on; the exact value is visible in Review Data.

Before the first send, and again whenever the Project, selected session, evidence publication,
disclosure, endpoint or model changes, Tracexy shows the **Review Data** sheet: the literal JSON that
would be sent, the destination and model, the disclosure decision, and the coverage limits that bound
any answer. Nothing is sent until you approve it there.

Answers stream, and an answer that was stopped or that hit a limit is always labelled incomplete —
partial text is never presented as a conclusion. Citations in an answer resolve to frames this capture
actually holds; an id the model invents resolves to nothing rather than to a wrong frame.
Conversations live in memory for the life of the app session and are not written to disk.

## The privileged helper and trust boundary

Live capture runs in a separate, signed privileged binary (`TracexyCaptureHelper/`) that communicates
with the app over XPC. This boundary is the highest-value part of the codebase to get right.

- **Typed, narrow XPC surface.** The helper exposes only a small, typed protocol: report helper info,
  start capture on an interface, stop capture, and fetch buffered frames. It does not expose arbitrary
  command execution, shell, or file access. Frames are drained as typed `NSSecureCoding` objects
  (`FrameBatchMessage`/`CapturedFrameMessage`) with the secure-coding class allow-list configured on
  both endpoints; the app validates every field defensively and rejects malformed metadata rather than
  trusting it. This is protocol **v4** — an older helper is classified incompatible and Start is
  gated with an update prompt, never silently downgraded to an untyped drain.
- **Bidirectional code-sign validation.** The helper validates every connecting caller (signing-team
  match with a certificate-chain fallback, plus a bundle-identity allowlist checked against the
  connection's audit token to resist PID races) before accepting it. Independently, the app validates
  the installed helper's signature before trusting it, so a signing mismatch surfaces as a diagnostic
  rather than being silently "fixed." That comparison targets the helper launchd actually executes — the
  binary embedded in the app bundle (`Contents/Library/HelperTools`) that SMAppService runs in place —
  not a legacy `/Library/PrivilegedHelperTools` artifact, which Tracexy never installs.
- **Bounded behavior.** The helper only captures and buffers frames. Its frame buffer is capped by a
  named bounded-buffer policy that counts every eviction, so a drop is reported (in the drain batch and,
  in the UI, as its own capture-stage figure — distinct from `pcap_stats` kernel/interface drops, and
  never folded into them) rather than hidden. Capture teardown is
  race-free: the caller requests stop and waits while the worker thread alone closes the pcap handle.
  The typed stop reply atomically returns the worker's final flush and final accounting, avoiding both
  silent tail loss and a stop→fetch race with the next capture generation.
  The helper stops capturing when the owning app disconnects — it does not run unbounded or unattended.

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Use GitHub Security Advisories on the
[Tracexy repository](https://github.com/RockxyApp/Tracexy/security/advisories), and see
[SECURITY.md](../SECURITY.md) for what to include and which areas — the helper/XPC surface, packet
decoding, and capture-file parsing — are most worth your attention.
