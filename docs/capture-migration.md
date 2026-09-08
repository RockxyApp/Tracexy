# Bring an existing capture into Tracexy

Choose the destination Project, then use **File → Import Capture… (⌘O)** or the
sidebar's Import action. Tracexy accepts **PCAP** and **PCAPNG** by content,
including captures with a different filename extension. It also expands gzip
captures and the capture payload from the observed TCP Viewer schema-1
`.tcpviewsession` format. Import leaves the original source unchanged and adds a
managed capture to the Project's Library. Direct PCAP/PCAPNG imports copy the
source bytes. For gzip and TCP Viewer archives, the managed item is the validated,
extracted capture; the outer archive and TCP Viewer sidecars stay only at their
original location. If a name is already taken, both managed captures are kept
under different names.

Copying runs in the background with progress and **Cancel Import**. Tracexy keeps
the current evidence until the imported capture opens successfully. Source-changing
actions stay unavailable while the copy finishes or cancellation cleans up. If a
complete copy was already published when cancellation arrived, it remains in the
Library but is not opened automatically. Switching Projects waits for the copy;
the capture stays in its original destination Project.

A recognized container does not mean every record is valid or every protocol can
be decoded. The subsequent streaming reader reports malformed input; protocol
coverage is described in [Protocol support](protocol-support.md). Existing displayed
results survive a failed open.

## Choose the right source artifact

| Coming from | What to bring |
|---|---|
| Wireshark | The original `.pcapng`, `.pcap`, or a gzip-compressed PCAP/PCAPNG. For another supported Wireshark input format, use its **File → Save As…** to create a separate PCAPNG. |
| TCP Viewer | A PCAP/PCAPNG packet export, or a schema-1 `.tcpviewsession` archive. A session archive transfers its capture payload only; use explicit PCAPNG export as the compatibility fallback. |
| tcpdump and other packet recorders | Their PCAP or PCAPNG output. The filename alone does not identify the underlying format. |
| Zui / NetworkMiner investigations | The original packet capture used for the investigation. Derived logs, extracted files and case summaries are different artifacts. |
| Browser, Charles or Proxyman HTTP sessions | HAR and proprietary HTTP session archives are not packet captures and cannot be imported as PCAP/PCAPNG. Keep them for HTTP transaction analysis in their source tool. |

Wireshark can convert input formats by saving a separate capture in another
format. Use **PCAPNG** where possible. Some formats cannot represent all of the
original information; retain the source alongside any converted copy. See
[Wireshark's saving guide](https://www.wireshark.org/docs/wsug_html_chunked/ChIOSaveSection.html).

## What is preserved

For a direct PCAP/PCAPNG import, the Library copy retains the source capture bytes,
including container metadata Tracexy does not interpret. For gzip and TCP Viewer
archives, the Library contains only the validated, extracted PCAP/PCAPNG payload;
outer container metadata and TCP Viewer sidecars are not copied into the Project
Library. In either case, preserving capture bytes does **not** mean all Wireshark
annotations, interface metadata, name-resolution records or embedded secrets
appear in the Tracexy UI. Tracexy builds its own session and evidence projections
from supported records. Its capture-loss and retained-frame coverage messages are
separate from whether a copy succeeded.

A classic PCAP has one link type and cannot carry all PCAPNG metadata. Converting
a multi-interface PCAPNG to classic PCAP can remove interface identities and
comments; mixed link types may prevent conversion altogether. Importing the
original PCAPNG avoids that conversion step.

Wireshark profiles, display filters, coloring rules, Decode As settings, packet
marks and layouts are not a Tracexy Project. They are not applied by importing a
capture. A `.tracexyproject` file transfers bounded Project configuration, not
packets or History; see [Projects](usage.md#projects).

## Recover from an import problem

- **Unsupported compression:** Tracexy expands gzip only. For zstd, lz4 or another
  container, expand it locally or save a separate PCAPNG in the source app.
- **Session archive rejected:** open it in TCP Viewer and export PCAPNG. Tracexy
  accepts only the observed schema-1 `TCPViewerSession` layout and refuses newer,
  ambiguous, encrypted, ZIP64, multi-disk or unsafe archives instead of guessing.
- **Unsupported content:** export real PCAP/PCAPNG packet data. Renaming a HAR,
  report, profile archive or vendor format does not convert it.
- **Truncated or malformed capture:** obtain a complete copy or recover a separate
  file with the source tool. Keep the original evidence unchanged.
- **Capture source busy:** finish or cancel the operation named by Tracexy's
  message before changing the source.
- **Project changed during the file picker:** reopen Import in the intended
  Project and choose the file again.

Review the selected Project, source and export scope before sharing any capture.
An original capture can contain payloads and metadata that are absent from the
session table. Protected session export and raw capture export have different
boundaries; see [Usage](usage.md).

## Reuse a saved capture filter

In **Settings → Capture → Filter**, choose **Import Capture Filter…**, then choose a capture-filter list such as Wireshark’s `cfilters`. Select a named entry, review its full BPF expression, and choose **Use Filter**. This replaces the active Project’s custom capture expression and selects Custom mode. It applies to the next capture you start; the capture backend checks BPF syntax then.

Reading, cancelling, or a failed import leaves your existing settings intact. The importer accepts UTF-8 lists up to 256 KiB and 256 entries; names are limited to 128 characters and expressions to 1,024. A malformed row rejects the list with its line number. Duplicate names remain separate choices.

This transfers one capture expression. Wireshark display filters, coloring rules, protocol settings, and profile archives are separate formats and are not converted. See [Wireshark’s configuration-file reference](https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html).

## Missing capture times and link coverage

Some PCAPNG records contain packet bytes without a capture timestamp. Tracexy
keeps those frames and their exact frame numbers. A session containing an untimed
frame shows unknown start time, duration and latency; it is not dated January 1970
and is not used to infer a timed cross-session relationship. A real timestamp at
the Unix epoch remains a known time. Activity charts count every frame and byte,
but only timed frames enter the chart's time buckets.

The saved-capture source summary reports link-type coverage, untimed frames and
frames without a decoded link layer. These are coverage counts, not a claim that
every protocol or container option was interpreted. Counts of distinct link types
are bounded; overflow is labelled as more than the retained count.

History labels an entry **Opened here** when the file cannot establish a complete
capture lifetime. Existing saved History entries created before time provenance
was recorded keep their original values and are labelled **Legacy time**. They are
not retroactively treated as verified capture timestamps.

Reconstructed classic PCAP export cannot represent untimed frames. PCAPNG export
uses untimed packet records where that format can represent the retained frame;
an unrepresentable frame or timestamp produces an error instead of a substituted
time. Keep the original capture for its complete container metadata. Session JSON
uses explicit null timing fields when timing is unknown; protected export keeps
its existing disclosure boundary. History automation likewise emits null JSON
or empty CSV timing fields, with the capture time basis identified separately.

## Linux server captures

Linux cooked SLL and SLL2 captures (link types 113 and 276) can be opened directly
in PCAP or PCAPNG. Tracexy displays the cooked header and passes supported IPv4,
IPv6 and ARP payloads to the existing decoders. SLL2 interface indexes describe
the capture machine; they are not resolved against this Mac. Unsupported hardware
payloads retain header facts without a guessed session. See [protocol support](protocol-support.md).

For TCP Viewer, **File → Export as pcapng** remains the most portable route.
Tracexy can also open the exact schema-1 `.tcpviewsession` layout observed in TCP
Viewer 1.15. It validates the archive and manifest, then extracts only
`TCPViewerSession/capture.pcapng`. TCP Viewer state, source paths, packet sidecars,
clients, annotations and icons are deliberately ignored; they do not become
Tracexy settings or evidence.

Archive expansion is streamed into a private staging file and published only
after checksum, capture signature and source-identity checks pass. Shipped limits
cap a compressed source at 512 MiB, expanded capture at 4 GiB, expansion ratio at
200× after a 64 MiB grace, ZIP entries at 4,096, the central directory at 4 MiB,
entry names at 1,024 bytes and the manifest at 64 KiB. Cancellation or any failed
check removes the staging output and leaves the current workspace unchanged.
