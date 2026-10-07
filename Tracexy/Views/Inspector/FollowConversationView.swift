import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - FollowConversationView

/// The Stream facet: an explicit, local-only reading of the selected conversation.
/// A TCP session is reconstructed as two byte streams; a UDP session is listed
/// datagram by datagram, with DNS messages read and paired. Merely selecting the
/// facet never scans the capture — the Follow button is the user action.
struct FollowConversationView: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator
    let session: SessionSummary

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            header

            Label(
                "Application data can contain credentials or personal information. Review it locally before copying.",
                systemImage: "hand.raised"
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)

            if coordinator.isLoadingFollowStream {
                loading
            } else if let error = coordinator.followStreamError {
                emptyState(error)
            } else if let result = coordinator.followStreamResult,
                      SessionBuilder.sessionID(for: result.tuple) == session.id
            {
                streamResult(result)
            } else if let result = coordinator.followDatagramResult,
                      SessionBuilder.sessionID(for: result.tuple) == session.id
            {
                datagramResult(result)
            } else {
                emptyState(coordinator.followStreamUnavailableReason ?? idleMessage)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(title)
    }

    // MARK: Private

    @State private var mode: FollowStreamDisplayMode = .text
    @State private var query = ""
    @State private var httpSaveError: String?
    @Environment(\.openWindow) private var openWindow

    private var isDatagram: Bool {
        !session.protocolStack.contains(.tcp) && session.protocolStack.contains(.udp)
    }

    private var title: String {
        isDatagram ? "Follow UDP Conversation" : "Follow TCP Stream"
    }

    private var idleMessage: String {
        isDatagram
            ? "List every datagram of this conversation from the stable capture source."
            : "Reconstruct both TCP directions from the stable capture source."
    }

    private var header: some View {
        HStack(alignment: .center, spacing: Theme.Metrics.spacingM) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(Theme.Typography.bodyEmphasis)
                Text("Reads this local capture on demand. Nothing is sent or exported.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            searchField
            Picker("Display", selection: $mode) {
                ForEach(FollowStreamDisplayMode.allCases) { mode in
                    Text(mode.title).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 132)
        }
    }

    private var searchField: some View {
        HStack(spacing: 5) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .font(.system(size: Theme.Icon.small))
            TextField("Find in transcript", text: $query)
                .textFieldStyle(.plain)
                .font(Theme.Typography.caption)
                .accessibilityLabel("Find in transcript")
            if !query.isEmpty {
                Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Clear find")
                    .help("Clear the find text")
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .tracexyContentSurface(in: Capsule(style: .continuous))
        .frame(minWidth: 150, idealWidth: 200, maxWidth: 240)
    }

    private var loading: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            if let fraction = coordinator.followStreamFraction {
                ProgressView(value: fraction)
                    .accessibilityLabel(isDatagram ? "Following UDP conversation" : "Following TCP stream")
                    .accessibilityValue(fraction.formatted(.percent.precision(.fractionLength(0))))
            } else {
                ProgressView()
                    .controlSize(.small)
            }
            HStack {
                if let progress = coordinator.followStreamProgress {
                    Text(
                        "Scanned \(progress.bytesConsumed.formatted()) of "
                            + "\(progress.totalBytes.formatted()) bytes"
                    )
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(.secondary)
                } else {
                    Text("Preparing stable local source…")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") {
                    coordinator.cancelFollowStream(clearResult: true)
                }
                .controlSize(.small)
            }
        }
        .padding(Theme.Metrics.spacingM)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
    }

    private func emptyState(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text(message)
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
            Button(isDatagram ? "Follow Conversation" : "Follow Stream") {
                coordinator.followSelectedStream()
            }
            .controlSize(.small)
            .disabled(coordinator.followStreamUnavailableReason != nil)
            .help(coordinator.followStreamUnavailableReason ?? idleMessage)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Theme.Metrics.spacingM)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
    }

    private func summaryRow(matched: (String, String), scanned: Int, completeness: FollowStreamCompleteness)
        -> some View
    {
        HStack(spacing: Theme.Metrics.spacingL) {
            field(matched.0, matched.1)
            field("Scanned Frames", scanned.formatted())
            field("Source", completeness == .complete ? "Complete file" : "Truncated tail")
            if !query.trimmingCharacters(in: .whitespaces).isEmpty {
                field("Matches", matchCount.formatted())
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            Button("Refresh") {
                coordinator.followSelectedStream()
            }
            .controlSize(.small)
            .disabled(coordinator.followStreamUnavailableReason != nil)
        }
    }

    private func limitationList(_ labels: [String]) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("Observed limitations")
                .font(Theme.Typography.captionMedium)
                .foregroundStyle(.secondary)
            ForEach(labels, id: \.self) { label in
                Label(label, systemImage: "info.circle")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func field(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(Theme.Typography.captionMedium).foregroundStyle(.secondary)
            Text(value).font(Theme.Typography.mono).textSelection(.enabled)
        }
    }

    private func frameButton(_ label: String, provenance: SessionFrameProvenance?) -> some View {
        Button(label) {
            if let provenance {
                coordinator.inspectFollowedFrame(provenance)
            }
        }
        .buttonStyle(.link)
        .font(Theme.Typography.captionMedium)
        .disabled(provenance?.locator == nil)
        .help(provenance?.locator == nil
            ? "This frame cannot be opened from the current source."
            : "Open this frame in Layers")
    }
}

// MARK: - TCP stream

private extension FollowConversationView {
    var matchCount: Int {
        let needle = query.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else {
            return 0
        }
        if let result = presentedStreamResult {
            return [result.aToB, result.bToA].reduce(0) { total, snapshot in
                FollowStreamDirectionPresentation(snapshot: snapshot, mode: mode).runSections
                    .reduce(total) { $0 + FollowTranscriptSearch.matches(of: needle, in: $1.text).count }
            }
        }
        if let result = coordinator.followDatagramResult {
            return FollowDatagramPresentation(result: result, mode: mode).rows.reduce(0) { total, row in
                let text = ([row.dnsHeadline ?? ""] + row.dnsAnswers + [row.payload]).joined(separator: "\n")
                return total + FollowTranscriptSearch.matches(of: needle, in: text).count
            }
        }
        return 0
    }

    /// Wireshark's Follow Stream footer: the turn summary, and Save as / Copy in its
    /// Show-as formats for both directions or one.
    func streamExportRow(_ result: FollowStreamResult) -> some View {
        let turns = FollowStreamExport.turns(of: result)
        return HStack(spacing: Theme.Metrics.spacingM) {
            Text(FollowStreamExport.summary(of: result, turns: turns))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
            Spacer(minLength: Theme.Metrics.spacingM)
            Menu("Save Stream") {
                ForEach(FollowStreamExport.Side.allCases) { side in
                    Section(sideTitle(side, result: result)) {
                        ForEach(FollowStreamExport.Format.allCases) { format in
                            Button(String(localized: "\(format.title)…")) {
                                saveStream(turns, format: format, side: side, tuple: result.tuple)
                            }
                        }
                    }
                }
                Divider()
                ForEach([FollowStreamExport.Format.cArrays, .yaml, .hexDump], id: \.self) { format in
                    Button(String(localized: "Copy as \(format.title)")) {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(
                            String(
                                bytes: FollowStreamExport
                                    .data(turns, format: format, side: .both, tuple: result.tuple),
                                encoding: .utf8
                            ) ?? "",
                            forType: .string
                        )
                    }
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .controlSize(.small)
            .disabled(turns.isEmpty)
            .help(
                "Save or copy the stream as raw bytes, ASCII, a hex dump, C arrays or YAML, as Wireshark's Follow Stream does"
            )
            Button("Filter Out This Stream") {
                coordinator.showSessions(narrowingWith: FollowStreamExport.filterOutTerm(result.tuple))
            }
            .buttonStyle(.link)
            .controlSize(.small)
            .help("Narrow the main window to every session except this stream's, as Wireshark's Follow Stream does")
        }
    }

    func sideTitle(_ side: FollowStreamExport.Side, result: FollowStreamResult) -> String {
        switch side {
        case .both: String(localized: "Both Directions")
        case .aToB: "\(result.tuple.a.display) → \(result.tuple.b.display)"
        case .bToA: "\(result.tuple.b.display) → \(result.tuple.a.display)"
        }
    }

    func saveStream(
        _ turns: [FollowStreamTurn],
        format: FollowStreamExport.Format,
        side: FollowStreamExport.Side,
        tuple: FiveTuple
    ) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "stream-\(tuple.a.port)-\(tuple.b.port).\(format.fileExtension)"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        do {
            try FollowStreamExport.data(turns, format: format, side: side, tuple: tuple).write(
                to: url,
                options: .atomic
            )
        } catch {
            httpSaveError = String(localized: "Couldn’t save the stream: \(error.localizedDescription)")
        }
    }

    /// The followed stream as the facet presents it: the installed reading's result,
    /// or the stream as captured.
    var presentedStreamResult: FollowStreamResult? {
        guard let captured = coordinator.followStreamResult else {
            return nil
        }
        return FollowStreamReadings.installed?.presentedResult(for: captured) ?? captured
    }

    func streamResult(_ captured: FollowStreamResult) -> some View {
        let reading = FollowStreamReadings.installed
        let result = reading?.presentedResult(for: captured) ?? captured
        return VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            summaryRow(
                matched: ("Matched Frames", captured.matchedFrameCount.formatted()),
                scanned: captured.scannedFrameCount,
                completeness: captured.completeness
            )
            if let controls = reading?.controls(for: captured) {
                controls
            }
            streamExportRow(result)
            let limitations = captured.limitations.presentationLabels
            if !limitations.isEmpty {
                limitationList(limitations)
            }

            FollowCertificatesSection(result: captured)

            if let http = FollowHTTPPresentation(result: result) {
                httpSection(http)
            }
            if let webSocket = FollowWebSocketPresentation(result: result) {
                FollowWebSocketSection(webSocket: webSocket, query: query) { coordinator.inspectFollowedFrame($0) }
            }
            if let http2 = FollowHTTP2Presentation(result: result) {
                FollowHTTP2Section(http2: http2, query: query) { coordinator.inspectFollowedFrame($0) }
            }

            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
                    directions(result)
                }
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                    directions(result)
                }
            }
        }
    }

    func httpSection(_ http: FollowHTTPPresentation) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(http.rows) { row in
                    httpRow(row, http: http)
                    if row.id != http.rows.last?.id {
                        Divider()
                    }
                }
                if let httpSaveError {
                    Text(httpSaveError)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(Color(nsColor: .systemRed))
                        .padding(.top, Theme.Metrics.spacingS)
                }
                ForEach(http.notes, id: \.self) { note in
                    Text(note)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, Theme.Metrics.spacingS)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(http.rows.count == 1 ? "HTTP, 1 request" : "HTTP, \(http.rows.count.formatted()) requests")
                .font(Theme.Typography.captionMedium)
        }
    }

    func httpRow(_ row: FollowHTTPExchangeRow, http: FollowHTTPPresentation) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: Theme.Metrics.spacingM) {
                Text(FollowTranscriptSearch.highlighted(row.request, query: query))
                    .font(Theme.Typography.monoSmall)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .help(row.host.map { "Host: \($0)" } ?? row.request)
                Spacer(minLength: Theme.Metrics.spacingM)
                Text(row.status)
                    .font(Theme.Typography.captionMedium)
                    .foregroundStyle(row.isError ? Color(nsColor: .systemRed) : Color.primary)
                    .lineLimit(1)
            }
            HStack(spacing: Theme.Metrics.spacingM) {
                if let elapsed = row.elapsed {
                    Text(elapsed)
                        .font(Theme.Typography.monoMicro)
                        .foregroundStyle(.secondary)
                        .help("From the frame that completed the request to the frame carrying the first response byte")
                }
                if let size = row.size {
                    Text(size)
                        .font(Theme.Typography.monoMicro)
                        .foregroundStyle(.secondary)
                        .help("Response body size")
                }
                Spacer(minLength: 0)
                if row.bodyFileName != nil {
                    Button("Show Body…") {
                        showHTTPBody(row, http: http)
                    }
                    .buttonStyle(.link)
                    .font(Theme.Typography.captionMedium)
                    .help("Decode the response body (gzip, deflate, Base64…) and read it as text, JSON or an image")
                    .accessibilityLabel("Show response body for \(row.request)")
                }
                if let fileName = row.bodyFileName {
                    Button("Save Body…") {
                        saveHTTPBody(row, http: http, fileName: fileName)
                    }
                    .buttonStyle(.link)
                    .font(Theme.Typography.captionMedium)
                    .help("Save the response body exactly as it was sent, without chunk framing")
                    .accessibilityLabel("Save response body for \(row.request)")
                }
                frameButton("Request", provenance: row.requestFrame)
                    .accessibilityLabel("Open request frame for \(row.request)")
                if row.responseFrame != nil {
                    frameButton("Response", provenance: row.responseFrame)
                        .accessibilityLabel("Open response frame for \(row.request)")
                }
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }

    func showHTTPBody(_ row: FollowHTTPExchangeRow, http: FollowHTTPPresentation) {
        guard let result = presentedStreamResult,
              let body = http.responseBody(of: row, in: result) else
        {
            httpSaveError = "This response body is no longer available."
            return
        }
        coordinator.packetBytesInspection.show(PacketBytesSubject(
            title: "\(row.request) — \(row.status)",
            bytes: body,
            suggestedDecoding: PacketBytesInspection.decoding(forContentEncoding: row.savableResponse?.contentEncoding),
            suggestedPresentation: PacketBytesInspection.presentation(forContentType: row.savableResponse?.contentType)
        ))
        openWindow(id: TracexyApp.packetBytesWindowID)
    }

    func saveHTTPBody(_ row: FollowHTTPExchangeRow, http: FollowHTTPPresentation, fileName: String) {
        guard let result = presentedStreamResult,
              let body = http.responseBody(of: row, in: result) else
        {
            httpSaveError = "This response body is no longer available to save."
            return
        }
        let panel = NSSavePanel()
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = fileName
        panel.message = "Saves the response body exactly as it was sent. Nothing is decompressed or run."
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        do {
            try Data(body).write(to: url, options: .atomic)
            httpSaveError = nil
        } catch {
            httpSaveError = "The body could not be saved: \(error.localizedDescription)"
        }
    }

    @ViewBuilder
    func directions(_ result: FollowStreamResult) -> some View {
        let origin = FollowStreamExport.origin(of: result)
        direction(result.aToB, title: "\(result.tuple.a.display) → \(result.tuple.b.display)", origin: origin)
        direction(result.bToA, title: "\(result.tuple.b.display) → \(result.tuple.a.display)", origin: origin)
    }

    func direction(_ snapshot: FollowStreamDirectionSnapshot, title: String, origin: Date?) -> some View {
        let presentation = FollowStreamDirectionPresentation(snapshot: snapshot, mode: mode)
        return GroupBox {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                Text(retainedLine(snapshot, presentation: presentation))
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .help("Bytes omitted by reader bounds or not drawn are counted, never guessed at.")

                if presentation.runSections.isEmpty {
                    Text("No application bytes were retained in this direction.")
                        .font(Theme.Typography.body)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(presentation.runSections) { section in
                        runView(section, origin: origin, gapsAreMissing: presentation.gapsAreMissing)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(title)
                .font(Theme.Typography.captionMedium)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .frame(minWidth: 280, maxWidth: .infinity, alignment: .topLeading)
    }

    func runView(
        _ section: FollowStreamDirectionPresentation.RunSection,
        origin: Date?,
        gapsAreMissing: Bool
    )
        -> some View
    {
        VStack(alignment: .leading, spacing: 4) {
            if section.followsGap {
                Group {
                    if let gap = section.gapByteCount, gapsAreMissing {
                        Label("\(gap.formatted()) bytes missing in the capture", systemImage: "ellipsis")
                    } else if let gap = section.gapByteCount {
                        Label("\(gap.formatted()) bytes between these runs were not retained", systemImage: "ellipsis")
                    } else {
                        Label("Bytes between these runs were not retained", systemImage: "ellipsis")
                    }
                }
                .font(Theme.Typography.micro)
                .foregroundStyle(.secondary)
            }
            HStack(spacing: Theme.Metrics.spacingM) {
                frameButton(
                    "Frame \(section.firstCaptureOrdinal.formatted())",
                    provenance: section.firstProvenance
                )
                if let origin, let stamp = section.firstProvenance?.timestamp {
                    Text(verbatim: "+" + String(format: "%.6f", stamp.timeIntervalSince(origin)) + " s")
                        .font(Theme.Typography.monoMicro)
                        .foregroundStyle(.secondary)
                        .help("Time since the stream's first frame")
                }
                Text(String(format: "Sequence 0x%08X", section.sequenceAnchor))
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            Text(FollowTranscriptSearch.highlighted(section.text, query: query))
                .font(Theme.Typography.zoomed(
                    .subheadline, zoom: coordinator.packetDetailOptions.textZoom, monospaced: true
                ))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    func retainedLine(
        _ snapshot: FollowStreamDirectionSnapshot,
        presentation: FollowStreamDirectionPresentation
    )
        -> String
    {
        var line = "\(snapshot.retainedByteCount.formatted()) bytes retained"
        let hidden = UInt64(presentation.viewOmittedByteCount) + snapshot.observedOmittedByteCount
        if hidden > 0 {
            line += ", \(hidden.formatted()) not shown"
        }
        return line
    }
}

// MARK: - UDP conversation

private extension FollowConversationView {
    func datagramResult(_ result: FollowDatagramResult) -> some View {
        let presentation = FollowDatagramPresentation(result: result, mode: mode)
        return VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            summaryRow(
                matched: ("Datagrams", result.matchedFrameCount.formatted()),
                scanned: result.scannedFrameCount,
                completeness: result.completeness
            )
            let limitations = result.limitations.presentationLabels
            if !limitations.isEmpty {
                limitationList(limitations)
            }
            if let section = FollowDatagramReadings.installed?.section(
                for: result, openFrame: { coordinator.inspectFollowedFrame($0) }
            ) {
                section
            }
            if presentation.rows.isEmpty {
                Text("No datagrams of this conversation were found in the capture source.")
                    .font(Theme.Typography.body)
                    .foregroundStyle(.secondary)
            } else {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(presentation.rows) { row in
                        datagramRow(row)
                        Divider()
                    }
                }
                .padding(.horizontal, Theme.Metrics.spacingM)
                .tracexyContentSurface(
                    in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
                )
            }
            if result.omittedMessageCount > 0 {
                Text("\(result.omittedMessageCount.formatted()) later datagrams are not listed")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                    .help("The list keeps the first datagrams in capture order and counts the rest.")
            }
        }
    }

    func datagramRow(_ row: FollowDatagramRowPresentation) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: Theme.Metrics.spacingM) {
                Text(row.route)
                    .font(Theme.Typography.captionMedium)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: Theme.Metrics.spacingM)
                Text(row.sizeLabel)
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                Text(row.timeLabel)
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                frameButton(row.frameLabel, provenance: row.provenance)
            }
            if let headline = row.dnsHeadline {
                Text(FollowTranscriptSearch.highlighted(headline, query: query))
                    .font(Theme.Typography.bodyMedium)
                    .textSelection(.enabled)
                ForEach(Array(row.dnsAnswers.enumerated()), id: \.offset) { _, answer in
                    Text(FollowTranscriptSearch.highlighted(answer, query: query))
                        .font(Theme.Typography.monoSmall)
                        .textSelection(.enabled)
                }
                if let pairing = row.pairing {
                    Text(pairing)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if !row.payload.isEmpty {
                Text(FollowTranscriptSearch.highlighted(row.payload, query: query))
                    .font(Theme.Typography.zoomed(
                        .subheadline, zoom: coordinator.packetDetailOptions.textZoom, monospaced: true
                    ))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if row.hiddenByteCount > 0 {
                Text("\(row.hiddenByteCount.formatted()) more bytes not shown")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }
}

// MARK: - FollowCertificatesSection

/// Certificates each direction sent in the clear, read from the follow result's
/// leading bytes under ``TLSCertificateExtraction``'s policy. Hidden entirely for a
/// stream that is not TLS.
private struct FollowCertificatesSection: View {
    // MARK: Internal

    let result: FollowStreamResult

    var body: some View {
        // Derived per render rather than in a `.task`: an empty body is never
        // rendered, so a task on it would never run. The walk is cheap — it stops
        // at the first Certificate message, ChangeCipherSpec or non-TLS byte.
        content(CertificatePair(
            aToB: TLSCertificateExtraction.extract(from: result.aToB),
            bToA: TLSCertificateExtraction.extract(from: result.bToA)
        ))
    }

    // MARK: Private

    private struct CertificatePair: Equatable {
        let aToB: TLSCertificateExtraction
        let bToA: TLSCertificateExtraction
    }

    private static let pemType = UTType(filenameExtension: "pem") ?? .data

    @State private var exportError: String?

    @ViewBuilder
    private func content(_ pair: CertificatePair) -> some View {
        let senders: [(String, TLSCertificateExtraction)] = [
            (result.tuple.b.display, pair.bToA),
            (result.tuple.a.display, pair.aToB),
        ]
        let withCertificates = senders.filter { !$0.1.certificates.isEmpty }
        if !withCertificates.isEmpty {
            ForEach(withCertificates, id: \.0) { sender, extraction in
                chain(sender: sender, extraction: extraction)
            }
            if let exportError {
                Label(exportError, systemImage: "exclamationmark.triangle")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        } else if let explanation = tlsAbsence(senders.map(\.1)) {
            HStack(spacing: Theme.Metrics.spacingS) {
                Image(systemName: "lock.doc")
                    .foregroundStyle(.secondary)
                Text(explanation)
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func chain(sender: String, extraction: TLSCertificateExtraction) -> some View {
        let certificates = extraction.certificates
        return GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(certificates.enumerated()), id: \.offset) { index, certificate in
                    certificateRow(certificate)
                    if index < certificates.count - 1 {
                        Divider()
                    }
                }
                if case let .certificates(_, unparsed, omitted) = extraction, unparsed + omitted > 0 {
                    Text("\((unparsed + omitted).formatted()) more entries could not be listed")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, Theme.Metrics.spacingS)
                }
            }
        } label: {
            HStack {
                Text("Certificates sent by \(sender)")
                    .font(Theme.Typography.captionMedium)
                Spacer()
                if certificates.count > 1 {
                    Button("Save Chain…") {
                        save(
                            Data(certificates.map(\.pem).joined().utf8),
                            name: "\(fileStem(certificates[0]))-chain.pem",
                            type: Self.pemType
                        )
                    }
                    .controlSize(.small)
                    .help("Save every certificate in the order sent, as PEM")
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Certificates sent by \(sender)")
    }

    private func certificateRow(_ certificate: X509CertificateSummary) -> some View {
        HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
            Image(systemName: "doc.text")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(certificate.displayName)
                    .font(Theme.Typography.bodyEmphasis)
                    .textSelection(.enabled)
                Text(certificate.isSelfIssued
                    ? "Issued by itself"
                    : "Issued by \(certificate.issuer.commonName ?? certificate.issuer.displayString)")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                    .help(certificate.issuer.displayString)
                Text(validity(certificate))
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                if !certificate.subjectAlternativeNames.isEmpty {
                    Text(certificate.subjectAlternativeNames.joined(separator: ", "))
                        .font(Theme.Typography.monoSmall)
                        .lineLimit(2)
                        .textSelection(.enabled)
                        .help("Subject alternative names")
                }
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            Menu {
                Button("Save as DER…") {
                    save(Data(certificate.der), name: "\(fileStem(certificate)).cer", type: .x509Certificate)
                }
                Button("Save as PEM…") {
                    save(Data(certificate.pem.utf8), name: "\(fileStem(certificate)).pem", type: Self.pemType)
                }
                Divider()
                Button("Copy PEM") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(certificate.pem, forType: .string)
                }
                Button("Copy SHA-256 Fingerprint") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(certificate.fingerprintHex, forType: .string)
                }
            } label: {
                Image(systemName: "square.and.arrow.up")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .accessibilityLabel("Export \(certificate.displayName)")
            .help("Save or copy this certificate exactly as it was sent")
        }
        .padding(.vertical, 6)
        .help("SHA-256 \(certificate.fingerprintHex)")
    }

    /// The one explanation worth showing when neither direction listed a
    /// certificate — only for a stream that actually carried TLS records.
    private func tlsAbsence(_ outcomes: [TLSCertificateExtraction]) -> String? {
        for outcome in outcomes {
            switch outcome {
            case .encryptedBeforeCertificate,
                 .certificates:
                return outcome.absenceExplanation
            default:
                continue
            }
        }
        return nil
    }

    private func validity(_ certificate: X509CertificateSummary) -> String {
        let style = Date.FormatStyle(date: .abbreviated, time: .omitted, timeZone: .gmt)
        return "Valid \(certificate.notBefore.formatted(style)) to \(certificate.notAfter.formatted(style))"
    }

    private func fileStem(_ certificate: X509CertificateSummary) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        let stem = String(certificate.displayName.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" })
        return stem.isEmpty ? "certificate" : stem
    }

    private func save(_ data: Data, name: String, type: UTType) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [type]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = name
        panel.message = "Saves the certificate exactly as it was sent. It contains no private key."
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        do {
            try data.write(to: url, options: .atomic)
            exportError = nil
        } catch {
            exportError = "The certificate could not be saved: \(error.localizedDescription)"
        }
    }
}
