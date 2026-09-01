import SwiftUI

// MARK: - SessionEvidenceTimelineView

/// Literal connection/TLS observations for one selected session. The list owns
/// no IO: choosing a citation delegates the exact-frame request to the
/// coordinator through `inspectFrame`.
struct SessionEvidenceTimelineView: View {
    // MARK: Internal

    let selection: SessionEvidenceSelection
    let selectedFrameOrdinal: FrameOrdinal?
    let isLoadingFrame: Bool
    let frameError: String?
    let frameUnavailable: Bool
    let inspectFrame: (SessionFrameProvenance) -> Void

    var body: some View {
        let items = SessionEvidenceItem.timeline(
            connections: selection.connections,
            tls: selection.tls
        )
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            evidenceHeader(items: items)

            if isLoadingFrame {
                ProgressView("Loading cited frame…")
                    .controlSize(.small)
            } else if frameUnavailable {
                evidenceNotice(
                    "This observation has no exact source locator. No replacement frame was loaded.",
                    systemImage: "location.slash"
                )
            } else if let frameError {
                evidenceNotice(frameError, systemImage: "exclamationmark.triangle")
            }

            coverage

            if items.isEmpty {
                evidenceNotice(
                    "No connection or direct-frame TLS observations were retained for this session. "
                        + "Capture-level bounds below may still limit what can be concluded.",
                    systemImage: "rectangle.dashed"
                )
            } else {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                        evidenceRow(item)
                        if index < items.count - 1 {
                            Divider()
                                .padding(.leading, 34)
                        }
                    }
                }
                .padding(.horizontal, Theme.Metrics.spacingM)
                .tracexyContentSurface(
                    in: RoundedRectangle(
                        cornerRadius: Theme.Metrics.cornerRadius,
                        style: .continuous
                    )
                )
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Retained session evidence")
    }

    // MARK: Private

    private var tlsCoverage: [String] {
        guard let tls = selection.tls else {
            return []
        }
        var labels: [String] = []
        if tls.omittedObservationCount > 0 {
            labels.append("\(tls.omittedObservationCount.formatted()) direct TLS observations omitted")
        }
        if tls.excludedReassembledRecordCount > 0 {
            labels.append(
                "\(tls.excludedReassembledRecordCount.formatted()) reassembled TLS records excluded because exact frame provenance is incomplete"
            )
        }
        if tls.recoveredTruncationIndicatorCount > 0 {
            labels.append(
                "\(tls.recoveredTruncationIndicatorCount.formatted()) recovered truncation indicators"
            )
        }
        if tls.decoderTruncatedFrameCount > 0 {
            labels.append(
                "\(tls.decoderTruncatedFrameCount.formatted()) direct frames reached the TLS record decode bound"
            )
        }
        if tls.snapLengthTruncationObserved {
            labels.append("TLS-bearing snap-length truncation was observed")
        }
        if tls.lossKnowledge != .noLossReported {
            labels.append(SessionEvidenceCopy.lossLabel(tls.lossKnowledge))
        }
        return labels
    }

    /// These counters describe the capture, not the selected session. The copy
    /// keeps that scope explicit so a global omission is never attributed here.
    private var captureCoverage: [String] {
        var labels: [String] = []
        let connection = selection.connectionCoverage
        if connection.omittedSummaryCount > 0 {
            labels.append(
                "Capture-level: \(connection.omittedSummaryCount.formatted()) connection summaries omitted; this does not identify which sessions were affected"
            )
        }
        if connection.countersOverflowed {
            labels.append("Capture-level: a connection evidence counter saturated")
        }

        let tls = selection.tlsCoverage
        if tls.omittedObservationCount > 0 {
            labels.append(
                "Capture-level: \(tls.omittedObservationCount.formatted()) direct TLS observations omitted"
            )
        }
        if tls.excludedReassembledRecordCount > 0 {
            labels.append(
                "Capture-level: \(tls.excludedReassembledRecordCount.formatted()) reassembled TLS records excluded from exact citation"
            )
        }
        if tls.decoderTruncatedFrameCount > 0 {
            labels.append(
                "Capture-level: \(tls.decoderTruncatedFrameCount.formatted()) TLS-bearing frames reached the record decode bound"
            )
        }
        if tls.capacityReached {
            labels.append("Capture-level: a TLS evidence retention bound was reached")
        }
        if tls.countersOverflowed {
            labels.append("Capture-level: a TLS evidence counter saturated")
        }
        return labels
    }

    @ViewBuilder private var coverage: some View {
        let connectionCaveats = selection.connections.enumerated().flatMap { index, connection in
            connectionCoverage(connection, index: index)
        }
        let tlsCaveats = tlsCoverage
        let globalCaveats = captureCoverage

        if !connectionCaveats.isEmpty || !tlsCaveats.isEmpty || !globalCaveats.isEmpty {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                Text("Coverage")
                    .font(Theme.Typography.captionMedium)
                    .foregroundStyle(.secondary)
                ForEach(connectionCaveats + tlsCaveats, id: \.self) { caveat in
                    Label(caveat, systemImage: "info.circle")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
                ForEach(globalCaveats, id: \.self) { caveat in
                    Label(caveat, systemImage: "scope")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(Theme.Metrics.spacingM)
            .tracexyContentSurface(
                in: RoundedRectangle(
                    cornerRadius: Theme.Metrics.cornerRadius,
                    style: .continuous
                )
            )
        }
    }

    private func evidenceHeader(items: [SessionEvidenceItem]) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.Metrics.spacingM) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Connection & TLS Evidence")
                    .font(Theme.Typography.bodyEmphasis)
                Text(headerSummary(items: items))
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            Text("capture order")
                .font(Theme.Typography.microMedium)
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .tracexyChipStyle(tint: .accentColor, isActive: false)
        }
    }

    private func evidenceRow(_ item: SessionEvidenceItem) -> some View {
        HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
            Image(systemName: item.systemImage)
                .font(.system(size: Theme.Icon.small))
                .foregroundStyle(item.kind == .tls ? Theme.color(for: .tls) : Theme.color(for: .tcp))
                .frame(width: 20, height: 20)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: Theme.Metrics.spacingS) {
                    Text(item.title)
                        .font(Theme.Typography.captionMedium)
                    Text(item.categoryLabel)
                        .font(Theme.Typography.microMedium)
                        .foregroundStyle(.secondary)
                }
                Text(item.detail)
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: Theme.Metrics.spacingS) {
                    Text("Frame \(item.ordinal.rawValue.formatted())")
                    Text("·")
                    Text(item.timestamp.formatted(date: .omitted, time: .standard))
                }
                .font(Theme.Typography.monoSmall)
                .foregroundStyle(.secondary)
            }

            Spacer(minLength: Theme.Metrics.spacingM)

            citationButtons(item.provenance)
        }
        .padding(.vertical, Theme.Metrics.spacingM)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private func citationButtons(_ citations: [SessionFrameProvenance]) -> some View {
        if citations.count == 1, let citation = citations.first {
            citationButton(citation, title: "Inspect Frame")
        } else {
            Menu("Inspect Frames") {
                ForEach(Array(citations.enumerated()), id: \.offset) { _, citation in
                    Button(
                        citation.locator == nil
                            ? "Frame \(citation.ordinal.rawValue.formatted()) — unavailable"
                            : "Frame \(citation.ordinal.rawValue.formatted())"
                    ) {
                        inspectFrame(citation)
                    }
                }
            }
            .controlSize(.small)
        }
    }

    private func citationButton(_ citation: SessionFrameProvenance, title: String) -> some View {
        Button(title) {
            inspectFrame(citation)
        }
        .controlSize(.small)
        .disabled(isLoadingFrame)
        .help(
            citation.locator == nil
                ? "This observation has no exact source locator"
                : "Load only frame \(citation.ordinal.rawValue) from the current local capture"
        )
        .accessibilityValue(
            selectedFrameOrdinal == citation.ordinal ? "Selected" : ""
        )
    }

    private func evidenceNotice(_ text: String, systemImage: String) -> some View {
        Label(text, systemImage: systemImage)
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(Theme.Metrics.spacingM)
            .frame(maxWidth: .infinity, alignment: .leading)
            .tracexyContentSurface(
                in: RoundedRectangle(
                    cornerRadius: Theme.Metrics.cornerRadius,
                    style: .continuous
                )
            )
    }

    private func headerSummary(items: [SessionEvidenceItem]) -> String {
        let connectionLabel = selection.connections.count == 1
            ? "1 connection"
            : "\(selection.connections.count) connection incarnations"
        let eventCount = items.count { $0.kind == .connection }
        let tlsCount = items.count { $0.kind == .tls }
        return "\(connectionLabel) · \(eventCount) TCP events · \(tlsCount) direct-frame TLS records"
    }

    private func connectionCoverage(_ connection: ConnectionSummary, index: Int) -> [String] {
        let prefix = selection.connections.count > 1 ? "Connection \(index + 1): " : ""
        var labels = SessionEvidenceCopy.limitationLabels(connection.limitations).map { prefix + $0 }
        if connection.omittedEventCount > 0 {
            labels.append(prefix + "\(connection.omittedEventCount.formatted()) older events omitted")
        }
        if connection.lossKnowledge != .noLossReported {
            labels.append(prefix + SessionEvidenceCopy.lossLabel(connection.lossKnowledge))
        }
        return labels
    }
}
