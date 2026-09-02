import SwiftUI

// MARK: - SessionEvidenceContextSummaryView

/// Compact right-dock explanation of the retained connection/TLS model. The
/// complete chronological observations stay in the bottom Evidence facet; this
/// view names the scope, coverage, and route to those literal citations.
struct SessionEvidenceContextSummaryView: View {
    // MARK: Internal

    let selection: SessionEvidenceSelection
    let openEvidence: () -> Void

    var body: some View {
        if !selection.connections.isEmpty {
            ContextInspectorFieldTable(
                title: "Connection Evidence",
                fields: connectionFields
            )
        }

        if let tls = selection.tls {
            ContextInspectorFieldTable(
                title: "TLS Evidence",
                fields: tlsFields(tls)
            )
        }

        if !selection.isEmpty || hasGlobalCoverageCaveat {
            ContextInspectorTable(title: "Evidence Navigation") {
                ContextInspectorFullRow {
                    VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                        Text(navigationExplanation)
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Open Evidence") {
                            openEvidence()
                        }
                        .controlSize(.small)
                        .help("Show retained connection and TLS observations in capture order")
                    }
                }
            }
        }
    }

    // MARK: Private

    private var connectionFields: [ContextTableField] {
        let connections = selection.connections
        var fields = [
            ContextTableField(
                label: connections.count == 1 ? "Connection" : "Incarnations",
                value: connections.count.formatted()
            ),
            ContextTableField(
                label: "Retained Events",
                value: connections.reduce(0) { $0 + $1.events.count }.formatted()
            ),
        ]

        if connections.count == 1, let connection = connections.first {
            fields.append(ContextTableField(
                label: "Phase",
                value: SessionEvidenceCopy.phaseLabel(connection.phase),
                monospaced: false
            ))
            fields.append(ContextTableField(
                label: "Handshake",
                value: SessionEvidenceCopy.handshakeLabel(connection.handshake),
                monospaced: false
            ))
            if let close = SessionEvidenceCopy.closeReasonLabel(connection.closeReason) {
                fields.append(ContextTableField(
                    label: "Close",
                    value: close,
                    monospaced: false
                ))
            }
        } else {
            fields.append(ContextTableField(
                label: "Scope",
                value: "Sequential tuple reuse; TLS evidence remains shared at session scope",
                monospaced: false
            ))
        }

        let omitted = connections.enumerated().compactMap { index, connection -> String? in
            guard connection.omittedEventCount > 0 else {
                return nil
            }
            return connections.count == 1
                ? connection.omittedEventCount.formatted()
                : "#\(index + 1): \(connection.omittedEventCount.formatted())"
        }
        if !omitted.isEmpty {
            fields.append(ContextTableField(
                label: "Omitted Events",
                value: omitted.joined(separator: " · ")
            ))
        }

        let loss = Set(connections.map { SessionEvidenceCopy.lossLabel($0.lossKnowledge) })
            .sorted()
        fields.append(ContextTableField(
            label: "Frame Coverage",
            value: loss.joined(separator: " · "),
            monospaced: false
        ))
        return fields
    }

    private var hasGlobalCoverageCaveat: Bool {
        selection.connectionCoverage.omittedSummaryCount > 0
            || selection.connectionCoverage.countersOverflowed
            || selection.tlsCoverage.omittedObservationCount > 0
            || selection.tlsCoverage.excludedReassembledRecordCount > 0
            || selection.tlsCoverage.capacityReached
            || selection.tlsCoverage.countersOverflowed
    }

    private var navigationExplanation: String {
        if selection.isEmpty {
            return "No exact session evidence was retained. Capture-level bounds still prevent treating that absence as proof."
        }
        return "Review retained observations in capture order, then load one cited frame from the current local source."
    }

    private func tlsFields(_ tls: TLSEvidenceSummary) -> [ContextTableField] {
        var fields = [
            ContextTableField(
                label: "Direct Records",
                value: tls.observations.count.formatted()
            ),
            ContextTableField(
                label: "Frame Coverage",
                value: SessionEvidenceCopy.lossLabel(tls.lossKnowledge),
                monospaced: false
            ),
        ]
        if tls.omittedObservationCount > 0 {
            fields.append(ContextTableField(
                label: "Omitted",
                value: tls.omittedObservationCount.formatted()
            ))
        }
        if tls.excludedReassembledRecordCount > 0 {
            fields.append(ContextTableField(
                label: "Not Citable",
                value: "\(tls.excludedReassembledRecordCount.formatted()) reassembled records",
                monospaced: false
            ))
        }
        if tls.decoderTruncatedFrameCount > 0 {
            fields.append(ContextTableField(
                label: "Decode Bound",
                value: "\(tls.decoderTruncatedFrameCount.formatted()) frames reached the record cap",
                monospaced: false
            ))
        }
        if tls.snapLengthTruncationObserved {
            fields.append(ContextTableField(
                label: "Snap Length",
                value: "Truncation observed",
                monospaced: false
            ))
        }
        return fields
    }
}
