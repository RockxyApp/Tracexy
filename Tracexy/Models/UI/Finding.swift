import SwiftUI

// MARK: - Finding

/// One presentation-ready projection of a typed Core analysis finding. Identity,
/// severity, session navigation, coverage and citation accounting are preserved
/// from Core; this value adds fixed UI copy but no new finding policy.
struct Finding: Identifiable, Hashable {
    let id: UUID
    let severity: Severity
    let title: String
    let subtitle: String
    /// The session whose typed fold produced this finding, for click-to-select.
    let sessionID: UUID
    let coverage: AnalysisCoverage
    let citedObservationCount: Int
    let omittedCitationCount: UInt64
    /// Exact bounded frame provenance copied from Core citations, in citation
    /// order. The presentation layer keeps no bytes and invents no fallback: an
    /// absent locator remains visibly unavailable when the user asks to inspect it.
    let citedFrames: [SessionFrameProvenance]
}

// MARK: Finding projection

extension Finding {
    init(_ finding: ConnectionAnalysisFinding, host: String) {
        id = finding.id
        severity = Severity(finding.severity)
        title = switch finding.kind {
        case .resetObserved: "TCP reset observed"
        case .retransmissionObserved: "TCP retransmission observed"
        case .overlapObserved: "TCP segment overlap observed"
        case .outOfOrderObserved: "TCP out-of-order delivery observed"
        }
        sessionID = SessionBuilder.sessionID(for: finding.tuple)
        coverage = finding.coverage
        citedObservationCount = finding.citations.count
        omittedCitationCount = finding.omittedCitationCount
        citedFrames = finding.citations.flatMap(\.provenance)
        subtitle = Self.subtitle(
            context: host,
            citedObservationCount: citedObservationCount,
            omittedCitationCount: omittedCitationCount,
            coverage: coverage
        )
    }

    init(_ finding: DatagramAnalysisFinding, host: String) {
        id = finding.id
        severity = Severity(finding.severity)
        title = switch finding.kind {
        case .dnsTruncationIndicated: "DNS truncation indicated"
        }
        sessionID = finding.sessionID
        coverage = finding.coverage
        citedObservationCount = finding.citations.count
        omittedCitationCount = finding.omittedCitationCount
        citedFrames = finding.citations.map(\.provenance)
        subtitle = Self.subtitle(
            context: "TC bit observed · \(host)",
            citedObservationCount: citedObservationCount,
            omittedCitationCount: omittedCitationCount,
            coverage: coverage
        )
    }

    private static func subtitle(
        context: String,
        citedObservationCount: Int,
        omittedCitationCount: UInt64,
        coverage: AnalysisCoverage
    )
        -> String
    {
        let citationLabel = citedObservationCount == 1 ? "1 cited observation" : "\(citedObservationCount) cited observations"
        let omittedLabel = omittedCitationCount == 0 ? "" : " · \(omittedCitationCount) omitted"
        return "\(context) · \(citationLabel)\(omittedLabel) · \(coverage.presentationLabel)"
    }
}

private extension Finding.Severity {
    init(_ severity: AnalysisSeverity) {
        self = switch severity {
        case .warning: .warning
        case .note: .note
        }
    }
}

private extension AnalysisCoverage {
    var presentationLabel: String {
        switch self {
        case .captureLossReported: "capture loss reported"
        case .omittedEvidence: "bounded evidence omitted"
        case .unknownLoss: "capture loss unknown"
        case .boundedNoKnownOmission: "bounded evidence"
        }
    }
}

// MARK: - Finding.Severity

extension Finding {
    /// Ranked worst→least, driving both sort order and the row's icon/color.
    enum Severity: Int, CaseIterable, Hashable {
        case error = 0
        case warning = 1
        case note = 2

        // MARK: Internal

        /// Real SF Symbol (never a colored dot — see design system).
        var systemImage: String {
            switch self {
            case .error: "xmark.octagon"
            case .warning: "exclamationmark.triangle"
            case .note: "info.circle"
            }
        }

        var tint: Color {
            switch self {
            case .error: .red
            case .warning: .orange
            case .note: .secondary
            }
        }
    }
}
