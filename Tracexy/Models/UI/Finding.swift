import SwiftUI

// MARK: - Finding

/// One presentation-ready projection of a typed Core analysis finding. Identity,
/// severity, session navigation, coverage and citation accounting are preserved
/// from Core; this value adds fixed UI copy but no new finding policy.
struct Finding: Identifiable, Hashable {
    let id: UUID
    let severity: Severity
    /// What kind of finding this is, so a report can group occurrences and lead back
    /// to their sessions: a Core analysis kind (`finding == …`), or a kind an
    /// installed ``FindingContributing`` source defines with its own expression.
    let kind: Kind
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
    /// Whether the cited frames are re-sent TCP segments (plain, fast or spurious
    /// retransmission), so the Overview can plot them over time.
    var citesRetransmittedSegments = false
}

// MARK: - Finding.Kind

extension Finding {
    enum Kind: Hashable {
        /// A Core analysis kind, which answers to `finding == name`.
        case analysis(QueryFindingKind)
        /// A kind an installed ``FindingContributing`` source defines.
        case contributed(ContributedFindingKind)
    }

    /// The Core kind, or `nil` for a contributed finding.
    var queryKind: QueryFindingKind? {
        if case let .analysis(kind) = kind {
            return kind
        }
        return nil
    }

    /// The name a findings table shows for the kind: the `finding ==` name of a
    /// Core kind, or a contributed kind's label.
    var kindName: String {
        switch kind {
        case let .analysis(kind): SessionQueryParser.findingName(kind)
        case let .contributed(kind): kind.label
        }
    }

    /// The Session Expression that leads back to every session with a finding of
    /// this kind.
    var kindExpression: String {
        switch kind {
        case let .analysis(kind): "finding == \(SessionQueryParser.findingName(kind))"
        case let .contributed(kind): kind.expression
        }
    }
}

// MARK: Finding projection

extension Finding {
    /// A finding an installed ``FindingContributing`` source reports. It cites no
    /// frames: the source decides from session measures, not from frame evidence.
    init(
        id: UUID,
        severity: Severity,
        kind: ContributedFindingKind,
        title: String,
        subtitle: String,
        sessionID: UUID,
        coverage: AnalysisCoverage
    ) {
        self.id = id
        self.severity = severity
        self.kind = .contributed(kind)
        self.title = title
        self.subtitle = subtitle
        self.sessionID = sessionID
        self.coverage = coverage
        citedObservationCount = 0
        omittedCitationCount = 0
        citedFrames = []
    }

    init(_ finding: ConnectionAnalysisFinding, host: String) {
        id = finding.id
        severity = Severity(finding.severity)
        kind = .analysis(InvestigationQueryEngine.projected(finding.kind))
        title = switch finding.kind {
        case .connectionRefusedObserved: "Connection refused by peer"
        case .handshakeUnansweredObserved: "Connection attempt unanswered"
        case .abortAfterDataObserved: "Connection aborted after data"
        case .halfCloseObserved: "TCP half-close observed"
        case .resetObserved: "TCP reset observed"
        case .retransmissionObserved: "TCP retransmission observed"
        case .overlapObserved: "TCP segment overlap observed"
        case .outOfOrderObserved: "TCP segment ahead of a sequence gap"
        case .zeroWindowObserved: "TCP zero window observed"
        case .windowFullObserved: "TCP receive window full"
        case .duplicateAcknowledgementObserved: "TCP duplicate acknowledgements observed"
        case .keepAliveObserved: "TCP keep-alive observed"
        case .fastRetransmissionObserved: "TCP fast retransmission observed"
        case .spuriousRetransmissionObserved: "TCP spurious retransmission observed"
        case .ackedUnseenSegmentObserved: "ACKed segment the capture did not see"
        case .cleartextCredentialsObserved: "Credentials sent in cleartext"
        case .tupleReuseObserved: "TCP connection tuple reused"
        }
        sessionID = SessionBuilder.sessionID(for: finding.tuple)
        coverage = finding.coverage
        citedObservationCount = finding.citations.count
        omittedCitationCount = finding.omittedCitationCount
        citedFrames = finding.citations.flatMap(\.provenance)
        citesRetransmittedSegments = [
            .retransmissionObserved, .fastRetransmissionObserved, .spuriousRetransmissionObserved,
        ].contains(finding.kind)
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
        kind = .analysis(InvestigationQueryEngine.projected(finding.kind))
        let context: String
        switch finding.kind {
        case .dnsTruncationIndicated:
            title = "DNS truncation indicated"
            context = "TC bit observed for \(host)"
        case .dnsNameErrorObserved:
            title = "DNS name does not exist"
            context = "NXDOMAIN response for \(host)"
        case .dnsServerFailureObserved:
            title = "DNS server failed or refused"
            context = "SERVFAIL or REFUSED response for \(host)"
        case .dnsQueryUnansweredObserved:
            title = "DNS query unanswered"
            context = "Retried query with no response observed for \(host)"
        case .icmpDestinationUnreachableObserved:
            title = "ICMP destination unreachable"
            context = "Unreachable message for \(host)"
        case .icmpPacketTooBigObserved:
            title = "ICMP packet too big"
            context = "Fragmentation needed for \(host)"
        case .icmpTimeExceededObserved:
            title = "ICMP time exceeded"
            context = "TTL or hop limit exceeded for \(host)"
        case .icmpUnreachableReportedForFlow:
            title = "ICMP unreachable reported for this session"
            context = "Unreachable message quoting this flow to \(host)"
        case .icmpPacketTooBigReportedForFlow:
            title = "ICMP path MTU limit reported for this session"
            context = "Packet too big quoting this flow to \(host)"
        case .icmpTimeExceededReportedForFlow:
            title = "ICMP time exceeded reported for this session"
            context = "Time exceeded quoting this flow to \(host)"
        }
        sessionID = finding.sessionID
        coverage = finding.coverage
        citedObservationCount = finding.citations.count
        omittedCitationCount = finding.omittedCitationCount
        citedFrames = finding.citations.map(\.provenance)
        subtitle = Self.subtitle(
            context: context,
            citedObservationCount: citedObservationCount,
            omittedCitationCount: omittedCitationCount,
            coverage: coverage
        )
    }

    init(_ finding: TLSAnalysisFinding, host: String) {
        id = finding.id
        severity = Severity(finding.severity)
        kind = .analysis(InvestigationQueryEngine.projected(finding.kind))
        let context: String
        switch finding.kind {
        case .tlsFatalAlertObserved:
            title = "TLS fatal alert observed"
            context = "Handshake or session with \(host) ended by an alert"
        case .tlsWarningAlertObserved:
            title = "TLS warning alert observed"
            context = "Alert other than an orderly close from \(host)"
        case .tlsDeprecatedVersionSelectedObserved:
            title = "Deprecated TLS version selected"
            context = "\(host) selected a version below TLS 1.2"
        case .tlsRepeatedHelloRetryRequestObserved:
            title = "TLS retry requested more than once"
            context = "More than one HelloRetryRequest from \(host)"
        case .tlsHandshakeUnansweredObserved:
            title = "TLS handshake unanswered"
            context = "ClientHello to \(host) with no reply observed"
        }
        sessionID = finding.sessionID
        coverage = finding.coverage
        citedObservationCount = finding.citations.count
        omittedCitationCount = finding.omittedCitationCount
        citedFrames = finding.citations.map(\.provenance)
        subtitle = Self.subtitle(
            context: context,
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
        let omittedLabel = omittedCitationCount == 0 ? "" : " (\(omittedCitationCount) omitted)"
        return "\(context). \(citationLabel)\(omittedLabel), \(coverage.presentationLabel)."
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
