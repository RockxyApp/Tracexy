import Foundation

// MARK: - SessionStatus

/// Health classification for a session, driving color + the Security view.
nonisolated enum SessionStatus: String, CaseIterable, Hashable {
    case ok
    case warning
    case error

    // MARK: Internal

    nonisolated var label: String {
        switch self {
        case .ok: "OK"
        case .warning: "Warning"
        case .error: "Error"
        }
    }

    /// Real SF Symbol (never a colored dot — see design system). Mirrors
    /// `Finding.Severity.systemImage` so the two severity scales read alike.
    nonisolated var systemImage: String {
        switch self {
        case .ok: "checkmark.circle"
        case .warning: "exclamationmark.triangle"
        case .error: "xmark.octagon"
        }
    }
}

// MARK: - SessionSummary

/// One network conversation as shown in the timeline / session list.
nonisolated struct SessionSummary: Identifiable, Hashable, Sendable {
    let id: UUID
    var startTime: Date
    var duration: TimeInterval

    /// Originating process, when known (pktap enrichment). Display only.
    var processName: String?
    /// Resolved display host (SNI / DNS name) or the responder IP.
    var host: String
    var sourceEndpoint: String
    var destinationEndpoint: String

    /// The decoded stack, outer→inner, e.g. [.tcp, .tls, .http2].
    var protocolStack: [ProtocolKind]
    var status: SessionStatus

    /// Most salient latency for this session (handshake / TTFB), if measured.
    var latencyMilliseconds: Double?
    var bytesUp: Int
    var bytesDown: Int

    /// Real decode of the representative packet — drives the Inspector's Layers
    /// and Decoded tabs (no placeholder data).
    var decodedLayers: [DecodedLayer] = []
    /// Captured on-wire bytes of the representative packet, for the hex pane.
    var representativeBytes: [UInt8] = []
    var sni: String?
    var dnsQuery: String?
    var dnsAnswers: [String] = []

    /// The innermost (most specific) protocol — used for sidebar bucketing.
    nonisolated var primaryProtocol: ProtocolKind {
        protocolStack.last ?? .other
    }

    /// A concise, human-readable "info" line for the session list's Summary
    /// column (Wireshark-style), derived from the real decode — never a placeholder.
    nonisolated var infoSummary: String {
        if let dnsQuery, !dnsQuery.isEmpty {
            if let answer = dnsAnswers.first {
                return "DNS \(dnsQuery) → \(answer)"
            }
            return "DNS query \(dnsQuery)"
        }
        if let sni, !sni.isEmpty {
            return "\(primaryProtocol.label) · \(sni)"
        }
        if let last = decodedLayers.last(where: { !$0.summary.isEmpty }) {
            return last.summary
        }
        return protocolStack.map(\.label).joined(separator: " · ")
    }

    nonisolated var totalBytes: Int {
        bytesUp + bytesDown
    }

    /// Whether this session carries an application-layer request/response
    /// exchange worth listing on its own — the condition for offering the
    /// Inspector's Requests facet.
    nonisolated var hasApplicationExchange: Bool {
        let applicationProtocols: Set<ProtocolKind> = [.http, .http2, .dns, .websocket]
        return protocolStack.contains(where: applicationProtocols.contains)
    }
}
