import Foundation

// MARK: - SessionStatus

/// Health classification for a session, driving row color and the exact Errors filter.
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
    /// When the session's earliest contributing frame was captured, or `nil` when
    /// at least one contributing frame carried no capture time at all. Unknown is
    /// never spelled as an epoch, the file's open instant, or the current clock.
    var startTime: Date?
    /// Wall-clock span from the earliest to the latest contributing frame, or `nil`
    /// on the same condition as ``startTime``: a span measured over only the timed
    /// subset would silently claim the whole session.
    var duration: TimeInterval?

    /// Originating process, when known (pktap enrichment). Display only.
    var processName: String?
    /// Resolved display host (SNI / DNS name) or the responder IP.
    var host: String
    var sourceEndpoint: String
    var destinationEndpoint: String

    /// Typed source/destination endpoints projected from the same ``FiveTuple`` fold
    /// that rendered ``sourceEndpoint``/``destinationEndpoint``. These retain the exact
    /// client/server ``IPEndpoint`` (canonical IP text plus numeric port) so a typed
    /// query can parse the address through `inet_pton` rather than re-parsing display
    /// copy. Optional with a `nil` default so hand-built summaries and existing call
    /// sites need no mechanical change; the accumulator always publishes them.
    var sourceEndpointValue: IPEndpoint?
    var destinationEndpointValue: IPEndpoint?

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
    /// DNS answer-record occurrences not published because a retention cap was
    /// reached (per-packet decode cap and/or the session publication cap). This is
    /// not presented as exact unique cardinality after the retained list fills.
    var dnsAnswersOmittedCount: Int = 0

    /// Capture ordinal of the first frame folded into this session, when the fold
    /// supplied one. It is a **source-order fallback for ordering only** — never an
    /// instant, and never an input to an elapsed-time calculation.
    var firstCaptureOrdinal: UInt64?
    /// Contributing frames whose source carried no capture time. Non-zero is exactly
    /// the condition that makes ``startTime``/``duration``/``latencyMilliseconds``
    /// unknown, while every byte total and decoded fact is still retained.
    var untimedFrameCount: Int = 0

    /// Whether this session's own timing could not be established because at least
    /// one contributing frame carried no capture time.
    nonisolated var hasUnknownTiming: Bool {
        untimedFrameCount > 0 || startTime == nil
    }

    /// Whether any DNS answers were omitted from ``dnsAnswers`` due to a cap.
    nonisolated var dnsAnswersTruncated: Bool {
        dnsAnswersOmittedCount > 0
    }

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

    // MARK: Column sort keys

    /// Start instant for column sorting: unknown timing sorts after every known
    /// instant in either direction rather than being spelled as an epoch.
    nonisolated var sortableStartTime: TimeInterval {
        startTime?.timeIntervalSince1970 ?? .infinity
    }

    /// Process name for column sorting; unattributed sessions sort after named ones.
    nonisolated var sortableProcessName: String {
        processName ?? "\u{10FFFF}"
    }

    /// The innermost protocol's label, the value the Protocol column shows.
    nonisolated var primaryProtocolLabel: String {
        primaryProtocol.label
    }

    /// Status severity for column sorting: OK, then Warning, then Error.
    nonisolated var statusRank: Int {
        switch status {
        case .ok: 0
        case .warning: 1
        case .error: 2
        }
    }

    /// Whether this session carries an application-layer request/response
    /// exchange worth listing on its own — the condition for offering the
    /// Inspector's Requests facet.
    nonisolated var hasApplicationExchange: Bool {
        let applicationProtocols: Set<ProtocolKind> = [.http, .http2, .dns, .websocket, .stun]
        return protocolStack.contains(where: applicationProtocols.contains)
    }
}

// MARK: - SessionChronology

/// The single documented ordering used wherever sessions are listed in time order.
///
/// Sessions with a known start time keep their existing chronology exactly. Sessions
/// whose start time is unknown are ordered **after** every known-time session — an
/// unknown instant is not an early one — and among themselves by their capture
/// ordinal, then by id. The ordinal is a source-order fallback for ordering only; no
/// sentinel date is ever substituted, and nothing here measures elapsed time.
nonisolated enum SessionChronology {
    // MARK: Internal

    /// Oldest first.
    static func ascending(_ lhs: SessionSummary, _ rhs: SessionSummary) -> Bool {
        switch (lhs.startTime, rhs.startTime) {
        case let (left?, right?):
            if left != right {
                return left < right
            }
            return lhs.id.uuidString < rhs.id.uuidString
        case (.some, .none):
            return true
        case (.none, .some):
            return false
        case (.none, .none):
            break
        }
        return fallback(lhs, rhs)
    }

    /// Newest first — the exact reverse of ``ascending(_:_:)`` on known times, with
    /// unknown-time sessions still trailing rather than leading.
    static func descending(_ lhs: SessionSummary, _ rhs: SessionSummary) -> Bool {
        switch (lhs.startTime, rhs.startTime) {
        case let (left?, right?):
            if left != right {
                return left > right
            }
            return lhs.id.uuidString > rhs.id.uuidString
        case (.some, .none):
            return true
        case (.none, .some):
            return false
        case (.none, .none):
            break
        }
        return fallback(lhs, rhs)
    }

    // MARK: Private

    /// Deterministic fallback for absent start times: capture ordinal
    /// first (sessions that carry one precede those that do not), then id.
    private static func fallback(_ lhs: SessionSummary, _ rhs: SessionSummary) -> Bool {
        switch (lhs.firstCaptureOrdinal, rhs.firstCaptureOrdinal) {
        case let (left?, right?):
            if left != right {
                return left < right
            }
        case (.some, .none):
            return true
        case (.none, .some):
            return false
        case (.none, .none):
            break
        }
        return lhs.id.uuidString < rhs.id.uuidString
    }
}
