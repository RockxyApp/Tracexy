import Foundation

// This file declares the only value an assistant ever sees: a pure, bounded,
// `Sendable` projection of one selected session, derived off-main from one
// immutable ``InvestigationSnapshot``.
//
// It is defined by what it *cannot* carry. There is no field for packet bytes, a
// payload body, a URL, a file path, an evidence locator, a source token, a
// database path, a capture-file identity, an independently decoded DNS/SNI
// evidence field or a credential — so a model cannot be handed one by mistake.
// The sensitive families that *can* appear (process, display host, endpoints) are gated by
// the same explicit ``AutomationDisclosure`` opt-ins the History automation
// boundary already uses, and default to off.
//
// Citations are frame-scoped identifiers, deterministic for a stable snapshot.
// The model receives an id and bounded frame facts; resolving one back to a local
// frame is the app's job, through the existing evidence-navigation coordinator.

// MARK: - AssistantBriefLimits

/// The fixed bounds on one brief. They exist so a large capture produces the same
/// shape of prompt as a small one, and so token cost is a property of the design
/// rather than of the user's traffic.
nonisolated enum AssistantBriefLimits {
    static let schemaVersion = 1
    static let maxConnections = 8
    static let maxFindings = 12
    static let maxCitationsPerFinding = 4
    static let maxCitations = 24
    static let maxProtocols = 8
    /// The hard ceiling on the serialized brief, in UTF-8 bytes. A brief that
    /// would exceed it is a construction bug, not a runtime condition — every
    /// collection above is already bounded — so the check is an assertion made
    /// visible rather than a silent truncation.
    static let maxSerializedBytes = 262_144
}

// MARK: - AssistantCitation

/// One cited local frame. It carries the frame's own bounded provenance facts and
/// **never** its locator: a `sourceToken`/offset pair identifies a capture stream,
/// and that is the app's private navigation detail, not something a model needs.
nonisolated struct AssistantCitation: Codable, Sendable, Equatable, Identifiable {
    // MARK: Lifecycle

    init(_ provenance: SessionFrameProvenance) {
        id = Self.identifier(forOrdinal: provenance.ordinal)
        frameOrdinal = provenance.ordinal.rawValue
        capturedLength = provenance.capturedLength
        originalLength = provenance.originalLength
        linkType = provenance.linkType
        capturedAt = provenance.timestamp?.timeIntervalSinceReferenceDate
        hasLocalFrame = provenance.locator != nil
    }

    // MARK: Internal

    let id: String
    let frameOrdinal: UInt64
    let capturedLength: Int
    let originalLength: Int
    let linkType: UInt32
    /// Seconds since the reference date, or `null` when the source carried no
    /// capture time. Unknown is never spelled as an epoch.
    let capturedAt: Double?
    /// Whether the app can navigate to this exact frame. `false` means the
    /// observation has no navigable local frame — it is not a claim about the
    /// frame's existence.
    let hasLocalFrame: Bool

    /// The stable citation id. One capture-local frame is one citation, so the
    /// same frame cited by two findings is the same id — and the id depends on
    /// nothing but the ordinal, so it is identical across snapshots of a stable
    /// capture.
    static func identifier(forOrdinal ordinal: FrameOrdinal) -> String {
        "frame-\(ordinal.rawValue)"
    }
}

// MARK: - AssistantFinding

/// One evidence-linked finding, reduced to its stable identity, fixed severity,
/// scope coverage and citation ids.
nonisolated struct AssistantFinding: Codable, Sendable, Equatable {
    let id: String
    /// The assessor's own stable discriminator — an internal token, never UI copy.
    let kind: String
    let severity: String
    let coverage: String
    let citationIDs: [String]
    /// Citations the assessor dropped to honor its own per-finding bound.
    let omittedCitationCount: UInt64
    /// Citations this brief dropped to honor ``AssistantBriefLimits``.
    let briefOmittedCitationCount: Int
}

// MARK: - AssistantConnectionFacts

/// One retained TCP connection incarnation for the selected session. Every value
/// is an observed count, phase or flag — never an interpretation.
nonisolated struct AssistantConnectionFacts: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(_ summary: ConnectionSummary) {
        id = summary.id.rawValue.uuidString
        phase = Self.name(for: summary.phase)
        handshake = Self.name(for: summary.handshake)
        closeReason = Self.name(for: summary.closeReason)
        packetCount = summary.packetCount
        capturedByteTotal = summary.capturedByteTotal
        originalByteTotal = summary.originalByteTotal
        lossKnowledge = Self.name(for: summary.lossKnowledge)
        limitations = Self.names(for: summary.limitations)
        retainedEventCount = summary.events.count
        omittedEventCount = summary.omittedEventCount
    }

    // MARK: Internal

    let id: String
    let phase: String
    let handshake: String
    /// `null` when the connection has not been observed to close.
    let closeReason: String?
    let packetCount: UInt64
    let capturedByteTotal: UInt64
    let originalByteTotal: UInt64
    let lossKnowledge: String
    /// The observed limitation flags by name, sorted. Each records that something
    /// was *seen*, never why.
    let limitations: [String]
    let retainedEventCount: Int
    let omittedEventCount: UInt64

    // MARK: Private

    private static func name(for phase: ConnectionPhase) -> String {
        switch phase {
        case .opening: "opening"
        case .active: "active"
        case .closing: "closing"
        case .closed: "closed"
        }
    }

    private static func name(for handshake: HandshakeObservation) -> String {
        switch handshake {
        case .none: "none"
        case .synObserved: "synObserved"
        case .synAckObserved: "synAckObserved"
        case .threeWayObserved: "threeWayObserved"
        }
    }

    private static func name(for reason: ConnectionCloseReason?) -> String? {
        switch reason {
        case .none: nil
        case .orderly: "orderly"
        // The reset direction is deliberately dropped: it names a canonical
        // endpoint, which belongs to the endpoint disclosure family.
        case .reset: "reset"
        case .stateEviction: "stateEviction"
        }
    }

    private static func name(for knowledge: CaptureLossKnowledge) -> String {
        switch knowledge {
        case .unknown: "unknown"
        case .noLossReported: "noLossReported"
        case .lossReported: "lossReported"
        }
    }

    private static func names(for limitations: ConnectionLimitations) -> [String] {
        let mapping: [(ConnectionLimitations, String)] = [
            (.startUnobserved, "startUnobserved"),
            (.handshakeIncomplete, "handshakeIncomplete"),
            (.payloadTruncated, "payloadTruncated"),
            (.ambiguousTupleReuse, "ambiguousTupleReuse"),
            (.priorStateEvicted, "priorStateEvicted"),
            (.eventHistoryTruncated, "eventHistoryTruncated"),
            (.counterOverflow, "counterOverflow"),
            (.sequenceGapObserved, "sequenceGapObserved"),
            (.serialDistanceAmbiguous, "serialDistanceAmbiguous"),
        ]
        return mapping.filter { limitations.contains($0.0) }.map(\.1).sorted()
    }
}

// MARK: - AssistantTLSFacts

/// The retained, tuple-scoped TLS record evidence for the selected session. It is
/// observation-only: no version judgement, no certificate, no server name.
nonisolated struct AssistantTLSFacts: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(_ summary: TLSEvidenceSummary) {
        retainedObservationCount = summary.observations.count
        omittedObservationCount = summary.omittedObservationCount
        excludedReassembledRecordCount = summary.excludedReassembledRecordCount
        recoveredTruncationIndicatorCount = summary.recoveredTruncationIndicatorCount
        decoderTruncatedFrameCount = summary.decoderTruncatedFrameCount
        snapLengthTruncationObserved = summary.snapLengthTruncationObserved
    }

    // MARK: Internal

    let retainedObservationCount: Int
    let omittedObservationCount: UInt64
    let excludedReassembledRecordCount: UInt64
    let recoveredTruncationIndicatorCount: UInt64
    let decoderTruncatedFrameCount: UInt64
    let snapLengthTruncationObserved: Bool
}

// MARK: - AssistantSessionFacts

/// The selected session's own bounded facts, gated by the disclosure opt-ins.
///
/// Timing is disclosed (an unknown span is an explicit `null`, never a zero);
/// process, host and endpoints appear only when their family is opted in, and are
/// absent by construction otherwise.
nonisolated struct AssistantSessionFacts: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(_ session: SessionSummary, disclosure: AutomationDisclosure) {
        protocols = session.protocolStack.prefix(AssistantBriefLimits.maxProtocols).map(\.rawValue)
        status = session.status.rawValue
        startTime = session.startTime?.timeIntervalSinceReferenceDate
        duration = session.duration
        latencyMilliseconds = session.latencyMilliseconds
        bytesUp = session.bytesUp
        bytesDown = session.bytesDown
        untimedFrameCount = session.untimedFrameCount
        hasUnknownTiming = session.hasUnknownTiming
        processName = disclosure.includesProcess ? session.processName : nil
        host = disclosure.includesHost ? session.host : nil
        sourceEndpoint = disclosure.includesEndpoints ? session.sourceEndpoint : nil
        destinationEndpoint = disclosure.includesEndpoints ? session.destinationEndpoint : nil
    }

    // MARK: Internal

    let protocols: [String]
    let status: String
    let startTime: Double?
    let duration: Double?
    let latencyMilliseconds: Double?
    let bytesUp: Int
    let bytesDown: Int
    let untimedFrameCount: Int
    let hasUnknownTiming: Bool
    let processName: String?
    let host: String?
    let sourceEndpoint: String?
    let destinationEndpoint: String?

    /// Explicit encoding for the same reason ``AutomationSessionValue`` has one:
    /// timing is disclosed and therefore always present (with `null` for unknown),
    /// while every privacy-gated key is omitted entirely when its family is off.
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(protocols, forKey: .protocols)
        try container.encode(status, forKey: .status)
        try container.encode(startTime, forKey: .startTime)
        try container.encode(duration, forKey: .duration)
        try container.encodeIfPresent(latencyMilliseconds, forKey: .latencyMilliseconds)
        try container.encode(bytesUp, forKey: .bytesUp)
        try container.encode(bytesDown, forKey: .bytesDown)
        try container.encode(untimedFrameCount, forKey: .untimedFrameCount)
        try container.encode(hasUnknownTiming, forKey: .hasUnknownTiming)
        try container.encodeIfPresent(processName, forKey: .processName)
        try container.encodeIfPresent(host, forKey: .host)
        try container.encodeIfPresent(sourceEndpoint, forKey: .sourceEndpoint)
        try container.encodeIfPresent(destinationEndpoint, forKey: .destinationEndpoint)
    }
}

// MARK: - AssistantCoverage

/// The capture-level coverage a reader must apply to everything above. These are
/// *global* facts about the capture, never proof about this one session, and they
/// are always present so absence can never be read as completeness.
nonisolated struct AssistantCoverage: Codable, Sendable, Equatable {
    let connectionOmittedSummaryCount: UInt64
    let connectionPublishedSummaryCount: Int
    let connectionRetainedEventCount: Int
    let connectionCountersOverflowed: Bool
    let tlsOmittedObservationCount: UInt64
    let tlsRetainedObservationCount: Int
    let tlsCapacityReached: Bool
    let tlsCountersOverflowed: Bool
    let connectionFindingsOmittedCount: UInt64
    let datagramFindingsOmittedCount: UInt64
    /// Connection incarnations this brief dropped to honor its own bound.
    let briefOmittedConnectionCount: Int
    /// Findings this brief dropped to honor its own bound.
    let briefOmittedFindingCount: Int
    /// Citations this brief dropped to honor its own global bound.
    let briefOmittedCitationCount: Int
}

// MARK: - AssistantRedaction

/// The exact disclosure decision behind one brief, plus the closed list of
/// families that are never included at any setting. It is carried *in* the brief
/// so the Review Data sheet and the model see the same statement.
nonisolated struct AssistantRedaction: Codable, Sendable, Equatable {
    // MARK: Lifecycle

    init(disclosure: AutomationDisclosure) {
        includesProcess = disclosure.includesProcess
        includesHost = disclosure.includesHost
        includesEndpoints = disclosure.includesEndpoints
        neverIncluded = Self.neverIncludedFamilies
    }

    // MARK: Internal

    /// The families no setting can turn on. This is the honest half of the
    /// redaction statement: what is structurally impossible here, not merely off.
    static let neverIncludedFamilies = [
        "captureFileIdentity",
        "certificates",
        "credentials",
        "databasePaths",
        "evidenceLocators",
        "filePaths",
        "packetBytes",
        "payloadBodies",
        "sourceTokens",
        "urls",
    ]

    let includesProcess: Bool
    let includesHost: Bool
    let includesEndpoints: Bool
    let neverIncluded: [String]
}

// MARK: - AssistantEvidenceBrief

/// The complete bounded brief for exactly one selected session.
nonisolated struct AssistantEvidenceBrief: Codable, Sendable, Equatable {
    let schemaVersion: Int
    let projectID: String
    let sessionID: String
    let session: AssistantSessionFacts
    let connections: [AssistantConnectionFacts]
    let tls: AssistantTLSFacts?
    let findings: [AssistantFinding]
    let citations: [AssistantCitation]
    let coverage: AssistantCoverage
    let redaction: AssistantRedaction

    /// The deterministic JSON a user reviews and a model receives. Sorted keys and
    /// unescaped slashes make it byte-stable for a stable snapshot, so the text in
    /// the Review Data sheet is exactly the text that is sent.
    func canonicalJSON() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        guard data.count <= AssistantBriefLimits.maxSerializedBytes,
              let text = String(data: data, encoding: .utf8) else
        {
            throw AssistantBriefError.oversizedBrief(byteCount: data.count)
        }
        return text
    }
}

// MARK: - AssistantBriefError

nonisolated enum AssistantBriefError: Error, Sendable, Equatable {
    /// The bounded brief still serialized past ``AssistantBriefLimits/maxSerializedBytes``.
    case oversizedBrief(byteCount: Int)
    /// The requested session is not present in the snapshot being read.
    case sessionNotFound
}
