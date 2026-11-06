import Foundation

// MARK: - FullTCPHealthScanResult

nonisolated struct FullTCPHealthScanResult: Sendable {
    let health: SessionStreamHealth
    let segmentCount: Int
}

// MARK: - TCPHealthSourceScanError

nonisolated enum TCPHealthSourceScanError: LocalizedError, Equatable {
    case sourceUnavailable(String)
    case incompleteSource
    case incompleteSegment
    case inconsistentSession
    case noSegments
    case segmentLimit(Int)

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case let .sourceUnavailable(reason): reason
        case .incompleteSource: String(localized: "The capture ended before the conversation scan finished.")
        case .incompleteSegment: String(
                localized: "A TCP segment in this conversation lacks the facts needed for the chart."
            )
        case .inconsistentSession: String(localized: "The selected session maps to more than one TCP conversation.")
        case .noSegments: String(localized: "No decoded TCP segments for this session were found in the capture.")
        case let .segmentLimit(limit):
            String(localized: "This conversation exceeds the \(limit.formatted()) segment analysis limit.")
        }
    }
}

// MARK: - TCPHealthSourceAccumulator

/// Retains one selected conversation while scanning the source, without copying a
/// dictionary-owned prefix on each segment. Capacity failures never yield a partial
/// summary as a full-source result.
nonisolated struct TCPHealthSourceAccumulator {
    // MARK: Lifecycle

    init(sessionID: UUID, maximumSegments: Int = maximumSegments) {
        self.sessionID = sessionID
        limit = max(1, min(maximumSegments, Self.maximumSegments))
    }

    // MARK: Internal

    static let maximumSegments = 65_536

    /// The scan stops at the first rejected segment, so this is a lower bound.
    private(set) var omittedSegmentCount = 0

    mutating func offer(_ packet: DecodedPacket, provenance: SessionFrameProvenance) throws {
        if let failure {
            throw failure
        }
        guard let tuple = packet.fiveTuple, SessionBuilder.sessionID(for: tuple) == sessionID else {
            return
        }
        guard let facts = packet.tcpFacts,
              let source = packet.sourceEndpoint, let destination = packet.destinationEndpoint else
        {
            failure = .incompleteSegment
            throw TCPHealthSourceScanError.incompleteSegment
        }
        let direction: ConnectionDirection
        if source == tuple.a, destination == tuple.b {
            direction = .aToB
        } else if source == tuple.b, destination == tuple.a {
            direction = .bToA
        } else {
            failure = .incompleteSegment
            throw TCPHealthSourceScanError.incompleteSegment
        }
        if let existing = self.tuple, existing != tuple {
            failure = .inconsistentSession
            throw TCPHealthSourceScanError.inconsistentSession
        }
        guard observations.count < limit else {
            omittedSegmentCount += 1
            failure = .segmentLimit(limit)
            throw TCPHealthSourceScanError.segmentLimit(limit)
        }
        self.tuple = tuple
        snapLengthTruncationObserved = snapLengthTruncationObserved || provenance.capturedLength < provenance
            .originalLength
        observations.append(TCPSegmentObservation(
            sessionID: sessionID, tuple: tuple, direction: direction, provenance: provenance,
            sequenceNumber: facts.sequenceNumber, acknowledgementNumber: facts.acknowledgementNumber,
            flags: facts.flags, windowSize: facts.windowSize, payloadLength: facts.payloadLength,
            windowScale: facts.options.windowScale,
            sackBlocks: Array(facts.options.sackBlocks.prefix(TCPOptionFacts.maximumSACKBlockCount))
        ))
    }

    func summary() throws -> TCPSegmentSeriesSummary {
        if let failure {
            throw failure
        }
        guard let tuple, !observations.isEmpty else {
            throw TCPHealthSourceScanError.noSegments
        }
        return TCPSegmentSeriesSummary(
            sessionID: sessionID, tuple: tuple, observations: observations,
            omittedObservationCount: 0, lossKnowledge: .unknown,
            snapLengthTruncationObserved: snapLengthTruncationObserved
        )
    }

    // MARK: Private

    private let sessionID: UUID
    private let limit: Int
    private var tuple: FiveTuple?
    private var observations: [TCPSegmentObservation] = []
    private var snapLengthTruncationObserved = false
    private var failure: TCPHealthSourceScanError?
}
