import Foundation
@testable import Tracexy

// MARK: - ProvenanceSnapshot

/// One frame's provenance, deterministic and cross-path comparable.
///
/// The optional evidence *locator* — its source-token identity and payload offset —
/// is the single field deliberately excluded: a batch or live frame carries none,
/// a saved frame carries a file-derived one, yet the connection *semantics* must
/// match across all paths. Every other provenance field (ordinal, instant,
/// captured/original length, link type) is preserved, so any drift there fails.
struct ProvenanceSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ provenance: SessionFrameProvenance) {
        ordinal = provenance.ordinal.rawValue
        timestampMicros = Int64((provenance.timestamp.timeIntervalSince1970 * 1_000_000).rounded())
        capturedLength = provenance.capturedLength
        originalLength = provenance.originalLength
        linkType = provenance.linkType
    }

    // MARK: Internal

    let ordinal: UInt64
    let timestampMicros: Int64
    let capturedLength: Int
    let originalLength: Int
    let linkType: UInt32
}

// MARK: - ConnectionEventSnapshot

/// One connection event, preserving its kind, citations, direction and typed
/// segment facts. Each cited provenance drops only its locator (see
/// ``ProvenanceSnapshot``).
struct ConnectionEventSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ event: ConnectionEvent) {
        kind = String(describing: event.kind)
        timestampMicros = Int64((event.timestamp.timeIntervalSince1970 * 1_000_000).rounded())
        provenance = event.provenance.map(ProvenanceSnapshot.init)
        direction = event.direction.map { String(describing: $0) }
        sequenceNumber = event.sequenceNumber
        acknowledgementNumber = event.acknowledgementNumber
        payloadLength = event.payloadLength
        applicationKind = event.applicationKind?.rawValue
        applicationComplete = event.applicationComplete
    }

    // MARK: Internal

    let kind: String
    let timestampMicros: Int64
    let provenance: [ProvenanceSnapshot]
    let direction: String?
    let sequenceNumber: UInt32?
    let acknowledgementNumber: UInt32?
    let payloadLength: Int
    /// The typed application protocol on an `.applicationRecord` event (`nil`
    /// otherwise). This plus `applicationComplete` are the only application data an
    /// event snapshot carries — never SNI, DNS names/answers, layers or bytes.
    let applicationKind: String?
    /// Whether the first application observation was complete on an
    /// `.applicationRecord` event (`nil` otherwise).
    let applicationComplete: Bool?
}

// MARK: - ConnectionSnapshot

/// A deterministic, cross-path snapshot of one ``ConnectionSummary``.
///
/// It preserves the connection id, canonical tuple, first/last provenance,
/// observed initiator, lifecycle phase/handshake/FIN/close state, packet and byte
/// totals, capture-loss knowledge, reconstruction limitations, every typed event,
/// and the omitted-event counter. Only the per-frame evidence locator identity is
/// excluded, so batch, live and saved folds of the same frames compare equal.
struct ConnectionSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ summary: ConnectionSummary) {
        id = summary.id.rawValue.uuidString
        tuple = "\(summary.tuple.proto.rawValue)|\(summary.tuple.a.display)|\(summary.tuple.b.display)"
        firstProvenance = ProvenanceSnapshot(summary.firstProvenance)
        lastProvenance = ProvenanceSnapshot(summary.lastProvenance)
        initiator = summary.initiator.map { String(describing: $0) }
        phase = String(describing: summary.phase)
        handshake = String(describing: summary.handshake)
        finDirections = summary.finDirections.rawValue
        closeReason = summary.closeReason.map { String(describing: $0) }
        packetCount = summary.packetCount
        capturedByteTotal = summary.capturedByteTotal
        originalByteTotal = summary.originalByteTotal
        lossKnowledge = String(describing: summary.lossKnowledge)
        limitations = summary.limitations.rawValue
        events = summary.events.map(ConnectionEventSnapshot.init)
        omittedEventCount = summary.omittedEventCount
    }

    // MARK: Internal

    let id: String
    let tuple: String
    let firstProvenance: ProvenanceSnapshot
    let lastProvenance: ProvenanceSnapshot
    let initiator: String?
    let phase: String
    let handshake: String
    let finDirections: UInt8
    let closeReason: String?
    let packetCount: UInt64
    let capturedByteTotal: UInt64
    let originalByteTotal: UInt64
    let lossKnowledge: String
    let limitations: UInt32
    let events: [ConnectionEventSnapshot]
    let omittedEventCount: UInt64
}

// MARK: - ConnectionTableSnapshot

/// A deterministic, cross-path snapshot of a whole ``ConnectionTable/Snapshot``,
/// used to assert batch == live == saved connection semantics. It preserves every
/// summary in snapshot order plus every bound/omission counter, and (like
/// ``ProvenanceSnapshot``) excludes only the per-frame evidence locator identity.
struct ConnectionTableSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ snapshot: ConnectionTable.Snapshot) {
        summaries = snapshot.summaries.map(ConnectionSnapshot.init)
        omittedSummaryCount = snapshot.omittedSummaryCount
        activeConnectionCount = snapshot.activeConnectionCount
        publishedSummaryCount = snapshot.publishedSummaryCount
        retainedEventCount = snapshot.retainedEventCount
        countersOverflowed = snapshot.countersOverflowed
    }

    // MARK: Internal

    let summaries: [ConnectionSnapshot]
    let omittedSummaryCount: UInt64
    let activeConnectionCount: Int
    let publishedSummaryCount: Int
    let retainedEventCount: Int
    let countersOverflowed: Bool
}
