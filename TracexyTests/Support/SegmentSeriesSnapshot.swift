import Foundation
@testable import Tracexy

// MARK: - SegmentObservationSnapshot

/// One retained TCP segment, deterministic and cross-path comparable. Like
/// ``ProvenanceSnapshot``, it drops only the per-frame evidence locator identity — a
/// batch or live frame carries none and a saved frame carries a file-derived one, yet
/// the retained *segment* must be identical across all three paths.
struct SegmentObservationSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ observation: TCPSegmentObservation) {
        provenance = ProvenanceSnapshot(observation.provenance)
        direction = String(describing: observation.direction)
        sequenceNumber = observation.sequenceNumber
        acknowledgementNumber = observation.acknowledgementNumber
        flags = observation.flags.rawValue
        windowSize = observation.windowSize
        payloadLength = observation.payloadLength
        windowScale = observation.windowScale
    }

    // MARK: Internal

    let provenance: ProvenanceSnapshot
    let direction: String
    let sequenceNumber: UInt32
    let acknowledgementNumber: UInt32
    let flags: UInt8
    let windowSize: UInt16
    let payloadLength: Int
    let windowScale: UInt8?
}

// MARK: - SegmentSeriesSnapshot

/// A deterministic, cross-path snapshot of a whole ``TCPSegmentSeriesTable/Snapshot``:
/// every flow's retained prefix in first-seen order, its session id and canonical
/// tuple, and every bound/omission counter.
struct SegmentSeriesSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ snapshot: TCPSegmentSeriesTable.Snapshot) {
        flows = snapshot.summaries.map { summary in
            Flow(
                sessionID: summary.sessionID.uuidString,
                tuple: "\(summary.tuple.proto.rawValue)|\(summary.tuple.a.display)|\(summary.tuple.b.display)",
                observations: summary.observations.map(SegmentObservationSnapshot.init),
                omittedObservationCount: summary.omittedObservationCount,
                lossKnowledge: String(describing: summary.lossKnowledge),
                snapLengthTruncationObserved: summary.snapLengthTruncationObserved
            )
        }
        omittedObservationCount = snapshot.omittedObservationCount
        retainedObservationCount = snapshot.retainedObservationCount
        capacityReached = snapshot.capacityReached
        countersOverflowed = snapshot.countersOverflowed
    }

    // MARK: Internal

    struct Flow: Codable, Equatable {
        let sessionID: String
        let tuple: String
        let observations: [SegmentObservationSnapshot]
        let omittedObservationCount: UInt64
        let lossKnowledge: String
        let snapLengthTruncationObserved: Bool
    }

    let flows: [Flow]
    let omittedObservationCount: UInt64
    let retainedObservationCount: Int
    let capacityReached: Bool
    let countersOverflowed: Bool
}
