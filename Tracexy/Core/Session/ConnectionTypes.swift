import Foundation

// This file declares the frozen, pure value types for passive TCP connection
// identity and lifecycle. Everything here is observation-only: it records what
// ordered frames prove, never what a live socket "is". No type stores raw bytes,
// URLs, file identity, findings, severities, or a loss *cause* claim — those
// belong to other layers. Nothing here reads a wall clock; the sole source of
// state is the ordered fold in `ConnectionTable`.

// MARK: - FrameOrdinal

/// A capture-local monotonic position for a frame. Ordering frames by this value
/// defines identity/order. Capture timestamps remain descriptive activity facts
/// and drive deterministic LRU selection, never connection identity.
nonisolated struct FrameOrdinal: RawRepresentable, Hashable, Comparable, Sendable {
    // MARK: Lifecycle

    init(_ rawValue: UInt64) {
        self.rawValue = rawValue
    }

    init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    // MARK: Internal

    let rawValue: UInt64

    static func < (lhs: FrameOrdinal, rhs: FrameOrdinal) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

// MARK: - SessionEvidenceLocator

/// An opaque, capture-local pointer back to the bytes that justify an
/// observation. It is deliberately just a `sourceToken` (identifying *which*
/// capture stream, without exposing a URL or file identity) plus a payload
/// `offset`. It stores no bytes and no path — a consumer that holds the same
/// capture-local source can resolve it; nothing here leaks capture contents.
nonisolated struct SessionEvidenceLocator: Hashable, Sendable {
    let sourceToken: UUID
    let offset: UInt64
}

// MARK: - SessionFrameProvenance

/// Everything the fold is allowed to know about one frame: where it sits in the
/// capture (`ordinal`), when it was seen (`timestamp`), how many bytes were
/// captured vs. originally on the wire, the link type, and an optional locator.
///
/// The initializer *normalizes* rather than rejects: a negative captured or
/// original length becomes zero, and `originalLength` is raised to at least
/// `capturedLength` (the original frame can never be shorter than what we
/// captured of it). This choice is pinned by tests.
nonisolated struct SessionFrameProvenance: Hashable, Sendable {
    // MARK: Lifecycle

    init(
        ordinal: FrameOrdinal,
        timestamp: Date,
        capturedLength: Int,
        originalLength: Int,
        linkType: UInt32,
        locator: SessionEvidenceLocator? = nil
    ) {
        self.ordinal = ordinal
        self.timestamp = timestamp
        let captured = max(0, capturedLength)
        self.capturedLength = captured
        self.originalLength = max(captured, originalLength)
        self.linkType = linkType
        self.locator = locator
    }

    // MARK: Internal

    let ordinal: FrameOrdinal
    let timestamp: Date
    let capturedLength: Int
    let originalLength: Int
    let linkType: UInt32
    let locator: SessionEvidenceLocator?
}

// MARK: - ConnectionDirection

/// Which canonical direction a frame travels, derived *only* by comparing the
/// packet source against the canonical `FiveTuple` endpoints. `aToB` is "from
/// the canonically-smaller endpoint"; `bToA` is the reverse. Neither side is
/// ever called client or server — that is an interpretation the passive fold
/// does not make.
nonisolated enum ConnectionDirection: Hashable, Sendable {
    case aToB
    case bToA

    // MARK: Internal

    var opposite: ConnectionDirection {
        self == .aToB ? .bToA : .aToB
    }
}

// MARK: - ConnectionID

/// A deterministic identity for one observed connection: the canonical tuple
/// plus the ordinal of the first frame that opened it. Reusing the shared
/// `SessionBuilder.stableID` primitive keeps the derivation in one place; the
/// `connection|…|firstOrdinal` seed is disjoint from the tuple-only session id
/// seed, so this never changes or collides with existing session ids.
nonisolated struct ConnectionID: Hashable, Sendable {
    // MARK: Lifecycle

    init(tuple: FiveTuple, firstOrdinal: FrameOrdinal) {
        rawValue = SessionBuilder.stableID(
            "connection|\(tuple.proto.rawValue)|\(tuple.a.display)|\(tuple.b.display)|\(firstOrdinal.rawValue)"
        )
    }

    // MARK: Internal

    let rawValue: UUID
}

// MARK: - ConnectionPhase

/// The passively-observed lifecycle phase. `opening` means we have seen setup
/// but not yet data flow or completion; `active` means data or a completed
/// handshake; `closing` means one FIN direction; `closed` is terminal.
nonisolated enum ConnectionPhase: Hashable, Sendable {
    case opening
    case active
    case closing
    case closed
}

// MARK: - HandshakeObservation

/// How much of the three-way handshake was observed. `synAckObserved` may be the
/// first captured setup frame and therefore does not alone prove an initiator;
/// `threeWayObserved` requires the full SYN/SYN+ACK/final-ACK sequence and validates
/// both acknowledgement numbers against the observed initial sequence numbers.
nonisolated enum HandshakeObservation: Hashable, Sendable {
    case none
    case synObserved
    case synAckObserved
    case threeWayObserved
}

// MARK: - FINDirection

/// The set of directions in which a FIN was observed. Both directions present
/// means an orderly close was observed end to end.
nonisolated struct FINDirection: OptionSet, Hashable, Sendable {
    static let aToB = FINDirection(rawValue: 1 << 0)
    static let bToA = FINDirection(rawValue: 1 << 1)

    let rawValue: UInt8
}

// MARK: - ConnectionCloseReason

/// Why a connection reached `closed`, as observed: an orderly bidirectional FIN,
/// a reset carrying its direction, or eviction of live state under a bound.
nonisolated enum ConnectionCloseReason: Hashable, Sendable {
    case orderly
    case reset(ConnectionDirection)
    case stateEviction
}

// MARK: - CaptureLossKnowledge

/// What we know about capture completeness for a connection's frames. The merge
/// is sticky and monotonic — `lossReported` is strongest and never downgrades —
/// and `noLossReported` is explicitly *not* a completeness guarantee, only the
/// absence of a report.
nonisolated enum CaptureLossKnowledge: Hashable, Sendable {
    case unknown
    case noLossReported
    case lossReported

    // MARK: Internal

    /// Sticky merge: the stronger of the two wins, so knowledge only ever
    /// strengthens across an ordered fold.
    func merged(with other: CaptureLossKnowledge) -> CaptureLossKnowledge {
        rank >= other.rank ? self : other
    }

    // MARK: Private

    private var rank: Int {
        switch self {
        case .unknown: 0
        case .noLossReported: 1
        case .lossReported: 2
        }
    }
}

// MARK: - ConnectionLimitations

/// Caveats about how faithfully this connection could be reconstructed from the
/// frames we saw. Bits 0–6 are the passive-lifecycle limitations. Bits 8+ carry
/// the sequence-analysis limitations (N2B2) and are numbered disjointly so those
/// additions never renumber the lifecycle bits.
nonisolated struct ConnectionLimitations: OptionSet, Hashable, Sendable {
    /// The connection's opening was not observed (capture began midstream, or a
    /// SYN+ACK arrived with no prior SYN).
    static let startUnobserved = ConnectionLimitations(rawValue: 1 << 0)
    /// The three-way handshake was not fully observed/validated.
    static let handshakeIncomplete = ConnectionLimitations(rawValue: 1 << 1)
    /// At least one attached frame was captured shorter than its wire length.
    static let payloadTruncated = ConnectionLimitations(rawValue: 1 << 2)
    /// Tuple reuse was observed that could not be split into a distinct id (a
    /// conflicting SYN before an observed terminal).
    static let ambiguousTupleReuse = ConnectionLimitations(rawValue: 1 << 3)
    /// This connection began after prior state for its tuple was evicted.
    static let priorStateEvicted = ConnectionLimitations(rawValue: 1 << 4)
    /// Older events were dropped to honor an event bound.
    static let eventHistoryTruncated = ConnectionLimitations(rawValue: 1 << 5)
    /// An integer total saturated at its maximum.
    static let counterOverflow = ConnectionLimitations(rawValue: 1 << 6)

    // Bits 1 << 8 and above are the N2B2 sequence-analysis limitations. They are
    // observation-only and sticky: each records that an ordered discontinuity was
    // *seen*, never why it happened, and once set is never cleared by later frames.

    /// A discontinuity was observed in one direction's sequence space (a segment
    /// buffered ahead of the expected sequence, or a pending interval discarded
    /// under the per-direction bound). It records only the observed gap, never its
    /// cause, and draining the gap does not erase this historical fact.
    static let sequenceGapObserved = ConnectionLimitations(rawValue: 1 << 8)
    /// At least one segment's serial distance could not be resolved as ahead or
    /// behind (an exact half-space distance, or a length outside the serial
    /// window), so its ordering was left unclassified.
    static let serialDistanceAmbiguous = ConnectionLimitations(rawValue: 1 << 9)
    /// Per-direction ordering state could not be kept faithfully: a buffered
    /// interval was dropped to honor the pending bound, or a late frame arrived
    /// after the connection's working state (and its trackers) had been released.
    static let sequenceStateTruncated = ConnectionLimitations(rawValue: 1 << 10)
    /// The bounded first-record application probe overflowed its byte/fragment
    /// bound (or saw an oversized single segment) in one direction, so its
    /// application bytes were dropped and first-record recovery permanently
    /// disabled for that direction. It is disjoint from the sequence-analysis bits:
    /// sequence observation is unaffected, and its absence is not proof of a
    /// complete application capture.
    static let applicationProbeTruncated = ConnectionLimitations(rawValue: 1 << 11)

    let rawValue: UInt32
}

// MARK: - ConnectionEventKind

/// The kind of passively-observed lifecycle or sequence event. No kind carries
/// raw bytes, a URL, a finding, a severity, or a loss-cause claim — those are out
/// of scope for this layer. The sequence kinds (bottom group) are additional typed
/// evidence emitted alongside the lifecycle kinds from the per-direction
/// `TCPSequenceTracker` fold; they describe a segment's ordering, never a stream.
nonisolated enum ConnectionEventKind: Hashable, Sendable {
    case firstObserved
    case syn
    case synAck
    case handshakeCompleted
    case payloadObserved
    case fin
    case rst
    case lateSegmentAfterClose
    case ambiguousTupleReuse
    case stateEvicted

    // Sequence-observation kinds (N2B2). Each is the direction tracker's verdict
    // on one segment's sequence space; a pure ACK / zero-sequence-space segment
    // emits none of these.

    /// The segment anchored or contiguously advanced its direction's expected
    /// sequence (tracker `initialized` or `advanced`).
    case sequenceAdvanced
    /// The segment carried no new sequence space at or behind the expected
    /// sequence — a retransmission or pure duplicate (tracker `duplicate`).
    case retransmission
    /// The segment straddled the expected sequence: part already seen, part new
    /// (tracker `overlap`).
    case overlap
    /// The segment began ahead of the expected sequence and was buffered as a
    /// pending interval (tracker `outOfOrderBuffered`).
    case outOfOrderBuffered
    /// An advance connected one or more buffered intervals (tracker
    /// `pendingDrained`).
    case pendingDrained
    /// Buffering the segment exceeded the per-direction pending bound and the
    /// farthest interval was discarded (tracker `pendingOverflow`).
    case pendingOverflow
    /// The segment's serial distance was irreducible and its ordering was left
    /// unchanged (tracker `serialAmbiguous`).
    case serialAmbiguous

    // Application-probe kinds (N2D2). These are the only additive evidence the
    // bounded first-record probe contributes to a connection; neither carries raw
    // bytes, SNI, DNS names/answers or decoded layers.

    /// Application metadata first became available for a direction: the bounded
    /// first-record probe classified the direction's opening TLS/HTTP/DNS record.
    /// The event carries only the typed `applicationKind` and whether that first
    /// observation was already complete (`applicationComplete`). Emitted at most
    /// once per direction; later richer handoffs update session evidence silently.
    case applicationRecord
    /// The bounded first-record probe overflowed its byte/fragment bound in a
    /// direction; its application bytes were dropped and recovery disabled. Pairs
    /// with the sticky `applicationProbeTruncated` limitation.
    case applicationProbeTruncated
}

// MARK: - ConnectionEvent

/// One lifecycle observation, citing between one and three frames of evidence.
/// Only `handshakeCompleted` cites three (SYN, SYN+ACK, final ACK); every other
/// kind cites the single frame that triggered it. The initializer clamps the
/// evidence to at most three so the bound holds by construction.
nonisolated struct ConnectionEvent: Hashable, Sendable {
    // MARK: Lifecycle

    init(
        connectionID: ConnectionID,
        kind: ConnectionEventKind,
        timestamp: Date,
        provenance: SessionFrameProvenance,
        relatedProvenance: [SessionFrameProvenance] = [],
        direction: ConnectionDirection? = nil,
        facts: TCPSegmentFacts? = nil,
        applicationKind: ProtocolKind? = nil,
        applicationComplete: Bool? = nil
    ) {
        self.connectionID = connectionID
        self.kind = kind
        self.timestamp = timestamp
        self.provenance = [provenance] + Array(relatedProvenance.prefix(2))
        self.direction = direction
        sequenceNumber = facts?.sequenceNumber
        acknowledgementNumber = facts?.acknowledgementNumber
        payloadLength = facts?.payloadLength ?? 0
        self.applicationKind = applicationKind
        self.applicationComplete = applicationComplete
    }

    // MARK: Internal

    let connectionID: ConnectionID
    let kind: ConnectionEventKind
    let timestamp: Date
    /// One to three frames of evidence, never more.
    let provenance: [SessionFrameProvenance]
    /// Canonical direction of the triggering segment. `nil` only for a synthetic
    /// state-eviction observation.
    let direction: ConnectionDirection?
    /// Typed triggering-segment facts needed by downstream passive analysis.
    let sequenceNumber: UInt32?
    let acknowledgementNumber: UInt32?
    let payloadLength: Int
    /// The classified application protocol, set only on `.applicationRecord`. It is
    /// the sole application datum an event carries — never SNI, DNS names/answers,
    /// raw layers or bytes.
    let applicationKind: ProtocolKind?
    /// Whether the first application observation was already complete, set only on
    /// `.applicationRecord`. `nil` on every other kind.
    let applicationComplete: Bool?

    /// The frame ordinal at which this event "occurred" — the latest cited
    /// ordinal, i.e. the frame that completed it. Used to drop the globally
    /// oldest event deterministically under the total-event bound.
    var occurrenceOrdinal: FrameOrdinal {
        provenance.map(\.ordinal).max() ?? FrameOrdinal(0)
    }
}

// MARK: - ConnectionSummary

/// The immutable published view of one observed connection. It reports only what
/// ordered frames proved: identity, first/last evidence, an optional observed
/// initiator direction, the passive phase/handshake/FIN/close state, counts and
/// byte totals, capture-loss knowledge, reconstruction limitations, and a
/// bounded event list with a count of events omitted to honor the bounds.
nonisolated struct ConnectionSummary: Hashable, Sendable {
    let id: ConnectionID
    let tuple: FiveTuple
    let firstProvenance: SessionFrameProvenance
    var lastProvenance: SessionFrameProvenance
    let initiator: ConnectionDirection?
    let phase: ConnectionPhase
    let handshake: HandshakeObservation
    let finDirections: FINDirection
    let closeReason: ConnectionCloseReason?
    var packetCount: UInt64
    var capturedByteTotal: UInt64
    var originalByteTotal: UInt64
    var lossKnowledge: CaptureLossKnowledge
    var limitations: ConnectionLimitations
    var events: [ConnectionEvent]
    var omittedEventCount: UInt64

    var isTerminal: Bool {
        phase == .closed
    }
}
