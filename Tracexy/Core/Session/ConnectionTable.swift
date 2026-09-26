import Foundation

// MARK: - ConnectionTable

/// A pure, bounded, passive fold from ordered decoded TCP frames to observed
/// connection identities and lifecycles.
///
/// The only source of state change is `ingest`, applied in capture order. No
/// wall clock, timer, or background work mutates anything — replaying the same
/// ordered frames through the same configuration always yields the same
/// `Snapshot`. Every retained collection has a named configuration bound, and
/// every drop is accounted for (event omission counts, summary omission count),
/// so nothing is silently lost.
///
/// This layer is observation-only. It records what the frames prove — it never
/// retains a full stream, produces findings, or reaches the UI. Each connection
/// folds every typed TCP segment once through one of two per-direction
/// `TCPSequenceTracker`s, emitting additional typed sequence events
/// (advance/retransmission/overlap/out-of-order/keep-alive) alongside the lifecycle
/// events; those trackers hold only sequence coordinates, never bytes. One
/// connection-wide `TCPFlowControlTracker` then classifies the same segment's
/// acknowledgement/window shape (duplicate ACK, zero window, zero-window probe,
/// window full) into further typed events from a few per-direction scalars.
///
/// Each connection also owns two per-direction `TCPApplicationPrefixProbe`s:
/// a bounded, first-record byte reassembler in `payloadSequence` coordinates that
/// recovers the direction's opening TLS/HTTP/DNS metadata, hands it back as a
/// transient `ingest` result, and appends a bounded typed `.applicationRecord`
/// event (or `.applicationProbeTruncated` on overflow). The probe carries no raw
/// bytes/SNI/DNS/URL into snapshots or events and can never mutate connection
/// lifecycle. Both trackers and probes are released with the connection's working
/// state on publish/eviction/reset.
nonisolated struct ConnectionTable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable bounds. Every value is clamped to at least one so no bound can
    /// disable a collection entirely; test configurations may be tiny.
    nonisolated struct Configuration: Hashable, Sendable {
        // MARK: Lifecycle

        init(
            maxActiveConnections: Int = 16_384,
            maxEventsPerConnection: Int = 256,
            maxTotalEvents: Int = 131_072,
            maxPublishedSummaries: Int = 50_000,
            maxPendingSegmentsPerDirection: Int = 32,
            maxApplicationPrefixBytes: Int = 16_384,
            maxApplicationFragmentsPerDirection: Int = 32
        ) {
            self.maxActiveConnections = max(1, maxActiveConnections)
            self.maxEventsPerConnection = max(1, maxEventsPerConnection)
            self.maxTotalEvents = max(1, maxTotalEvents)
            self.maxPublishedSummaries = max(1, maxPublishedSummaries)
            self.maxPendingSegmentsPerDirection = max(1, maxPendingSegmentsPerDirection)
            self.maxApplicationPrefixBytes = max(5, maxApplicationPrefixBytes)
            self.maxApplicationFragmentsPerDirection = max(1, maxApplicationFragmentsPerDirection)
        }

        // MARK: Internal

        let maxActiveConnections: Int
        let maxEventsPerConnection: Int
        let maxTotalEvents: Int
        let maxPublishedSummaries: Int
        /// The per-direction buffered-interval bound handed to each connection's
        /// two `TCPSequenceTracker`s. Clamped to at least one.
        let maxPendingSegmentsPerDirection: Int
        /// Total contiguous-plus-pending bytes each per-direction
        /// `TCPApplicationPrefixProbe` may retain before it overflows, drops its
        /// application bytes and disables first-record recovery. Clamped to at
        /// least five.
        let maxApplicationPrefixBytes: Int
        /// The per-direction discrete-fragment bound handed to each connection's two
        /// application probes. Clamped to at least one.
        let maxApplicationFragmentsPerDirection: Int
    }

    // MARK: Snapshot

    /// An immutable, first-observed-ordered view of every retained connection
    /// (active and published) plus the count of summaries dropped to honor the
    /// published-summary bound. The extra counts let a caller prove the bounds
    /// hold.
    nonisolated struct Snapshot: Hashable, Sendable {
        static let empty = Snapshot(
            summaries: [],
            omittedSummaryCount: 0,
            activeConnectionCount: 0,
            publishedSummaryCount: 0,
            retainedEventCount: 0,
            countersOverflowed: false
        )

        let summaries: [ConnectionSummary]
        let omittedSummaryCount: UInt64
        let activeConnectionCount: Int
        let publishedSummaryCount: Int
        let retainedEventCount: Int
        let countersOverflowed: Bool
    }

    // MARK: IngestOutcome

    /// The additive, transient result of one `ingest`. It carries the optional
    /// first-record application metadata recovered by the triggering segment's
    /// direction probe, so the session fold can apply it to a local packet copy
    /// before folding session state. Non-TCP, tupleless and
    /// published-without-working-state paths carry no application. Every connection
    /// fact/event is still folded once regardless of this value.
    nonisolated struct IngestOutcome: Sendable {
        static let none = IngestOutcome(application: nil)

        let application: PacketDecoder.ReassembledTCPApplication?
    }

    /// Saturating unsigned addition. Returns the max on overflow together with a
    /// flag, so callers can both cap the total and record `counterOverflow`.
    /// Exposed as the test seam for the saturating-counter contract, since real
    /// ingestion cannot reach `UInt64` overflow on the packet counter.
    static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> (value: UInt64, overflowed: Bool) {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? (UInt64.max, true) : (sum, false)
    }

    /// Fold one decoded frame. Non-TCP or tupleless packets are ignored. Frames
    /// must arrive in capture order; `provenance.ordinal` is the sequencing key.
    /// Returns the transient application handoff for the triggering direction; the
    /// connection fold itself is unconditional and is `@discardableResult` for the
    /// callers that only want the fold.
    @discardableResult
    mutating func ingest(
        _ packet: DecodedPacket,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge = .unknown
    )
        -> IngestOutcome
    {
        guard packet.transport == .tcp,
              let tuple = packet.fiveTuple,
              let facts = packet.tcpFacts,
              let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint else
        {
            return .none
        }
        let direction: ConnectionDirection
        if source == tuple.a, destination == tuple.b {
            direction = .aToB
        } else if source == tuple.b, destination == tuple.a {
            direction = .bToA
        } else {
            return .none
        }

        let credential = packet.tcpPayloadBytes.isEmpty ? nil : CleartextCredentialDetector.detect(
            payload: packet.tcpPayloadBytes, sourcePort: source.port, destinationPort: destination.port
        )
        defer {
            if let credential {
                noteCredential(credential, tuple: tuple, direction: direction, provenance: provenance, facts: facts)
            }
        }

        let application = ApplicationInput(
            payloadSequence: facts.payloadSequence,
            payload: packet.tcpPayloadBytes,
            sourcePort: source.port,
            destinationPort: destination.port,
            packetIsClassified: packet.appProtocol != nil
        )

        guard var state = active[tuple] else {
            if attachToPublishedTerminalIfNeeded(
                tuple: tuple,
                direction: direction,
                facts: facts,
                provenance: provenance,
                loss: loss
            ) {
                return .none
            }
            let metadata = startConnection(
                tuple: tuple, direction: direction, facts: facts,
                provenance: provenance, loss: loss, application: application
            )
            return IngestOutcome(application: metadata)
        }

        if state.isTerminal {
            let pureSYN = facts.flags.contains(.syn) && !facts.flags.contains(.ack)
            if pureSYN {
                // A fresh SYN-without-ACK after an observed terminal is a new
                // connection: finalize the old id, then open a new one here (a new
                // probe, per tuple-reuse policy).
                publish(state)
                active[tuple] = nil
                let metadata = startConnection(
                    tuple: tuple, direction: direction, facts: facts,
                    provenance: provenance, loss: loss, application: application
                )
                return IngestOutcome(application: metadata)
            }
            // Anything else after terminal stays attached as a late segment and
            // never reopens the connection. The trackers and probes still exist
            // while the terminal state lingers in `active`, so the segment folds.
            attach(&state, provenance: provenance, loss: loss)
            let sequenceEvents = sequenceFold(&state, direction: direction, facts: facts, provenance: provenance)
            var appEvents: [ConnectionEvent] = []
            let metadata = foldApplication(
                &state, direction: direction, input: application,
                provenance: provenance, facts: facts, into: &appEvents
            )
            store(state, at: tuple)
            appendEvent(
                event(state.id, .lateSegmentAfterClose, provenance, direction: direction, facts: facts),
                to: tuple
            )
            // A reset that arrives after the observed close (a lingering socket
            // being torn down) is still an observed reset: the session already
            // reads as reset, so the evidence must carry the same fact. The close
            // reason stays what was observed first.
            if facts.flags.contains(.rst) {
                appendEvent(event(state.id, .rst, provenance, direction: direction, facts: facts), to: tuple)
            }
            for produced in sequenceEvents {
                appendEvent(produced, to: tuple)
            }
            for produced in appEvents {
                appendEvent(produced, to: tuple)
            }
            return IngestOutcome(application: metadata)
        }

        let result = foldOngoing(
            &state, direction: direction, facts: facts,
            provenance: provenance, loss: loss, application: application
        )
        store(state, at: tuple)
        for produced in result.events {
            appendEvent(produced, to: tuple)
        }
        return IngestOutcome(application: result.application)
    }

    /// A first-observed-ordered snapshot of active and published connections.
    func snapshot() -> Snapshot {
        var all = zip(published, publishedAlive).compactMap { $1 ? $0 : nil }
        for state in active.values {
            all.append(state.summary())
        }
        all.sort { lhs, rhs in
            let lo = lhs.firstProvenance.ordinal.rawValue
            let ro = rhs.firstProvenance.ordinal.rawValue
            if lo != ro {
                return lo < ro
            }
            return lhs.id.rawValue.uuidString < rhs.id.rawValue.uuidString
        }
        return Snapshot(
            summaries: all,
            omittedSummaryCount: omittedSummaryCount,
            activeConnectionCount: active.count,
            publishedSummaryCount: publishedLiveCount,
            retainedEventCount: retainedEventTotal,
            countersOverflowed: countersOverflowed
        )
    }

    // MARK: Private

    // MARK: Application integration

    /// The eviction ordering key described on ``leastRecentlyUsedTuple()``. It is a
    /// plain comparable tuple of already-known facts, so no optional `Date` is ever
    /// compared against another optional directly.
    private struct RecencyKey {
        // MARK: Lifecycle

        init(_ state: ConnectionState) {
            isTimed = state.lastProvenance.timestamp != nil
            timestamp = state.lastProvenance.timestamp
            lastOrdinal = state.lastProvenance.ordinal.rawValue
            firstOrdinal = state.firstProvenance.ordinal.rawValue
        }

        // MARK: Internal

        let isTimed: Bool
        let timestamp: Date?
        let lastOrdinal: UInt64
        let firstOrdinal: UInt64

        func precedes(_ other: RecencyKey) -> Bool {
            if isTimed != other.isTimed {
                return isTimed
            }
            if isTimed, let mine = timestamp, let theirs = other.timestamp, mine != theirs {
                return mine < theirs
            }
            if !isTimed, lastOrdinal != other.lastOrdinal {
                return lastOrdinal < other.lastOrdinal
            }
            return firstOrdinal < other.firstOrdinal
        }

        func equals(_ other: RecencyKey) -> Bool {
            !precedes(other) && !other.precedes(self)
        }
    }

    /// The bounded first-record probe inputs for one segment, projected out of the
    /// decoded packet in `ingest` so the fold helpers stay packet-agnostic.
    private struct ApplicationInput {
        let payloadSequence: UInt32
        let payload: [UInt8]
        let sourcePort: UInt16
        let destinationPort: UInt16
        let packetIsClassified: Bool
    }

    /// One recency record for eviction: the documented total order (see
    /// ``leastRecentlyUsedTuple()``), then tuple order.
    private struct RecencyEntry: Comparable {
        let key: RecencyKey
        let tuple: FiveTuple
        let version: UInt64

        static func < (lhs: RecencyEntry, rhs: RecencyEntry) -> Bool {
            lhs.key.precedes(rhs.key) || (lhs.key.equals(rhs.key) && ConnectionTable.isLower(
                lhs.tuple,
                than: rhs.tuple
            ))
        }

        static func == (lhs: RecencyEntry, rhs: RecencyEntry) -> Bool {
            lhs.tuple == rhs.tuple && lhs.version == rhs.version
        }
    }

    /// A connection's front event for ``enforceTotalEventCap()``: ordered by the
    /// event's occurrence ordinal, then its connection id's text, as the bound names.
    private struct FrontEntry: Comparable {
        enum Place {
            case active(FiveTuple)
            case published
        }

        let ordinal: UInt64
        let idText: String
        let connection: ConnectionID
        let place: Place
        let version: UInt64

        static func < (lhs: FrontEntry, rhs: FrontEntry) -> Bool {
            (lhs.ordinal, lhs.idText) < (rhs.ordinal, rhs.idText)
        }

        static func == (lhs: FrontEntry, rhs: FrontEntry) -> Bool {
            lhs.connection == rhs.connection && lhs.version == rhs.version
        }
    }

    private struct PublishedEntry: Comparable {
        let firstOrdinal: UInt64
        let sequence: UInt64
        let id: ConnectionID

        static func < (lhs: PublishedEntry, rhs: PublishedEntry) -> Bool {
            (lhs.firstOrdinal, lhs.sequence) < (rhs.firstOrdinal, rhs.sequence)
        }
    }

    private let configuration: Configuration

    /// Eviction order over `active`: a heap of recency records, each valid while its
    /// version is the tuple's latest.
    private var recency = MinHeap<RecencyEntry>()
    private var recencyVersions: [FiveTuple: UInt64] = [:]
    private var recencyCounter: UInt64 = 0
    /// Each connection's oldest retained event, for the global event bound: valid
    /// while its version is the connection's latest in `frontVersions`.
    private var fronts = MinHeap<FrontEntry>()
    private var frontVersions: [ConnectionID: UInt64] = [:]
    private var frontCounter: UInt64 = 0
    /// Where each live published summary sits in `published`. A dropped summary stays
    /// in the array marked dead in `publishedAlive` (its events freed) until the array
    /// is compacted, so dropping one never shifts the others.
    private var publishedIndexByID: [ConnectionID: Int] = [:]
    private var publishedAlive: [Bool] = []
    private var publishedLiveCount = 0
    /// Publication bound order: least first ordinal, then publication order.
    private var publishedOrder = MinHeap<PublishedEntry>()
    private var publicationCounter: UInt64 = 0

    /// Live connections keyed by canonical tuple, bounded by
    /// `maxActiveConnections`. A terminal connection lingers here (so late
    /// segments can attach) until replaced by a new SYN or evicted.
    private var active: [FiveTuple: ConnectionState] = [:]
    /// Which credential kinds each connection already reported, so a login is one
    /// event per kind rather than one per segment. Bounded with the connections.
    private var reportedCredentials: [ConnectionID: Set<CleartextCredentialKind>] = [:]
    /// Finalized (terminal or evicted) summaries, bounded by
    /// `maxPublishedSummaries`.
    private var published: [ConnectionSummary] = []
    /// Latest finalized identity per tuple, bounded by the published-summary list.
    /// It preserves truthful late-after-close attachment after terminal working
    /// state leaves the active-cap budget.
    private var latestPublishedByTuple: [FiveTuple: ConnectionID] = [:]
    /// Cumulative published summaries dropped to honor the bound.
    private var omittedSummaryCount: UInt64 = 0
    private var countersOverflowed = false
    /// Running total of events held across active states and published summaries.
    /// It is the exact global `maxTotalEvents` accounting source.
    private var retainedEventTotal = 0
    /// FIFO memory of recently evicted tuples so a later frame for one opens a
    /// new id carrying `priorStateEvicted`. Bounded by `maxActiveConnections`.
    /// Oldest first from `evictedHead`; an entry counts only while its version is
    /// the tuple's current one in `evictedVersions`, so trimming and consuming a
    /// marker are O(1) amortized instead of shifting the whole array.
    private var evictedOrder: [(tuple: FiveTuple, version: UInt64)] = []
    private var evictedHead = 0
    private var evictedVersions: [FiveTuple: UInt64] = [:]
    private var evictedCounter: UInt64 = 0

    /// The per-direction tracker configuration derived from the table bounds,
    /// handed to both trackers of every connection so buffering stays bounded.
    private var trackerConfiguration: TCPSequenceTracker.Configuration {
        TCPSequenceTracker.Configuration(maxPendingSegments: configuration.maxPendingSegmentsPerDirection)
    }

    /// A fresh, empty application probe bounded by the table configuration, copied
    /// into both directions of every new connection. Value semantics mean each
    /// direction gets an independent probe.
    private var applicationProbeTemplate: TCPApplicationPrefixProbe {
        TCPApplicationPrefixProbe(
            maxBufferedBytes: configuration.maxApplicationPrefixBytes,
            maxFragments: configuration.maxApplicationFragmentsPerDirection
        )
    }

    /// The fixed mapping from a tracker disposition to its event kind and the
    /// sticky limitations it implies. `noSequenceSpace` maps to `nil` — no event
    /// and no limitation. A gap records only that a discontinuity was observed;
    /// overflow additionally truncates ordering state.
    private static func sequenceMapping(
        for disposition: TCPSequenceTracker.Disposition
    )
        -> (kind: ConnectionEventKind, limitations: ConnectionLimitations)?
    {
        switch disposition {
        case .initialized,
             .advanced:
            (.sequenceAdvanced, [])
        case .duplicate:
            (.retransmission, [])
        case .overlap:
            (.overlap, [])
        case .outOfOrderBuffered:
            (.outOfOrderBuffered, .sequenceGapObserved)
        case .pendingDrained:
            (.pendingDrained, [])
        case .pendingOverflow:
            (.pendingOverflow, [.sequenceGapObserved, .sequenceStateTruncated])
        case .serialAmbiguous:
            (.serialAmbiguous, .serialDistanceAmbiguous)
        case .keepAlive:
            (.keepAlive, [])
        case .noSequenceSpace:
            nil
        }
    }

    /// A total order over tuples, used only as a final deterministic tie-break.
    private static func isLower(_ tuple: FiveTuple, than other: FiveTuple?) -> Bool {
        guard let other else {
            return true
        }
        if tuple.proto.rawValue != other.proto.rawValue {
            return tuple.proto.rawValue < other.proto.rawValue
        }
        if tuple.a != other.a {
            return tuple.a < other.a
        }
        return tuple.b < other.b
    }

    private mutating func attachToPublishedTerminalIfNeeded(
        tuple: FiveTuple,
        direction: ConnectionDirection,
        facts: TCPSegmentFacts,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge
    )
        -> Bool
    {
        guard let id = latestPublishedByTuple[tuple],
              let index = publishedIndexByID[id],
              published[index].closeReason != .stateEviction else
        {
            return false
        }
        let pureSYN = facts.flags.contains(.syn) && !facts.flags.contains(.ack)
        guard !pureSYN else {
            return false
        }

        accumulatePublished(index, provenance: provenance, loss: loss)
        // The connection's working state — and its per-direction trackers — was
        // released at publication, so there is no ordering to fold this late frame
        // into. Record the truncation rather than fabricate a sequence event.
        published[index].limitations.insert(.sequenceStateTruncated)
        appendPublishedEvent(
            event(id, .lateSegmentAfterClose, provenance, direction: direction, facts: facts),
            at: index
        )
        // Same rule as the active terminal path: a late reset is an observed reset.
        if facts.flags.contains(.rst) {
            appendPublishedEvent(event(id, .rst, provenance, direction: direction, facts: facts), at: index)
        }
        return true
    }

    // MARK: New connections

    @discardableResult
    private mutating func startConnection(
        tuple: FiveTuple,
        direction: ConnectionDirection,
        facts: TCPSegmentFacts,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge,
        application: ApplicationInput
    )
        -> PacketDecoder.ReassembledTCPApplication?
    {
        let id = ConnectionID(tuple: tuple, firstOrdinal: provenance.ordinal)
        var state = ConnectionState(
            id: id, tuple: tuple, provenance: provenance,
            trackerConfiguration: trackerConfiguration, applicationProbe: applicationProbeTemplate
        )
        accumulate(&state, provenance: provenance, loss: loss)
        state.limitations.insert(.handshakeIncomplete)

        if consumeEvictedMarker(tuple) {
            state.limitations.insert(.priorStateEvicted)
            state.limitations.insert(.startUnobserved)
        }

        // Fold this first segment through its direction tracker before the
        // lifecycle events are decided; the typed sequence events (if any) trail
        // them as additional evidence.
        let sequenceEvents = sequenceFold(&state, direction: direction, facts: facts, provenance: provenance)

        var events: [ConnectionEvent] = [
            event(id, .firstObserved, provenance, direction: direction, facts: facts),
        ]
        let flags = facts.flags
        let hasPayload = facts.payloadLength > 0

        if flags.contains(.rst) {
            // Observed only a reset: the open was never seen.
            state.limitations.insert(.startUnobserved)
            state.phase = .closed
            state.closeReason = .reset(direction)
            events.append(event(id, .rst, provenance, direction: direction, facts: facts))
        } else if flags.contains(.syn), !flags.contains(.ack) {
            // A clean SYN: initiator and its ISN are known.
            state.phase = .opening
            state.initiator = direction
            state.initiatorISN = facts.sequenceNumber
            state.handshake = .synObserved
            state.synProvenance = provenance
            events.append(event(id, .syn, provenance, direction: direction, facts: facts))
        } else if flags.contains(.syn), flags.contains(.ack) {
            // SYN+ACK with no prior SYN: the initiator is unknown, so the
            // three-way can never be validated for this id.
            state.limitations.insert(.startUnobserved)
            state.limitations.insert(.handshakeIncomplete)
            state.phase = .opening
            state.handshake = .synAckObserved
            state.responderISN = facts.sequenceNumber
            state.synAckProvenance = provenance
            events.append(event(id, .synAck, provenance, direction: direction, facts: facts))
        } else {
            // Midstream: an ACK, payload, FIN or bare segment with no handshake.
            state.limitations.insert(.startUnobserved)
            state.phase = .active
            if hasPayload {
                events.append(event(id, .payloadObserved, provenance, direction: direction, facts: facts))
            }
            if flags.contains(.fin) {
                state.finDirections.insert(finMask(direction))
                state.phase = .closing
                events.append(event(id, .fin, provenance, direction: direction, facts: facts))
            }
        }

        if hasPayload, !events.contains(where: { $0.kind == .payloadObserved }) {
            events.append(event(id, .payloadObserved, provenance, direction: direction, facts: facts))
            if state.phase == .opening, !flags.contains(.rst) {
                state.phase = .active
            }
        }

        events.append(contentsOf: sequenceEvents)

        // Fold the first segment's payload through its direction probe last, so any
        // application event trails the lifecycle and sequence evidence.
        let metadata = foldApplication(
            &state, direction: direction, input: application,
            provenance: provenance, facts: facts, into: &events
        )

        store(state, at: tuple)
        for produced in events {
            appendEvent(produced, to: tuple)
        }
        enforceActiveCap()
        return metadata
    }

    // MARK: Ongoing folds

    private func foldOngoing(
        _ state: inout ConnectionState,
        direction: ConnectionDirection,
        facts: TCPSegmentFacts,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge,
        application: ApplicationInput
    )
        -> (events: [ConnectionEvent], application: PacketDecoder.ReassembledTCPApplication?)
    {
        accumulate(&state, provenance: provenance, loss: loss)
        let id = state.id
        let flags = facts.flags
        var events: [ConnectionEvent] = []
        // Fold once through the direction tracker before the lifecycle branches;
        // the typed sequence events (if any) trail this frame's lifecycle events.
        let sequenceEvents = sequenceFold(&state, direction: direction, facts: facts, provenance: provenance)
        // Fold the segment's payload through the direction probe exactly once. Its
        // application event(s), if any, trail every other event on this frame; the
        // metadata handoff is returned to the session fold.
        var appEvents: [ConnectionEvent] = []
        let appMetadata = foldApplication(
            &state, direction: direction, input: application,
            provenance: provenance, facts: facts, into: &appEvents
        )

        if flags.contains(.rst) {
            state.phase = .closed
            state.closeReason = .reset(direction)
            events.append(event(id, .rst, provenance, direction: direction, facts: facts))
            events.append(contentsOf: sequenceEvents)
            events.append(contentsOf: appEvents)
            return (events, appMetadata)
        }

        if flags.contains(.syn) {
            events.append(contentsOf: foldSYN(&state, direction: direction, facts: facts, provenance: provenance))
            if facts.payloadLength > 0 {
                events.append(event(id, .payloadObserved, provenance, direction: direction, facts: facts))
                if state.phase == .opening {
                    state.phase = .active
                }
            }
            events.append(contentsOf: sequenceEvents)
            events.append(contentsOf: appEvents)
            return (events, appMetadata)
        }

        // Three-way completion: the initiator's ACK matching responder ISN+1.
        if flags.contains(.ack),
           state.handshake == .synAckObserved,
           let initiator = state.initiator,
           direction == initiator,
           let responderISN = state.responderISN,
           facts.acknowledgementNumber == responderISN &+ 1
        {
            state.handshake = .threeWayObserved
            state.limitations.remove(.handshakeIncomplete)
            if state.phase == .opening {
                state.phase = .active
            }
            let cited = [state.synProvenance, state.synAckProvenance, provenance].compactMap { $0 }
            events.append(event(
                id, .handshakeCompleted, cited.isEmpty ? [provenance] : cited,
                direction: direction, facts: facts
            ))
        }

        if facts.payloadLength > 0 {
            events.append(event(id, .payloadObserved, provenance, direction: direction, facts: facts))
            if state.phase == .opening {
                state.phase = .active
            }
        }

        if flags.contains(.fin) {
            state.finDirections.insert(finMask(direction))
            events.append(event(id, .fin, provenance, direction: direction, facts: facts))
            if state.finDirections.contains(.aToB), state.finDirections.contains(.bToA) {
                state.phase = .closed
                state.closeReason = .orderly
            } else if state.phase != .closed {
                state.phase = .closing
            }
        }

        events.append(contentsOf: sequenceEvents)
        events.append(contentsOf: appEvents)
        return (events, appMetadata)
    }

    private func foldSYN(
        _ state: inout ConnectionState,
        direction: ConnectionDirection,
        facts: TCPSegmentFacts,
        provenance: SessionFrameProvenance
    )
        -> [ConnectionEvent]
    {
        let id = state.id
        if facts.flags.contains(.ack) {
            // SYN+ACK: valid only from the responder, acking the initiator ISN+1.
            if let initiator = state.initiator,
               let initiatorISN = state.initiatorISN,
               direction == initiator.opposite,
               facts.acknowledgementNumber == initiatorISN &+ 1
            {
                if state.handshake == .synObserved || state.handshake == .none {
                    state.responderISN = facts.sequenceNumber
                    state.handshake = .synAckObserved
                    state.synAckProvenance = provenance
                    return [event(id, .synAck, provenance, direction: direction, facts: facts)]
                }
                if state.handshake == .synAckObserved || state.handshake == .threeWayObserved,
                   state.responderISN == facts.sequenceNumber
                {
                    // A retransmitted SYN+ACK: same connection, re-observed.
                    return [event(id, .synAck, provenance, direction: direction, facts: facts)]
                }
            }
            state.limitations.insert(.ambiguousTupleReuse)
            return [event(id, .ambiguousTupleReuse, provenance, direction: direction, facts: facts)]
        }

        // A bare SYN on a live connection: a retransmission if it matches the
        // known initiator+ISN, otherwise ambiguous tuple reuse (never a split
        // before an observed terminal).
        if let initiator = state.initiator,
           direction == initiator,
           state.initiatorISN == facts.sequenceNumber
        {
            return [event(id, .syn, provenance, direction: direction, facts: facts)]
        }
        state.limitations.insert(.ambiguousTupleReuse)
        return [event(id, .ambiguousTupleReuse, provenance, direction: direction, facts: facts)]
    }

    // MARK: Per-frame accumulation

    /// Fold one frame's totals into a connection: packet count, byte totals
    /// (saturating, marking `counterOverflow`), truncation, last provenance and
    /// loss knowledge. Shared by new, ongoing and late-segment folds.
    private func accumulate(
        _ state: inout ConnectionState,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge
    ) {
        let (packets, overflow1) = Self.saturatingAdd(state.packetCount, 1)
        let (captured, overflow2) = Self.saturatingAdd(state.capturedByteTotal, UInt64(provenance.capturedLength))
        let (original, overflow3) = Self.saturatingAdd(state.originalByteTotal, UInt64(provenance.originalLength))
        state.packetCount = packets
        state.capturedByteTotal = captured
        state.originalByteTotal = original
        if overflow1 || overflow2 || overflow3 {
            state.limitations.insert(.counterOverflow)
        }
        if provenance.originalLength > provenance.capturedLength {
            state.limitations.insert(.payloadTruncated)
        }
        state.lastProvenance = provenance
        state.lossKnowledge = state.lossKnowledge.merged(with: loss)
    }

    private func attach(
        _ state: inout ConnectionState,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge
    ) {
        accumulate(&state, provenance: provenance, loss: loss)
    }

    private mutating func accumulatePublished(
        _ index: Int,
        provenance: SessionFrameProvenance,
        loss: CaptureLossKnowledge
    ) {
        let packets = Self.saturatingAdd(published[index].packetCount, 1)
        let captured = Self.saturatingAdd(
            published[index].capturedByteTotal, UInt64(provenance.capturedLength)
        )
        let original = Self.saturatingAdd(
            published[index].originalByteTotal, UInt64(provenance.originalLength)
        )
        published[index].packetCount = packets.value
        published[index].capturedByteTotal = captured.value
        published[index].originalByteTotal = original.value
        if packets.overflowed || captured.overflowed || original.overflowed {
            published[index].limitations.insert(.counterOverflow)
        }
        if provenance.originalLength > provenance.capturedLength {
            published[index].limitations.insert(.payloadTruncated)
        }
        published[index].lastProvenance = provenance
        published[index].lossKnowledge = published[index].lossKnowledge.merged(with: loss)
    }

    // MARK: Event bounds

    /// One `.cleartextCredential` event per connection and kind, on the frame that
    /// carried it. The detector's kind is kept; the payload is not.
    private mutating func noteCredential(
        _ kind: CleartextCredentialKind,
        tuple: FiveTuple,
        direction: ConnectionDirection,
        provenance: SessionFrameProvenance,
        facts: TCPSegmentFacts
    ) {
        guard let id = active[tuple]?.id, reportedCredentials[id]?.contains(kind) != true,
              reportedCredentials.count < configuration.maxActiveConnections * 4 else
        {
            return
        }
        reportedCredentials[id, default: []].insert(kind)
        appendEvent(ConnectionEvent(
            connectionID: id, kind: .cleartextCredential, timestamp: provenance.timestamp,
            provenance: provenance, direction: direction, facts: facts, credentialKind: kind
        ), to: tuple)
    }

    private mutating func appendEvent(_ produced: ConnectionEvent, to tuple: FiveTuple) {
        guard var state = active[tuple] else {
            return
        }
        state.events.append(produced)
        store(state, at: tuple)
        retainedEventTotal += 1
        enforcePerConnectionEventCap(tuple)
        enforceTotalEventCap()
    }

    private mutating func appendPublishedEvent(_ produced: ConnectionEvent, at index: Int) {
        published[index].events.append(produced)
        retainedEventTotal += 1
        while published[index].events.count > configuration.maxEventsPerConnection {
            published[index].events.removeFirst()
            let omitted = Self.saturatingAdd(published[index].omittedEventCount, 1)
            published[index].omittedEventCount = omitted.value
            published[index].limitations.insert(.eventHistoryTruncated)
            if omitted.overflowed {
                published[index].limitations.insert(.counterOverflow)
            }
            retainedEventTotal -= 1
        }
        noteFront(of: published[index].id, events: published[index].events, place: .published)
        enforceTotalEventCap()
    }

    private mutating func enforcePerConnectionEventCap(_ tuple: FiveTuple) {
        guard var state = active[tuple] else {
            return
        }
        let cap = configuration.maxEventsPerConnection
        guard state.events.count > cap else {
            return
        }
        while state.events.count > cap {
            state.events.removeFirst()
            let omitted = Self.saturatingAdd(state.omittedEventCount, 1)
            state.omittedEventCount = omitted.value
            state.limitations.insert(.eventHistoryTruncated)
            if omitted.overflowed {
                state.limitations.insert(.counterOverflow)
            }
            retainedEventTotal -= 1
        }
        store(state, at: tuple)
    }

    private mutating func enforceTotalEventCap() {
        let cap = configuration.maxTotalEvents
        while retainedEventTotal > cap {
            // Drop the globally oldest front event across both active and finalized
            // summaries — least occurrence ordinal, then connection id text — found
            // through the front heap rather than a scan, independently of dictionary order.
            let victim = oldestFront()
            let activeVictim = victim?.tuple
            let publishedVictim = victim?.index
            if let tuple = activeVictim, var state = active[tuple], !state.events.isEmpty {
                state.events.removeFirst()
                let omitted = Self.saturatingAdd(state.omittedEventCount, 1)
                state.omittedEventCount = omitted.value
                state.limitations.insert(.eventHistoryTruncated)
                if omitted.overflowed {
                    state.limitations.insert(.counterOverflow)
                }
                store(state, at: tuple)
            } else if let index = publishedVictim, !published[index].events.isEmpty {
                published[index].events.removeFirst()
                let omitted = Self.saturatingAdd(
                    published[index].omittedEventCount, 1
                )
                published[index].omittedEventCount = omitted.value
                published[index].limitations.insert(.eventHistoryTruncated)
                if omitted.overflowed {
                    published[index].limitations.insert(.counterOverflow)
                }
                noteFront(of: published[index].id, events: published[index].events, place: .published)
            } else {
                retainedEventTotal = 0
                return
            }
            retainedEventTotal -= 1
        }
    }

    // MARK: Active-cap eviction

    private mutating func enforceActiveCap() {
        let cap = configuration.maxActiveConnections
        while active.count > cap {
            guard let tuple = leastRecentlyUsedTuple() else {
                break
            }
            guard var state = active[tuple] else {
                break
            }
            let wasTerminal = state.isTerminal
            if !wasTerminal {
                state.phase = .closed
                state.closeReason = .stateEviction
                store(state, at: tuple)
                // Record the eviction against the connection's last evidence,
                // then finalize and release it.
                appendEvent(event(state.id, .stateEvicted, state.lastProvenance), to: tuple)
            }
            let finalized = active[tuple] ?? state
            active[tuple] = nil
            publish(finalized)
            if !wasTerminal {
                markEvicted(tuple)
            }
        }
    }

    /// The eviction victim, chosen by a documented total order that never compares
    /// two optionals directly and never infers elapsed time from a missing one:
    ///
    /// 1. Connections whose last frame carried a capture time are ranked ahead of
    ///    those whose last frame did not, and compare among themselves by that
    ///    timestamp (least recent first). An unknown last-capture time is not a
    ///    small time, so such a connection is only evicted once every timed
    ///    connection has been considered.
    /// 2. Connections with no known last-capture time compare among themselves by
    ///    their last frame's capture **ordinal** — the named source-order fallback,
    ///    used purely for ordering.
    /// 3. Remaining ties break on the earliest first ordinal, then tuple order.
    private mutating func leastRecentlyUsedTuple() -> FiveTuple? {
        // Entries are pushed on every write and skipped here once superseded or
        // removed, so the first valid one is the victim the total order names.
        while let top = recency.min {
            if recencyVersions[top.tuple] == top.version, active[top.tuple] != nil {
                return top.tuple
            }
            recency.popMin()
        }
        return nil
    }

    /// Writes a live connection and records its recency for eviction.
    private mutating func store(_ state: ConnectionState, at tuple: FiveTuple) {
        active[tuple] = state
        recencyCounter &+= 1
        recencyVersions[tuple] = recencyCounter
        recency.push(RecencyEntry(key: RecencyKey(state), tuple: tuple, version: recencyCounter))
        noteFront(of: state.id, events: state.events, place: .active(tuple))
        // Superseded entries accumulate; rebuild from the live table when they dominate.
        if recency.count > 4 * active.count + 1_024 {
            recencyVersions = recencyVersions.filter { active[$0.key] != nil }
            recency.rebuild(active.map { tuple, state in
                RecencyEntry(key: RecencyKey(state), tuple: tuple, version: recencyVersions[tuple] ?? 0)
            })
        }
    }

    /// Records a connection's current front event (or that it has none).
    private mutating func noteFront(of id: ConnectionID, events: [ConnectionEvent], place: FrontEntry.Place) {
        frontCounter &+= 1
        frontVersions[id] = frontCounter
        if let first = events.first {
            fronts.push(FrontEntry(
                ordinal: first.occurrenceOrdinal.rawValue, idText: first.connectionID.rawValue.uuidString,
                connection: id, place: place, version: frontCounter
            ))
        }
        if fronts.count > 4 * (active.count + publishedLiveCount) + 1_024 {
            var rebuilt: [FrontEntry] = []
            for (tuple, state) in active {
                if let entry = currentFront(state.id, events: state.events, place: .active(tuple)) {
                    rebuilt.append(entry)
                }
            }
            for (summary, isAlive) in zip(published, publishedAlive) where isAlive {
                if let entry = currentFront(summary.id, events: summary.events, place: .published) {
                    rebuilt.append(entry)
                }
            }
            fronts.rebuild(rebuilt)
        }
    }

    private func currentFront(_ id: ConnectionID, events: [ConnectionEvent], place: FrontEntry.Place) -> FrontEntry? {
        guard let first = events.first, let version = frontVersions[id] else {
            return nil
        }
        return FrontEntry(
            ordinal: first.occurrenceOrdinal.rawValue, idText: first.connectionID.rawValue.uuidString,
            connection: id, place: place, version: version
        )
    }

    /// The globally oldest front event's owner: an active tuple or a published index.
    private mutating func oldestFront() -> (tuple: FiveTuple?, index: Int?)? {
        while let top = fronts.min {
            if frontVersions[top.connection] == top.version {
                switch top.place {
                case let .active(tuple):
                    if active[tuple]?.id == top.connection, active[tuple]?.events.isEmpty == false {
                        return (tuple, nil)
                    }
                case .published:
                    if let index = publishedIndexByID[top.connection], !published[index].events.isEmpty {
                        return (nil, index)
                    }
                }
            }
            fronts.popMin()
        }
        return nil
    }

    // MARK: Publication bound

    private mutating func publish(_ state: ConnectionState) {
        let summary = state.summary()
        published.append(summary)
        publishedAlive.append(true)
        publishedLiveCount += 1
        publishedIndexByID[summary.id] = published.count - 1
        publicationCounter &+= 1
        publishedOrder.push(PublishedEntry(
            firstOrdinal: summary.firstProvenance.ordinal.rawValue, sequence: publicationCounter, id: summary.id
        ))
        noteFront(of: summary.id, events: summary.events, place: .published)
        latestPublishedByTuple[state.tuple] = state.id
        let cap = configuration.maxPublishedSummaries
        while publishedLiveCount > cap, let oldest = publishedOrder.popMin() {
            // Drop the oldest terminal/evicted summary: least first ordinal, then the
            // earliest published — found through the heap, not a scan.
            guard let index = publishedIndexByID.removeValue(forKey: oldest.id) else {
                continue
            }
            let removed = published[index]
            publishedAlive[index] = false
            publishedLiveCount -= 1
            published[index].events = []
            frontVersions[removed.id] = nil
            retainedEventTotal -= removed.events.count
            if latestPublishedByTuple[removed.tuple] == removed.id {
                latestPublishedByTuple.removeValue(forKey: removed.tuple)
            }
            let omitted = Self.saturatingAdd(omittedSummaryCount, 1)
            omittedSummaryCount = omitted.value
            countersOverflowed = countersOverflowed || omitted.overflowed
        }
        if published.count > 2 * publishedLiveCount + 1_024 {
            compactPublished()
        }
    }

    /// Drops dead summaries from `published`, keeping publication order, and
    /// re-points the index map (whose front entries record no index, only the id).
    private mutating func compactPublished() {
        published = zip(published, publishedAlive).compactMap { $1 ? $0 : nil }
        publishedAlive = Array(repeating: true, count: published.count)
        publishedIndexByID = Dictionary(uniqueKeysWithValues: published.enumerated().map { ($1.id, $0) })
    }

    // MARK: Evicted-tuple memory

    private mutating func markEvicted(_ tuple: FiveTuple) {
        guard evictedVersions[tuple] == nil else {
            return
        }
        evictedCounter &+= 1
        evictedVersions[tuple] = evictedCounter
        evictedOrder.append((tuple, evictedCounter))
        let cap = configuration.maxActiveConnections
        while evictedVersions.count > cap, evictedHead < evictedOrder.count {
            let old = evictedOrder[evictedHead]
            evictedHead += 1
            if evictedVersions[old.tuple] == old.version {
                evictedVersions[old.tuple] = nil
            }
        }
        if evictedHead > 1_024, evictedHead * 2 > evictedOrder.count {
            evictedOrder.removeFirst(evictedHead)
            evictedHead = 0
        }
    }

    private mutating func consumeEvictedMarker(_ tuple: FiveTuple) -> Bool {
        evictedVersions.removeValue(forKey: tuple) != nil
    }

    // MARK: Sequence integration

    /// Fold one segment through its direction tracker and the connection's
    /// flow-control tracker exactly once each, mark the mapped sticky limitations
    /// on the connection, and return the typed sequence/flow-control events to
    /// append (sequence verdict first, then window/acknowledgement shapes in a
    /// fixed order). A pure ACK with an ordinary window returns nothing. Mutates
    /// only the passed-in `state` (its trackers and limitations), never `self`.
    private func sequenceFold(
        _ state: inout ConnectionState,
        direction: ConnectionDirection,
        facts: TCPSegmentFacts,
        provenance: SessionFrameProvenance
    )
        -> [ConnectionEvent]
    {
        let output = state.foldSequence(direction: direction, facts: facts)
        let flow = state.foldFlowControl(
            direction: direction, facts: facts, keepAlive: output.disposition == .keepAlive,
            retransmission: output.disposition == .duplicate
        )
        var events: [ConnectionEvent] = []
        if let mapped = Self.sequenceMapping(for: output.disposition) {
            state.limitations.formUnion(mapped.limitations)
            // A zero-window probe is a byte sent to be refused: its ordering verdict
            // (an advance the peer will not accept, then duplicates of it) is not
            // evidence, so the probe event stands in for the sequence event. Any
            // limitation the tracker recorded still sticks.
            if flow.contains(.zeroWindowProbe) {
                events.append(event(state.id, .zeroWindowProbe, provenance, direction: direction, facts: facts))
            } else {
                events.append(event(state.id, mapped.kind, provenance, direction: direction, facts: facts))
            }
        } else if flow.contains(.zeroWindowProbe) {
            events.append(event(state.id, .zeroWindowProbe, provenance, direction: direction, facts: facts))
        }
        if flow.contains(.fastRetransmission) {
            events.append(event(state.id, .fastRetransmission, provenance, direction: direction, facts: facts))
        }
        if flow.contains(.spuriousRetransmission) {
            events.append(event(
                state.id, .spuriousRetransmission, provenance, direction: direction, facts: facts
            ))
        }
        if flow.contains(.windowFull) {
            events.append(event(state.id, .windowFull, provenance, direction: direction, facts: facts))
        }
        if flow.contains(.zeroWindow) {
            events.append(event(state.id, .zeroWindow, provenance, direction: direction, facts: facts))
        }
        if flow.contains(.duplicateAcknowledgement) {
            events.append(event(
                state.id, .duplicateAcknowledgement, provenance, direction: direction, facts: facts
            ))
        }
        if flow.contains(.ackedUnseenSegment) {
            events.append(event(state.id, .ackedUnseenSegment, provenance, direction: direction, facts: facts))
        }
        return events
    }

    /// Fold one segment's payload through its direction probe exactly once. On
    /// overflow it marks the sticky `applicationProbeTruncated` limitation and
    /// appends the truncation event; on the first availability of application
    /// metadata for the direction it appends one bounded `.applicationRecord`
    /// event. Returns the transient metadata handoff for the session fold. Mutates
    /// only the passed-in `state` (its probe and limitations), never `self`.
    private func foldApplication(
        _ state: inout ConnectionState,
        direction: ConnectionDirection,
        input: ApplicationInput,
        provenance: SessionFrameProvenance,
        facts: TCPSegmentFacts,
        into events: inout [ConnectionEvent]
    )
        -> PacketDecoder.ReassembledTCPApplication?
    {
        guard !input.payload.isEmpty else {
            return nil
        }
        let folded = state.foldApplication(
            direction: direction,
            payloadSequence: input.payloadSequence,
            payload: input.payload,
            sourcePort: input.sourcePort,
            destinationPort: input.destinationPort,
            packetIsClassified: input.packetIsClassified
        )
        if folded.outcome.truncated {
            state.limitations.insert(.applicationProbeTruncated)
            events.append(event(
                state.id, .applicationProbeTruncated, provenance, direction: direction, facts: facts
            ))
        }
        if folded.firstAvailability, let application = folded.outcome.application {
            events.append(ConnectionEvent(
                connectionID: state.id,
                kind: .applicationRecord,
                timestamp: provenance.timestamp,
                provenance: provenance,
                direction: direction,
                facts: facts,
                applicationKind: application.appProtocol,
                applicationComplete: application.isComplete
            ))
        }
        return folded.outcome.application
    }

    // MARK: Helpers

    private func event(
        _ id: ConnectionID,
        _ kind: ConnectionEventKind,
        _ provenance: SessionFrameProvenance,
        direction: ConnectionDirection? = nil,
        facts: TCPSegmentFacts? = nil
    )
        -> ConnectionEvent
    {
        ConnectionEvent(
            connectionID: id, kind: kind, timestamp: provenance.timestamp,
            provenance: provenance, direction: direction, facts: facts
        )
    }

    private func event(
        _ id: ConnectionID,
        _ kind: ConnectionEventKind,
        _ provenances: [SessionFrameProvenance],
        direction: ConnectionDirection? = nil,
        facts: TCPSegmentFacts? = nil
    )
        -> ConnectionEvent
    {
        precondition(!provenances.isEmpty)
        // The completing frame's own capture time — `nil` when it carried none.
        // There is deliberately no epoch fallback here.
        let timestamp = provenances.last?.timestamp
        return ConnectionEvent(
            connectionID: id, kind: kind, timestamp: timestamp,
            provenance: provenances[0], relatedProvenance: Array(provenances.dropFirst()),
            direction: direction, facts: facts
        )
    }

    private func finMask(_ direction: ConnectionDirection) -> FINDirection {
        direction == .aToB ? .aToB : .bToA
    }
}

// MARK: - ConnectionState

/// The mutable working state for one connection while it is live. It is folded
/// frame by frame and converted to an immutable `ConnectionSummary` on publish.
///
/// It owns exactly two `TCPSequenceTracker`s — one per canonical direction —
/// selected by `foldSequence`, plus two per-direction `TCPApplicationPrefixProbe`s
/// selected by `foldApplication`. The trackers order byte-free sequence space; the
/// probes recover a bounded first-record application prefix in the disjoint
/// `payloadSequence`/byte coordinate space. Neither store outlives this working
/// state: both are released together at publication/eviction.
nonisolated private struct ConnectionState {
    // MARK: Lifecycle

    init(
        id: ConnectionID,
        tuple: FiveTuple,
        provenance: SessionFrameProvenance,
        trackerConfiguration: TCPSequenceTracker.Configuration,
        applicationProbe: TCPApplicationPrefixProbe
    ) {
        self.id = id
        self.tuple = tuple
        firstProvenance = provenance
        lastProvenance = provenance
        sequenceAToB = TCPSequenceTracker(configuration: trackerConfiguration)
        sequenceBToA = TCPSequenceTracker(configuration: trackerConfiguration)
        applicationAToB = applicationProbe
        applicationBToA = applicationProbe
    }

    // MARK: Internal

    let id: ConnectionID
    let tuple: FiveTuple
    let firstProvenance: SessionFrameProvenance
    var lastProvenance: SessionFrameProvenance

    /// Per-direction ordering trackers, chosen by `foldSequence`. `aToB` folds
    /// frames from the canonically-smaller endpoint; `bToA` the reverse.
    var sequenceAToB: TCPSequenceTracker
    var sequenceBToA: TCPSequenceTracker
    /// The connection-wide acknowledgement/window tracker, advanced by
    /// `foldFlowControl` after the direction tracker on every segment. It holds
    /// only per-direction scalars — never bytes — and is released with this state.
    var flowControl = TCPFlowControlTracker()

    /// Per-direction first-record application probes, chosen by `foldApplication`.
    /// They hold raw payload bytes (in `payloadSequence` coordinates) only until the
    /// first record classifies or a bound overflows.
    var applicationAToB: TCPApplicationPrefixProbe
    var applicationBToA: TCPApplicationPrefixProbe
    /// The directions for which an `.applicationRecord` availability event has
    /// already been emitted, so later richer handoffs never spam duplicates.
    var applicationRecordEmitted: Set<ConnectionDirection> = []

    var initiator: ConnectionDirection?
    var initiatorISN: UInt32?
    var responderISN: UInt32?
    var synProvenance: SessionFrameProvenance?
    var synAckProvenance: SessionFrameProvenance?

    var phase: ConnectionPhase = .opening
    var handshake: HandshakeObservation = .none
    var finDirections: FINDirection = []
    var closeReason: ConnectionCloseReason?

    var packetCount: UInt64 = 0
    var capturedByteTotal: UInt64 = 0
    var originalByteTotal: UInt64 = 0
    var lossKnowledge: CaptureLossKnowledge = .unknown
    var limitations: ConnectionLimitations = []

    var events: [ConnectionEvent] = []
    var omittedEventCount: UInt64 = 0

    var isTerminal: Bool {
        phase == .closed
    }

    /// Fold one segment through the tracker for its canonical direction and return
    /// the tracker's verdict. This is the single point where a direction's tracker
    /// is advanced, so every segment folds exactly once.
    mutating func foldSequence(
        direction: ConnectionDirection,
        facts: TCPSegmentFacts
    )
        -> TCPSequenceTracker.Output
    {
        switch direction {
        case .aToB:
            sequenceAToB.ingest(facts)
        case .bToA:
            sequenceBToA.ingest(facts)
        }
    }

    /// Fold one segment through the connection's flow-control tracker and return
    /// the acknowledgement/window shapes it matched. Called exactly once per
    /// segment, after `foldSequence`, whose keep-alive verdict it needs.
    mutating func foldFlowControl(
        direction: ConnectionDirection,
        facts: TCPSegmentFacts,
        keepAlive: Bool,
        retransmission: Bool
    )
        -> TCPFlowControlTracker.Observations
    {
        flowControl.ingest(
            direction: direction, facts: facts, keepAlive: keepAlive, retransmission: retransmission
        )
    }

    /// Fold one segment's payload through the probe for its canonical direction and
    /// report the probe outcome plus whether this is the first availability of
    /// application metadata for the direction (the only time an `.applicationRecord`
    /// event is emitted). This is the single point where a direction's probe is
    /// advanced, so every segment folds exactly once.
    mutating func foldApplication(
        direction: ConnectionDirection,
        payloadSequence: UInt32,
        payload: [UInt8],
        sourcePort: UInt16,
        destinationPort: UInt16,
        packetIsClassified: Bool
    )
        -> (outcome: TCPApplicationPrefixProbe.Outcome, firstAvailability: Bool)
    {
        let outcome: TCPApplicationPrefixProbe.Outcome = switch direction {
        case .aToB:
            applicationAToB.ingest(
                payloadSequence: payloadSequence, payload: payload,
                sourcePort: sourcePort, destinationPort: destinationPort,
                packetIsClassified: packetIsClassified
            )
        case .bToA:
            applicationBToA.ingest(
                payloadSequence: payloadSequence, payload: payload,
                sourcePort: sourcePort, destinationPort: destinationPort,
                packetIsClassified: packetIsClassified
            )
        }
        var firstAvailability = false
        if outcome.application != nil, !applicationRecordEmitted.contains(direction) {
            applicationRecordEmitted.insert(direction)
            firstAvailability = true
        }
        return (outcome, firstAvailability)
    }

    func summary() -> ConnectionSummary {
        ConnectionSummary(
            id: id,
            tuple: tuple,
            firstProvenance: firstProvenance,
            lastProvenance: lastProvenance,
            initiator: initiator,
            phase: phase,
            handshake: handshake,
            finDirections: finDirections,
            closeReason: closeReason,
            packetCount: packetCount,
            capturedByteTotal: capturedByteTotal,
            originalByteTotal: originalByteTotal,
            lossKnowledge: lossKnowledge,
            limitations: limitations,
            events: events,
            omittedEventCount: omittedEventCount
        )
    }
}
