import Foundation

// MARK: - SessionAccumulator

/// Incremental accumulation of decoded packets into session summaries without a
/// decoded-packet history.
///
/// The batch `SessionBuilder.build` and the live `LiveSessionEngine` both fold
/// packets through *this* type, so an incremental snapshot equals a full batch
/// rebuild — the same code produces both. Crucially, it never retains packet
/// history: each five-tuple keeps only the running state a summary needs (two
/// representative packets, per-direction byte tallies, a handful of "firsts",
/// and the DNS answer values that the published summary itself retains). It does
/// not retain decoded-packet history, and nothing is ever re-decoded.
///
/// Every field mirrors the batch summary computation exactly, including its quirks
/// — first-seen tie-breaks, the "richest by layer count" representative,
/// first-non-empty-wins — because the incremental and batch paths must stay
/// indistinguishable.
nonisolated struct SessionAccumulator {
    // MARK: Lifecycle

    /// - Parameters:
    ///   - connectionConfiguration: bounds for the owned ``ConnectionTable``.
    ///     Injectable so bounds tests can force tiny caps; the default matches the
    ///     table's own production default. `reset` rebuilds the table with the same
    ///     configuration.
    ///   - datagramConfiguration: bounds for the owned ``DatagramEvidenceTable``,
    ///     injectable on the same terms. `reset` rebuilds it with this configuration.
    ///   - tlsConfiguration: bounds for the owned ``TLSEvidenceTable``, injectable on
    ///     the same terms. `reset` rebuilds it with this configuration.
    init(
        connectionConfiguration: ConnectionTable.Configuration = ConnectionTable.Configuration(),
        datagramConfiguration: DatagramEvidenceTable.Configuration = DatagramEvidenceTable.Configuration(),
        tlsConfiguration: TLSEvidenceTable.Configuration = TLSEvidenceTable.Configuration()
    ) {
        self.connectionConfiguration = connectionConfiguration
        self.datagramConfiguration = datagramConfiguration
        self.tlsConfiguration = tlsConfiguration
        connections = ConnectionTable(configuration: connectionConfiguration)
        datagrams = DatagramEvidenceTable(configuration: datagramConfiguration)
        tlsEvidence = TLSEvidenceTable(configuration: tlsConfiguration)
    }

    // MARK: Internal

    /// Distinct five-tuples currently accumulated. This grows with the number of
    /// sessions, never with the number of decoded packet objects. Exposed so a
    /// test can assert repeated packets do not create more session entries.
    var sessionCount: Int {
        order.count
    }

    /// A session-only fold of one already-decoded packet's per-frame metadata. It
    /// performs **no** cross-frame TCP reassembly — that is owned by the connection
    /// table and reaches session state only through ``add(_:context:)``. This
    /// compatibility seam has no production caller (batch/live/saved all use the
    /// context overload); it exists for focused tests of the session-only fold.
    ///
    /// - Returns: the folded packet's session id **only when this packet became
    ///   that session's representative** — either the first packet of a new
    ///   session, or a later packet that displaced the prior representative by
    ///   decoded-layer richness. Returns `nil` for a packet with no five-tuple, or
    ///   one that folded in without changing the representative. This is a
    ///   format-neutral selection signal: a streaming loader can map the id to the
    ///   current frame's evidence reference without retaining a per-frame index, and
    ///   Session imports no Capture types. `@discardableResult` so folds that ignore
    ///   it are unchanged.
    @discardableResult
    mutating func add(_ packet: DecodedPacket) -> UUID? {
        foldSession(packet, hasReassembledApplication: false, ordinal: nil, interfaceID: nil)
    }

    /// The common production fold shared by batch, live and saved paths. Assigns
    /// exactly one one-based capture ordinal in accepted-frame order, folds the
    /// existing session state and the owned connection table once each, and returns
    /// the same representative-session selection signal `add(_:)` reports.
    ///
    /// The ordinal is assigned per *accepted frame*, before any tuple/TCP filtering,
    /// so a non-TCP or tupleless frame still consumes its ordinal and capture order
    /// stays exact. The provenance's timestamp and original length come from the
    /// decoded packet (truthful per-frame values); the captured length, link type,
    /// optional locator and loss come from the format-neutral `context`.
    @discardableResult
    mutating func add(_ packet: DecodedPacket, context: SessionFrameContext) -> UUID? {
        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(nextOrdinal),
            timestamp: packet.timestamp,
            capturedLength: context.capturedLength,
            originalLength: packet.originalLength,
            linkType: context.linkType,
            locator: context.locator
        )
        // A capture cannot realistically exhaust UInt64 ordinals, but malformed
        // test input or a future long-lived source must still never wrap back to
        // zero and collide with earlier connection identities. Saturate at the
        // representable horizon; reset starts a new capture at one.
        if nextOrdinal < UInt64.max {
            nextOrdinal += 1
        }
        // Connection → metadata → session (mandatory order). Fold the connection
        // table once — the single owner of TCP ordering and first-record recovery —
        // then apply any returned application metadata to a local packet copy, then
        // fold session state once. Neither side is double-folded.
        let outcome = connections.ingest(packet, provenance: provenance, loss: context.loss)
        var enriched = packet
        let hasReassembledApplication: Bool
        if let application = outcome.application {
            Self.apply(application, to: &enriched)
            hasReassembledApplication = true
        } else {
            hasReassembledApplication = false
        }
        // Offer the enriched frame and the same provenance/loss to the datagram
        // table once, between the connection/application fold and the session fold.
        // The table retains only UDP DNS / ICMP facts and excludes-counts any
        // TCP-DNS fact (per-frame or the reassembled `dnsFacts` `apply` propagated).
        datagrams.offer(enriched, provenance: provenance, loss: context.loss)
        // Offer the *original* per-frame packet (its direct `tlsRecords` cite exactly
        // this frame) plus the connection's reassembled application handoff to the TLS
        // table, before the session fold. The table retains direct records only and
        // excludes-counts any multi-frame recovered records the handoff carries; the
        // recovered facts are never propagated onto `enriched`/the representative.
        tlsEvidence.offer(packet, application: outcome.application, provenance: provenance, loss: context.loss)
        let priorClient: IPEndpoint? = enriched.fiveTuple.flatMap { key in
            states[key]?.orientedEndpoints(proto: key.proto).client
        }
        let selection = foldSession(
            enriched,
            hasReassembledApplication: hasReassembledApplication,
            ordinal: provenance.ordinal,
            interfaceID: context.interfaceID
        )
        if let key = enriched.fiveTuple,
           let priorClient,
           let currentClient = states[key]?.orientedEndpoints(proto: key.proto).client,
           priorClient != currentClient
        {
            // Earlier columns were folded under a different client direction.
            // Their total bytes remain exact, but a directional split would
            // present provisional assignments as final session facts.
            trafficTimeline.markDirectionUnstable()
        }
        // Every accepted frame reaches the capture-wide traffic timeline once, after
        // the session fold so its direction is judged against the client the
        // session knows at this point. A tupleless frame still carries wire bytes
        // and is counted as unattributed rather than dropped.
        trafficTimeline.add(
            timestamp: packet.timestamp,
            originalLength: packet.originalLength,
            direction: trafficDirection(of: enriched)
        )
        return selection
    }

    /// Emit summaries in first-seen five-tuple order. Pure; decodes nothing and
    /// reads the final resolved map, so a session's host can resolve via an IP
    /// learned from a later packet in a different session — matching the batch.
    func summaries() -> [SessionSummary] {
        order.compactMap { states[$0]?.summary(key: $0, resolved: resolved) }
    }

    /// A first-observed-ordered snapshot of the owned connection table for the
    /// frames folded so far. Pure; decodes nothing.
    func connectionSnapshot() -> ConnectionTable.Snapshot {
        connections.snapshot()
    }

    /// The additive common-fold snapshot: the unchanged session summaries, the
    /// connection snapshot and the datagram evidence for the same accepted frames.
    /// Pure; decodes nothing. Each owned table is snapshotted exactly once here.
    func foldSnapshot() -> SessionFoldSnapshot {
        SessionFoldSnapshot(
            sessions: summaries(),
            connections: connections.snapshot(),
            datagramEvidence: datagrams.snapshot(),
            tlsEvidence: tlsEvidence.snapshot(),
            trafficTimeline: trafficTimeline.timeline()
        )
    }

    /// Clears every accumulated session, the DNS map, the connection table, the
    /// datagram evidence table and the TLS evidence table, and restarts the capture
    /// ordinal at 1. Called at capture boundaries so table state and the ordinal reset
    /// together; each table is rebuilt from its preserved configuration.
    mutating func reset() {
        order.removeAll(keepingCapacity: false)
        states.removeAll(keepingCapacity: false)
        resolved.removeAll(keepingCapacity: false)
        connections = ConnectionTable(configuration: connectionConfiguration)
        datagrams = DatagramEvidenceTable(configuration: datagramConfiguration)
        tlsEvidence = TLSEvidenceTable(configuration: tlsConfiguration)
        trafficTimeline.reset()
        nextOrdinal = 1
    }

    // MARK: Private

    /// Five-tuples in first-seen order, so summaries emit oldest→newest and rows
    /// stay put as a live capture grows.
    private var order: [FiveTuple] = []
    private var states: [FiveTuple: State] = [:]
    /// IP → hostname learned from DNS responses, accumulated across the capture.
    private var resolved: [String: String] = [:]

    /// The single owned connection table folded in lock-step with the session
    /// state. Rebuilt from `connectionConfiguration` on `reset`.
    private var connections: ConnectionTable
    private let connectionConfiguration: ConnectionTable.Configuration
    /// The single owned datagram evidence table, folded once per accepted frame
    /// beside the connection table. Rebuilt from `datagramConfiguration` on `reset`.
    private var datagrams: DatagramEvidenceTable
    private let datagramConfiguration: DatagramEvidenceTable.Configuration
    /// The single owned TLS evidence table, folded once per accepted frame beside the
    /// connection and datagram tables. Rebuilt from `tlsConfiguration` on `reset`.
    private var tlsEvidence: TLSEvidenceTable
    private let tlsConfiguration: TLSEvidenceTable.Configuration
    /// The one-based capture ordinal handed to the next common-path frame, in
    /// accepted-frame order. Independent of batch chunking and of timestamp order.
    private var nextOrdinal: UInt64 = 1
    /// Bounded capture-wide bytes-over-time, folded once per common-path frame
    /// beside the tables. Reset with them at every capture boundary.
    private var trafficTimeline = TrafficTimelineAccumulator()

    /// Apply the connection table's bounded first-record application metadata to a
    /// local packet copy. This is the exact enrichment the session-owned reassembler
    /// used to perform inline, moved to the single connection owner: the reassembled
    /// application layers replace any same-protocol per-frame layer and carry no
    /// frame byte ranges (their bytes span multiple frames).
    private static func apply(_ metadata: PacketDecoder.ReassembledTCPApplication, to packet: inout DecodedPacket) {
        packet.appProtocol = metadata.appProtocol
        packet.sni = metadata.sni ?? packet.sni
        packet.dnsQuery = metadata.dnsQuery ?? packet.dnsQuery
        if !metadata.dnsAnswers.isEmpty {
            packet.dnsAnswers = metadata.dnsAnswers
        }
        // Propagate any reassembled DNS fixed-header facts transiently onto this
        // local copy. Session state ignores `dnsFacts`, so summaries/digests are
        // unchanged; it exists solely so the datagram table can excluded-count a
        // reassembled TCP-DNS fact whose frame the prefix probe did not fully cite.
        packet.dnsFacts = metadata.dnsFacts ?? packet.dnsFacts
        packet.dnsAnswersOmittedCount = max(packet.dnsAnswersOmittedCount, metadata.dnsAnswersOmittedCount)
        packet.layers.removeAll { $0.proto == metadata.appProtocol }
        packet.layers.append(contentsOf: metadata.layers)
    }

    /// A frame's direction relative to the client of the session it just folded
    /// into — the same client `SessionSummary.bytesUp` is measured against.
    private func trafficDirection(of packet: DecodedPacket) -> TrafficDirection {
        guard let key = packet.fiveTuple, let state = states[key] else {
            return .unattributed
        }
        return packet.sourceEndpoint == state.orientedEndpoints(proto: key.proto).client ? .sent : .received
    }

    // MARK: Private session fold

    /// Fold DNS learning plus one packet's per-session state, updating the richest
    /// representative. `hasReassembledApplication` is `true` only when the packet was
    /// enriched by the connection table's first-record probe, so a reassembly-driven
    /// application handoff can displace a representative even without a strictly
    /// larger layer count.
    private mutating func foldSession(
        _ packet: DecodedPacket,
        hasReassembledApplication: Bool,
        ordinal: FrameOrdinal?,
        interfaceID: Int?
    )
        -> UUID?
    {
        SessionBuilder.learnResolved(from: packet, into: &resolved)
        guard let key = packet.fiveTuple else {
            return nil
        }
        let becameRepresentative: Bool
        if var state = states[key] {
            becameRepresentative = state.merge(packet, hasReassembledApplication: hasReassembledApplication)
            state.noteInterface(interfaceID)
            states[key] = state
        } else {
            order.append(key)
            var state = State(first: packet, ordinal: ordinal)
            state.noteInterface(interfaceID)
            states[key] = state
            becameRepresentative = true
        }
        return becameRepresentative ? SessionBuilder.sessionID(for: key) : nil
    }
}

// MARK: SessionAccumulator.State

private extension SessionAccumulator {
    /// The running per-session state — the minimum needed to reproduce the batch
    /// session summary, folded one packet at a time.
    nonisolated struct State {
        // MARK: Lifecycle

        /// The packet is already enriched (or not) before it reaches session state:
        /// the connection table's first-record probe applies any reassembled
        /// application metadata upstream, so this fold never reassembles.
        init(first packet: DecodedPacket, ordinal: FrameOrdinal?) {
            earliest = packet
            firstSource = packet.sourceEndpoint
            firstDestination = packet.destinationEndpoint
            latestTime = packet.timestamp
            rich = packet
            firstOrdinal = ordinal
            fold(packet)
        }

        // MARK: Internal

        /// Apply the same current orientation to the traffic timeline and the
        /// published summary. A server-first capture must not put its first
        /// bytes in the client-sent series while the session calls them received.
        func orientedEndpoints(proto: ProtocolKind) -> (client: IPEndpoint?, server: IPEndpoint?) {
            let observedClient = untimedFrameCount > 0 ? firstSource : earliest.sourceEndpoint
            let observedServer = untimedFrameCount > 0 ? firstDestination : earliest.destinationEndpoint
            return Self.orient(
                client: observedClient, server: observedServer, synSource: synSource, proto: proto
            )
        }

        /// Fold a subsequent packet of the same five-tuple. `merge` also updates
        /// the representatives; the first packet is folded via `fold` directly
        /// from `init`, where the representatives are already seeded.
        ///
        /// - Parameter hasReassembledApplication: whether the connection table's
        ///   first-record probe enriched this packet, so a richer application
        ///   handoff can displace the representative even without a larger layer
        ///   count.
        /// - Returns: `true` when this packet displaced the richest representative
        ///   (by layer count, or by reassembly-driven application richness), so a
        ///   caller can map the session id to this packet's frame reference.
        @discardableResult
        mutating func merge(_ packet: DecodedPacket, hasReassembledApplication: Bool) -> Bool {
            // Earliest packet: a strictly-smaller timestamp wins, so equal
            // timestamps keep the first-seen packet — matching `sorted.first`.
            // Untimed packets never participate in this comparison. A mixed
            // session uses the separately retained first endpoint pair below.
            if let candidate = packet.timestamp, let current = earliest.timestamp, candidate < current {
                earliest = packet
            }
            // Latest instant: `>=` lets an equal timestamp advance to the
            // last-seen packet — matching `sorted.last`. An untimed packet cannot
            // advance an instant it does not have.
            if let candidate = packet.timestamp, candidate >= (latestTime ?? candidate) {
                latestTime = candidate
            }
            // Richest representative: only a strictly-greater layer count wins, so
            // ties keep the first-seen packet — matching `packets.max(by:)`.
            var becameRepresentative = false
            if rich.layers.count < packet.layers.count
                || (hasReassembledApplication && applicationRichness(packet) > applicationRichness(rich))
            {
                rich = packet
                becameRepresentative = true
            }
            fold(packet)
            return becameRepresentative
        }

        func summary(key: FiveTuple, resolved: [String: String]) -> SessionSummary {
            let (client, server) = orientedEndpoints(proto: key.proto)

            let httpHost = rich.layers.first { $0.proto == .http }?
                .fields.first { $0.name == "Host" }?.value
            let serverIP = server?.ip ?? ""
            let host = SessionBuilder.resolveHost(
                appProto: rich.appProtocol, dnsQuery: dnsQuery, sni: sni,
                httpHost: httpHost, serverIP: serverIP, resolved: resolved, clientIP: client?.ip
            )

            // Bytes are tallied by actual source endpoint, so "up" (the client's
            // direction) is chosen against the final earliest packet — identical
            // to the batch summing `originalLength` where `source == client`.
            let bytesUp = bytesBySource[client] ?? 0
            let bytesDown = totalBytes - bytesUp

            let stack = rich.protocolStack.filter { $0 != .ipv4 && $0 != .ipv6 }
            let protocolStack: [ProtocolKind] = stack.isEmpty ? [rich.transport ?? .other] : stack
            let id = SessionBuilder.sessionID(for: key)
            // One untimed contributing frame makes the session's own span unknown:
            // a start/duration derived from the timed subset would silently claim
            // the whole session. Bytes, direction and every other fact are retained.
            let start: Date? = untimedFrameCount > 0 ? nil : earliest.timestamp
            let duration: TimeInterval? = if untimedFrameCount > 0 {
                nil
            } else if let latestTime, let first = earliest.timestamp {
                max(0, latestTime.timeIntervalSince(first))
            } else {
                nil
            }

            return SessionSummary(
                id: id,
                startTime: start,
                duration: duration,
                processName: processName,
                host: host,
                sourceEndpoint: client?.display ?? "—",
                destinationEndpoint: server?.display ?? "—",
                sourceEndpointValue: client,
                destinationEndpointValue: server,
                protocolStack: protocolStack,
                status: status,
                latencyMilliseconds: latency,
                bytesUp: bytesUp,
                bytesDown: bytesDown,
                decodedLayers: rich.layers,
                representativeBytes: rich.rawBytes,
                sni: sni,
                dnsQuery: dnsQuery,
                dnsAnswers: dnsAnswers,
                dnsAnswersOmittedCount: dnsAnswersOmittedCount,
                firstCaptureOrdinal: firstOrdinal?.rawValue,
                untimedFrameCount: untimedFrameCount,
                captureInterfaceIDs: interfaceIDs.sorted(),
                captureInterfaceOverflow: interfaceOverflow
            )
        }

        /// Record which capture interface a contributing frame came from. Bounded
        /// to ``SessionSummary/maxCaptureInterfaces`` distinct ids; further ids set
        /// the overflow flag rather than growing the set.
        mutating func noteInterface(_ interfaceID: Int?) {
            guard let interfaceID else {
                return
            }
            if interfaceIDs.contains(interfaceID) {
                return
            }
            if interfaceIDs.count < SessionSummary.maxCaptureInterfaces {
                interfaceIDs.insert(interfaceID)
            } else {
                interfaceOverflow = true
            }
        }

        // MARK: Private

        /// Largest number of unique DNS answers a session publishes, in first-seen
        /// order. Beyond this, further unique answers are counted, not stored.
        private static let dnsAnswerPublicationCap = 64

        /// IANA system ports plus the registered service ports a client on this
        /// Mac commonly dials. A session whose *first captured* frame came from one
        /// of these while the other end used an ephemeral port was almost certainly
        /// captured mid-stream from the server side; the same likely-server-port
        /// rule Zeek uses to orient a connection (concept only).
        private static let likelyServerPorts: Set<UInt16> = [
            1_080, 1_194, 1_433, 1_521, 3_128, 3_306, 3_389, 5_060, 5_061, 5_222, 5_223, 5_228,
            5_432, 5_900, 6_379, 8_000, 8_080, 8_443, 8_883, 27_017,
        ]

        /// Earliest packet by timestamp (first-seen tie-break), used for fully
        /// timed session direction/start. Mixed sessions use the first endpoint
        /// pair and expose unknown timing instead.
        private var earliest: DecodedPacket
        private let firstSource: IPEndpoint?
        private let firstDestination: IPEndpoint?
        /// Latest known instant (last-seen tie-break) — drives duration. `nil` while
        /// no contributing packet has carried a capture time.
        private var latestTime: Date?
        /// Richest packet by layer count (first-seen tie-break) — drives the
        /// decoded layers, protocol stack, and host resolution inputs.
        private var rich: DecodedPacket
        /// Capture ordinal of the first frame folded into this session. Used only as
        /// a deterministic source-order fallback for ordering; never elapsed time.
        private let firstOrdinal: FrameOrdinal?
        /// Contributing frames that carried no capture time. One is enough to make
        /// the session's start, duration and latency unknown.
        private var untimedFrameCount = 0
        private var interfaceIDs: Set<Int> = []
        private var interfaceOverflow = false
        /// The endpoint that sent the first pure SYN, when one was captured: the
        /// strongest evidence of which side opened the connection.
        private var synSource: IPEndpoint?

        /// Cumulative `originalLength` per source endpoint. Within a canonical
        /// five-tuple this holds at most the two directions; "up" vs "down" is
        /// resolved at summary time against the final client endpoint.
        private var bytesBySource: [IPEndpoint?: Int] = [:]
        private var totalBytes = 0

        private var sni: String?
        private var dnsQuery: String?
        private var processName: String?
        /// Unique published answers in first-seen order, bounded by the publication
        /// cap. Dedup scans this bounded list, so no unbounded Set is retained.
        private var dnsAnswers: [String] = []
        /// Answer-record occurrences omitted because a decode/publication cap was
        /// reached. This does not claim exact unique cardinality after the retained
        /// list fills, which would require unbounded state.
        private var dnsAnswersOmittedCount = 0

        /// Earliest DNS query (no answers) / response (with answers) instants, for
        /// the DNS handshake latency. Min timestamp, first-seen tie-break.
        private var dnsQueryTime: Date?
        private var dnsResponseTime: Date?

        private var anyTCPRST = false

        private var status: SessionStatus {
            // Only observed evidence sets status. An explicit TCP RST is a real
            // reset and reads as an error. The absence of a decoded application
            // protocol is *not* evidence of anything — a bare SYN, a midstream
            // TCP payload we could not classify, or a tunnel we do not parse are
            // all normal traffic, so they stay `.ok` rather than being invented
            // into a warning that then feeds Security/findings.
            anyTCPRST ? .error : .ok
        }

        /// The DNS handshake latency, and only when every contributing frame was
        /// timed: an interval measured across a session with a missing instant
        /// would be an inference from an input we do not have.
        private var latency: Double? {
            guard untimedFrameCount == 0,
                  let query = dnsQueryTime,
                  let response = dnsResponseTime,
                  response > query else
            {
                return nil
            }
            return response.timeIntervalSince(query) * 1_000
        }

        /// A reset is decided from the typed control bits, never a rendered "Flags"
        /// string — a display value can never spoof a real RST.
        private static func hasTCPRST(_ packet: DecodedPacket) -> Bool {
            packet.tcpFacts?.flags.contains(.rst) ?? false
        }

        private static func isLikelyServerPort(_ port: UInt16) -> Bool {
            port != 0 && (port < 1_024 || likelyServerPorts.contains(port))
        }

        /// Decide which observed endpoint is the client. A captured SYN names the
        /// opener outright. Without one, a connection first seen from a service
        /// port toward an ephemeral port is flipped so the remote service — not
        /// this Mac's ephemeral socket — reads as the host. Anything else keeps
        /// the first-observed direction: nothing is inferred from two ephemeral
        /// or two service ports, and port-0 sessions (ARP, ICMP) never flip.
        private static func orient(
            client: IPEndpoint?, server: IPEndpoint?, synSource: IPEndpoint?, proto: ProtocolKind
        )
            -> (client: IPEndpoint?, server: IPEndpoint?)
        {
            guard let client, let server else {
                return (client, server)
            }
            if let synSource {
                return synSource == server ? (server, client) : (client, server)
            }
            guard proto == .tcp || proto == .udp,
                  isLikelyServerPort(client.port), !isLikelyServerPort(server.port) else
            {
                return (client, server)
            }
            return (server, client)
        }

        private func applicationRichness(_ packet: DecodedPacket) -> Int {
            func layerScore(_ layer: DecodedLayer) -> Int {
                layer.fields.count + layer.children.reduce(0) { $0 + 1 + layerScore($1) }
            }
            return packet.layers.reduce(0) { $0 + layerScore($1) }
                + (packet.sni == nil ? 0 : 100)
                + (packet.dnsQuery == nil ? 0 : 50)
        }

        /// Fold the parts of a packet that accumulate the same way for the first
        /// and every subsequent packet: byte tallies, the "firsts", DNS answers
        /// and timing, and the status inputs.
        private mutating func fold(_ packet: DecodedPacket) {
            bytesBySource[packet.sourceEndpoint, default: 0] += packet.originalLength
            totalBytes += packet.originalLength
            if packet.timestamp == nil {
                untimedFrameCount += 1
            }

            if sni == nil, let value = packet.sni {
                sni = value
            }
            if dnsQuery == nil, let query = packet.dnsQuery, !query.isEmpty {
                dnsQuery = query
            }
            if processName == nil, let name = packet.processName, !name.isEmpty {
                processName = name
            }
            // Publish unique answers in first-seen order, deduped against the
            // bounded published list (never an unbounded Set). A duplicate is
            // deduplication, not an omission. After the list fills, each unretained
            // answer occurrence is counted; records dropped at decode time are
            // folded in too.
            for answer in packet.dnsAnswers {
                if dnsAnswers.contains(answer) {
                    continue
                }
                if dnsAnswers.count < Self.dnsAnswerPublicationCap {
                    dnsAnswers.append(answer)
                } else {
                    dnsAnswersOmittedCount += 1
                }
            }
            dnsAnswersOmittedCount += packet.dnsAnswersOmittedCount

            // Only a timed DNS frame can contribute a handshake instant. The
            // header's QR bit decides query versus response; an answerless reply
            // (NXDOMAIN, NODATA, a refused query) is still the response that ends
            // the exchange, so it must not be mistaken for a second query.
            if packet.appProtocol == .dns, let instant = packet.timestamp {
                let isResponse = packet.dnsFacts?.isResponse ?? !packet.dnsAnswers.isEmpty
                if isResponse {
                    dnsResponseTime = earlier(dnsResponseTime, instant)
                } else {
                    dnsQueryTime = earlier(dnsQueryTime, instant)
                }
            }

            if !anyTCPRST, Self.hasTCPRST(packet) {
                anyTCPRST = true
            }
            if synSource == nil, let facts = packet.tcpFacts,
               facts.flags.contains(.syn), !facts.flags.contains(.ack)
            {
                synSource = packet.sourceEndpoint
            }
        }

        /// Keep the earlier of a stored instant and a candidate, preferring the
        /// stored one on a tie so the first-seen packet wins.
        private func earlier(_ stored: Date?, _ candidate: Date) -> Date {
            guard let stored else {
                return candidate
            }
            return candidate < stored ? candidate : stored
        }
    }
}
