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
    // MARK: Internal

    /// Distinct five-tuples currently accumulated. This grows with the number of
    /// sessions, never with the number of decoded packet objects. Exposed so a
    /// test can assert repeated packets do not create more session entries.
    var sessionCount: Int {
        order.count
    }

    /// Fold DNS learning plus one decoded packet's per-session state. Decodes
    /// nothing and stores no packet array — only the running summary state.
    mutating func add(_ packet: DecodedPacket) {
        SessionBuilder.learnResolved(from: packet, into: &resolved)
        guard let key = packet.fiveTuple else {
            return
        }
        if states[key] == nil {
            order.append(key)
            states[key] = State(first: packet)
        } else {
            states[key]?.merge(packet)
        }
    }

    /// Emit summaries in first-seen five-tuple order. Pure; decodes nothing and
    /// reads the final resolved map, so a session's host can resolve via an IP
    /// learned from a later packet in a different session — matching the batch.
    func summaries() -> [SessionSummary] {
        order.compactMap { states[$0]?.summary(key: $0, resolved: resolved) }
    }

    /// Clears every accumulated session and the DNS map. Called at capture
    /// boundaries.
    mutating func reset() {
        order.removeAll(keepingCapacity: false)
        states.removeAll(keepingCapacity: false)
        resolved.removeAll(keepingCapacity: false)
    }

    // MARK: Private

    /// Five-tuples in first-seen order, so summaries emit oldest→newest and rows
    /// stay put as a live capture grows.
    private var order: [FiveTuple] = []
    private var states: [FiveTuple: State] = [:]
    /// IP → hostname learned from DNS responses, accumulated across the capture.
    private var resolved: [String: String] = [:]
}

// MARK: SessionAccumulator.State

private extension SessionAccumulator {
    /// The running per-session state — the minimum needed to reproduce the batch
    /// session summary, folded one packet at a time.
    nonisolated struct State {
        // MARK: Lifecycle

        init(first packet: DecodedPacket) {
            earliest = packet
            latestTime = packet.timestamp
            rich = packet
            fold(packet)
        }

        // MARK: Internal

        /// Fold a subsequent packet of the same five-tuple. `merge` also updates
        /// the representatives; the first packet is folded via `fold` directly
        /// from `init`, where the representatives are already seeded.
        mutating func merge(_ packet: DecodedPacket) {
            // Earliest packet: a strictly-smaller timestamp wins, so equal
            // timestamps keep the first-seen packet — matching `sorted.first`.
            if packet.timestamp < earliest.timestamp {
                earliest = packet
            }
            // Latest instant: `>=` lets an equal timestamp advance to the
            // last-seen packet — matching `sorted.last`.
            if packet.timestamp >= latestTime {
                latestTime = packet.timestamp
            }
            // Richest representative: only a strictly-greater layer count wins, so
            // ties keep the first-seen packet — matching `packets.max(by:)`.
            if rich.layers.count < packet.layers.count {
                rich = packet
            }
            fold(packet)
        }

        func summary(key: FiveTuple, resolved: [String: String]) -> SessionSummary {
            let client = earliest.sourceEndpoint
            let server = earliest.destinationEndpoint

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
            let duration = max(0, latestTime.timeIntervalSince(earliest.timestamp))

            return SessionSummary(
                id: id,
                startTime: earliest.timestamp,
                duration: duration,
                processName: processName,
                host: host,
                sourceEndpoint: client?.display ?? "—",
                destinationEndpoint: server?.display ?? "—",
                protocolStack: protocolStack,
                status: status,
                latencyMilliseconds: latency,
                bytesUp: bytesUp,
                bytesDown: bytesDown,
                decodedLayers: rich.layers,
                representativeBytes: rich.rawBytes,
                sni: sni,
                dnsQuery: dnsQuery,
                dnsAnswers: dnsAnswers
            )
        }

        // MARK: Private

        /// Earliest packet by timestamp (first-seen tie-break) — drives direction
        /// (client/server) and the session start.
        private var earliest: DecodedPacket
        /// Latest instant by timestamp (last-seen tie-break) — drives duration.
        private var latestTime: Date
        /// Richest packet by layer count (first-seen tie-break) — drives the
        /// decoded layers, protocol stack, and host resolution inputs.
        private var rich: DecodedPacket

        /// Cumulative `originalLength` per source endpoint. Within a canonical
        /// five-tuple this holds at most the two directions; "up" vs "down" is
        /// resolved at summary time against the final client endpoint.
        private var bytesBySource: [IPEndpoint?: Int] = [:]
        private var totalBytes = 0

        private var sni: String?
        private var dnsQuery: String?
        private var processName: String?
        private var dnsAnswers: [String] = []

        /// Earliest DNS query (no answers) / response (with answers) instants, for
        /// the DNS handshake latency. Min timestamp, first-seen tie-break.
        private var dnsQueryTime: Date?
        private var dnsResponseTime: Date?

        private var anyAppProtocol = false
        private var anyTCPRST = false

        private var status: SessionStatus {
            if anyTCPRST {
                return .error
            }
            if !anyAppProtocol, rich.transport == .tcp {
                return .warning
            }
            return .ok
        }

        private var latency: Double? {
            guard let query = dnsQueryTime, let response = dnsResponseTime, response > query else {
                return nil
            }
            return response.timeIntervalSince(query) * 1_000
        }

        private static func hasTCPRST(_ packet: DecodedPacket) -> Bool {
            packet.layers.contains { layer in
                layer.proto == .tcp && (layer.fields.first { $0.name == "Flags" }?.value.contains("RST") ?? false)
            }
        }

        /// Fold the parts of a packet that accumulate the same way for the first
        /// and every subsequent packet: byte tallies, the "firsts", DNS answers
        /// and timing, and the status inputs.
        private mutating func fold(_ packet: DecodedPacket) {
            bytesBySource[packet.sourceEndpoint, default: 0] += packet.originalLength
            totalBytes += packet.originalLength

            if sni == nil, let value = packet.sni {
                sni = value
            }
            if dnsQuery == nil, let query = packet.dnsQuery, !query.isEmpty {
                dnsQuery = query
            }
            if processName == nil, let name = packet.processName, !name.isEmpty {
                processName = name
            }
            dnsAnswers.append(contentsOf: packet.dnsAnswers)

            if packet.appProtocol == .dns {
                if packet.dnsAnswers.isEmpty {
                    dnsQueryTime = earlier(dnsQueryTime, packet.timestamp)
                } else {
                    dnsResponseTime = earlier(dnsResponseTime, packet.timestamp)
                }
            }

            if packet.appProtocol != nil {
                anyAppProtocol = true
            }
            if !anyTCPRST, Self.hasTCPRST(packet) {
                anyTCPRST = true
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
