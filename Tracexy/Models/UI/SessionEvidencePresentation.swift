import Foundation

// MARK: - SessionEvidenceItem

/// One literal, chronologically sortable row in the bottom Evidence facet.
///
/// The value is deliberately presentation-only: it keeps the already-bounded
/// Core fact and its exact provenance, but adds no finding, endpoint role, loss
/// cause, or TLS policy. A row may cite more than one frame (the completed TCP
/// handshake); every cited frame remains independently inspectable.
struct SessionEvidenceItem: Identifiable, Hashable {
    enum Kind: Hashable {
        case connection
        case tls
    }

    let id: String
    let kind: Kind
    let title: String
    let detail: String
    let timestamp: Date
    let ordinal: FrameOrdinal
    let provenance: [SessionFrameProvenance]

    var systemImage: String {
        switch kind {
        case .connection: "point.3.connected.trianglepath.dotted"
        case .tls: "lock.shield"
        }
    }

    var categoryLabel: String {
        switch kind {
        case .connection: "TCP"
        case .tls: "TLS"
        }
    }
}

extension SessionEvidenceItem {
    /// Merge retained connection events and direct-frame TLS observations on the
    /// capture's monotonic frame axis. Stable source-order tie breakers preserve
    /// deterministic display when several observations cite the same frame.
    static func timeline(
        connections: [ConnectionSummary],
        tls: TLSEvidenceSummary?
    )
        -> [SessionEvidenceItem]
    {
        var indexed: [(item: SessionEvidenceItem, sourceRank: Int, sourceIndex: Int)] = []

        for (connectionIndex, connection) in connections.enumerated() {
            for (eventIndex, event) in connection.events.enumerated() {
                let occurrence = event.occurrenceOrdinal
                indexed.append((
                    item: SessionEvidenceItem(
                        id: "connection-\(connection.id.rawValue.uuidString)-\(eventIndex)",
                        kind: .connection,
                        title: SessionEvidenceCopy.connectionEventTitle(event.kind),
                        detail: SessionEvidenceCopy.connectionEventDetail(
                            event,
                            tuple: connection.tuple,
                            incarnation: connectionIndex + 1,
                            incarnationCount: connections.count
                        ),
                        timestamp: event.timestamp,
                        ordinal: occurrence,
                        provenance: event.provenance
                    ),
                    sourceRank: 0,
                    sourceIndex: eventIndex
                ))
            }
        }

        if let tls {
            for (observationIndex, observation) in tls.observations.enumerated() {
                indexed.append((
                    item: SessionEvidenceItem(
                        id: "tls-\(observation.provenance.ordinal.rawValue)-"
                            + "\(observation.recordIndex)-\(observationIndex)",
                        kind: .tls,
                        title: SessionEvidenceCopy.tlsRecordTitle(observation.fact),
                        detail: SessionEvidenceCopy.tlsRecordDetail(observation),
                        timestamp: observation.provenance.timestamp,
                        ordinal: observation.provenance.ordinal,
                        provenance: [observation.provenance]
                    ),
                    sourceRank: 1,
                    sourceIndex: observationIndex
                ))
            }
        }

        return indexed.sorted { lhs, rhs in
            if lhs.item.ordinal != rhs.item.ordinal {
                return lhs.item.ordinal < rhs.item.ordinal
            }
            if lhs.sourceRank != rhs.sourceRank {
                return lhs.sourceRank < rhs.sourceRank
            }
            return lhs.sourceIndex < rhs.sourceIndex
        }.map(\.item)
    }
}

// MARK: - SessionEvidenceCopy

/// Fixed, neutral copy for the evidence UI. Keeping these mappings outside the
/// views makes the claims directly testable and prevents slightly different TLS
/// or coverage wording from appearing in the bottom and right inspectors.
nonisolated enum SessionEvidenceCopy {
    static func connectionEventTitle(_ kind: ConnectionEventKind) -> String {
        switch kind {
        case .firstObserved: "First frame observed"
        case .syn: "SYN observed"
        case .synAck: "SYN + ACK observed"
        case .handshakeCompleted: "Three-way handshake observed"
        case .payloadObserved: "TCP payload observed"
        case .fin: "FIN observed"
        case .rst: "Reset observed"
        case .lateSegmentAfterClose: "Late segment after close"
        case .ambiguousTupleReuse: "Ambiguous tuple reuse observed"
        case .stateEvicted: "Connection state evicted"
        case .sequenceAdvanced: "Sequence advanced"
        case .retransmission: "Retransmission observed"
        case .overlap: "Segment overlap observed"
        case .outOfOrderBuffered: "Out-of-order segment buffered"
        case .pendingDrained: "Buffered sequence gap drained"
        case .pendingOverflow: "Pending sequence bound reached"
        case .serialAmbiguous: "Sequence distance ambiguous"
        case .applicationRecord: "Application record identified"
        case .applicationProbeTruncated: "Application probe bound reached"
        }
    }

    static func connectionEventDetail(
        _ event: ConnectionEvent,
        tuple: FiveTuple,
        incarnation: Int,
        incarnationCount: Int
    )
        -> String
    {
        var parts: [String] = []
        if incarnationCount > 1 {
            parts.append("connection \(incarnation) of \(incarnationCount)")
        }
        if let direction = event.direction {
            parts.append(directionLabel(direction, tuple: tuple))
        }
        if event.payloadLength > 0 {
            parts.append("\(event.payloadLength.formatted()) payload bytes")
        }
        if let applicationKind = event.applicationKind {
            let completeness = event.applicationComplete == true ? "complete first record" : "partial first record"
            parts.append("\(applicationKind.label) · \(completeness)")
        }
        if event.provenance.count > 1 {
            parts.append("\(event.provenance.count) cited frames")
        }
        return parts.isEmpty ? "Retained connection observation" : parts.joined(separator: " · ")
    }

    static func directionLabel(_ direction: ConnectionDirection, tuple: FiveTuple) -> String {
        switch direction {
        case .aToB: "\(tuple.a.display) → \(tuple.b.display)"
        case .bToA: "\(tuple.b.display) → \(tuple.a.display)"
        }
    }

    static func phaseLabel(_ phase: ConnectionPhase) -> String {
        switch phase {
        case .opening: "Opening observed"
        case .active: "Active traffic observed"
        case .closing: "Closing observed"
        case .closed: "Terminal observation retained"
        }
    }

    static func handshakeLabel(_ handshake: HandshakeObservation) -> String {
        switch handshake {
        case .none: "Not observed"
        case .synObserved: "SYN observed"
        case .synAckObserved: "SYN + ACK observed"
        case .threeWayObserved: "Three-way handshake observed"
        }
    }

    static func lossLabel(_ loss: CaptureLossKnowledge) -> String {
        switch loss {
        case .unknown: "Capture loss unknown"
        case .noLossReported: "No loss reported for retained flow frames"
        case .lossReported: "Capture loss reported"
        }
    }

    static func closeReasonLabel(_ reason: ConnectionCloseReason?) -> String? {
        switch reason {
        case .none: nil
        case .orderly: "Bidirectional FIN observed"
        case let .reset(direction): "Reset observed · \(direction == .aToB ? "A → B" : "B → A")"
        case .stateEviction: "State evicted under bound"
        }
    }

    static func limitationLabels(_ limitations: ConnectionLimitations) -> [String] {
        var labels: [String] = []
        let values: [(ConnectionLimitations, String)] = [
            (.startUnobserved, "Connection start was not observed"),
            (.handshakeIncomplete, "Handshake evidence is incomplete"),
            (.payloadTruncated, "Snap-length truncation was observed"),
            (.ambiguousTupleReuse, "Tuple reuse could not be split confidently"),
            (.priorStateEvicted, "Earlier state for this tuple was evicted"),
            (.eventHistoryTruncated, "Older connection events were omitted"),
            (.counterOverflow, "A connection counter saturated"),
            (.sequenceGapObserved, "A sequence-space gap was observed"),
            (.serialDistanceAmbiguous, "A serial distance was ambiguous"),
            (.sequenceStateTruncated, "Sequence tracking state was truncated"),
            (.applicationProbeTruncated, "The bounded application probe was truncated"),
        ]
        for (flag, label) in values where limitations.contains(flag) {
            labels.append(label)
        }
        return labels
    }

    static func tlsRecordTitle(_ fact: TLSRecordFact) -> String {
        if let handshake = fact.handshake {
            switch handshake {
            case .clientHello: return "TLS ClientHello"
            case let .serverHello(server):
                return server.isHelloRetryRequest ? "TLS HelloRetryRequest" : "TLS ServerHello"
            }
        }
        return switch fact.contentType {
        case 20: "TLS ChangeCipherSpec record"
        case 21: "TLS Alert record"
        case 22: "TLS Handshake record"
        case 23: "TLS Application Data record"
        case 24: "TLS Heartbeat record"
        default: "TLS record type \(fact.contentType)"
        }
    }

    static func tlsRecordDetail(_ observation: TLSEvidenceObservation) -> String {
        let fact = observation.fact
        var parts = [
            directionLabel(observation.direction, tuple: observation.tuple),
            "record \(observation.recordIndex + 1)",
            "\(fact.capturedBodyLength.formatted())/\(fact.declaredBodyLength.formatted()) body bytes",
            fact.bodyComplete ? "body complete" : "body incomplete",
            "legacy record version \(versionLabel(fact.legacyRecordVersion))",
        ]

        switch fact.handshake {
        case let .clientHello(client):
            if client.offeredVersions.isEmpty {
                parts
                    .append(client
                        .extensionsComplete ? "no supported_versions values retained" : "extensions incomplete")
            } else {
                parts.append("offered \(client.offeredVersions.map(versionLabel).joined(separator: ", "))")
            }
            if client.offeredVersionsOmittedCount > 0 {
                parts.append("\(client.offeredVersionsOmittedCount) offered versions omitted")
            }
        case let .serverHello(server):
            parts.append(String(format: "cipher 0x%04X", server.selectedCipher))
            if server.isHelloRetryRequest {
                parts.append("retry request; no final version claimed")
            } else if let selectedVersion = server.selectedVersion {
                parts.append("selected \(versionLabel(selectedVersion))")
            } else {
                parts.append("selected version unavailable")
            }
        case .none:
            break
        }
        return parts.joined(separator: " · ")
    }

    static func versionLabel(_ rawValue: UInt16) -> String {
        let name: String? = switch rawValue {
        case 0x0300: "SSL 3.0"
        case 0x0301: "TLS 1.0"
        case 0x0302: "TLS 1.1"
        case 0x0303: "TLS 1.2"
        case 0x0304: "TLS 1.3"
        default: nil
        }
        let raw = String(format: "0x%04X", rawValue)
        return name.map { "\($0) (\(raw))" } ?? raw
    }
}
