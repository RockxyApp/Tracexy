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
        case dns
        case icmp
    }

    let id: String
    let kind: Kind
    let title: String
    let detail: String
    /// The cited frame's capture time, or `nil` when the capture file recorded
    /// none. Ordering is already the frame ordinal, so an unknown instant costs the
    /// chronology nothing and is never replaced by a stand-in.
    let timestamp: Date?
    let ordinal: FrameOrdinal
    let provenance: [SessionFrameProvenance]

    var systemImage: String {
        switch kind {
        case .connection: "point.3.connected.trianglepath.dotted"
        case .tls: "lock.shield"
        case .dns: "character.magnify"
        case .icmp: "exclamationmark.bubble"
        }
    }

    var categoryLabel: String {
        switch kind {
        case .connection: "TCP"
        case .tls: "TLS"
        case .dns: "DNS"
        case .icmp: "ICMP"
        }
    }
}

extension SessionEvidenceItem {
    /// Merge retained connection events, direct-frame TLS observations and retained
    /// DNS/ICMP datagram observations on the capture's monotonic frame axis. Stable
    /// source-order tie breakers preserve deterministic display when several
    /// observations cite the same frame.
    static func timeline(
        connections: [ConnectionSummary],
        tls: TLSEvidenceSummary?,
        datagrams: DatagramEvidenceSummary? = nil
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

        if let datagrams {
            for (observationIndex, observation) in datagrams.observations.enumerated() {
                let kind: Kind
                let title: String
                let detail: String
                switch observation.kind {
                case let .dns(facts):
                    kind = .dns
                    title = SessionEvidenceCopy.dnsMessageTitle(facts)
                    detail = SessionEvidenceCopy.dnsMessageDetail(facts, observation: observation)
                case let .icmp(facts):
                    kind = .icmp
                    title = SessionEvidenceCopy.icmpMessageTitle(facts)
                    detail = SessionEvidenceCopy.icmpMessageDetail(facts, observation: observation)
                }
                indexed.append((
                    item: SessionEvidenceItem(
                        id: "datagram-\(observation.provenance.ordinal.rawValue)-\(observationIndex)",
                        kind: kind,
                        title: title,
                        detail: detail,
                        timestamp: observation.provenance.timestamp,
                        ordinal: observation.provenance.ordinal,
                        provenance: [observation.provenance]
                    ),
                    sourceRank: 2,
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
        case .keepAlive: "Keep-alive probe observed"
        case .duplicateAcknowledgement: "Duplicate acknowledgement observed"
        case .fastRetransmission: "Fast retransmission observed"
        case .spuriousRetransmission: "Spurious retransmission observed"
        case .zeroWindow: "Zero window advertised"
        case .zeroWindowProbe: "Zero window probe observed"
        case .windowFull: "Receive window full"
        case .ackedUnseenSegment: "Acknowledged bytes the capture did not see"
        case .cleartextCredential: "Credentials sent without encryption"
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
            parts.append("\(applicationKind.label) (\(completeness))")
        }
        if event.provenance.count > 1 {
            parts.append("\(event.provenance.count) cited frames")
        }
        return parts.isEmpty ? "Retained connection observation" : parts.joined(separator: ", ")
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
        case let .reset(direction): "Reset observed \(direction == .aToB ? "A → B" : "B → A")"
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

    // MARK: Datagram copy

    /// The neutral title for one retained DNS observation. Only the fixed-header
    /// facts are available, so the title names the message shape and never a name,
    /// answer or resolver role.
    static func dnsMessageTitle(_ facts: DNSMessageFacts) -> String {
        if facts.opcode != 0 {
            return facts.isResponse ? "DNS opcode \(facts.opcode) response" : "DNS opcode \(facts.opcode) query"
        }
        return facts.isResponse ? "DNS response" : "DNS query"
    }

    static func dnsMessageDetail(
        _ facts: DNSMessageFacts,
        observation: DatagramEvidenceObservation
    )
        -> String
    {
        var parts = [
            directionLabel(observation.direction, tuple: observation.tuple),
            String(format: "transaction 0x%04X", facts.transactionID),
        ]
        if facts.isResponse {
            parts.append(dnsResponseCodeLabel(facts.responseCode))
            parts.append(facts.answerCount == 1 ? "1 answer record" : "\(facts.answerCount.formatted()) answer records")
            if facts.isAuthoritativeAnswer {
                parts.append("authoritative")
            }
        } else {
            parts.append(facts.questionCount == 1 ? "1 question" : "\(facts.questionCount.formatted()) questions")
            if facts.recursionDesired {
                parts.append("recursion desired")
            }
        }
        if facts.isTruncated {
            parts.append("truncated on the wire")
        }
        return parts.joined(separator: ", ")
    }

    static func dnsResponseCodeLabel(_ responseCode: UInt8) -> String {
        switch responseCode {
        case 0: "no error"
        case 1: "format error"
        case 2: "server failure"
        case 3: "name does not exist"
        case 4: "not implemented"
        case 5: "refused"
        default: "response code \(responseCode)"
        }
    }

    /// The neutral title for one retained ICMP observation, from the decoder's
    /// family/type facts only.
    static func icmpMessageTitle(_ facts: ICMPMessageFacts) -> String {
        "\(facts.family == .ipv6 ? "ICMPv6" : "ICMP") \(icmpTypeLabel(facts))"
    }

    static func icmpMessageDetail(
        _ facts: ICMPMessageFacts,
        observation: DatagramEvidenceObservation
    )
        -> String
    {
        var parts = [
            directionLabel(observation.direction, tuple: observation.tuple),
            "type \(facts.type) code \(facts.code)",
        ]
        if let quoted = facts.quotedFlow {
            parts.append("quotes \(quoted.proto.label) \(quoted.source.display) → \(quoted.destination.display)")
        }
        return parts.joined(separator: ", ")
    }

    /// Type names for the message shapes Tracexy's decoder retains. Anything else
    /// keeps its raw type number rather than a guessed name.
    static func icmpTypeLabel(_ facts: ICMPMessageFacts) -> String {
        switch (facts.family, facts.type) {
        case (.ipv4, 0): "echo reply"
        case (.ipv4, 3): facts.code == 4 ? "fragmentation needed" : "destination unreachable"
        case (.ipv4, 5): "redirect"
        case (.ipv4, 8): "echo request"
        case (.ipv4, 11): "time exceeded"
        case (.ipv6, 1): "destination unreachable"
        case (.ipv6, 2): "packet too big"
        case (.ipv6, 3): "time exceeded"
        case (.ipv6, 4): "parameter problem"
        case (.ipv6, 128): "echo request"
        case (.ipv6, 129): "echo reply"
        case (.ipv6, 135): "neighbor solicitation"
        case (.ipv6, 136): "neighbor advertisement"
        default: "type \(facts.type)"
        }
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
            // A plaintext alert's two bytes are named; an encrypted alert has no
            // fact at all and stays a bare "TLS Alert record" row.
            if let alert = fact.alert {
                parts.append(alertLevelLabel(alert))
                parts.append(alertDescriptionLabel(alert))
            }
        }
        return parts.joined(separator: ", ")
    }

    /// The RFC 8446 §6 `AlertLevel` byte. An unassigned value keeps its raw number
    /// rather than being normalized into warning or fatal.
    static func alertLevelLabel(_ alert: TLSAlertFact) -> String {
        switch alert.level {
        case 1: "warning"
        case 2: "fatal"
        default: "level \(alert.level)"
        }
    }

    /// The RFC 8446 §6 `AlertDescription` byte, in its wire spelling. An unassigned
    /// description keeps its raw number rather than a guessed name.
    static func alertDescriptionLabel(_ alert: TLSAlertFact) -> String {
        let name: String? = switch alert.description {
        case 0: "close_notify"
        case 10: "unexpected_message"
        case 20: "bad_record_mac"
        case 22: "record_overflow"
        case 40: "handshake_failure"
        case 42: "bad_certificate"
        case 43: "unsupported_certificate"
        case 44: "certificate_revoked"
        case 45: "certificate_expired"
        case 46: "certificate_unknown"
        case 47: "illegal_parameter"
        case 48: "unknown_ca"
        case 49: "access_denied"
        case 50: "decode_error"
        case 51: "decrypt_error"
        case 70: "protocol_version"
        case 71: "insufficient_security"
        case 80: "internal_error"
        case 86: "inappropriate_fallback"
        case 90: "user_canceled"
        case 109: "missing_extension"
        case 110: "unsupported_extension"
        case 112: "unrecognized_name"
        case 113: "bad_certificate_status_response"
        case 115: "unknown_psk_identity"
        case 116: "certificate_required"
        case 120: "no_application_protocol"
        default: nil
        }
        return name ?? "description \(alert.description)"
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
