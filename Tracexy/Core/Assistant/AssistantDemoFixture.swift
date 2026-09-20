import Foundation

// MARK: - AssistantDemoFixture

/// A deterministic, documentation-range investigation snapshot for the AI
/// Assistant's privacy-safe demo/automation path — and, through the same type,
/// for its tests.
///
/// Every address is from RFC 5737's `203.0.113.0/24` documentation range or the
/// RFC 1918 private range, every host is under `example.com`, and every process
/// name is a placeholder — nothing here resembles a real capture, so a screenshot
/// or a fixture brief can be shared without redaction.
nonisolated enum AssistantDemoFixture {
    // MARK: Internal

    static let clientEndpoint = IPEndpoint(ip: "192.0.2.10", port: 51_314)
    static let serverEndpoint = IPEndpoint(ip: "203.0.113.42", port: 443)

    static let projectID = UUID(uuidString: "0B4E3F1C-9A1D-4C2E-8E8D-5F6A7B8C9D01") ?? UUID()

    static var tuple: FiveTuple {
        FiveTuple(proto: .tcp, source: clientEndpoint, destination: serverEndpoint)
    }

    static var sessionID: UUID {
        SessionBuilder.sessionID(for: tuple)
    }

    /// One frame's provenance at `ordinal`, optionally carrying a locator so the
    /// "has a navigable local frame" citation flag can be exercised both ways.
    static func provenance(ordinal: UInt64, hasLocator: Bool = true) -> SessionFrameProvenance {
        provenance(
            ordinal: ordinal,
            locator: hasLocator
                ? SessionEvidenceLocator(
                    sourceToken: UUID(uuidString: "1A2B3C4D-5E6F-4A8B-9C0D-1E2F3A4B5C6D") ?? UUID(),
                    offset: ordinal * 64
                )
                : nil
        )
    }

    /// Build provenance with the exact locator minted by the walkthrough's live
    /// spool. Tests that exercise serialization can keep using the deterministic
    /// synthetic locator above; the native walkthrough uses this overload so a
    /// visible citation always resolves to bytes that actually exist.
    static func provenance(ordinal: UInt64, locator: SessionEvidenceLocator?) -> SessionFrameProvenance {
        SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSinceReferenceDate: 760_000_000 + Double(ordinal)),
            capturedLength: 128,
            originalLength: 1_514,
            linkType: LinkType.ethernet,
            locator: locator
        )
    }

    /// Three valid, documentation-range Ethernet/TCP frames for the native
    /// walkthrough. Each is padded to the provenance's captured length; the IP
    /// packet's own length remains exact, so the decoder safely ignores padding.
    static func capturedFrames(eventOrdinals: [UInt64] = [10, 11, 12]) -> [CapturedFrame] {
        eventOrdinals.enumerated().map { index, ordinal in
            let isReset = index == 0
            var bytes = PacketBuilder.ethernetIPv4(
                proto: 6,
                src: isReset ? serverEndpoint.ip : clientEndpoint.ip,
                dst: isReset ? clientEndpoint.ip : serverEndpoint.ip,
                payload: PacketBuilder.tcp(
                    srcPort: isReset ? serverEndpoint.port : clientEndpoint.port,
                    dstPort: isReset ? clientEndpoint.port : serverEndpoint.port,
                    flags: isReset ? 0x04 : 0x10,
                    payload: [],
                    sequence: UInt32(index + 1)
                )
            )
            bytes.append(contentsOf: repeatElement(0, count: max(0, 128 - bytes.count)))
            return CapturedFrame(
                bytes: bytes,
                timestamp: Date(timeIntervalSinceReferenceDate: 760_000_000 + Double(ordinal)),
                originalLength: 1_514,
                capturedLength: bytes.count,
                linkType: LinkType.ethernet,
                processName: "ExampleClient"
            )
        }
    }

    static func session(
        host: String = "service.example.com",
        processName: String? = "ExampleClient"
    )
        -> SessionSummary
    {
        SessionSummary(
            id: sessionID,
            startTime: Date(timeIntervalSinceReferenceDate: 760_000_000),
            duration: 1.25,
            processName: processName,
            host: host,
            sourceEndpoint: clientEndpoint.display,
            destinationEndpoint: serverEndpoint.display,
            sourceEndpointValue: clientEndpoint,
            destinationEndpointValue: serverEndpoint,
            protocolStack: [.tcp, .tls],
            status: .warning,
            latencyMilliseconds: 42,
            bytesUp: 2_048,
            bytesDown: 16_384,
            sni: "service.example.com",
            dnsQuery: "service.example.com",
            dnsAnswers: ["203.0.113.42"]
        )
    }

    /// One retained connection carrying a reset and a retransmission, so the
    /// assessor produces both a `warning` and a `note` finding with real citations.
    static func connectionSummary(
        eventOrdinals: [UInt64] = [10, 11, 12],
        locatorByOrdinal: [UInt64: SessionEvidenceLocator]? = nil
    )
        -> ConnectionSummary
    {
        let id = ConnectionID(tuple: tuple, firstOrdinal: FrameOrdinal(1))
        var events: [ConnectionEvent] = []
        if let first = eventOrdinals.first {
            events.append(ConnectionEvent(
                connectionID: id,
                kind: .rst,
                timestamp: Date(timeIntervalSinceReferenceDate: 760_000_010),
                provenance: eventProvenance(ordinal: first, locatorByOrdinal: locatorByOrdinal),
                direction: .bToA
            ))
        }
        for ordinal in eventOrdinals.dropFirst() {
            events.append(ConnectionEvent(
                connectionID: id,
                kind: .retransmission,
                timestamp: Date(timeIntervalSinceReferenceDate: 760_000_000 + Double(ordinal)),
                provenance: eventProvenance(ordinal: ordinal, locatorByOrdinal: locatorByOrdinal),
                direction: .aToB
            ))
        }
        let firstOrdinal = eventOrdinals.first ?? 1
        let lastOrdinal = eventOrdinals.last ?? firstOrdinal
        return ConnectionSummary(
            id: id,
            tuple: tuple,
            firstProvenance: eventProvenance(
                ordinal: firstOrdinal,
                locatorByOrdinal: locatorByOrdinal
            ),
            lastProvenance: eventProvenance(
                ordinal: lastOrdinal,
                locatorByOrdinal: locatorByOrdinal
            ),
            initiator: .aToB,
            phase: .closed,
            handshake: .threeWayObserved,
            finDirections: [],
            closeReason: .reset(.bToA),
            packetCount: 24,
            capturedByteTotal: 4_096,
            originalByteTotal: 18_432,
            lossKnowledge: .noLossReported,
            limitations: [.payloadTruncated],
            events: events,
            omittedEventCount: 3
        )
    }

    /// A snapshot whose one session holds `connectionCount` retained incarnations,
    /// each carrying `eventsPerConnection` retransmissions at distinct ordinals.
    /// It exists to push past the brief's own finding and citation bounds.
    static func crowdedSnapshot(
        connectionCount: Int,
        eventsPerConnection: Int
    )
        -> InvestigationSnapshot
    {
        var summaries: [ConnectionSummary] = []
        var ordinal: UInt64 = 100
        for index in 0 ..< connectionCount {
            let id = ConnectionID(tuple: tuple, firstOrdinal: FrameOrdinal(UInt64(index) + 1))
            var events: [ConnectionEvent] = []
            for _ in 0 ..< eventsPerConnection {
                events.append(ConnectionEvent(
                    connectionID: id,
                    kind: .retransmission,
                    timestamp: Date(timeIntervalSinceReferenceDate: 760_000_000 + Double(ordinal)),
                    provenance: provenance(ordinal: ordinal),
                    direction: .aToB
                ))
                ordinal += 1
            }
            var summary = connectionSummary()
            summary = ConnectionSummary(
                id: id,
                tuple: summary.tuple,
                firstProvenance: summary.firstProvenance,
                lastProvenance: summary.lastProvenance,
                initiator: summary.initiator,
                phase: summary.phase,
                handshake: summary.handshake,
                finDirections: summary.finDirections,
                closeReason: summary.closeReason,
                packetCount: summary.packetCount,
                capturedByteTotal: summary.capturedByteTotal,
                originalByteTotal: summary.originalByteTotal,
                lossKnowledge: summary.lossKnowledge,
                limitations: summary.limitations,
                events: events,
                omittedEventCount: 0
            )
            summaries.append(summary)
        }
        let connections = ConnectionTable.Snapshot(
            summaries: summaries,
            omittedSummaryCount: 0,
            activeConnectionCount: connectionCount,
            publishedSummaryCount: connectionCount,
            retainedEventCount: connectionCount * eventsPerConnection,
            countersOverflowed: false
        )
        return InvestigationSnapshot(
            sessions: [session()],
            connections: connections,
            datagramEvidence: .empty,
            tlsEvidence: .empty,
            connectionAnalysis: ConnectionAssessor().assess(connections),
            datagramAnalysis: .empty
        )
    }

    /// The complete snapshot: one session, one retained connection, the assessed
    /// connection analysis, and empty datagram/TLS evidence.
    static func snapshot(
        host: String = "service.example.com",
        processName: String? = "ExampleClient",
        eventOrdinals: [UInt64] = [10, 11, 12],
        locatorByOrdinal: [UInt64: SessionEvidenceLocator]? = nil
    )
        -> InvestigationSnapshot
    {
        let connections = ConnectionTable.Snapshot(
            summaries: [connectionSummary(
                eventOrdinals: eventOrdinals,
                locatorByOrdinal: locatorByOrdinal
            )],
            omittedSummaryCount: 7,
            activeConnectionCount: 1,
            publishedSummaryCount: 1,
            retainedEventCount: eventOrdinals.count,
            countersOverflowed: false
        )
        return InvestigationSnapshot(
            sessions: [session(host: host, processName: processName)],
            connections: connections,
            datagramEvidence: .empty,
            tlsEvidence: .empty,
            connectionAnalysis: ConnectionAssessor().assess(connections),
            datagramAnalysis: .empty
        )
    }

    // MARK: Private

    private static func eventProvenance(
        ordinal: UInt64,
        locatorByOrdinal: [UInt64: SessionEvidenceLocator]?
    )
        -> SessionFrameProvenance
    {
        guard let locatorByOrdinal else {
            return provenance(ordinal: ordinal)
        }
        return provenance(ordinal: ordinal, locator: locatorByOrdinal[ordinal])
    }
}

// MARK: - AssistantDemoLaunchMode

/// Development- and automation-only composition policy for the AI Assistant
/// walkthrough.
///
/// The flag adopts one deterministic, documentation-range investigation snapshot
/// so the Assistant surface can be driven end to end without a real capture. It
/// grants no capture access, opens no file, and touches no History or Project
/// data — it only publishes a fixture snapshot the same way a finished saved-file
/// load would.
nonisolated enum AssistantDemoLaunchMode {
    static let launchArgument = "--assistant-demo"
    static let narrowLaunchArgument = "--assistant-demo-narrow"

    static func isEnabled(arguments: [String] = CommandLine.arguments) -> Bool {
        arguments.contains(launchArgument) || arguments.contains(narrowLaunchArgument)
    }

    static func prefersNarrowWindow(arguments: [String] = CommandLine.arguments) -> Bool {
        arguments.contains(narrowLaunchArgument)
    }
}
