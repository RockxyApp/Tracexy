import Foundation
import UniformTypeIdentifiers

// MARK: - SessionExportFormat

nonisolated enum SessionExportFormat: String, CaseIterable, Identifiable, Sendable {
    case session
    case pcap
    case pcapng

    // MARK: Internal

    nonisolated var id: Self {
        self
    }

    nonisolated var title: String {
        switch self {
        case .session: "Export Session"
        case .pcap: "Export as pcap"
        case .pcapng: "Export as pcapng"
        }
    }

    nonisolated var fileExtension: String {
        switch self {
        case .session: "tracexysession"
        case .pcap: "pcap"
        case .pcapng: "pcapng"
        }
    }

    nonisolated var contentType: UTType {
        switch self {
        case .session:
            UTType(filenameExtension: "tracexysession", conformingTo: .json) ?? .json
        case .pcap:
            UTType(filenameExtension: "pcap") ?? .data
        case .pcapng:
            UTType(filenameExtension: "pcapng") ?? .data
        }
    }
}

// MARK: - SessionExportArtifact

nonisolated struct SessionExportArtifact: Sendable {
    let data: Data
    let suggestedFileName: String
    let contentType: UTType
}

// MARK: - SessionExportError

nonisolated enum SessionExportError: LocalizedError {
    case noRetainedFrames
    case mixedLinkTypes
    case unsupportedLinkType

    // MARK: Internal

    nonisolated var errorDescription: String? {
        switch self {
        case .noRetainedFrames:
            "The packet frames for this session are no longer in the local export window."
        case .mixedLinkTypes:
            "Classic pcap cannot represent a session containing multiple link types. Use pcapng instead."
        case .unsupportedLinkType:
            "The session contains a link type that cannot be represented by pcapng."
        }
    }
}

// MARK: - SessionExporter

nonisolated enum SessionExporter {
    // MARK: Internal

    static func frames(
        matching sessionID: SessionSummary.ID,
        in frames: [CapturedFrame],
        defaultLinkType: UInt32
    )
        -> [CapturedFrame]
    {
        frames.filter { frame in
            let packet = SessionBuilder.decodePacket(frame, linkType: defaultLinkType)
            guard let key = packet.fiveTuple else {
                return false
            }
            return SessionBuilder.sessionID(for: key) == sessionID
        }
    }

    static func artifact(
        for session: SessionSummary,
        frames: [CapturedFrame],
        defaultLinkType: UInt32,
        format: SessionExportFormat
    )
        throws -> SessionExportArtifact
    {
        guard !frames.isEmpty else {
            throw SessionExportError.noRetainedFrames
        }

        let data: Data
        switch format {
        case .session:
            data = try sessionDocumentData(
                session: session,
                frames: frames,
                defaultLinkType: defaultLinkType
            )
        case .pcap:
            let linkTypes = Set(frames.map { $0.linkType ?? defaultLinkType })
            guard linkTypes.count == 1, let linkType = linkTypes.first else {
                throw SessionExportError.mixedLinkTypes
            }
            data = PcapWriter.data(linkType: linkType, frames: frames)
        case .pcapng:
            data = try PcapngWriter.data(defaultLinkType: defaultLinkType, frames: frames)
        }

        return SessionExportArtifact(
            data: data,
            suggestedFileName: "Session \(safeFileComponent(session.host)).\(format.fileExtension)",
            contentType: format.contentType
        )
    }

    // MARK: Private

    private struct Document: Codable {
        let formatVersion: Int
        let exportedAt: Date
        let session: Summary
        let frames: [Frame]
    }

    private struct Summary: Codable {
        let id: UUID
        let startTime: Date
        let duration: TimeInterval
        let processName: String?
        let host: String
        let sourceEndpoint: String
        let destinationEndpoint: String
        let protocols: [String]
        let status: String
        let latencyMilliseconds: Double?
        let bytesUp: Int
        let bytesDown: Int
        let sni: String?
        let dnsQuery: String?
        let dnsAnswers: [String]
        let summary: String
    }

    private struct Frame: Codable {
        let timestamp: Date
        let originalLength: Int
        let capturedLength: Int
        let linkType: UInt32
        let processName: String?
        let bytes: Data
    }

    private static func sessionDocumentData(
        session: SessionSummary,
        frames: [CapturedFrame],
        defaultLinkType: UInt32
    )
        throws -> Data
    {
        let document = Document(
            formatVersion: 1,
            exportedAt: Date(),
            session: Summary(
                id: session.id,
                startTime: session.startTime,
                duration: session.duration,
                processName: session.processName,
                host: session.host,
                sourceEndpoint: session.sourceEndpoint,
                destinationEndpoint: session.destinationEndpoint,
                protocols: session.protocolStack.map(\.rawValue),
                status: session.status.rawValue,
                latencyMilliseconds: session.latencyMilliseconds,
                bytesUp: session.bytesUp,
                bytesDown: session.bytesDown,
                sni: session.sni,
                dnsQuery: session.dnsQuery,
                dnsAnswers: session.dnsAnswers,
                summary: session.infoSummary
            ),
            frames: frames.map { frame in
                Frame(
                    timestamp: frame.timestamp,
                    originalLength: frame.originalLength,
                    capturedLength: frame.capturedLength,
                    linkType: frame.linkType ?? defaultLinkType,
                    processName: frame.processName,
                    bytes: Data(frame.bytes)
                )
            }
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(document)
    }

    private static func safeFileComponent(_ value: String) -> String {
        let invalid = CharacterSet(charactersIn: "/:\\?%*|\"<>")
            .union(.newlines)
            .union(.controlCharacters)
        let components = value.components(separatedBy: invalid)
        let cleaned = components.joined(separator: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty || cleaned == "—" ? "Traffic" : String(cleaned.prefix(80))
    }
}
