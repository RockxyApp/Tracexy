import Darwin
import Foundation
import UniformTypeIdentifiers

// MARK: - SessionExportPrivacyPolicy

/// Conservative, non-UI privacy controls applied when producing an export
/// artifact. Every protection is opt-in and defaults off so existing callers
/// keep their current raw round trips (see ``none``).
///
/// The policy governs only the native `.tracexysession` document and the raw
/// pcap/pcapng refusal gate. It never rewrites packets: because on-wire frame
/// bytes carry payloads, credentials, and addresses that cannot be honestly
/// scrubbed in place, any active protection removes the raw frame bytes from the
/// native document instead of pretending to redact them.
nonisolated struct SessionExportPrivacyPolicy: Sendable, Equatable {
    // MARK: Lifecycle

    init(redactPayloadBodies: Bool = false, stripCredentials: Bool = false, maskIPAddresses: Bool = false) {
        self.redactPayloadBodies = redactPayloadBodies
        self.stripCredentials = stripCredentials
        self.maskIPAddresses = maskIPAddresses
    }

    // MARK: Internal

    /// The permissive default: no protection, raw bytes preserved.
    static let none = SessionExportPrivacyPolicy()

    /// Drop captured frame payload bodies from the native document.
    var redactPayloadBodies: Bool
    /// Remove free-form decoded metadata that can carry credentials (DNS
    /// query/answer strings and the human-readable info summary).
    var stripCredentials: Bool
    /// Replace literal IPv4/IPv6 addresses in decoded strings with a fixed
    /// placeholder. Because addresses also live in raw packet headers, this
    /// protection likewise removes the raw frame bytes.
    var maskIPAddresses: Bool

    /// Whether any protection is active. Raw pcap/pcapng export is refused while
    /// this is true.
    var hasProtections: Bool {
        redactPayloadBodies || stripCredentials || maskIPAddresses
    }

    /// Whether the policy makes the on-wire frame bytes unsafe to include in the
    /// native document. Each protection independently forces raw-byte removal,
    /// because payloads, credentials, and addresses all survive in raw frames.
    var removesRawFrameBytes: Bool {
        redactPayloadBodies || stripCredentials || maskIPAddresses
    }
}

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
    case rawExportRequiresAcknowledgement

    // MARK: Internal

    nonisolated var errorDescription: String? {
        switch self {
        case .noRetainedFrames:
            String(localized: "The packet frames for this session are no longer in the local export window.")
        case .mixedLinkTypes:
            String(
                localized: "Classic pcap cannot represent a session containing multiple link types. Use pcapng instead."
            )
        case .unsupportedLinkType:
            String(localized: "The session contains a link type that cannot be represented by pcapng.")
        case .rawExportRequiresAcknowledgement:
            String(
                localized: """
                Raw pcap/pcapng export cannot apply the active privacy protections. \
                Explicitly acknowledge an unredacted raw export, or export the protected session document instead.
                """
            )
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
        format: SessionExportFormat,
        privacy: SessionExportPrivacyPolicy = .none
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
                defaultLinkType: defaultLinkType,
                privacy: privacy
            )
        case .pcap:
            // Raw formats emit unmodified on-wire bytes; we cannot honor a
            // privacy policy in place, so refuse rather than silently leak.
            guard !privacy.hasProtections else {
                throw SessionExportError.rawExportRequiresAcknowledgement
            }
            let linkTypes = Set(frames.map { $0.linkType ?? defaultLinkType })
            guard linkTypes.count == 1, let linkType = linkTypes.first else {
                throw SessionExportError.mixedLinkTypes
            }
            data = PcapWriter.data(linkType: linkType, frames: frames)
        case .pcapng:
            guard !privacy.hasProtections else {
                throw SessionExportError.rawExportRequiresAcknowledgement
            }
            data = try PcapngWriter.data(defaultLinkType: defaultLinkType, frames: frames)
        }

        return SessionExportArtifact(
            data: data,
            suggestedFileName: "Session \(safeFileComponent(session.host)).\(format.fileExtension)",
            contentType: format.contentType
        )
    }

    // MARK: Private

    /// Unprotected native document. Version 1; carries raw frame bytes and is
    /// preserved for backward compatibility whenever the policy is ``none``.
    private struct Document: Codable {
        let formatVersion: Int
        let exportedAt: Date
        let session: Summary
        let frames: [Frame]
    }

    /// Protected native document. Version 2; omits the `bytes` key entirely and
    /// carries machine-readable ``PrivacyMetadata`` describing what was applied.
    private struct ProtectedDocument: Codable {
        let formatVersion: Int
        let exportedAt: Date
        let privacy: PrivacyMetadata
        let session: Summary
        let frames: [ProtectedFrame]
    }

    /// Machine-readable record of the applied protections. `includesRawFrameBytes`
    /// is always false here — an honest statement that no on-wire bytes are present.
    private struct PrivacyMetadata: Codable {
        let redactedPayloadBodies: Bool
        let strippedCredentials: Bool
        let maskedIPAddresses: Bool
        let includesRawFrameBytes: Bool
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

    /// Frame metadata with the `bytes` key deliberately absent, so no raw payload
    /// can survive in a protected document.
    private struct ProtectedFrame: Codable {
        let timestamp: Date
        let originalLength: Int
        let capturedLength: Int
        let linkType: UInt32
        let processName: String?
    }

    private static func sessionDocumentData(
        session: SessionSummary,
        frames: [CapturedFrame],
        defaultLinkType: UInt32,
        privacy: SessionExportPrivacyPolicy
    )
        throws -> Data
    {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        guard privacy.removesRawFrameBytes else {
            let document = Document(
                formatVersion: 1,
                exportedAt: Date(),
                session: summary(for: session, privacy: privacy),
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
            return try encoder.encode(document)
        }

        let document = ProtectedDocument(
            formatVersion: 2,
            exportedAt: Date(),
            privacy: PrivacyMetadata(
                redactedPayloadBodies: privacy.redactPayloadBodies,
                strippedCredentials: privacy.stripCredentials,
                maskedIPAddresses: privacy.maskIPAddresses,
                includesRawFrameBytes: false
            ),
            session: summary(for: session, privacy: privacy),
            frames: frames.map { frame in
                ProtectedFrame(
                    timestamp: frame.timestamp,
                    originalLength: frame.originalLength,
                    capturedLength: frame.capturedLength,
                    linkType: frame.linkType ?? defaultLinkType,
                    processName: frame.processName
                )
            }
        )
        return try encoder.encode(document)
    }

    /// Builds the encoded ``Summary``, applying credential stripping and address
    /// masking as the policy requires. Never invents decoded data: stripped
    /// fields become empty/nil and the summary collapses to protocol labels.
    private static func summary(
        for session: SessionSummary,
        privacy: SessionExportPrivacyPolicy
    )
        -> Summary
    {
        let mask = privacy.maskIPAddresses
        let strip = privacy.stripCredentials

        func masked(_ value: String) -> String {
            mask ? PrivacyMask.maskingAddresses(in: value) : value
        }
        func maskedEndpoint(_ value: String) -> String {
            mask ? PrivacyMask.maskingEndpoint(value) : value
        }
        func maskedOptional(_ value: String?) -> String? {
            value.map { masked($0) }
        }

        let protocolLabels = session.protocolStack.map(\.label).joined(separator: " · ")

        return Summary(
            id: session.id,
            startTime: session.startTime,
            duration: session.duration,
            processName: session.processName,
            host: masked(session.host),
            sourceEndpoint: maskedEndpoint(session.sourceEndpoint),
            destinationEndpoint: maskedEndpoint(session.destinationEndpoint),
            protocols: session.protocolStack.map(\.rawValue),
            status: session.status.rawValue,
            latencyMilliseconds: session.latencyMilliseconds,
            bytesUp: session.bytesUp,
            bytesDown: session.bytesDown,
            sni: maskedOptional(session.sni),
            dnsQuery: strip ? nil : maskedOptional(session.dnsQuery),
            dnsAnswers: strip ? [] : session.dnsAnswers.map { masked($0) },
            summary: strip ? protocolLabels : masked(session.infoSummary)
        )
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

// MARK: - PrivacyMask

/// Deterministic, offline address masker. It replaces genuine IPv4/IPv6 literals
/// with a fixed placeholder while leaving hostnames, punctuation, and arbitrary
/// text byte-for-byte intact. Address validity is decided by the platform parser
/// (`inet_pton`) rather than a broad regex, so ordinary hostnames are never
/// corrupted. Malformed or unknown input is handled totally — it is simply left
/// unchanged. No network calls, no hashing of sensitive input.
///
/// Kept module-internal (not `private`) so terminal-history projection can apply
/// byte-for-byte identical host/endpoint masking to the neutral summaries it
/// persists, rather than reimplementing the same semantics.
nonisolated enum PrivacyMask {
    // MARK: Internal

    /// The honest, fixed stand-in written wherever an address is removed.
    static let placeholder = "[masked-ip]"

    /// Replaces every embedded IPv4/IPv6 literal in `text` with ``placeholder``.
    /// Runs of address-shaped characters are validated as whole tokens, so a
    /// fragment such as `16.34` inside other text is not a valid address and is
    /// preserved verbatim.
    static func maskingAddresses(in text: String) -> String {
        guard !text.isEmpty else {
            return text
        }
        var result = ""
        result.reserveCapacity(text.count)
        var token = ""

        func flush() {
            if !token.isEmpty {
                result += maskingAddressToken(token)
                token = ""
            }
        }

        for character in text {
            if isAddressCharacter(character) {
                token.append(character)
            } else {
                flush()
                result.append(character)
            }
        }
        flush()
        return result
    }

    /// Endpoint-aware masking that preserves a trailing numeric `:port`. When the
    /// value is not an `address:port` pair (including the `—` placeholder or an
    /// IPv6 literal without a port), it falls back to whole-string masking.
    static func maskingEndpoint(_ endpoint: String) -> String {
        guard let separator = endpoint.lastIndex(of: ":") else {
            return maskingAddresses(in: endpoint)
        }
        let address = String(endpoint[endpoint.startIndex ..< separator])
        let port = String(endpoint[endpoint.index(after: separator)...])
        if !port.isEmpty, port.allSatisfy(\.isNumber), isIPAddress(address) {
            return "\(placeholder):\(port)"
        }
        return maskingAddresses(in: endpoint)
    }

    // MARK: Private

    private static func isAddressCharacter(_ character: Character) -> Bool {
        guard character.unicodeScalars.count == 1, let scalar = character.unicodeScalars.first else {
            return false
        }
        if scalar == "." || scalar == ":" {
            return true
        }
        return character.isHexDigit
    }

    /// A sentence-ending period is address-shaped but is not part of the
    /// address. Try the whole token first, then peel only trailing periods so an
    /// address at the end of prose cannot escape masking. Preserve the punctuation
    /// exactly; malformed tokens remain untouched.
    private static func maskingAddressToken(_ token: String) -> String {
        if isIPAddress(token) {
            return placeholder
        }

        var candidate = token
        var suffix = ""
        while candidate.last == "." {
            candidate.removeLast()
            suffix.append(".")
            if isIPAddress(candidate) {
                return placeholder + suffix
            }
        }
        return token
    }

    private static func isIPAddress(_ token: String) -> Bool {
        guard token.contains(".") || token.contains(":") else {
            return false
        }
        var v4 = in_addr()
        if token.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            return true
        }
        var v6 = in6_addr()
        if token.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return true
        }
        return false
    }
}
