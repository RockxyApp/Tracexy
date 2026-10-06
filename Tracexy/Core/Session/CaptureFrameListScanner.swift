import Foundation

// MARK: - CaptureFrameRow

/// One frame of a whole capture, as Wireshark's packet list shows it: number, time,
/// source, destination, protocol, length and a one-line summary — plus the session
/// it folded into and the locator that re-reads its exact bytes. References only;
/// no bytes are retained.
nonisolated struct CaptureFrameRow: Identifiable, Hashable, Sendable {
    let provenance: SessionFrameProvenance
    let source: String
    let destination: String
    let protocolName: String
    let info: String
    /// The session this frame belongs to, by the fold's own identity; `nil` for a
    /// frame that folds into none (IGMP, an undecodable frame).
    let sessionID: UUID?
    let interfaceID: Int
    let hasComment: Bool
    /// Why decoding stopped early — Wireshark's malformed and short frames.
    var decodeStop: DecodeStop?
    /// An HTTP/1 request or response line, for Statistics ▸ HTTP.
    var http: HTTPFrameFact?
    /// A DNS header and question, for Statistics ▸ DNS.
    var dns: DNSFrameFact?
    /// The RTP header, for Statistics ▸ RTP Streams (see ``RTPFrameFact``).
    var rtp: RTPFrameFact?
    /// A SIP message with its endpoints, for Statistics ▸ SIP.
    var sip: SIPFrameFact?
    /// A UDP datagram to a multicast group, for Statistics ▸ UDP Multicast Streams.
    var multicast: MulticastFrameFact?
    /// The innermost IP header, for Statistics ▸ IPv4 and IPv6.
    var ip: IPFrameFact?
    /// An SMB2, LDAP or Kerberos message, for Statistics ▸ Service Response Time.
    var srt: SRTFrameFact?
    /// The values of the columns applied from Layers (Apply as Column), in their
    /// order; a field that occurs more than once lists each occurrence, comma-separated.
    var columnValues: [String] = []
    /// An IPv4, TCP, UDP or ICMP checksum is wrong; shown only with View ▸ Validate
    /// Checksums on, since frames sent from this Mac are often offloaded.
    var hasBadChecksum = false

    var id: UInt64 {
        provenance.ordinal.rawValue
    }

    var ordinal: UInt64 {
        provenance.ordinal.rawValue
    }

    var length: Int {
        provenance.originalLength
    }
}

// MARK: - HTTPFrameFact

/// What an HTTP/1 frame's first line said, for Statistics ▸ HTTP: a request's
/// method, Host and URI, or a response's status code. Read from the decoded layer;
/// the URI is cut at ``maxURILength`` characters.
nonisolated enum HTTPFrameFact: Hashable, Sendable {
    /// A request, with its Referer when it sent one (Statistics ▸ HTTP ▸ Request
    /// Sequences).
    case request(method: String, host: String, uri: String, referer: String? = nil)
    /// A response, with its Location when it redirects.
    case response(status: Int, location: String? = nil)

    // MARK: Lifecycle

    init?(_ packet: DecodedPacket, bytes: [UInt8] = []) {
        guard let layer = packet.layers.last(where: { $0.proto == .http }) else {
            return nil
        }
        if let status = layer.fields.first(where: { $0.name == "Status" })?.value {
            guard let code = SessionMessageTally.httpStatus(fromStatus: status) else {
                return nil
            }
            self = .response(status: code, location: Self.header("location", in: bytes, range: layer.byteRange))
            return
        }
        guard let line = layer.fields.first(where: { $0.name == "Request" })?.value,
              let method = SessionMessageTally.httpMethod(fromRequestLine: line) else
        {
            return nil
        }
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        let uri = parts.count > 1 ? String(parts[1].prefix(Self.maxURILength)) : "/"
        let host = layer.fields.first { $0.name == "Host" }?.value ?? "—"
        self = .request(
            method: method, host: host, uri: uri, referer: Self.header("referer", in: bytes, range: layer.byteRange)
        )
    }

    // MARK: Internal

    static let maxURILength = 2_048

    /// The first value of `name` (lowercase) in the message's header block, read from
    /// the frame's bytes and cut at ``maxURILength`` characters; `nil` when absent.
    static func header(_ name: String, in bytes: [UInt8], range: Range<Int>?) -> String? {
        guard let range, range.upperBound <= bytes.count else {
            return nil
        }
        let window = bytes[range.lowerBound ..< min(range.upperBound, range.lowerBound + 8_192)]
        let text = String(bytes: window, encoding: .utf8) ?? String(bytes: window, encoding: .isoLatin1) ?? ""
        for line in text.components(separatedBy: "\r\n").dropFirst() {
            if line.isEmpty {
                break
            }
            guard let colon = line.firstIndex(of: ":"),
                  line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == name else
            {
                continue
            }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            return String(value.prefix(maxURILength))
        }
        return nil
    }
}

// MARK: - DNSFrameFact

/// What a DNS frame's header and first question said, for Statistics ▸ DNS
/// (Wireshark's `dns,tree`). Numbers and type codes only; the name is kept as its
/// length and label count.
nonisolated struct DNSFrameFact: Hashable, Sendable {
    // MARK: Lifecycle

    init?(_ packet: DecodedPacket) {
        guard let facts = packet.dnsFacts, packet.appProtocol == .dns, let length = packet.dnsMessageLength else {
            return nil
        }
        transactionID = facts.transactionID
        isResponse = facts.isResponse
        opcode = facts.opcode
        responseCode = facts.responseCode
        queryType = packet.dnsQueryType
        queryClass = packet.dnsQueryClass
        answerTypes = packet.dnsAnswerTypes
        messageLength = length
        let name = packet.dnsQuery.flatMap { $0.isEmpty ? nil : $0 }
        queryNameLength = name?.count
        queryLabelCount = name.map { $0.split(separator: ".").count }
        questionCount = Int(facts.questionCount)
        answerCount = Int(facts.answerCount)
        authorityCount = Int(facts.authorityCount)
        additionalCount = Int(facts.additionalCount)
    }

    // MARK: Internal

    let transactionID: UInt16
    let isResponse: Bool
    let opcode: UInt8
    let responseCode: UInt8
    let queryType: UInt16?
    let queryClass: UInt16?
    let answerTypes: [UInt16]
    let messageLength: Int
    let queryNameLength: Int?
    let queryLabelCount: Int?
    let questionCount: Int
    let answerCount: Int
    let authorityCount: Int
    let additionalCount: Int
}

// MARK: - CaptureFrameList

/// The bounded outcome of one ``CaptureFrameListScanner`` pass.
nonisolated struct CaptureFrameList: Sendable, Equatable {
    let identity: PcapFileIdentity
    /// Frames in capture order, at most ``CaptureFrameListScanner/Configuration/maxRetainedFrames``.
    let rows: [CaptureFrameRow]
    let scannedFrameCount: Int
    let completeness: CaptureLoadCompleteness
    /// Listed frames whose decoding stopped early (malformed or cut short).
    var decodeProblemCount = 0
    /// Listed frames with a wrong checksum that decoded cleanly otherwise.
    var badChecksumOnlyCount = 0

    var omittedFrameCount: Int {
        max(0, scannedFrameCount - rows.count)
    }

    /// Frames Only Decode Problems lists: decode stops, plus wrong checksums when
    /// they are being validated.
    func problemCount(countingBadChecksums: Bool) -> Int {
        decodeProblemCount + (countingBadChecksums ? badChecksumOnlyCount : 0)
    }
}

// MARK: - CaptureFrameListScanner

/// A pure, synchronous, on-demand scan of a *stable* capture that lists every
/// frame, decoded once through the shared decode seam — the same contract as
/// ``SessionFrameScanner`` (identity checked before and after, cooperative
/// cancellation, progress), without the per-session match. Memory is bounded by
/// ``Configuration/maxRetainedFrames`` rows; frames past it are counted only.
nonisolated final class CaptureFrameListScanner {
    // MARK: Lifecycle

    init(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        sourceToken: UUID,
        configuration: Configuration = Configuration()
    )
        throws
    {
        self.sourceToken = sourceToken
        self.configuration = configuration
        let reader = try CaptureStreamReader(
            contentsOf: url,
            configuration: .init(
                maxCapturedLength: configuration.maxCapturedLength,
                isCancelled: configuration.isCancelled
            )
        )
        guard reader.identity.matches(expectedIdentity) else {
            throw FollowStreamError.identityMismatch
        }
        self.reader = reader
        sourceURL = url
    }

    // MARK: Internal

    nonisolated struct Configuration: Sendable {
        // MARK: Lifecycle

        init(
            maxCapturedLength: Int = CapturedFrame.maxReasonableLength,
            maxRetainedFrames: Int = Configuration.defaultMaxRetainedFrames,
            progressStride: Int = 1_024,
            columns: [FieldKey] = [],
            isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
        ) {
            self.columns = columns
            self.maxCapturedLength = maxCapturedLength
            self.maxRetainedFrames = min(Configuration.defaultMaxRetainedFrames, max(1, maxRetainedFrames))
            self.progressStride = max(1, progressStride)
            self.isCancelled = isCancelled
        }

        // MARK: Internal

        static let defaultMaxRetainedFrames = 200_000

        let maxCapturedLength: Int
        let maxRetainedFrames: Int
        let progressStride: Int
        /// Fields whose values each row carries, as Wireshark's custom columns.
        let columns: [FieldKey]
        let isCancelled: @Sendable () -> Bool
    }

    static let maxInfoLength = 120

    /// The innermost named protocol and a Wireshark-style Info line: TCP flags,
    /// sequence, acknowledgement, window and length; TLS record types; DNS query or
    /// response with its name — else the innermost layer's own summary.
    static func info(of packet: DecodedPacket) -> (protocolName: String, info: String) {
        guard let layer = packet.layers.last else {
            return ("—", "")
        }
        // A fragment that completed nothing reads as Wireshark lists it.
        if let fragment = packet.ipFragment, packet.reassembly == nil {
            // "UDP (17)" reads "UDP 17" here, as Wireshark writes it.
            let proto = PacketDecoder.ipProtoName(fragment.protocolNumber)
                .replacingOccurrences(of: "(", with: "").replacingOccurrences(of: ")", with: "")
            let text = "Fragmented IP protocol (proto=\(proto), "
                + "off=\(fragment.offset), ID=\(PacketDecoder.hex(fragment.identification, digits: 4).dropFirst(2)))"
            return (layer.proto.label, text)
        }
        // An application layer above TCP (HTTP, …) speaks for the frame, as in
        // Wireshark's Info; a bare TCP segment gets the flags/sequence line.
        let applicationSummary = layer.proto == .tcp || layer.summary.isEmpty ? nil : layer.summary
        var text = tlsInfo(packet) ?? dnsInfo(packet) ?? applicationSummary ?? tcpInfo(packet)
            ?? (layer.summary.isEmpty ? layer.title : layer.summary)
        if text.count > maxInfoLength {
            text = String(text.prefix(maxInfoLength - 1)) + "…"
        }
        return (layer.proto.label, text)
    }

    func scan(onProgress: (PcapStreamProgress) -> Void = { _ in }) throws -> CaptureFrameList {
        var scanned = 0
        var rows: [CaptureFrameRow] = []
        var sequential = SequentialFrameDecoder()
        let completion: CaptureStreamCompletion
        walk: while true {
            switch try reader.next() {
            case let .frame(event):
                scanned += 1
                if rows.count < configuration.maxRetainedFrames {
                    rows.append(row(event, ordinal: scanned, sequential: &sequential))
                }
                if scanned % configuration.progressStride == 0 {
                    onProgress(event.progress)
                }
            case let .end(end):
                completion = end
                break walk
            }
        }
        try revalidateSourceIdentity()
        onProgress(completion.progress)
        let completeness: CaptureLoadCompleteness = switch completion.reason {
        case .cleanEndOfFile: .complete
        case .partialHeader,
             .partialBody: .incompleteTruncatedTail(completion.reason)
        }
        return CaptureFrameList(
            identity: reader.identity, rows: rows, scannedFrameCount: scanned, completeness: completeness,
            decodeProblemCount: rows.count { $0.decodeStop != nil },
            badChecksumOnlyCount: rows.count { $0.hasBadChecksum && $0.decodeStop == nil }
        )
    }

    // MARK: Private

    private let sourceToken: UUID
    private let configuration: Configuration
    private let reader: CaptureStreamReader
    private let sourceURL: URL

    /// `443 → 51000 [SYN, ACK] Seq=5000 Ack=1001 Win=65535 Len=0` — raw sequence
    /// numbers (Wireshark shows them relative by default).
    private static func tcpInfo(_ packet: DecodedPacket) -> String? {
        guard let facts = packet.tcpFacts, let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint else
        {
            return nil
        }
        let names: [(TCPFlags, String)] = [
            (.fin, "FIN"), (.syn, "SYN"), (.rst, "RST"), (.psh, "PSH"), (.ack, "ACK"), (.urg, "URG"),
            (.ece, "ECE"), (.cwr, "CWR"),
        ]
        let flags = names.filter { facts.flags.contains($0.0) }.map(\.1).joined(separator: ", ")
        var text = "\(source.port) → \(destination.port) [\(flags)] Seq=\(facts.sequenceNumber)"
        if facts.flags.contains(.ack) {
            text += " Ack=\(facts.acknowledgementNumber)"
        }
        return text + " Win=\(facts.windowSize) Len=\(facts.payloadLength)"
    }

    private static func tlsInfo(_ packet: DecodedPacket) -> String? {
        guard !packet.tlsRecords.isEmpty else {
            return nil
        }
        let parts = packet.tlsRecords.map { record -> String in
            switch record.handshake {
            case .clientHello: return "Client Hello"
            case .serverHello: return "Server Hello"
            case nil: break
            }
            return switch record.contentType {
            case 20: "Change Cipher Spec"
            case 21: "Alert"
            case 22: "Handshake"
            case 23: "Application Data"
            case 24: "Heartbeat"
            default: "Record \(record.contentType)"
            }
        }
        var unique: [String] = []
        for part in parts where unique.last != part {
            unique.append(part)
        }
        return unique.joined(separator: ", ")
    }

    private static func dnsInfo(_ packet: DecodedPacket) -> String? {
        guard let facts = packet.dnsFacts else {
            return nil
        }
        let kind = facts.isResponse ? "Standard query response" : "Standard query"
        let id = String(format: "0x%04x", facts.transactionID)
        var text = "\(kind) \(id)"
        if let type = packet.dnsQueryType {
            text += " \(PacketDecoder.dnsTypeName(type))"
        }
        if let name = packet.dnsQuery {
            text += " \(name)"
        }
        if facts.isResponse, facts.responseCode != 0 {
            text += " rcode \(facts.responseCode)"
        }
        return text
    }

    /// An IP address as Wireshark prints it (IPv6 compressed per RFC 5952).
    private static func display(_ address: String?) -> String? {
        guard let address else {
            return nil
        }
        return IPAddressValue(parsing: address)?.compressedText ?? address
    }

    /// The innermost IP header's address when decoding stopped before a transport
    /// endpoint was read (a frame cut short inside its TCP header), as Wireshark shows.
    private static func ipAddress(_ packet: DecodedPacket, field: String) -> String? {
        // The innermost IP header that states it: an IPv6 extension header (a
        // Fragment header, say) is an IPv6 layer without addresses of its own.
        packet.layers.reversed().lazy.compactMap { layer in
            layer.proto == .ipv4 || layer.proto == .ipv6 ? layer.fields.first { $0.name == field }?.value : nil
        }.first
    }

    /// The Ethernet address when a frame carries no IP endpoint (ARP, LLDP…).
    private static func linkAddress(_ packet: DecodedPacket, field: String) -> String? {
        packet.layers.first { $0.proto == .ethernet }?.fields.first { $0.name == field }?.value
    }

    private func row(
        _ event: CaptureFrameEvent,
        ordinal: Int,
        sequential: inout SequentialFrameDecoder
    )
        -> CaptureFrameRow
    {
        let frame = CapturedFrame(
            bytes: event.bytes,
            timestamp: event.reference.timestamp,
            originalLength: event.reference.originalLength,
            capturedLength: event.reference.capturedLength,
            linkType: event.reference.linkType
        )
        let locator = SessionEvidenceLocator(sourceToken: sourceToken, offset: event.reference.payloadOffset)
        let packet = sequential.decode(
            frame,
            linkType: reader.defaultLinkType ?? event.reference.linkType,
            ordinal: UInt64(ordinal),
            locator: locator
        )
        var (protocolName, info) = Self.info(of: packet)
        if let stop = packet.decodeStop {
            info = info.isEmpty ? stop.infoSuffix : "\(info) \(stop.infoSuffix)"
        }
        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(UInt64(ordinal)),
            timestamp: event.reference.timestamp,
            capturedLength: event.reference.capturedLength,
            originalLength: event.reference.originalLength,
            linkType: event.reference.linkType,
            locator: locator,
            reassembledFrom: sequential.lastReassembledFrom
        )
        return CaptureFrameRow(
            provenance: provenance,
            source: Self.display(packet.sourceEndpoint?.ip ?? Self.ipAddress(packet, field: "Source"))
                ?? Self.linkAddress(packet, field: "Source") ?? "—",
            destination: Self.display(packet.destinationEndpoint?.ip ?? Self.ipAddress(packet, field: "Destination"))
                ?? Self.linkAddress(packet, field: "Destination") ?? "—",
            protocolName: protocolName,
            info: info,
            sessionID: packet.fiveTuple.map(SessionBuilder.sessionID(for:)),
            interfaceID: event.reference.interfaceID,
            hasComment: event.reference.hasComment,
            decodeStop: packet.decodeStop,
            http: HTTPFrameFact(packet, bytes: event.bytes),
            dns: DNSFrameFact(packet),
            rtp: RTPFrameFact(packet, bytes: event.bytes),
            sip: SIPFrameFact(packet, bytes: event.bytes),
            multicast: MulticastFrameFact(packet, bytes: event.bytes),
            ip: IPFrameFact(packet),
            srt: SRTFrameFact(packet, bytes: event.bytes),
            columnValues: configuration.columns.map {
                FieldValueScanner.values(of: $0, in: packet.layers).joined(separator: ",")
            },
            hasBadChecksum: ChecksumValidation.hasIncorrectChecksum(packet.layers, bytes: event.bytes)
        )
    }

    private func revalidateSourceIdentity() throws {
        let handle = try FileHandle(forReadingFrom: sourceURL)
        defer { try? handle.close() }
        guard PcapFileIdentity.snapshot(of: handle).matches(reader.identity) else {
            throw FollowStreamError.identityMismatch
        }
    }
}
