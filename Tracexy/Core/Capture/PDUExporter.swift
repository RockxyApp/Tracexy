import Foundation

// MARK: - PDUExportSummary

nonisolated struct PDUExportSummary: Equatable, Sendable {
    let pduCount: Int
    let streamCount: Int
    /// TCP streams past ``PDUExporter/maximumStreams``, not read.
    let skippedStreamCount: Int
    /// PDUs left out past the PDU or byte bound.
    let omittedPDUCount: Int
}

// MARK: - PDUExporter

/// Wireshark's File ▸ Export PDUs to File at the application layer: each
/// recognized UDP datagram's payload, and each reassembled turn of a recognized TCP
/// stream, written as one packet of link type 252 (Wireshark Upper PDU) behind TLVs
/// naming its dissector and its endpoints, so Wireshark dissects the payload
/// directly. Bounded and cancellable; the source is only read.
nonisolated enum PDUExporter {
    // MARK: Internal

    /// A TCP stream to export, with the application protocol its session carries.
    struct Stream: Sendable {
        let tuple: FiveTuple
        let kind: ProtocolKind
    }

    static let linkType: UInt32 = 252
    static let maximumStreams = 200
    static let maximumPDUs = 100_000
    static let maximumBytes = 512 << 20

    /// Wireshark's dissector name for a protocol Tracexy recognizes, per transport.
    static func dissectorName(_ kind: ProtocolKind, tcp: Bool) -> String? {
        switch (kind, tcp) {
        case (.http, true): "http"
        case (.tls, true): "tls"
        case (.smtp, true): "smtp"
        case (.ftp, true): "ftp"
        case (.imap, true): "imap"
        case (.pop3, true): "pop"
        case (.ssh, true): "ssh"
        case (.sip, _): "sip"
        case (.dns, false): "dns"
        case (.mdns, false): "mdns"
        case (.ssdp, false): "ssdp"
        case (.ntp, false): "ntp"
        case (.dhcp, false): "dhcp"
        case (.stun, false): "stun-udp"
        case (.quic, false): "quic"
        default: nil
        }
    }

    /// The TLVs and payload of one Upper PDU packet.
    static func packet(
        name: String,
        source: IPEndpoint,
        destination: IPEndpoint,
        tcp: Bool,
        payload: [UInt8]
    )
        -> [UInt8]
    {
        var bytes: [UInt8] = []
        func tlv(_ tag: UInt16, _ value: [UInt8]) {
            bytes += [UInt8(tag >> 8), UInt8(tag & 0xFF), UInt8(value.count >> 8), UInt8(value.count & 0xFF)] + value
        }
        func be32(_ value: UInt32) -> [UInt8] {
            (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> (24 - 8 * $0)) }
        }
        var nameBytes = Array(name.utf8)
        nameBytes += [UInt8](repeating: 0, count: (4 - nameBytes.count % 4) % 4)
        tlv(12, nameBytes)
        if let sourceAddress = IPAddressValue(parsing: source.ip),
           let destinationAddress = IPAddressValue(parsing: destination.ip)
        {
            let isV4 = sourceAddress.family == .v4
            tlv(isV4 ? 20 : 22, sourceAddress.bytes)
            tlv(isV4 ? 21 : 23, destinationAddress.bytes)
        }
        tlv(24, be32(tcp ? 2 : 3))
        tlv(25, be32(UInt32(source.port)))
        tlv(26, be32(UInt32(destination.port)))
        tlv(0, [])
        return bytes + payload
    }

    static func export(
        from url: URL,
        expectedIdentity: PcapFileIdentity,
        streams: [Stream],
        datagramSessions: Set<UUID>,
        to output: URL,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> PDUExportSummary
    {
        var pdus: [(order: UInt64, time: Date?, bytes: [UInt8])] = []
        var total = 0
        var omitted = 0
        func keep(_ order: UInt64, _ time: Date?, _ bytes: [UInt8]) {
            guard pdus.count < maximumPDUs, total + bytes.count <= maximumBytes else {
                omitted += 1
                return
            }
            total += bytes.count
            pdus.append((order, time, bytes))
        }
        if !datagramSessions.isEmpty {
            let reader = try CaptureStreamReader(contentsOf: url)
            guard reader.identity.matches(expectedIdentity) else {
                throw FollowStreamError.identityMismatch
            }
            var ordinal: UInt64 = 0
            var sequential = SequentialFrameDecoder()
            walk: while true {
                guard case let .frame(event) = try reader.next() else {
                    break walk
                }
                ordinal += 1
                if ordinal % 1_024 == 0, isCancelled() {
                    throw CancellationError()
                }
                let decoded = sequential.decode(
                    CapturedFrame(
                        bytes: event.bytes, timestamp: event.reference.timestamp,
                        originalLength: event.reference.originalLength,
                        capturedLength: event.reference.capturedLength, linkType: event.reference.linkType
                    ),
                    linkType: reader.defaultLinkType ?? event.reference.linkType,
                    ordinal: ordinal
                )
                guard let tuple = decoded.fiveTuple, tuple.proto == .udp,
                      datagramSessions.contains(SessionBuilder.sessionID(for: tuple)),
                      let kind = decoded.appProtocol, let name = dissectorName(kind, tcp: false),
                      let source = decoded.sourceEndpoint, let destination = decoded.destinationEndpoint else
                {
                    continue
                }
                // A rebuilt datagram's payload comes with the decode, not this frame.
                let payload: [UInt8]
                if let reassembled = decoded.reassembledUDPPayload {
                    payload = reassembled
                } else if let range = decoded.udpPayloadRange, range.upperBound <= event.bytes.count {
                    payload = Array(event.bytes[range])
                } else {
                    continue
                }
                keep(ordinal, event.reference.timestamp, packet(
                    name: name, source: source, destination: destination, tcp: false,
                    payload: payload
                ))
            }
        }
        let read = Array(streams.prefix(maximumStreams))
        // Streams are followed a group at a time, one file pass per group; a tuple
        // listed twice is read once and exported under each of its listings.
        let named = read.compactMap { stream in dissectorName(stream.kind, tcp: true).map { (stream.tuple, $0) } }
        let namesOn = Dictionary(grouping: named, by: \.0).mapValues { $0.map(\.1) }
        func keepTurns(of result: FollowStreamResult, as name: String) {
            for turn in FollowStreamExport.turns(of: result) {
                let aToB = turn.direction == .aToB
                keep(turn.firstOrdinal, turn.timestamp, packet(
                    name: name,
                    source: aToB ? result.tuple.a : result.tuple.b,
                    destination: aToB ? result.tuple.b : result.tuple.a,
                    tcp: true, payload: turn.bytes
                ))
            }
        }
        try FollowStreamReader.readEach(
            contentsOf: url, expectedIdentity: expectedIdentity, tuples: named.map(\.0),
            configuration: .init(isCancelled: isCancelled)
        ) { result in
            for name in namesOn[result.tuple] ?? [] {
                keepTurns(of: result, as: name)
            }
        }
        pdus.sort { $0.order < $1.order }
        try write(pdus.map { ($0.time, $0.bytes) }, to: output)
        return PDUExportSummary(
            pduCount: pdus.count, streamCount: read.count, skippedStreamCount: streams.count - read.count,
            omittedPDUCount: omitted
        )
    }

    // MARK: Private

    /// Written beside `output` and moved into place, so a failure leaves no partial file.
    private static func write(_ packets: [(Date?, [UInt8])], to output: URL) throws {
        let staging = output.deletingLastPathComponent()
            .appendingPathComponent(".\(output.lastPathComponent).\(UUID().uuidString).partial")
        var data = PcapngBlockWriter.sectionHeader(comment: nil)
        data += PcapngBlockWriter.interfaceDescription(linkType: linkType, name: "Exported PDUs", fileName: "")
        for (time, bytes) in packets {
            data += try PcapngBlockWriter.enhancedPacket(bytes: bytes, interfaceID: 0, time: time)
        }
        do {
            try data.write(to: staging, options: .atomic)
            if FileManager.default.fileExists(atPath: output.path) {
                _ = try FileManager.default.replaceItemAt(output, withItemAt: staging)
            } else {
                try FileManager.default.moveItem(at: staging, to: output)
            }
        } catch {
            try? FileManager.default.removeItem(at: staging)
            throw error
        }
    }
}
