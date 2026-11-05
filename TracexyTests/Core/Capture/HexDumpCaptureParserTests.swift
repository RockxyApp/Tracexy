import Foundation
import Testing
@testable import Tracexy

struct HexDumpCaptureParserTests {
    // MARK: Internal

    @Test
    func syntheticSCTPDataBuildsDecodableIPv4AndIPv6WithDirectionalEndpoints() throws {
        let ipv4 = SyntheticSCTPPacketBuilder.Options(
            sourceAddress: "192.0.2.1", destinationAddress: "192.0.2.2",
            sourcePort: 5_000, destinationPort: 5_001, ipv6: false,
            mode: .data(payloadProtocolIdentifier: 42)
        )
        let frames = try HexDumpCaptureParser.parse(
            Data(
                "O 2026-10-24T10:30:00Z\n000000 aa bb\nI 2026-10-24T10:30:01Z\n000000 cc\nO 2026-10-24T10:30:02Z\n000000 dd\n"
                    .utf8
            ),
            linkType: LinkType.ethernet, timestampMode: .iso8601UTC,
            directionIndicators: true, syntheticSCTP: ipv4
        )
        #expect(frames.count == 3)
        #expect(Array(frames[0].bytes[34 ..< 38]) == [0x13, 0x88, 0x13, 0x89])
        #expect(Array(frames[1].bytes[34 ..< 38]) == [0x13, 0x89, 0x13, 0x88])
        #expect(Array(frames[0].bytes[46 ..< 50]) == [0, 3, 0, 18])
        #expect(Array(frames[0].bytes[50 ..< 54]) == [0, 0, 0, 0])
        #expect(Array(frames[1].bytes[50 ..< 54]) == [0, 0, 0, 0])
        #expect(Array(frames[2].bytes[50 ..< 54]) == [0, 0, 0, 1])
        #expect(Array(frames[0].bytes[42 ..< 46]) == [0x6C, 0xE6, 0x95, 0x0D])
        #expect(Array(frames[0].bytes[58 ..< 62]) == [0, 0, 0, 42])
        #expect(Array(frames[0].bytes[62 ..< 64]) == [0xAA, 0xBB])
        for frame in frames {
            let decoded = PacketDecoder.decode(
                PacketBuffer(frame.bytes), linkType: LinkType.ethernet,
                timestamp: frame.timestamp, originalLength: frame.originalLength
            )
            #expect(decoded.layers.map(\.proto).prefix(3) == [.ethernet, .ipv4, .sctp])
            #expect(decoded.decodeStop == nil)
        }
        let encoded = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        #expect(try PcapngReader.read(Array(encoded)).frames.map(\.bytes) == frames.map(\.bytes))

        let ipv6 = SyntheticSCTPPacketBuilder.Options(
            sourceAddress: "2001:db8::1", destinationAddress: "2001:db8::2",
            sourcePort: 5_000, destinationPort: 5_001, ipv6: true,
            mode: .data(payloadProtocolIdentifier: 42)
        )
        let v6 = try HexDumpCaptureParser.parse(
            Data("000000 11\n".utf8), linkType: LinkType.raw, syntheticSCTP: ipv6
        )
        let decoded6 = PacketDecoder.decode(
            PacketBuffer(v6[0].bytes), linkType: LinkType.raw,
            timestamp: nil, originalLength: v6[0].originalLength
        )
        #expect(decoded6.layers.map(\.proto).prefix(2) == [.ipv6, .sctp])
        #expect(decoded6.decodeStop == nil)
    }

    @Test
    func syntheticSCTPChunksPreserveInputAndRefuseInvalidPublication() throws {
        let options = SyntheticSCTPPacketBuilder.Options(
            sourceAddress: "192.0.2.1", destinationAddress: "192.0.2.2",
            sourcePort: 5_000, destinationPort: 5_001, ipv6: false,
            mode: .chunks(verificationTag: 0x12345678)
        )
        let chunk: [UInt8] = [0, 3, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 42, 1, 2, 3, 4]
        let validText = "000000 " + chunk.map { String(format: "%02x", $0) }.joined(separator: " ") + "\n"
        let frames = try HexDumpCaptureParser.parse(
            Data(validText.utf8), linkType: LinkType.ethernet, syntheticSCTP: options
        )
        #expect(Array(frames[0].bytes[38 ..< 42]) == [0x12, 0x34, 0x56, 0x78])
        #expect(Array(frames[0].bytes[42 ..< 46]) == [0xD3, 0x8F, 0xE3, 0x21])
        #expect(Array(frames[0].bytes.suffix(chunk.count)) == chunk)
        let decoded = PacketDecoder.decode(
            PacketBuffer(frames[0].bytes), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: frames[0].originalLength
        )
        #expect(decoded.layers.map(\.proto).prefix(3) == [.ethernet, .ipv4, .sctp])
        #expect(decoded.decodeStop == nil)
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("sctp-chunks.txt")
            try Data(validText.utf8).write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet,
                syntheticSCTP: options, intoDirectory: library
            )
            #expect(capture.lastPathComponent.contains("synthetic-sctp"))
            #expect(try PcapngReader.read(contentsOf: capture).frames.first?.bytes == frames[0].bytes)
            try Data("000000 00 03 00 03\n".utf8).write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.invalidSyntheticSCTP(packet: 1)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet,
                    syntheticSCTP: options, intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    @Test
    func syntheticTCPTracksEachDirectionWithoutInventingHandshake() throws {
        let options = SyntheticTCPPacketBuilder.Options(
            sourceAddress: "192.0.2.1", destinationAddress: "192.0.2.2",
            sourcePort: 40_000, destinationPort: 80, ipv6: false
        )
        let input = Data("""
        O 2026-10-24T10:30:00Z
        000000 aa bb
        I 2026-10-24T10:30:01Z
        000000 cc
        O 2026-10-24T10:30:02Z
        000000 dd ee ff

        """.utf8)
        let frames = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet, timestampMode: .iso8601UTC,
            directionIndicators: true, syntheticTCP: options
        )
        #expect(frames.count == 3)
        #expect(frames.map { Array($0.bytes[38 ..< 42]) } == [
            [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 2],
        ])
        #expect(frames.map { $0.bytes[47] } == [8, 8, 8])
        #expect(Array(frames[1].bytes[34 ..< 38]) == [0, 80, 0x9C, 0x40])
        #expect(Array(frames[0].bytes[24 ..< 26]) == [0xF6, 0xCA])
        #expect(Array(frames[0].bytes[50 ..< 52]) == [0xE4, 0x8A])
        #expect(Array(frames[0].bytes.suffix(2)) == [0xAA, 0xBB])
        #expect(Array(frames[2].bytes.suffix(3)) == [0xDD, 0xEE, 0xFF])
        let decoded = PacketDecoder.decode(
            PacketBuffer(frames[0].bytes), linkType: LinkType.ethernet,
            timestamp: frames[0].timestamp, originalLength: frames[0].originalLength
        )
        #expect(decoded.layers.map(\.proto).prefix(3) == [.ethernet, .ipv4, .tcp])
        let encoded = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        #expect(try PcapngReader.read(Array(encoded)).frames.map(\.bytes) == frames.map(\.bytes))
    }

    @Test
    func syntheticTCPIPv6AndManagedImportValidateBeforePublication() throws {
        let options = SyntheticTCPPacketBuilder.Options(
            sourceAddress: "2001:db8::1", destinationAddress: "2001:db8::2",
            sourcePort: 40_000, destinationPort: 443, ipv6: true
        )
        let frames = try HexDumpCaptureParser.parse(
            Data("000000 11 22 33\n".utf8), linkType: LinkType.raw,
            syntheticTCP: options
        )
        #expect(frames[0].bytes[0] >> 4 == 6)
        #expect(Array(frames[0].bytes[40 ..< 44]) == [0x9C, 0x40, 1, 0xBB])
        #expect(Array(frames[0].bytes[56 ..< 58]) == [0x72, 0x47])
        let decoded = PacketDecoder.decode(
            PacketBuffer(frames[0].bytes), linkType: LinkType.raw,
            timestamp: frames[0].timestamp, originalLength: frames[0].originalLength
        )
        #expect(decoded.layers.map(\.proto).prefix(2) == [.ipv6, .tcp])
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("tcp-payload.txt")
            try Data("000000 11 22 33\n".utf8).write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.raw,
                syntheticTCP: options, intoDirectory: library
            )
            #expect(capture.lastPathComponent.contains("synthetic-tcp"))
            #expect(try PcapngReader.read(contentsOf: capture).frames.first.map { Array($0.bytes.suffix(3)) }
                == [0x11, 0x22, 0x33])
            let invalid = SyntheticTCPPacketBuilder.Options(
                sourceAddress: "invalid", destinationAddress: "2001:db8::2",
                sourcePort: 40_000, destinationPort: 443, ipv6: true
            )
            #expect(throws: HexDumpCaptureParser.ParseError.invalidSyntheticTCPOptions) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.raw,
                    syntheticTCP: invalid, intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    @Test
    func syntheticUDPCreatesDecodableIPv4AndIPv6WithDirectionalEndpoints() throws {
        let ipv4 = SyntheticUDPPacketBuilder.Options(
            sourceAddress: "192.0.2.1", destinationAddress: "192.0.2.2",
            sourcePort: 40_000, destinationPort: 53, ipv6: false
        )
        let outbound = try HexDumpCaptureParser.parse(
            Data("000000 de ad be ef\n".utf8), linkType: LinkType.ethernet,
            syntheticUDP: ipv4
        )
        #expect(outbound.count == 1)
        #expect(Array(outbound[0].bytes.suffix(4)) == [0xDE, 0xAD, 0xBE, 0xEF])
        #expect(Array(outbound[0].bytes[26 ..< 30]) == [192, 0, 2, 1])
        #expect(Array(outbound[0].bytes[30 ..< 34]) == [192, 0, 2, 2])
        #expect(Array(outbound[0].bytes[34 ..< 38]) == [0x9C, 0x40, 0, 53])
        #expect(Array(outbound[0].bytes[24 ..< 26]) == [0xF6, 0xC9])
        #expect(Array(outbound[0].bytes[40 ..< 42]) == [0x41, 0xBF])
        let decoded4 = PacketDecoder.decode(
            PacketBuffer(outbound[0].bytes), linkType: LinkType.ethernet,
            timestamp: outbound[0].timestamp, originalLength: outbound[0].originalLength
        )
        #expect(decoded4.layers.map(\.proto).prefix(3) == [.ethernet, .ipv4, .udp])

        let ipv6 = SyntheticUDPPacketBuilder.Options(
            sourceAddress: "2001:db8::1", destinationAddress: "2001:db8::2",
            sourcePort: 40_000, destinationPort: 53, ipv6: true
        )
        let inbound = try HexDumpCaptureParser.parse(
            Data("I 2026-10-24T10:30:00Z\n000000 aa bb\n".utf8),
            linkType: LinkType.raw, timestampMode: .iso8601UTC, directionIndicators: true,
            syntheticUDP: ipv6
        )
        #expect(inbound[0].bytes[0] >> 4 == 6)
        #expect(inbound[0].bytes[23] == 2)
        #expect(inbound[0].bytes[39] == 1)
        #expect(Array(inbound[0].bytes[40 ..< 44]) == [0, 53, 0x9C, 0x40])
        #expect(Array(inbound[0].bytes[46 ..< 48]) == [0x5D, 0x34])
        let decoded6 = PacketDecoder.decode(
            PacketBuffer(inbound[0].bytes), linkType: LinkType.raw,
            timestamp: inbound[0].timestamp, originalLength: inbound[0].originalLength
        )
        #expect(decoded6.layers.map(\.proto).prefix(2) == [.ipv6, .udp])
        let encoded = try PcapngWriter.data(defaultLinkType: LinkType.raw, frames: inbound)
        #expect(try PcapngReader.read(Array(encoded)).frames.map(\.bytes) == inbound.map(\.bytes))
    }

    @Test
    func syntheticUDPRefusesInvalidConfigurationAndDoesNotPublish() throws {
        let invalid = SyntheticUDPPacketBuilder.Options(
            sourceAddress: "not an IP", destinationAddress: "192.0.2.2",
            sourcePort: 40_000, destinationPort: 53, ipv6: false
        )
        #expect(throws: HexDumpCaptureParser.ParseError.invalidSyntheticUDPOptions) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 aa bb\n".utf8), linkType: LinkType.ethernet,
                syntheticUDP: invalid
            )
        }
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("payload.txt")
            try Data("000000 aa bb\n".utf8).write(to: source)
            let valid = SyntheticUDPPacketBuilder.Options(
                sourceAddress: "192.0.2.1", destinationAddress: "192.0.2.2",
                sourcePort: 40_000, destinationPort: 53, ipv6: false
            )
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet,
                syntheticUDP: valid, intoDirectory: library
            )
            #expect(capture.lastPathComponent.contains("synthetic-udp"))
            #expect(try PcapngReader.read(contentsOf: capture).frames.first.map { Array($0.bytes.suffix(2)) } == [
                0xAA,
                0xBB
            ])
            #expect(throws: HexDumpCaptureParser.ParseError.invalidSyntheticUDPOptions) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet,
                    syntheticUDP: invalid, intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    @Test
    func syntheticEthernetWrapsCompleteIPAndRejectsIncompletePackets() throws {
        let ipv4: [UInt8] = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0,
            192, 0, 2, 1, 192, 0, 2, 2,
        ]
        let ipv6: [UInt8] = [
            0x60, 0, 0, 0, 0, 0, 59, 64,
        ] + Array(repeating: 0, count: 32)
        let input = Data(
            "000000 \(ipv4.map { String(format: "%02x", $0) }.joined(separator: " "))\n000000 \(ipv6.map { String(format: "%02x", $0) }.joined(separator: " "))\n"
                .utf8
        )
        let frames = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet, syntheticEthernetForIP: true
        )
        #expect(frames.map(\.bytes.count) == [34, 54])
        #expect(Array(frames[0].bytes.prefix(14)) == [
            2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0,
        ])
        #expect(Array(frames[1].bytes.suffix(40)) == ipv6)
        #expect(Array(frames[1].bytes[12 ..< 14]) == [0x86, 0xDD])
        let decoded4 = PacketDecoder.decode(
            PacketBuffer(frames[0].bytes), linkType: LinkType.ethernet,
            timestamp: frames[0].timestamp, originalLength: frames[0].originalLength
        )
        let decoded6 = PacketDecoder.decode(
            PacketBuffer(frames[1].bytes), linkType: LinkType.ethernet,
            timestamp: frames[1].timestamp, originalLength: frames[1].originalLength
        )
        #expect(decoded4.layers.map(\.proto).prefix(2) == [.ethernet, .ipv4])
        #expect(decoded6.layers.map(\.proto).prefix(2) == [.ethernet, .ipv6])
        let encoded = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        #expect(try PcapngReader.read(Array(encoded)).frames.map(\.bytes) == frames.map(\.bytes))
        #expect(throws: HexDumpCaptureParser.ParseError.unsupportedLinkType) {
            _ = try HexDumpCaptureParser.parse(
                input, linkType: LinkType.raw, syntheticEthernetForIP: true
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidSyntheticIP(packet: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 45 00 00 15 00 00 00 00 40 01 00 00 c0 00 02 01 c0 00 02 02\n".utf8),
                linkType: LinkType.ethernet, syntheticEthernetForIP: true
            )
        }
    }

    @Test
    func managedSyntheticEthernetImportPublishesOnlyCompletePackets() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("ip-hex.txt")
            try Data("000000 45 00 00 14 00 00 00 00 40 01 00 00 c0 00 02 01 c0 00 02 02\n".utf8)
                .write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet,
                syntheticEthernetForIP: true, intoDirectory: library
            )
            #expect(capture.lastPathComponent.contains("synthetic-ethernet"))
            #expect(try PcapngReader.read(contentsOf: capture).frames.first?.bytes.count == 34)
            try Data("000000 45 00 00 15 00 00 00 00 40 01 00 00 c0 00 02 01 c0 00 02 02\n".utf8)
                .write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.invalidSyntheticIP(packet: 1)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet,
                    syntheticEthernetForIP: true, intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    @Test
    func multilineRegexExtractsBoundedPacketsAndRejectsUnmatchedText() throws {
        let pattern = #"(?m)^record (?<seqno>\d+) (?<time>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\n(?<data>[0-9a-f]+\n[0-9a-f]+)$"#
        let input = Data("""
        # captured locally
        record 7 2026-10-24T10:30:00Z
        aabb
        ccdd
        # next packet
        record 8 2026-10-24T10:30:01Z
        eeff
        0011

        """.utf8)
        let frames = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet, regexPattern: pattern,
            regexPacketMode: .acrossFile
        )
        #expect(frames.map(\.bytes) == [[0xAA, 0xBB, 0xCC, 0xDD], [0xEE, 0xFF, 0, 0x11]])
        #expect(frames.map(\.packetID) == [7, 8])
        let encoded = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        #expect(try PcapngReader.read(Array(encoded)).frames.map(\.packetID) == [7, 8])
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 4)) {
            let invalid = Data("""
            record 7 2026-10-24T10:30:00Z
            aabb
            ccdd
            this text must not disappear
            record 8 2026-10-24T10:30:01Z
            eeff
            0011
            """.utf8)
            _ = try HexDumpCaptureParser.parse(
                invalid, linkType: LinkType.ethernet, regexPattern: pattern,
                regexPacketMode: .acrossFile
            )
        }
        #expect(throws: CancellationError.self) {
            _ = try HexDumpCaptureParser.parse(
                input, linkType: LinkType.ethernet, regexPattern: pattern,
                regexPacketMode: .acrossFile, isCancelled: { true }
            )
        }
        var ticks = 0.0
        #expect(throws: HexDumpCaptureParser.ParseError.regexTimeLimit(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                input, linkType: LinkType.ethernet, regexPattern: pattern,
                regexPacketMode: .acrossFile, uptime: {
                    ticks += 1
                    return ticks
                }
            )
        }
    }

    @Test
    func managedMultilineRegexImportPublishesMatchedPacketsOnly() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("multiline-log.txt")
            let pattern = #"(?m)^packet (?<data>[0-9a-f]+\n[0-9a-f]+)$"#
            try Data("packet aabb\nccdd\npacket eeff\n0011\n".utf8).write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet, regexPattern: pattern,
                regexPacketMode: .acrossFile, intoDirectory: library
            )
            #expect(try PcapngReader.read(contentsOf: capture).frames.map(\.bytes) == [
                [0xAA, 0xBB, 0xCC, 0xDD], [0xEE, 0xFF, 0, 0x11],
            ])
            try Data("packet aabb\nccdd\nnot a packet\n".utf8).write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 3)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet, regexPattern: pattern,
                    regexPacketMode: .acrossFile, intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    @Test
    func regexSequenceNumbersSurvivePcapngAndRequireRealTime() throws {
        let pattern = #"^(?<time>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (?<seqno>\d+) (?<data>[0-9a-f]+)$"#
        let frames = try HexDumpCaptureParser.parse(
            Data("2026-10-24T10:30:00Z 18446744073709551615 aabb\n".utf8),
            linkType: LinkType.ethernet, regexPattern: pattern
        )
        #expect(frames.map(\.packetID) == [UInt64.max])
        let encoded = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        #expect(try PcapngReader.read(Array(encoded)).frames.map(\.packetID) == [UInt64.max])
        let source = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-seqno-\(UUID().uuidString).pcapng")
        try encoded.write(to: source)
        defer { try? FileManager.default.removeItem(at: source) }
        let stream = try CaptureStreamReader(contentsOf: source)
        guard case let .frame(event) = try stream.next() else {
            Issue.record("Expected a packet from the saved pcapng stream")
            return
        }
        #expect(event.reference.packetID == UInt64.max)
        var rebuilt = PcapngBlockWriter.sectionHeader(comment: nil)
        rebuilt.append(PcapngBlockWriter.interfaceDescription(
            linkType: LinkType.ethernet, name: nil, fileName: "imported.pcapng"
        ))
        try rebuilt.append(PcapngBlockWriter.enhancedPacket(
            event, interfaceID: 0, time: #require(event.reference.timestamp)
        ))
        #expect(try PcapngReader.read(Array(rebuilt)).frames.map(\.packetID) == [UInt64.max])
        #expect(throws: SessionExportError.self) {
            _ = try PcapWriter.data(linkType: LinkType.ethernet, frames: frames)
        }
        let untimedID = CapturedFrame(bytes: [0xAA], timestamp: nil, originalLength: 1, packetID: 7)
        do {
            _ = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: [untimedID])
            Issue.record("An untimed packet ID cannot be represented in a Simple Packet Block")
        } catch SessionExportError.untimedPacketIDNotRepresentable {
            // The caller gets the specific cause rather than a captured-length error.
        }
        for invalid in ["0", "18446744073709551616"] {
            #expect(throws: HexDumpCaptureParser.ParseError.invalidRegexSequenceNumber(line: 1)) {
                _ = try HexDumpCaptureParser.parse(
                    Data("2026-10-24T10:30:00Z \(invalid) aabb\n".utf8),
                    linkType: LinkType.ethernet, regexPattern: pattern
                )
            }
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidRegexSequenceNumber(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("7 aabb\n".utf8), linkType: LinkType.ethernet,
                regexPattern: #"^(?<seqno>\d+) (?<data>[0-9a-f]+)$"#
            )
        }
    }

    @Test
    func regexDataEncodingsKeepExactBytesAndRejectPartialValues() throws {
        let pattern = "^pkt=(?<data>.+)$"
        let cases: [(HexDumpCaptureParser.RegexDataEncoding, String)] = [
            (.hexadecimal, "00 ff"),
            (.octal, "000 377"),
            (.binary, "00000000 11111111"),
            (.base64, "AP8="),
        ]
        for (encoding, encoded) in cases {
            let frames = try HexDumpCaptureParser.parse(
                Data("pkt=\(encoded)\n".utf8), linkType: LinkType.ethernet,
                regexPattern: pattern, regexDataEncoding: encoding
            )
            #expect(frames.map(\.bytes) == [[0, 255]])
            let pcapng = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
            #expect(try PcapngReader.read(Array(pcapng)).frames.map(\.bytes) == [[0, 255]])
        }
        for (encoding, encoded) in [
            (HexDumpCaptureParser.RegexDataEncoding.hexadecimal, "0"),
            (.octal, "400"),
            (.binary, "0000000"),
            (.base64, "AP9="),
            (.base64, "AP8"),
        ] {
            #expect(throws: HexDumpCaptureParser.ParseError.invalidRegexData(line: 1)) {
                _ = try HexDumpCaptureParser.parse(
                    Data("pkt=\(encoded)\n".utf8), linkType: LinkType.ethernet,
                    regexPattern: pattern, regexDataEncoding: encoding
                )
            }
        }
    }

    @Test
    func regexModeExtractsTimedDirectionalLogPacketsWithoutDroppingLines() throws {
        let pattern = #"^(?<dir>[<>]) (?<time>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (?<data>[0-9A-Fa-f:]+)$"#
        let input = Data("> 2026-10-24T10:30:00Z 00:01\n< 2026-10-24T10:30:01Z aabb\n".utf8)
        let frames = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet, regexPattern: pattern
        )
        #expect(frames.map(\.bytes) == [[0, 1], [0xAA, 0xBB]])
        #expect(frames.map(\.direction) == [.outbound, .inbound])
        let pcapng = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        let reread = try PcapngReader.read(Array(pcapng))
        #expect(reread.frames.map(\.direction) == [.outbound, .inbound])
        #expect(reread.frames.map(\.bytes) == frames.map(\.bytes))
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 2)) {
            _ = try HexDumpCaptureParser.parse(
                Data("> 2026-10-24T10:30:00Z 00:01\nthis line would be lost\n".utf8),
                linkType: LinkType.ethernet, regexPattern: pattern
            )
        }
    }

    @Test
    func regexModeRefusesAmbiguousOrIncompleteCaptures() throws {
        #expect(throws: HexDumpCaptureParser.ParseError.invalidRegex) {
            _ = try HexDumpCaptureParser.parse(
                Data("aa\n".utf8), linkType: LinkType.ethernet,
                regexPattern: "(?<data>[a-f]+)"
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.regexDataGroupRequired) {
            _ = try HexDumpCaptureParser.parse(
                Data("aa\n".utf8), linkType: LinkType.ethernet,
                regexPattern: "^(?<bytes>[a-f]+)$"
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidRegexData(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("abc\n".utf8), linkType: LinkType.ethernet,
                regexPattern: "^(?<data>[a-f]+)$"
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.directionRequiresTimestamp) {
            _ = try HexDumpCaptureParser.parse(
                Data("I aa\n".utf8), linkType: LinkType.ethernet,
                regexPattern: "^(?<dir>[IO]) (?<data>[a-f]+)$"
            )
        }
        let untimed = try HexDumpCaptureParser.parse(
            Data("log: aabb\n".utf8), linkType: LinkType.ethernet,
            regexPattern: "^log: (?<data>[a-f]+)$"
        )
        #expect(untimed.count == 1)
        #expect(untimed[0].timestamp == nil)
        #expect(untimed[0].bytes == [0xAA, 0xBB])

        var cancellationChecks = 0
        #expect(throws: CancellationError.self) {
            _ = try HexDumpCaptureParser.parse(
                Data("log: aabb\n".utf8), linkType: LinkType.ethernet,
                regexPattern: "^log: (?<data>[a-f]+)$",
                isCancelled: {
                    cancellationChecks += 1
                    return cancellationChecks >= 2
                }
            )
        }

        var clockReads = 0
        #expect(throws: HexDumpCaptureParser.ParseError.regexTimeLimit(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("log: aabb\n".utf8), linkType: LinkType.ethernet,
                regexPattern: "^log: (?<data>[a-f]+)$",
                uptime: {
                    clockReads += 1
                    return clockReads >= 4 ? 2 : 0
                }
            )
        }
    }

    @Test
    func managedRegexImportPublishesOnlyCompleteCapture() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("packet-log.txt")
            try Data("packet=0001\npacket=aabb\n".utf8).write(to: source)
            let pattern = "^packet=(?<data>[0-9A-Fa-f]+)$"
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet, regexPattern: pattern,
                intoDirectory: library
            )
            #expect(try PcapngReader.read(contentsOf: capture).frames.map(\.bytes) == [[0, 1], [0xAA, 0xBB]])
            try Data("packet=0001\nnot a packet\n".utf8).write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 2)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet, regexPattern: pattern,
                    intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    @Test
    func timestampedDirectionPreamblesPersistWithoutInventingTime() throws {
        let input = Data("I 2026-10-24T10:30:00Z\n000000 01 02\nO 2026-10-24T10:30:01Z\n000000 03 04\n".utf8)
        let frames = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet,
            timestampMode: .iso8601UTC, directionIndicators: true
        )
        #expect(frames.map(\.direction) == [.inbound, .outbound])
        #expect(frames.map(\.bytes) == [[1, 2], [3, 4]])
        let data = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        #expect(try PcapngReader.read(Array(data)).frames.map(\.direction) == [.inbound, .outbound])
        #expect(throws: HexDumpCaptureParser.ParseError.directionRequiresTimestamp) {
            _ = try HexDumpCaptureParser.parse(input, linkType: LinkType.ethernet, directionIndicators: true)
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                input, linkType: LinkType.ethernet, timestampMode: .iso8601UTC
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidTimestamp(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("I not-a-time\n000000 aa\n".utf8), linkType: LinkType.ethernet,
                timestampMode: .iso8601UTC, directionIndicators: true
            )
        }
    }

    @Test
    func multiplePacketsRoundTripWithoutInventedTime() throws {
        let first = [UInt8](0 ..< 16)
        let nativeDump = PacketBytesFormat.hexDump.text(for: first[...])
        let input = Data("\(nativeDump)\n000010 10 11\n000000 aa bb\n000002\n".utf8)
        let frames = try HexDumpCaptureParser.parse(input, linkType: LinkType.ethernet)
        #expect(frames.map(\.bytes) == [first + [0x10, 0x11], [0xAA, 0xBB]])
        #expect(frames.allSatisfy { $0.timestamp == nil })

        let pcapng = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        let reread = try PcapngReader.read(Array(pcapng))
        #expect(reread.frames.map(\.bytes) == frames.map(\.bytes))
        #expect(reread.frames.allSatisfy { $0.timestamp == nil })
    }

    @Test
    func optedInUTCPreamblesPreserveFrameTimesThroughPcapng() throws {
        let text = """
        2026-10-24T10:30:00Z
        000000 00 01
        2026-10-24T10:30:01.250Z
        000000 aa bb

        """
        let frames = try HexDumpCaptureParser.parse(
            Data(text.utf8), linkType: LinkType.ethernet, timestampMode: .iso8601UTC
        )
        #expect(frames.map(\.bytes) == [[0, 1], [0xAA, 0xBB]])
        let firstTime = try #require(frames[0].timestamp)
        let secondTime = try #require(frames[1].timestamp)
        #expect(abs(secondTime.timeIntervalSince(firstTime) - 1.25) < 1e-6)
        let pcapng = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        let reread = try PcapngReader.read(Array(pcapng))
        #expect(reread.frames.map(\.bytes) == frames.map(\.bytes))
        let firstRereadTime = try #require(reread.frames[0].timestamp)
        let secondRereadTime = try #require(reread.frames[1].timestamp)
        #expect(abs(secondRereadTime.timeIntervalSince(firstRereadTime) - 1.25) < 1e-6)
    }

    @Test
    func explicitOffsetBasesPreserveExactBytesAndRejectWrongBase() throws {
        let decimal = Data("000000 00 01 02 03 04 05 06 07 08 09\n000010 aa\n".utf8)
        let decimalFrames = try HexDumpCaptureParser.parse(
            decimal, linkType: LinkType.ethernet, offsetRadix: .decimal
        )
        #expect(decimalFrames.map(\.bytes) == [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xAA]])
        let decimalPcapng = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: decimalFrames)
        #expect(try PcapngReader.read(Array(decimalPcapng)).frames.map(\.bytes) == decimalFrames.map(\.bytes))
        #expect(throws: HexDumpCaptureParser.ParseError.offsetMismatch(line: 2, expected: 10, actual: 16)) {
            _ = try HexDumpCaptureParser.parse(decimal, linkType: LinkType.ethernet)
        }

        let octal = Data("000000 00 01 02 03 04 05 06 07\n000010 aa\n".utf8)
        let octalFrames = try HexDumpCaptureParser.parse(
            octal, linkType: LinkType.ethernet, offsetRadix: .octal
        )
        #expect(octalFrames.map(\.bytes) == [[0, 1, 2, 3, 4, 5, 6, 7, 0xAA]])
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 2)) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 00\n000008 aa\n".utf8),
                linkType: LinkType.ethernet, offsetRadix: .octal
            )
        }
    }

    @Test
    func noOffsetModeCombinesRowsIntoOneUntimedFrame() throws {
        let input = Data("# one packet\n00 01\n\n02 03\n".utf8)
        let frames = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet, offsetRadix: .none
        )
        #expect(frames.count == 1)
        #expect(frames[0].bytes == [0, 1, 2, 3])
        #expect(frames[0].timestamp == nil)
        let pcapng = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        let reread = try PcapngReader.read(Array(pcapng))
        #expect(reread.frames.map(\.bytes) == [[0, 1, 2, 3]])
        #expect(reread.frames[0].timestamp == nil)
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 00 01\n".utf8), linkType: LinkType.ethernet, offsetRadix: .none
            )
        }
    }

    @Test
    func noOffsetModeAcceptsOneOptionalTimestampAndRejectsAnother() throws {
        let input = Data("2026-10-24T10:30:01.250Z\n00 01\n02 03\n".utf8)
        let frames = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet, timestampMode: .iso8601UTC,
            offsetRadix: .none
        )
        #expect(frames.count == 1)
        #expect(frames[0].bytes == [0, 1, 2, 3])
        let pcapng = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: frames)
        let reread = try PcapngReader.read(Array(pcapng))
        let importedTime = try #require(frames[0].timestamp)
        let rereadTime = try #require(reread.frames[0].timestamp)
        #expect(abs(rereadTime.timeIntervalSince(importedTime)) < 1e-6)
        #expect(throws: HexDumpCaptureParser.ParseError.invalidTimestamp(line: 3)) {
            _ = try HexDumpCaptureParser.parse(
                Data("2026-10-24T10:30:00Z\n00\n2026-10-24T10:30:01Z\n01\n".utf8),
                linkType: LinkType.ethernet, timestampMode: .iso8601UTC, offsetRadix: .none
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.missingTimestamp(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("00 01\n".utf8), linkType: LinkType.ethernet,
                timestampMode: .iso8601UTC, offsetRadix: .none
            )
        }
    }

    @Test
    func explicitByteGroupsPreserveOrderAndRejectAmbiguousDefault() throws {
        let input = Data("000000 0102 aabbcc 11223344\n000009 ff\n".utf8)
        let network = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet, byteGroupMode: .networkOrder
        )
        #expect(network.map(\.bytes) == [[1, 2, 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33, 0x44, 0xFF]])
        let little = try HexDumpCaptureParser.parse(
            input, linkType: LinkType.ethernet, byteGroupMode: .littleEndian
        )
        #expect(little.map(\.bytes) == [[2, 1, 0xCC, 0xBB, 0xAA, 0x44, 0x33, 0x22, 0x11, 0xFF]])
        let pcapng = try PcapngWriter.data(defaultLinkType: LinkType.ethernet, frames: little)
        #expect(try PcapngReader.read(Array(pcapng)).frames.map(\.bytes) == little.map(\.bytes))
        let noOffsets = try HexDumpCaptureParser.parse(
            Data("0102 aabbcc\n11223344 ff\n".utf8), linkType: LinkType.ethernet,
            offsetRadix: .none, byteGroupMode: .littleEndian
        )
        #expect(noOffsets.map(\.bytes) == little.map(\.bytes))
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(input, linkType: LinkType.ethernet)
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 123\n".utf8), linkType: LinkType.ethernet,
                byteGroupMode: .networkOrder
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 0011223344\n".utf8), linkType: LinkType.ethernet,
                byteGroupMode: .networkOrder
            )
        }
    }

    @Test
    func timestampModeRejectsMissingMalformedAndOrphanPreambles() {
        #expect(throws: HexDumpCaptureParser.ParseError.missingTimestamp(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 00\n".utf8), linkType: LinkType.ethernet, timestampMode: .iso8601UTC
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidTimestamp(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("2026-13-24T10:30:00Z\n000000 00\n".utf8),
                linkType: LinkType.ethernet, timestampMode: .iso8601UTC
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidTimestamp(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("2026-10-24T10:30:00.123456789Z\n000000 00\n".utf8),
                linkType: LinkType.ethernet, timestampMode: .iso8601UTC
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.duplicateTimestamp(line: 2)) {
            _ = try HexDumpCaptureParser.parse(
                Data("2026-10-24T10:30:00Z\n2026-10-24T10:30:01Z\n000000 00\n".utf8),
                linkType: LinkType.ethernet, timestampMode: .iso8601UTC
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.timestampWithoutPacket(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("2026-10-24T10:30:00Z\n".utf8), linkType: LinkType.ethernet,
                timestampMode: .iso8601UTC
            )
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(
                Data("2026-10-24T10:30:00Z\n000000 00\n".utf8), linkType: LinkType.ethernet
            )
        }
    }

    @Test
    func offsetGapAndBadByteRefuseCapture() {
        #expect(throws: HexDumpCaptureParser.ParseError.offsetMismatch(line: 2, expected: 2, actual: 3)) {
            _ = try HexDumpCaptureParser.parse(Data("000000 00 01\n000003 02\n".utf8), linkType: LinkType.ethernet)
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(Data("000000 00 gg\n".utf8), linkType: LinkType.ethernet)
        }
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(Data("000000 0\n".utf8), linkType: LinkType.ethernet)
        }
    }

    @Test
    func nativeAsciiColumnCannotHideHexLookingBytes() throws {
        let bytes: [UInt8] = [0x61, 0x62]
        let dump = PacketBytesFormat.hexDump.text(for: bytes[...])
        let frames = try HexDumpCaptureParser.parse(Data(dump.utf8), linkType: LinkType.ethernet)
        #expect(frames.map(\.bytes) == [bytes])
        #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
            _ = try HexDumpCaptureParser.parse(Data("\(dump.dropLast(2))cd".utf8), linkType: LinkType.ethernet)
        }
    }

    @Test
    func boundsAndLateCancellationRefusePartialCapture() {
        #expect(throws: HexDumpCaptureParser.ParseError.inputTooLarge) {
            _ = try HexDumpCaptureParser.parse(
                Data(repeating: 0x20, count: HexDumpCaptureParser.maxInputBytes + 1),
                linkType: LinkType.ethernet
            )
        }
        var checks = 0
        #expect(throws: CancellationError.self) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 00\n000001 01\n".utf8), linkType: LinkType.ethernet,
                isCancelled: {
                    checks += 1
                    return checks == 2
                }
            )
        }
    }

    @Test
    func emptyAndCancelledInputProduceControlledOutcomes() {
        #expect(throws: HexDumpCaptureParser.ParseError.noFrames) {
            _ = try HexDumpCaptureParser.parse(Data("# comment\n\n".utf8), linkType: LinkType.ethernet)
        }
        #expect(throws: CancellationError.self) {
            _ = try HexDumpCaptureParser.parse(
                Data("000000 00\n".utf8), linkType: LinkType.ethernet, isCancelled: { true }
            )
        }
    }

    @Test
    func onlyAdvertisedLinkTypesCanBecomeCaptures() throws {
        let input = Data("000000 00\n".utf8)
        for linkType in [LinkType.ethernet, LinkType.raw, LinkType.linuxSLL, LinkType.linuxSLL2] {
            let frames = try HexDumpCaptureParser.parse(input, linkType: linkType)
            #expect(frames.count == 1)
            #expect(frames[0].linkType == linkType)
        }
        for linkType: UInt32 in [0, 65_535, 65_536] {
            #expect(throws: HexDumpCaptureParser.ParseError.unsupportedLinkType) {
                _ = try HexDumpCaptureParser.parse(input, linkType: linkType)
            }
        }
    }

    @Test
    func managedImportPublishesOnlyCompleteUntimedCaptureWithoutOverwrite() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("packet-bytes.txt")
            try Data("000000 00 01 02\n000000 aa bb\n".utf8).write(to: source)

            let first = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet, intoDirectory: library
            )
            let second = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet, intoDirectory: library
            )
            #expect(first != second)
            #expect(first.pathExtension == "pcapng")
            let reread = try PcapngReader.read(contentsOf: first)
            #expect(reread.frames.map(\.bytes) == [[0, 1, 2], [0xAA, 0xBB]])
            #expect(reread.frames.allSatisfy { $0.timestamp == nil })

            try Data("000000 00 01\n000003 02\n".utf8).write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.offsetMismatch(line: 2, expected: 2, actual: 3)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet, intoDirectory: library
                )
            }
            let visible = try FileManager.default.contentsOfDirectory(atPath: library.path)
            #expect(Set(visible) == Set([first.lastPathComponent, second.lastPathComponent]))
        }
    }

    @Test
    func managedTimestampImportPublishesExactTimesOnlyAfterValidation() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("timed-packet-bytes.txt")
            try Data("2026-10-24T10:30:00Z\n000000 00 01\n2026-10-24T10:30:01.250Z\n000000 aa bb\n".utf8)
                .write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet, timestampMode: .iso8601UTC,
                intoDirectory: library
            )
            let reread = try PcapngReader.read(contentsOf: capture)
            #expect(reread.frames.map(\.bytes) == [[0, 1], [0xAA, 0xBB]])
            let firstTime = try #require(reread.frames[0].timestamp)
            let secondTime = try #require(reread.frames[1].timestamp)
            #expect(abs(secondTime.timeIntervalSince(firstTime) - 1.25) < 1e-6)

            try Data("2026-10-24T10:30:00Z\n000000 00\n000000 aa\n".utf8).write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.missingTimestamp(line: 3)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet, timestampMode: .iso8601UTC,
                    intoDirectory: library
                )
            }
            let visible = try FileManager.default.contentsOfDirectory(atPath: library.path)
            #expect(visible == [capture.lastPathComponent])
        }
    }

    @Test
    func managedDecimalOffsetImportPreservesFrameAndRefusesWrongOffset() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("decimal-offsets.txt")
            try Data("000000 00 01 02 03 04 05 06 07 08 09\n000010 aa\n".utf8).write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet, offsetRadix: .decimal,
                intoDirectory: library
            )
            let reread = try PcapngReader.read(contentsOf: capture)
            #expect(reread.frames.map(\.bytes) == [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xAA]])
            try Data("000000 00 01\n000003 aa\n".utf8).write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.offsetMismatch(line: 2, expected: 2, actual: 3)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet, offsetRadix: .decimal,
                    intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    @Test
    func managedNoOffsetImportPublishesOneFrameOnlyAfterCompleteValidation() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("one-frame.txt")
            try Data("00 01\n02 03\n".utf8).write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet, offsetRadix: .none,
                intoDirectory: library
            )
            let reread = try PcapngReader.read(contentsOf: capture)
            #expect(reread.frames.map(\.bytes) == [[0, 1, 2, 3]])
            try Data("00 01\n02 gg\n".utf8).write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 2)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet, offsetRadix: .none,
                    intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    @Test
    func managedDirectionImportKeepsPacketFlags() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("directed.txt")
            try Data("I 2026-10-24T10:30:00Z\n000000 aa\nO 2026-10-24T10:30:01Z\n000000 bb\n".utf8)
                .write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet, timestampMode: .iso8601UTC,
                directionIndicators: true, intoDirectory: library
            )
            let reread = try PcapngReader.read(contentsOf: capture)
            #expect(reread.frames.map(\.direction) == [.inbound, .outbound])
            let stream = try CaptureStreamReader(contentsOf: capture)
            var directions: [CaptureDirection] = []
            while directions.count < 2 {
                guard case let .frame(event) = try stream.next() else {
                    break
                }
                directions.append(event.reference.direction)
            }
            #expect(directions == [.inbound, .outbound])
        }
    }

    @Test
    func managedGroupedByteImportPublishesSelectedEndianness() throws {
        try withTemporaryDirectory { root in
            let library = root.appendingPathComponent("Library")
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("grouped-bytes.txt")
            try Data("000000 0102 aabbcc\n".utf8).write(to: source)
            let capture = try HexDumpCaptureImporter.importCapture(
                from: source, linkType: LinkType.ethernet,
                byteGroupMode: .littleEndian, intoDirectory: library
            )
            let reread = try PcapngReader.read(contentsOf: capture)
            #expect(reread.frames.map(\.bytes) == [[2, 1, 0xCC, 0xBB, 0xAA]])
            try Data("000000 0102 aab\n".utf8).write(to: source)
            #expect(throws: HexDumpCaptureParser.ParseError.invalidLine(line: 1)) {
                _ = try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: LinkType.ethernet,
                    byteGroupMode: .littleEndian, intoDirectory: library
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: library.path) == [capture.lastPathComponent])
        }
    }

    // MARK: Private

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("hex-dump-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}
