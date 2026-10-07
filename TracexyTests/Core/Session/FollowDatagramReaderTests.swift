import Foundation
import Testing
@testable import Tracexy

// MARK: - FollowDatagramReaderTests

/// The on-demand UDP follow must list one conversation's datagrams in capture order
/// from a stable source: exact-tuple matching, direction from the canonical tuple,
/// payload bounded by the UDP length (never Ethernet padding), DNS read and paired
/// query-to-response, and a retained set that is always a complete prefix.
struct FollowDatagramReaderTests {
    // MARK: Internal

    /// A DNS message with an explicit id, flags word and A answers.
    static func dnsMessage(id: UInt16, flags: UInt16, name: String, answers: [String] = []) -> [UInt8] {
        var dns = be16(id) + be16(flags) + be16(1) + be16(UInt16(answers.count)) + be16(0) + be16(0)
        dns += qname(name) + be16(1) + be16(1)
        for answer in answers {
            dns += [0xC0, 0x0C] + be16(1) + be16(1) + [0, 0, 1, 44] + be16(4)
            dns += answer.split(separator: ".").compactMap { UInt8($0) }
        }
        return dns
    }

    static func classicPcap(_ records: [(captured: [UInt8], originalLength: UInt32)]) -> [UInt8] {
        var bytes: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1] + le16(2) + le16(4) + le32(0) + le32(0) + le32(65_535)
        bytes += le32(LinkType.ethernet)
        for (index, record) in records.enumerated() {
            bytes += le32(UInt32(index + 1)) + le32(UInt32(index) * 1_000)
            bytes += le32(UInt32(record.captured.count)) + le32(record.originalLength)
            bytes += record.captured
        }
        return bytes
    }

    @Test
    func listsBothDirectionsInCaptureOrderWithDNSReading() throws {
        let frames = [
            Self.dns(client: true, id: 0x0101, flags: 0x0100, name: "www.example.test"),
            Self.dns(client: false, id: 0x0101, flags: 0x8180, name: "www.example.test", answers: ["192.0.2.80"]),
        ]
        try Self.withCapture(frames) { url, identity in
            let result = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()

            #expect(result.matchedFrameCount == 2)
            #expect(result.scannedFrameCount == 2)
            #expect(result.completeness == .complete)
            #expect(result.limitations.isEmpty)
            #expect(result.messages.map(\.direction) == [.aToB, .bToA])
            #expect(result.messages.map(\.provenance.ordinal.rawValue) == [1, 2])

            let query = try #require(result.messages[0].dns)
            #expect(!query.isResponse)
            #expect(query.questionName == "www.example.test")
            #expect(query.questionType == 1)
            #expect(query.pairedMessageIndex == 1)

            let response = try #require(result.messages[1].dns)
            #expect(response.isResponse)
            #expect(response.responseCode == 0)
            #expect(response.answerRecords == ["A 192.0.2.80"])
            #expect(response.pairedMessageIndex == 0)
        }
    }

    @Test
    func retriedQueryStaysUnpairedAndErrorCodesSurvive() throws {
        let frames = [
            Self.dns(client: true, id: 0x0202, flags: 0x0100, name: "missing.example.test"),
            Self.dns(client: true, id: 0x0202, flags: 0x0100, name: "missing.example.test"),
            Self.dns(client: false, id: 0x0202, flags: 0x8183, name: "missing.example.test"),
            Self.dns(client: true, id: 0x0303, flags: 0x0100, name: "slow.example.test"),
        ]
        try Self.withCapture(frames) { url, identity in
            let messages = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read().messages

            // The response pairs with the *first* query carrying its id; the retry
            // and the unanswered query remain visibly unpaired.
            #expect(messages[0].dns?.pairedMessageIndex == 2)
            #expect(messages[1].dns?.pairedMessageIndex == nil)
            #expect(messages[2].dns?.pairedMessageIndex == 0)
            #expect(messages[2].dns?.responseCode == 3)
            #expect(messages[3].dns?.pairedMessageIndex == nil)
        }
    }

    @Test
    func responseInTheSameDirectionIsNeverPaired() {
        let query = Self.message(direction: .aToB, id: 7, response: false)
        let echoed = Self.message(direction: .aToB, id: 7, response: true)
        let paired = FollowDatagramReader.pairDNS([query, echoed])
        #expect(paired[0].dns?.pairedMessageIndex == nil)
        #expect(paired[1].dns?.pairedMessageIndex == nil)
    }

    @Test
    func payloadIsBoundedByTheDeclaredLengthNotPadding() throws {
        // A 4-byte datagram in a 60-byte Ethernet minimum frame is padded with 4
        // zero bytes after the IP packet; none of them are payload.
        var frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "10.0.0.5", dst: "203.0.113.9",
            payload: PacketBuilder.udp(srcPort: 50_000, dstPort: 9_999, payload: [0xDE, 0xAD, 0xBE, 0xEF])
        )
        frame += [UInt8](repeating: 0, count: max(0, 60 - frame.count))
        let tuple = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
            destination: IPEndpoint(ip: "203.0.113.9", port: 9_999)
        )
        try Self.withCapture([frame]) { url, identity in
            let message = try #require(try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: tuple
            ).read().messages.first)
            #expect(message.payload == [0xDE, 0xAD, 0xBE, 0xEF])
            #expect(message.declaredPayloadLength == 4)
            #expect(message.dns == nil)
            #expect(!message.isCaptureTruncated)
        }
    }

    @Test
    func captureTruncationIsFlaggedWithoutGuessing() throws {
        let full = PacketBuilder.ethernetIPv4(
            proto: 17, src: "10.0.0.5", dst: "203.0.113.9",
            payload: PacketBuilder.udp(
                srcPort: 50_000, dstPort: 53, payload: [UInt8](repeating: 0x41, count: 200)
            )
        )
        let captured = Array(full.prefix(full.count - 150))
        try Self.withRawCapture([(captured, UInt32(full.count))]) { url, identity in
            let result = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()
            let message = try #require(result.messages.first)
            #expect(message.capturedPayloadLength == 50)
            #expect(message.declaredPayloadLength == 200)
            #expect(message.isCaptureTruncated)
            #expect(result.limitations.contains(.capturedPayloadTruncated))
        }
    }

    @Test
    func retentionIsACompletePrefixWithExactCounts() throws {
        let frames = (0 ..< 5).map { index in
            Self.dns(client: index.isMultiple(of: 2), id: UInt16(index), flags: 0x0100, name: "a.example.test")
        }
        try Self.withCapture(frames) { url, identity in
            let result = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple,
                configuration: .init(maxMessages: 3)
            ).read()
            #expect(result.messages.map(\.provenance.ordinal.rawValue) == [1, 2, 3])
            #expect(result.omittedMessageCount == 2)
            #expect(result.omittedPayloadByteCount > 0)
            #expect(result.matchedFrameCount == 5)
            #expect(result.limitations.contains(.messageRetentionTruncated))
        }
    }

    @Test
    func aRefusedLargeDatagramEndsThePrefixEvenForLaterSmallOnes() throws {
        let big = PacketBuilder.ethernetIPv4(
            proto: 17, src: "10.0.0.5", dst: "203.0.113.9",
            payload: PacketBuilder.udp(srcPort: 50_000, dstPort: 53, payload: [UInt8](repeating: 1, count: 900))
        )
        let small = Self.dns(client: true, id: 9, flags: 0x0100, name: "b.example.test")
        try Self.withCapture([small, big, small]) { url, identity in
            let result = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple,
                configuration: .init(maxRetainedPayloadBytes: 500)
            ).read()
            #expect(result.messages.count == 1)
            #expect(result.omittedMessageCount == 2)
        }
    }

    @Test
    func perMessageBoundKeepsAPrefixAndCountsTheRest() throws {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "10.0.0.5", dst: "203.0.113.9",
            payload: PacketBuilder.udp(srcPort: 50_000, dstPort: 53, payload: Array(0 ..< 100))
        )
        try Self.withCapture([frame]) { url, identity in
            let result = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple,
                configuration: .init(maxPayloadBytesPerMessage: 10)
            ).read()
            let message = try #require(result.messages.first)
            #expect(message.payload == Array(0 ..< 10))
            #expect(message.boundOmittedByteCount == 90)
            #expect(result.limitations.contains(.messageBytesBounded))
        }
    }

    @Test
    func unrelatedConversationsAreNotListed() throws {
        let frames = [
            Self.dns(client: true, id: 1, flags: 0x0100, name: "mine.example.test"),
            PacketBuilder.dnsQueryFrame(
                name: "other.example.test",
                src: "10.0.0.5",
                dst: "203.0.113.9",
                srcPort: 50_001
            ),
        ]
        try Self.withCapture(frames) { url, identity in
            let result = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()
            #expect(result.scannedFrameCount == 2)
            #expect(result.matchedFrameCount == 1)
            #expect(result.messages.first?.dns?.questionName == "mine.example.test")
        }
    }

    @Test
    func groupedReadsEqualSingleReads() throws {
        let other = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "10.0.0.5", port: 50_001),
            destination: IPEndpoint(ip: "203.0.113.9", port: 53)
        )
        let frames = [
            Self.dns(client: true, id: 1, flags: 0x0100, name: "mine.example.test"),
            PacketBuilder.dnsQueryFrame(
                name: "other.example.test",
                src: "10.0.0.5",
                dst: "203.0.113.9",
                srcPort: 50_001
            ),
            Self.dns(client: false, id: 1, flags: 0x8180, name: "mine.example.test", answers: ["192.0.2.1"]),
        ]
        let small = FollowDatagramReader.Configuration(maxMessages: 1)
        try Self.withCapture(frames) { url, identity in
            for configuration in [FollowDatagramReader.Configuration(), small] {
                let singles = try [Self.tuple, other].map {
                    try FollowDatagramReader(
                        contentsOf: url, expectedIdentity: identity, tuple: $0, configuration: configuration
                    ).read()
                }
                var grouped: [FollowDatagramResult] = []
                try FollowDatagramReader.readEach(
                    contentsOf: url, expectedIdentity: identity, tuples: [Self.tuple, other, Self.tuple],
                    configuration: configuration
                ) { grouped.append($0) }
                #expect(grouped == singles)
            }
            let pair = try FollowDatagramReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            #expect(pair.messages.first?.dns?.pairedMessageIndex == 1)
        }
    }

    @Test
    func sourceTokenMakesEveryDatagramNavigable() throws {
        let token = UUID()
        try Self.withCapture([Self.dns(client: true, id: 1, flags: 0x0100, name: "n.example.test")]) { url, identity in
            let withToken = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple, sourceToken: token
            ).read()
            #expect(withToken.messages.first?.provenance.locator?.sourceToken == token)
            let withoutToken = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()
            #expect(withoutToken.messages.first?.provenance.locator == nil)
        }
    }

    @Test
    func nonUDPTupleAndIdentityMismatchAreRefused() throws {
        let tcp = FiveTuple(proto: .tcp, source: Self.tuple.a, destination: Self.tuple.b)
        try Self.withCapture([Self.dns(client: true, id: 1, flags: 0x0100, name: "x.example.test")]) { url, identity in
            #expect(throws: FollowStreamError.tupleNotUDP) {
                _ = try FollowDatagramReader(contentsOf: url, expectedIdentity: identity, tuple: tcp)
            }
            let stale = PcapFileIdentity(
                size: identity.size &+ 1,
                modifiedAt: identity.modifiedAt,
                device: identity.device,
                inode: identity.inode
            )
            #expect(throws: FollowStreamError.identityMismatch) {
                _ = try FollowDatagramReader(contentsOf: url, expectedIdentity: stale, tuple: Self.tuple)
            }
        }
    }

    /// tshark's `dns.response_to` is the independent oracle for pairing, and its
    /// per-frame UDP length for where the payload ends under Ethernet padding.
    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkAgreesOnPairingAndPayloadLength() throws {
        let frames = [
            Self.dns(client: true, id: 0x0A0A, flags: 0x0100, name: "www.example.test"),
            Self.dns(client: false, id: 0x0A0A, flags: 0x8180, name: "www.example.test", answers: ["192.0.2.80"]),
            Self.dns(client: true, id: 0x0B0B, flags: 0x0100, name: "missing.example.test"),
            Self.dns(client: false, id: 0x0B0B, flags: 0x8183, name: "missing.example.test"),
            Self.dns(client: true, id: 0x0C0C, flags: 0x0100, name: "slow.example.test"),
            Self.dns(client: true, id: 0x0C0C, flags: 0x0100, name: "slow.example.test"),
        ].map { $0 + [UInt8](repeating: 0, count: max(0, 60 - $0.count)) }
        try Self.withCapture(frames) { url, identity in
            let result = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: identity, tuple: Self.tuple
            ).read()
            let rows = try WiresharkOracle.tsharkFields(
                url, fields: ["frame.number", "dns.response_to", "udp.length"], filter: "dns"
            )
            #expect(rows.count == result.messages.count)
            for (row, message) in zip(rows, result.messages) {
                let pairedOrdinal = message.dns?.isResponse == true
                    ? message.dns?.pairedMessageIndex.map { String(result.messages[$0].provenance.ordinal.rawValue) }
                    : nil
                #expect(row[1] == (pairedOrdinal ?? ""))
                #expect(Int(row[2]) == message.payload.count + 8)
            }
        }
    }

    @Test
    func repeatedReadsAreDeterministic() throws {
        let frames = [
            Self.dns(client: true, id: 4, flags: 0x0100, name: "d.example.test"),
            Self.dns(client: false, id: 4, flags: 0x8180, name: "d.example.test", answers: ["192.0.2.4"]),
        ]
        try Self.withCapture(frames) { url, identity in
            let first = try FollowDatagramReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            let second = try FollowDatagramReader(contentsOf: url, expectedIdentity: identity, tuple: Self.tuple).read()
            #expect(first == second)
        }
    }

    // MARK: Private

    /// 10.0.0.5:50000 ↔ 203.0.113.9:53; the client sorts first, so it is `a`.
    private static let tuple = FiveTuple(
        proto: .udp,
        source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
        destination: IPEndpoint(ip: "203.0.113.9", port: 53)
    )

    private static func be16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    private static func qname(_ name: String) -> [UInt8] {
        name.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
    }

    private static func dns(
        client: Bool, id: UInt16, flags: UInt16, name: String, answers: [String] = []
    )
        -> [UInt8]
    {
        let payload = dnsMessage(id: id, flags: flags, name: name, answers: answers)
        return client
            ? PacketBuilder.ethernetIPv4(
                proto: 17, src: "10.0.0.5", dst: "203.0.113.9",
                payload: PacketBuilder.udp(srcPort: 50_000, dstPort: 53, payload: payload)
            )
            : PacketBuilder.ethernetIPv4(
                proto: 17, src: "203.0.113.9", dst: "10.0.0.5",
                payload: PacketBuilder.udp(srcPort: 53, dstPort: 50_000, payload: payload)
            )
    }

    private static func message(direction: ConnectionDirection, id: UInt16, response: Bool) -> FollowDatagramMessage {
        FollowDatagramMessage(
            direction: direction,
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(1), timestamp: nil, capturedLength: 0, originalLength: 0, linkType: 1
            ),
            payload: [],
            capturedPayloadLength: 0,
            declaredPayloadLength: nil,
            dns: FollowDNSMessage(
                transactionID: id, isResponse: response, opcode: 0, responseCode: 0, isTruncated: false,
                questionName: "", questionType: nil, answerRecords: [], omittedAnswerCount: 0
            )
        )
    }

    // MARK: Capture harness

    private static func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8(value >> 8)]
    }

    private static func le32(_ value: UInt32) -> [UInt8] {
        (0 ..< 4).map { UInt8((value >> (8 * $0)) & 0xFF) }
    }

    private static func withCapture(_ frames: [[UInt8]], _ body: (URL, PcapFileIdentity) throws -> Void) throws {
        try withRawCapture(frames.map { ($0, UInt32($0.count)) }, body)
    }

    private static func withRawCapture(
        _ records: [(captured: [UInt8], originalLength: UInt32)],
        _ body: (URL, PcapFileIdentity) throws -> Void
    )
        throws
    {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("followdatagram-\(UUID().uuidString).pcap")
        try Data(classicPcap(records)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url, CaptureStreamReader(contentsOf: url).identity)
    }
}
