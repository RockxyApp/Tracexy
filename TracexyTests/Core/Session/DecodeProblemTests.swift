import Foundation
import Testing
@testable import Tracexy

/// Frames whose decoding stopped early — a header the decoder rejected, or a
/// frame the snapshot length cut inside a header — are marked in All Frames the
/// way Wireshark's Expert Info marks them, and can be listed on their own.
@MainActor
struct DecodeProblemTests {
    // MARK: Internal

    @Test
    func malformedAndCutShortFramesAreMarked() throws {
        let good = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.5", dst: "203.0.113.9",
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: Array("hello".utf8))
        )
        var bogus = good
        bogus[14] = 0x44 // IHL 4: a 16-byte IPv4 header
        let cut = Array(good.prefix(40)) // ends inside the TCP header

        #expect(Self.decode(good).decodeStop == nil)
        #expect(Self.decode(bogus).decodeStop == .malformed("Invalid IPv4 header length"))
        #expect(Self.decode(cut, originalLength: good.count).decodeStop == .cutShort)
        // Cut to the same length but not by the snapshot length: that is malformed.
        #expect(Self.decode(cut).decodeStop == .malformed("A header runs past the end of the frame"))

        var file = ReplayCorpus.classicPcapBytes([
            ReplayCorpus.Frame(bytes: good, offsetSeconds: 0, linkType: LinkType.ethernet),
            ReplayCorpus.Frame(bytes: bogus, offsetSeconds: 1, linkType: LinkType.ethernet),
        ])
        file += ReplayCorpus.classicRecordHeaderLE(
            seconds: 1_700_000_002, fraction: 0, inclLen: UInt32(cut.count), origLen: UInt32(good.count)
        ) + cut
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("decode-problems-\(UUID().uuidString).pcap")
        try Data(file).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let identity = try CaptureStreamReader(contentsOf: url).identity
        let list = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
        #expect(list.decodeProblemCount == 2)
        #expect(list.rows.map(\.decodeStop) == [nil, .malformed("Invalid IPv4 header length"), .cutShort])
        #expect(list.rows[1].info.hasSuffix("[Malformed Packet]"))
        #expect(list.rows[2].info.hasSuffix("[Packet size limited during capture]"))
        // The IPv4 header of the cut frame was read: its addresses, not the MACs, as in Wireshark.
        #expect(list.rows[2].source == "10.0.0.5" && list.rows[2].destination == "203.0.113.9")

        let state = CaptureFrameListState()
        state.list = list
        state.limitToSessionsInView = false
        state.showsDecodeProblemsOnly = true
        #expect(state.visibleRows(sessionsInView: []).map(\.id) == [2, 3])
        // Both fold into no session, so limiting to sessions in view still lists them.
        state.limitToSessionsInView = true
        #expect(state.visibleRows(sessionsInView: []).map(\.id) == [2, 3])
        state.showsDecodeProblemsOnly = false
        #expect(state.visibleRows(sessionsInView: []).isEmpty)

        // Synthetic frames carry zero checksums: wrong wherever an IP header was read.
        #expect(list.rows.map(\.hasBadChecksum) == [true, false, true])
        #expect(list.badChecksumOnlyCount == 1)
        #expect(list.problemCount(countingBadChecksums: false) == 2)
        #expect(list.problemCount(countingBadChecksums: true) == 3)
        state.limitToSessionsInView = false
        state.showsDecodeProblemsOnly = true
        state.countsBadChecksums = true
        #expect(state.visibleRows(sessionsInView: []).map(\.id) == [1, 2, 3])

        guard WiresharkOracle.isAvailable else {
            return
        }
        let malformed = try WiresharkOracle.tsharkFields(
            url, fields: ["frame.number"], filter: "_ws.malformed || _ws.expert.severity == error"
        )
        let short = try WiresharkOracle.tsharkFields(url, fields: ["frame.number"], filter: "_ws.short")
        #expect(malformed == [["2"]])
        #expect(short == [["3"]])
        let badChecksums = try WiresharkOracle.tsharkFields(
            url, fields: ["frame.number"], filter: "ip.checksum.status == 0 || tcp.checksum.status == 0",
            extraArguments: ["-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE"]
        )
        #expect(badChecksums == [["1"], ["3"]])
    }

    // MARK: Private

    private static func decode(_ frame: [UInt8], originalLength: Int? = nil) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet, timestamp: nil,
            originalLength: originalLength ?? frame.count
        )
    }
}
