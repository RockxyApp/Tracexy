import Foundation
import Testing
@testable import Tracexy

struct PcapngReaderTests {
    // MARK: Internal

    @Test
    func parsesLittleEndianEnhancedPacket() throws {
        let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let ticks: UInt64 = 1_700_000_000_500_000 // microseconds since the epoch

        var file: [UInt8] = []
        appendBlock(&file, type: 0x0A0D0D0A) { body in // Section Header Block
            append32(&body, 0x1A2B3C4D) // byte-order magic
            append16(&body, 1)
            append16(&body, 0) // version 1.0
            append64(&body, 0xFFFFFFFFFFFFFFFF) // section length = unspecified
        }
        appendBlock(&file, type: 0x00000001) { body in // Interface Description Block
            append16(&body, 1) // link type: Ethernet
            append16(&body, 0) // reserved
            append32(&body, 262_144) // snaplen
        }
        appendBlock(&file, type: 0x00000006) { body in // Enhanced Packet Block
            append32(&body, 0) // interface id
            append32(&body, UInt32(ticks >> 32))
            append32(&body, UInt32(ticks & 0xFFFFFFFF))
            append32(&body, UInt32(payload.count)) // captured length
            append32(&body, UInt32(payload.count)) // original length
            body += payload
        }

        #expect(PcapngReader.isPcapng(file))
        let result = try PcapngReader.read(file)
        #expect(result.linkType == LinkType.ethernet)
        #expect(result.frames.count == 1)
        #expect(result.frames[0].bytes == payload)
        #expect(result.frames[0].linkType == LinkType.ethernet)
        #expect(abs(result.frames[0].timestamp.timeIntervalSince1970 - 1_700_000_000.5) < 0.0001)
    }

    @Test
    func captureFileReaderSniffsClassicPcap() throws {
        // A classic .pcap must still route correctly through the sniffing reader.
        let frame = CapturedFrame(bytes: [0x01, 0x02], timestamp: Date(timeIntervalSince1970: 1), originalLength: 2)
        let pcap = [UInt8](PcapWriter.data(linkType: LinkType.ethernet, frames: [frame]))
        #expect(!PcapngReader.isPcapng(pcap))
        let result = try CaptureFileReader.read(pcap)
        #expect(result.frames.count == 1)
        #expect(result.frames[0].bytes == [0x01, 0x02])
    }

    // MARK: Private

    private func append16(_ data: inout [UInt8], _ value: UInt16) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    private func append32(_ data: inout [UInt8], _ value: UInt32) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    private func append64(_ data: inout [UInt8], _ value: UInt64) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    /// Frames a block body with the type / total-length / trailing-length envelope,
    /// padding the body to a 32-bit boundary as the spec requires.
    private func appendBlock(_ data: inout [UInt8], type: UInt32, body build: (inout [UInt8]) -> Void) {
        var body: [UInt8] = []
        build(&body)
        while body.count % 4 != 0 {
            body.append(0)
        }
        let total = UInt32(12 + body.count)
        append32(&data, type)
        append32(&data, total)
        data.append(contentsOf: body)
        append32(&data, total)
    }
}
