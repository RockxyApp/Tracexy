import Foundation
import Testing
@testable import Tracexy

struct PcapWriterTests {
    @Test
    func roundTripsFramesThroughReader() throws {
        let dns = PacketBuilder.dnsQueryFrame(name: "example.com", src: "192.168.1.2", dst: "1.1.1.1")
        let tls = PacketBuilder.tlsClientHelloFrame(sni: "example.com", src: "192.168.1.2", dst: "93.184.16.34")
        let frames = [
            CapturedFrame(
                bytes: dns,
                timestamp: Date(timeIntervalSince1970: 1_700_000_000.5),
                originalLength: dns.count
            ),
            CapturedFrame(bytes: tls, timestamp: Date(timeIntervalSince1970: 1_700_000_001), originalLength: tls.count),
        ]

        let bytes = [UInt8](PcapWriter.data(linkType: LinkType.ethernet, frames: frames))
        let result = try PcapReader.read(bytes)

        #expect(result.linkType == LinkType.ethernet)
        #expect(result.frames.count == 2)
        #expect(result.frames[0].bytes == dns)
        #expect(result.frames[1].bytes == tls)
        // Microsecond timestamp survives the round-trip.
        #expect(abs(result.frames[0].timestamp.timeIntervalSince1970 - 1_700_000_000.5) < 0.0001)
    }

    @Test
    func writesClassicLittleEndianMagic() {
        let frame = CapturedFrame(bytes: [0xDE, 0xAD], timestamp: Date(), originalLength: 2)
        let bytes = [UInt8](PcapWriter.data(linkType: LinkType.ethernet, frames: [frame]))
        // D4 C3 B2 A1 == classic little-endian, microsecond.
        #expect(Array(bytes.prefix(4)) == [0xD4, 0xC3, 0xB2, 0xA1])
    }

    @Test
    func rebuildsSameSessionsAfterRoundTrip() throws {
        let original = SessionBuilder.build(from: SampleCapture.frames(now: Date()), linkType: LinkType.ethernet)
        let bytes = [UInt8](PcapWriter.data(linkType: LinkType.ethernet, frames: SampleCapture.frames(now: Date())))
        let reread = try PcapReader.read(bytes)
        let rebuilt = SessionBuilder.build(from: reread.frames, linkType: reread.linkType)
        #expect(rebuilt.count == original.count)
        #expect(rebuilt.map(\.id) == original.map(\.id))
    }
}
