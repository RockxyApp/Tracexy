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

        let bytes = try [UInt8](PcapWriter.data(linkType: LinkType.ethernet, frames: frames))
        let result = try PcapReader.read(bytes)

        #expect(result.linkType == LinkType.ethernet)
        #expect(result.frames.count == 2)
        #expect(result.frames[0].bytes == dns)
        #expect(result.frames[1].bytes == tls)
        // Microsecond timestamp survives the round-trip.
        let instant = try #require(result.frames[0].timestamp)
        #expect(abs(instant.timeIntervalSince1970 - 1_700_000_000.5) < 0.0001)
    }

    @Test
    func writesClassicLittleEndianMagic() throws {
        let frame = CapturedFrame(bytes: [0xDE, 0xAD], timestamp: Date(), originalLength: 2)
        let bytes = try [UInt8](PcapWriter.data(linkType: LinkType.ethernet, frames: [frame]))
        // D4 C3 B2 A1 == classic little-endian, microsecond.
        #expect(Array(bytes.prefix(4)) == [0xD4, 0xC3, 0xB2, 0xA1])
    }

    @Test
    func rebuildsSameSessionsAfterRoundTrip() throws {
        let original = SessionBuilder.build(from: SampleCapture.frames(now: Date()), linkType: LinkType.ethernet)
        let bytes = try [UInt8](
            PcapWriter.data(linkType: LinkType.ethernet, frames: SampleCapture.frames(now: Date()))
        )
        let reread = try PcapReader.read(bytes)
        let rebuilt = SessionBuilder.build(from: reread.frames, linkType: reread.linkType)
        #expect(rebuilt.count == original.count)
        #expect(rebuilt.map(\.id) == original.map(\.id))
    }

    @Test("Classic pcap refuses an untimed frame instead of inventing a record timestamp")
    func rejectsUntimedFrames() {
        let timed = CapturedFrame(bytes: [0x01], timestamp: Date(timeIntervalSince1970: 10), originalLength: 1)
        let untimed = CapturedFrame(bytes: [0x02], timestamp: nil, originalLength: 1)
        #expect(!PcapWriter.canRepresent(frames: [timed, untimed]))
        #expect(PcapWriter.canRepresent(frames: [timed]))
        var thrown: SessionExportError?
        do {
            _ = try PcapWriter.data(linkType: LinkType.ethernet, frames: [timed, untimed])
        } catch let error as SessionExportError {
            thrown = error
        } catch {
            thrown = nil
        }
        #expect(thrown == .untimedFramesRequirePcapng)
    }
}
