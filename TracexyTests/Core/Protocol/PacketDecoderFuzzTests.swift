import Foundation
import Testing
@testable import Tracexy

// MARK: - PacketDecoderFuzzTests

/// The decoder must never crash on hostile or truncated input — it returns a partial
/// `DecodedPacket` and silently drops whatever it could not parse. These tests assert
/// that contract across every truncation prefix and a large body of random bytes.
@Suite("PacketDecoder robustness")
struct PacketDecoderFuzzTests {
    // MARK: Internal

    @Test("truncating a valid DNS frame to every prefix never crashes")
    func truncatedDNS() {
        let frame = PacketBuilder.dnsQueryFrame(name: "api.example.com", src: "192.168.1.42", dst: "1.1.1.1")
        for length in 0 ... frame.count {
            let prefix = Array(frame.prefix(length))
            for linkType in linkTypes {
                _ = decode(prefix, linkType: linkType)
            }
        }
    }

    @Test("truncating a valid TLS ClientHello frame to every prefix never crashes")
    func truncatedTLS() {
        let frame = PacketBuilder.tlsClientHelloFrame(sni: "api.example.com", src: "192.168.1.42", dst: "93.184.16.34")
        for length in 0 ... frame.count {
            let prefix = Array(frame.prefix(length))
            for linkType in linkTypes {
                let packet = decode(prefix, linkType: linkType)
                // A partial decode is always a valid object; truncation can only lose
                // layers relative to the full frame, never produce a malformed result.
                #expect(packet.layers.count <= 4)
            }
        }
    }

    @Test("truncating a valid HTTP request frame to every prefix never crashes")
    func truncatedHTTP() {
        let frame = PacketBuilder.httpRequestFrame(
            host: "example.com",
            path: "/index.html",
            src: "192.168.1.42",
            dst: "93.184.16.34"
        )
        for length in 0 ... frame.count {
            let prefix = Array(frame.prefix(length))
            for linkType in linkTypes {
                _ = decode(prefix, linkType: linkType)
            }
        }
    }

    @Test("the empty frame decodes to an empty-but-valid packet")
    func emptyFrame() {
        for linkType in linkTypes {
            let packet = decode([], linkType: linkType)
            #expect(packet.layers.isEmpty)
            #expect(packet.fiveTuple == nil)
            #expect(packet.appProtocol == nil)
        }
    }

    @Test("a full valid frame still decodes once truncations are interleaved (sanity)")
    func fullFrameStillDecodes() {
        let frame = PacketBuilder.dnsQueryFrame(name: "sanity.test", src: "10.0.0.1", dst: "10.0.0.2")
        let packet = decode(frame, linkType: LinkType.ethernet)
        #expect(packet.appProtocol == .dns)
        #expect(packet.dnsQuery == "sanity.test")
    }

    @Test("thousands of random byte blobs never crash the decoder")
    func randomBytes() {
        var generator = SeededGenerator(seed: 0xDEADBEEF)
        for _ in 0 ..< 4_000 {
            let length = Int.random(in: 0 ... 200, using: &generator)
            let blob = (0 ..< length).map { _ in UInt8.random(in: 0 ... 255, using: &generator) }
            let linkType = linkTypes.randomElement(using: &generator) ?? LinkType.ethernet
            // The only contract under fuzz: it returns a DecodedPacket and does not trap.
            _ = decode(blob, linkType: linkType)
        }
    }

    @Test("random bytes wearing a valid Ethernet+IPv4 header never crash")
    func randomPayloadValidHeaders() {
        var generator = SeededGenerator(seed: 0x12345678)
        for _ in 0 ..< 2_000 {
            let payloadLen = Int.random(in: 0 ... 120, using: &generator)
            let payload = (0 ..< payloadLen).map { _ in UInt8.random(in: 0 ... 255, using: &generator) }
            let proto = UInt8.random(in: 0 ... 255, using: &generator)
            let frame = PacketBuilder.ethernetIPv4(
                proto: proto,
                src: "192.168.0.1",
                dst: "192.168.0.2",
                payload: payload
            )
            _ = decode(frame, linkType: LinkType.ethernet)
        }
    }

    // MARK: Private

    /// Every linkType the decoder knows about, plus an unknown one (falls back to Ethernet).
    private let linkTypes: [UInt32] = [LinkType.ethernet, LinkType.raw, LinkType.null, 9_999]

    private func decode(_ frame: [UInt8], linkType: UInt32) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(frame),
            linkType: linkType,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            originalLength: frame.count
        )
    }
}

// MARK: - SeededGenerator

/// Deterministic PRNG so fuzz runs are reproducible across machines and CI.
private struct SeededGenerator: RandomNumberGenerator {
    // MARK: Lifecycle

    init(seed: UInt64) {
        state = seed == 0 ? 0x9E3779B97F4A7C15 : seed
    }

    // MARK: Internal

    mutating func next() -> UInt64 {
        // xorshift64*
        state ^= state >> 12
        state ^= state << 25
        state ^= state >> 27
        return state &* 0x2545F4914F6CDD1D
    }

    // MARK: Private

    private var state: UInt64
}
