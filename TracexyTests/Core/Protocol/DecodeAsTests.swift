import Foundation
import Testing
@testable import Tracexy

/// Capture ▸ Decode As…: a port → protocol rule makes that port's payload decode as the
/// chosen protocol; without it the decoder keeps its own detection.
struct DecodeAsTests {
    // MARK: Internal

    @Test
    func aRuleMakesAnUnusualPortDecodeAsDNS() {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "198.51.100.53",
            payload: PacketBuilder.udp(
                srcPort: 50_000,
                dstPort: 5_300,
                payload: PacketBuilder.dnsQuery(name: "decode.example")
            )
        )
        let plain = decode(frame, rules: [])
        #expect(plain.appProtocol == nil)
        #expect(plain.dnsQuery == nil)

        let forced = decode(frame, rules: [DecodeAsRule(transport: .udp, port: 5_300, decode: .dns)])
        #expect(forced.appProtocol == .dns)
        #expect(forced.dnsQuery == "decode.example")

        let otherTransport = decode(frame, rules: [DecodeAsRule(transport: .tcp, port: 5_300, decode: .dns)])
        #expect(otherTransport.appProtocol == nil, "a TCP rule does not apply to UDP")
    }

    @Test
    func invalidRulesAreNotApplied() {
        #expect(!DecodeAsRule(transport: .udp, port: 0, decode: .dns).isValid)
        #expect(!DecodeAsRule(transport: .tcp, port: 8_080, decode: .quic).isValid, "QUIC rides on UDP only")
        #expect(DecodeAsRule(transport: .tcp, port: 8_080, decode: .http).isValid)
    }

    @MainActor
    @Test
    func settingsPersistPerProject() throws {
        let suite = "decode-as-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let settings = DecodeAsSettings()
        settings.bind(to: defaults)
        #expect(settings.rules.isEmpty)
        settings.setRules([DecodeAsRule(transport: .udp, port: 5_300, decode: .dns)])
        #expect(settings.needsRedecode)
        let reopened = DecodeAsSettings()
        reopened.bind(to: defaults)
        #expect(reopened.rules.map(\.port) == [5_300])
        #expect(!reopened.needsRedecode)
    }

    // MARK: Private

    private func decode(_ frame: [UInt8], rules: [DecodeAsRule]) -> DecodedPacket {
        DecodeAs.$scopedRules.withValue(rules) {
            SessionBuilder.decodePacket(
                CapturedFrame(bytes: frame, timestamp: Date(), originalLength: frame.count),
                linkType: LinkType.ethernet
            )
        }
    }
}
