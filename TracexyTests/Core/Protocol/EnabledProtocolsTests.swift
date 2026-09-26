import Foundation
import Testing
@testable import Tracexy

/// Capture ▸ Enabled Protocols: a switched-off protocol is not recognized — its payload
/// stays plain TCP or UDP data, whether it came by port, by content or by a Decode As
/// rule — and the choice belongs to the Project.
@MainActor
struct EnabledProtocolsTests {
    @Test
    func aDisabledProtocolLeavesItsPayloadUndecoded() {
        let dns = PacketBuilder.dnsQueryFrame(name: "a.test", src: "192.0.2.10", dst: "192.0.2.53")
        let tls = PacketBuilder.tlsClientHelloFrame(sni: "a.test", src: "192.0.2.10", dst: "198.51.100.7")
        let decode = { (bytes: [UInt8]) in
            SessionBuilder.decodePacket(
                CapturedFrame(bytes: bytes, timestamp: nil, originalLength: bytes.count), linkType: LinkType.ethernet
            )
        }
        #expect(decode(dns).layers.map(\.proto).last == .dns)
        DecodeAs.$scopedDisabled.withValue([.dns]) {
            let packet = decode(dns)
            #expect(packet.layers.map(\.proto) == [.ethernet, .ipv4, .udp])
            #expect(packet.dnsQuery == nil)
            #expect(decode(tls).layers.map(\.proto).last == .tls)
            // A Decode As rule does not bring a switched-off protocol back.
            DecodeAs.$scopedRules.withValue([DecodeAsRule(transport: .udp, port: 53, decode: .dns)]) {
                #expect(decode(dns).layers.map(\.proto).last == .udp)
            }
        }
        DecodeAs.$scopedDisabled.withValue([.tls]) {
            #expect(!decode(tls).layers.map(\.proto).contains(.tls))
            #expect(decode(tls).sni == nil)
        }
    }

    @Test
    func theChoiceIsKeptPerProject() throws {
        let suite = "enabled-protocols-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = DecodeAsSettings()
        settings.publishesToDecoder = false
        settings.bind(to: defaults)
        #expect(settings.disabledProtocols.isEmpty)
        settings.setEnabled(false, .ssdp)
        settings.setEnabled(false, .mdns)
        settings.setEnabled(true, .mdns)
        #expect(settings.disabledProtocols == [.ssdp])
        #expect(settings.needsRedecode)
        let reopened = DecodeAsSettings()
        reopened.publishesToDecoder = false
        reopened.bind(to: defaults)
        #expect(reopened.disabledProtocols == [.ssdp])
        #expect(!reopened.needsRedecode)
        #expect(DecodeAsProtocol.allCases.allSatisfy { $0.kind != .other })
    }
}
