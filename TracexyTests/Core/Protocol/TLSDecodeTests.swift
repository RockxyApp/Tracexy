import Foundation
import Testing
@testable import Tracexy

@Suite("TLS enrichment decode")
struct TLSEnrichmentTests {
    @Test
    func clientHelloCarriesVersionCipherAndSNI() {
        let frame = PacketBuilder.tlsClientHelloFrame(
            sni: "secure.example.com", src: "192.168.1.10", dst: "93.184.216.34"
        )
        let packet = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        )
        let tls = packet.layers.first { $0.title == "Transport Layer Security" }
        let hello = tls?.children.first { $0.title == "Handshake: Client Hello" }
        #expect(hello != nil)
        #expect(hello?.fields.contains(DecodedField(name: "Version", value: "TLS 1.2")) == true)
        #expect(hello?.fields.contains { $0.name == "Cipher Suites" } == true)
        #expect(hello?.fields.contains(DecodedField(name: "server_name", value: "secure.example.com")) == true)
        #expect(packet.sni == "secure.example.com")
    }
}
