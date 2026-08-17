import Foundation
import Testing
@testable import Tracexy

// MARK: - Helpers

private func decodeFrame(_ frame: [UInt8], linkType: UInt32 = LinkType.ethernet) -> DecodedPacket {
    PacketDecoder.decode(
        PacketBuffer(frame),
        linkType: linkType,
        timestamp: Date(timeIntervalSince1970: 1_700_000_000),
        originalLength: frame.count
    )
}

private extension DecodedPacket {
    func tlsLayer() -> DecodedLayer? {
        layers.first { $0.proto == .tls }
    }
}

// MARK: - TLSRecordTests

/// Content-based TLS *record* recognition on any TCP port — metadata only. The
/// decoder never decrypts, parses certificates, or reassembles the TCP stream; it
/// surfaces the honest record header (content type, version, captured-vs-declared
/// length) so real midstream Application Data / Alert / Change Cipher Spec /
/// Heartbeat records stop showing up as bare TCP. ClientHello/ServerHello
/// enrichment is unchanged and lives in the sibling enrichment suites.
@Suite("TLS record recognition")
struct TLSRecordTests {
    @Test("Application Data is recognized and labelled without a handshake child")
    func applicationData() {
        let body = [UInt8](repeating: 0xAB, count: 32)
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 23, version: 0x0303, body: body, src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .tls)
        #expect(packet.transport == .tcp)
        #expect(packet.protocolStack == [.ipv4, .tcp, .tls])

        let tls = packet.tlsLayer()
        #expect(tls?.fields.contains(DecodedField(name: "Content Type", value: "Application Data (23)")) == true)
        #expect(tls?.fields.contains(DecodedField(name: "Version", value: "TLS 1.2")) == true)
        #expect(tls?.fields.contains(DecodedField(name: "Record Length", value: "32")) == true)
        // No plaintext is decoded: encrypted records must not sprout handshake children.
        #expect(tls?.children.isEmpty == true)
        #expect(packet.sni == nil)
    }

    @Test("Alert records are recognized and not mislabelled Handshake")
    func alert() {
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 21, version: 0x0303, body: [0x02, 0x28], src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decodeFrame(frame)

        #expect(packet.protocolStack == [.ipv4, .tcp, .tls])
        #expect(packet.tlsLayer()?.fields.contains(DecodedField(name: "Content Type", value: "Alert (21)")) == true)
        #expect(packet.tlsLayer()?.children.isEmpty == true)
    }

    @Test("Change Cipher Spec is recognized")
    func changeCipherSpec() {
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 20, version: 0x0303, body: [0x01], src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decodeFrame(frame)
        #expect(packet.protocolStack == [.ipv4, .tcp, .tls])
        #expect(
            packet.tlsLayer()?.fields.contains(DecodedField(name: "Content Type", value: "Change Cipher Spec (20)"))
                == true
        )
    }

    @Test("Heartbeat is recognized")
    func heartbeat() {
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 24, version: 0x0303, body: [0x01, 0x00, 0x00], src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decodeFrame(frame)
        #expect(packet.tlsLayer()?.fields.contains(DecodedField(name: "Content Type", value: "Heartbeat (24)")) == true)
    }

    @Test("Recognition is port-independent")
    func anyPort() {
        let body = [UInt8](repeating: 0x11, count: 16)
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 23, version: 0x0303, body: body,
            src: "10.0.0.5", dst: "93.184.216.34", srcPort: 44_100, dstPort: 8_443
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == .tls)
        #expect(packet.protocolStack == [.ipv4, .tcp, .tls])
    }

    @Test("An undefined content type is not recognized as TLS")
    func invalidContentTypeStaysTCP() {
        // 0x19 (25) is outside the defined 20…24 range.
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 25, version: 0x0303, body: [UInt8](repeating: 0x00, count: 8),
            src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .tcp])
    }

    @Test("A non-3 record major version is not recognized as TLS")
    func invalidVersionStaysTCP() {
        // Major version 2 (0x02xx) is not a TLS record-layer version.
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 23, version: 0x0203, body: [UInt8](repeating: 0x00, count: 8),
            src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .tcp])
    }

    @Test("A declared length beyond the ciphertext allowance is rejected")
    func oversizedLengthStaysTCP() {
        // 20000 > 2^14 + 2048; impossible for a real TLS record fragment.
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 23, version: 0x0303, body: [UInt8](repeating: 0x00, count: 8),
            declaredLength: 20_000, src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .tcp])
    }

    @Test("An incomplete 5-byte record header is not recognized as TLS")
    func incompleteHeaderStaysTCP() {
        // Only 3 of the 5 required header bytes are present on the TCP payload.
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.5", dst: "93.184.216.34",
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: [0x17, 0x03, 0x03])
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .tcp])
    }

    @Test("A record whose declared body exceeds the captured bytes is labelled a fragment")
    func fragmentedRecordLabelledHonestly() {
        // 40 bytes captured, but the record header declares 4096 — a mid-stream
        // fragment (no TCP reassembly). Recognition still succeeds on the header.
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 23, version: 0x0303, body: [UInt8](repeating: 0xCD, count: 40),
            declaredLength: 4_096, src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == .tls)
        #expect(
            packet.tlsLayer()?.fields.contains(
                DecodedField(name: "Record Length", value: "4096 declared, 40 captured (fragment)")
            ) == true
        )
    }

    @Test("ClientHello enrichment still decodes SNI and a Client Hello child")
    func clientHelloEnrichmentPreserved() {
        let frame = PacketBuilder.tlsClientHelloFrame(sni: "secure.example.com", src: "10.0.0.5", dst: "93.184.216.34")
        let packet = decodeFrame(frame)
        #expect(packet.sni == "secure.example.com")
        let hello = packet.tlsLayer()?.children.first { $0.title == "Handshake: Client Hello" }
        #expect(hello?.fields.contains(DecodedField(name: "server_name", value: "secure.example.com")) == true)
        #expect(packet.tlsLayer()?.fields.contains(DecodedField(name: "Content Type", value: "Handshake (22)")) == true)
    }

    @Test("Coalesced TLS records are all surfaced without duplicating the protocol stack")
    func coalescedRecords() {
        let first = [UInt8(22), 0x03, 0x03, 0x00, 0x01, 0x00]
        let second = [UInt8(23), 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC]
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6,
            src: "10.0.0.5",
            dst: "93.184.216.34",
            payload: PacketBuilder.tcp(
                srcPort: 50_000,
                dstPort: 443,
                flags: 0x18,
                payload: first + second
            )
        )
        let packet = decodeFrame(frame)

        #expect(packet.layers.filter { $0.proto == .tls }.count == 2)
        #expect(packet.protocolStack == [.ipv4, .tcp, .tls])
        #expect(packet.layers.last?.fields.contains(
            DecodedField(name: "Content Type", value: "Application Data (23)")
        ) == true)
    }

    @Test("A TLS-only session stays [.tcp, .tls] and offers no application exchange")
    func tlsOnlySessionHasNoApplicationExchange() {
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 23, version: 0x0303, body: [UInt8](repeating: 0xAB, count: 64),
            src: "10.0.0.5", dst: "93.184.216.34"
        )
        let captured = CapturedFrame(
            bytes: frame, timestamp: Date(timeIntervalSince1970: 1_700_000_000), originalLength: frame.count
        )
        let sessions = SessionBuilder.build(from: [captured], linkType: LinkType.ethernet)
        #expect(sessions.count == 1)
        #expect(sessions.first?.protocolStack == [.tcp, .tls])
        // Encrypted TLS carries no decoded request/response, so no Requests facet.
        #expect(sessions.first?.hasApplicationExchange == false)
    }
}
