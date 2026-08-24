import Foundation
import Testing
@testable import Tracexy

// MARK: - Byte helpers

private func be16(_ value: UInt16) -> [UInt8] {
    [UInt8(value >> 8), UInt8(value & 0xFF)]
}

private func be24(_ value: Int) -> [UInt8] {
    [UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
}

/// The RFC 8446 §4.1.3 HelloRetryRequest sentinel random.
private let helloRetryRandom: [UInt8] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
]

private let zeroRandom = [UInt8](repeating: 0, count: 32)

// MARK: - Record / handshake builders

/// Wraps a raw TLS record body into a single-record Ethernet+IPv4+TCP frame.
private func tlsRecordBytes(contentType: UInt8, version: UInt16 = 0x0303, body: [UInt8]) -> [UInt8] {
    [contentType] + be16(version) + be16(UInt16(body.count)) + body
}

private func frame(payload: [UInt8]) -> [UInt8] {
    PacketBuilder.ethernetIPv4(
        proto: 6, src: "10.0.0.5", dst: "93.184.216.34",
        payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: payload)
    )
}

/// Builds a ServerHello handshake message. `extensions` are the raw extension bytes; a
/// `nil` value omits the extensions-length block entirely (a legacy ≤ TLS 1.2 shape).
private func serverHelloHandshake(
    legacyVersion: UInt16, cipher: UInt16, random: [UInt8], extensions: [UInt8]?
)
    -> [UInt8]
{
    var body = be16(legacyVersion) + random + [0x00] // server_version, random, session_id len 0
    body += be16(cipher) + [0x00] // cipher_suite, compression_method
    if let extensions {
        body += be16(UInt16(extensions.count)) + extensions
    }
    return [0x02] + be24(body.count) + body
}

/// The ServerHello `supported_versions` extension carrying one selected version.
private func serverSupportedVersionsExtension(_ version: UInt16) -> [UInt8] {
    be16(0x002B) + be16(2) + be16(version)
}

/// Builds a ClientHello handshake carrying a `supported_versions` extension.
private func clientHelloHandshake(legacyVersion: UInt16, offeredVersions: [UInt16]) -> [UInt8] {
    var body = be16(legacyVersion) + zeroRandom + [0x00] // client version, random, session_id len 0
    body += be16(2) + be16(0x1301) // cipher_suites: one suite
    body += [0x01, 0x00] // compression_methods
    var svData: [UInt8] = [UInt8(offeredVersions.count * 2)]
    for version in offeredVersions {
        svData += be16(version)
    }
    let sv = be16(0x002B) + be16(UInt16(svData.count)) + svData
    body += be16(UInt16(sv.count)) + sv
    return [0x01] + be24(body.count) + body
}

private func decode(_ bytes: [UInt8]) -> DecodedPacket {
    PacketDecoder.decode(
        PacketBuffer(bytes), linkType: LinkType.ethernet,
        timestamp: Date(timeIntervalSince1970: 1_700_000_000), originalLength: bytes.count
    )
}

private extension DecodedPacket {
    var soleServerHello: TLSServerHelloFact? {
        guard case let .serverHello(fact)? = tlsRecords.first?.handshake else {
            return nil
        }
        return fact
    }

    var soleClientHello: TLSClientHelloFact? {
        guard case let .clientHello(fact)? = tlsRecords.first?.handshake else {
            return nil
        }
        return fact
    }
}

// MARK: - TLSFactsTests

/// Neutral, typed per-packet TLS record/hello facts (N3C1). These assert wire facts and
/// completeness only — never a policy verdict, and never a selected version the standard
/// forbids concluding from partial framing.
@Suite("TLS neutral facts")
struct TLSFactsTests {
    @Test("TLS 1.3 ServerHello publishes the supported_versions selection, not the legacy value")
    func tls13ServerHelloSelectsFromSupportedVersions() {
        let handshake = serverHelloHandshake(
            legacyVersion: 0x0303, cipher: 0x1301, random: zeroRandom,
            extensions: serverSupportedVersionsExtension(0x0304)
        )
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, body: handshake)))
        let hello = packet.soleServerHello
        #expect(hello?.legacyVersion == 0x0303)
        #expect(hello?.selectedCipher == 0x1301)
        #expect(hello?.isHelloRetryRequest == false)
        #expect(hello?.extensionsComplete == true)
        #expect(hello?.selectedVersion == 0x0304)
    }

    @Test("A complete TLS 1.2 ServerHello without supported_versions selects the legacy version")
    func tls12ServerHelloFallsBackToLegacy() {
        let handshake = serverHelloHandshake(
            legacyVersion: 0x0303, cipher: 0xC02F, random: zeroRandom, extensions: []
        )
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, body: handshake)))
        let hello = packet.soleServerHello
        #expect(hello?.legacyVersion == 0x0303)
        #expect(hello?.selectedCipher == 0xC02F)
        #expect(hello?.extensionsComplete == true)
        #expect(hello?.selectedVersion == 0x0303)
    }

    @Test("A truncated extension region exposes legacy 0x0303 but yields no selected version")
    func truncatedServerHelloYieldsNoSelectedVersion() {
        let handshake = serverHelloHandshake(
            legacyVersion: 0x0303, cipher: 0x1301, random: zeroRandom,
            extensions: serverSupportedVersionsExtension(0x0304)
        )
        // Declared record/handshake lengths stay intact; the captured bytes stop inside
        // the extension region, so the whole handshake was not captured.
        var record = tlsRecordBytes(contentType: 22, body: handshake)
        record.removeLast(5)
        let packet = decode(frame(payload: record))
        let hello = packet.soleServerHello
        #expect(hello?.legacyVersion == 0x0303)
        #expect(hello?.extensionsComplete == false)
        #expect(hello?.selectedVersion == nil)
        // The record fact itself honestly reports the body as a fragment.
        #expect(packet.tlsRecords.first?.bodyComplete == false)
    }

    @Test("A HelloRetryRequest is detected and never published as a final selection")
    func helloRetryRequestExcluded() {
        let handshake = serverHelloHandshake(
            legacyVersion: 0x0303, cipher: 0x1301, random: helloRetryRandom,
            extensions: serverSupportedVersionsExtension(0x0304)
        )
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, body: handshake)))
        let hello = packet.soleServerHello
        #expect(hello?.isHelloRetryRequest == true)
        #expect(hello?.extensionsComplete == true)
        #expect(hello?.selectedVersion == nil)
        #expect(hello?.selectedCipher == 0x1301)
    }

    @Test("ClientHello offered versions are bounded with an explicit omission count")
    func clientHelloOffersAreBounded() {
        let offered = (0 ..< 20).map { UInt16(0x0300 + $0) } // 20 distinct versions, cap is 16
        let handshake = clientHelloHandshake(legacyVersion: 0x0303, offeredVersions: offered)
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, version: 0x0301, body: handshake)))
        let hello = packet.soleClientHello
        #expect(hello?.legacyVersion == 0x0303)
        #expect(hello?.offeredVersions.count == 16)
        #expect(hello?.offeredVersions.first == 0x0300)
        #expect(hello?.offeredVersionsOmittedCount == 4)
        #expect(hello?.extensionsComplete == true)
    }

    @Test("A ServerHello cannot consume a following coalesced record")
    func serverHelloDoesNotCrossRecordBoundary() {
        let partialHandshake = [UInt8(0x02)] + be24(64) + be16(0x0303)
        let first = tlsRecordBytes(contentType: 22, body: partialHandshake)
        let second = tlsRecordBytes(contentType: 23, body: [UInt8](repeating: 0, count: 80))
        let packet = decode(frame(payload: first + second))
        #expect(packet.tlsRecords.count == 2)
        #expect(packet.tlsRecords.first?.handshake == nil)
        #expect(packet.layers.first { $0.proto == .tls }?.children.isEmpty == true)
    }

    @Test("Trailing bytes outside the declared extension list prevent selection")
    func serverHelloTrailingExtensionBytesFailClosed() {
        let validExtension = serverSupportedVersionsExtension(0x0304)
        var handshake = serverHelloHandshake(
            legacyVersion: 0x0303, cipher: 0x1301, random: zeroRandom,
            extensions: validExtension + [0xFF]
        )
        // Keep the trailing byte in the handshake but make extensions_total_length
        // describe only the otherwise-valid extension.
        let extensionsLengthOffset = 4 + 2 + 32 + 1 + 2 + 1
        handshake[extensionsLengthOffset] = 0
        handshake[extensionsLengthOffset + 1] = UInt8(validExtension.count)
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, body: handshake)))
        #expect(packet.soleServerHello?.extensionsComplete == false)
        #expect(packet.soleServerHello?.selectedVersion == nil)
    }

    @Test("Malformed supported_versions never falls back to the legacy value")
    func malformedSupportedVersionFailsClosed() {
        let malformed = be16(0x002B) + be16(3) + be16(0x0304) + [0]
        let handshake = serverHelloHandshake(
            legacyVersion: 0x0303, cipher: 0x1301, random: zeroRandom,
            extensions: malformed
        )
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, body: handshake)))
        #expect(packet.soleServerHello?.extensionsComplete == false)
        #expect(packet.soleServerHello?.selectedVersion == nil)
    }

    @Test("An over-cap extension walk is incomplete and publishes no selection")
    func serverExtensionWalkCapFailsClosed() {
        let emptyExtension = be16(0x1234) + be16(0)
        let extensions = Array(repeating: emptyExtension, count: 65).flatMap { $0 }
            + serverSupportedVersionsExtension(0x0304)
        let handshake = serverHelloHandshake(
            legacyVersion: 0x0303, cipher: 0x1301, random: zeroRandom,
            extensions: extensions
        )
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, body: handshake)))
        #expect(packet.soleServerHello?.extensionsComplete == false)
        #expect(packet.soleServerHello?.selectedVersion == nil)
    }

    @Test("Malformed ClientHello supported_versions is explicitly incomplete")
    func malformedClientSupportedVersionsIsIncomplete() {
        var handshake = clientHelloHandshake(legacyVersion: 0x0303, offeredVersions: [0x0304])
        // supported_versions vector length is one byte too short for its extension.
        let vectorLengthOffset = handshake.count - 3
        handshake[vectorLengthOffset] = 1
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, body: handshake)))
        #expect(packet.soleClientHello?.extensionsComplete == false)
        #expect(packet.soleClientHello?.offeredVersions.isEmpty == true)
    }

    @Test("An Alert record is content-type presence only, with no handshake fact")
    func alertIsPresenceOnly() {
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 21, body: [0x02, 0x28])))
        #expect(packet.tlsRecords.count == 1)
        #expect(packet.tlsRecords.first?.contentType == 21)
        #expect(packet.tlsRecords.first?.handshake == nil)
    }

    @Test("A ServerHello truncated before its cipher yields no handshake fact but a record fact")
    func incompleteHandshakeYieldsNoHandshakeFact() {
        // Handshake header + version + only 10 of 32 random bytes: cipher is unreachable.
        var body = be16(0x0303) + [UInt8](repeating: 0, count: 10)
        body = [0x02] + be24(64) + body // declared handshake length overstates the captured body
        let packet = decode(frame(payload: tlsRecordBytes(contentType: 22, body: body)))
        #expect(packet.tlsRecords.count == 1)
        #expect(packet.tlsRecords.first?.contentType == 22)
        #expect(packet.tlsRecords.first?.handshake == nil)
        #expect(packet.tlsRecords.first?.bodyComplete == true) // record body fully captured; handshake is not
    }

    @Test("A record fact separates content type, legacy version, declared and captured length")
    func recordFactSeparatesFraming() {
        // 40 captured body bytes but a declared body of 4096 — a mid-stream fragment.
        let record = [UInt8(23)] + be16(0x0303) + be16(4_096) + [UInt8](repeating: 0xCD, count: 40)
        let packet = decode(frame(payload: record))
        let fact = packet.tlsRecords.first
        #expect(fact?.contentType == 23)
        #expect(fact?.legacyRecordVersion == 0x0303)
        #expect(fact?.declaredBodyLength == 4_096)
        #expect(fact?.capturedBodyLength == 40)
        #expect(fact?.bodyComplete == false)
        #expect(fact?.handshake == nil)
    }

    @Test("Coalesced records past the 32-record cap set the explicit truncation flag")
    func coalescedRecordsAreCappedAndFlagged() {
        let unit = tlsRecordBytes(contentType: 23, body: [0xAB])
        let packet = decode(frame(payload: Array(repeating: unit, count: 33).flatMap { $0 }))
        #expect(packet.tlsRecords.count == 32)
        #expect(packet.tlsRecordsTruncated == true)
        // The rendered layers are capped the same way, unchanged from before.
        #expect(packet.layers.filter { $0.proto == .tls }.count == 32)
    }

    @Test("Exactly 32 coalesced records are not flagged as truncated")
    func exactCapIsNotFlagged() {
        let unit = tlsRecordBytes(contentType: 23, body: [0xAB])
        let packet = decode(frame(payload: Array(repeating: unit, count: 32).flatMap { $0 }))
        #expect(packet.tlsRecords.count == 32)
        #expect(packet.tlsRecordsTruncated == false)
    }

    @Test("Decoding the same frame twice produces identical TLS facts")
    func decodeIsDeterministic() {
        let handshake = serverHelloHandshake(
            legacyVersion: 0x0303, cipher: 0x1301, random: zeroRandom,
            extensions: serverSupportedVersionsExtension(0x0304)
        )
        let bytes = frame(payload: tlsRecordBytes(contentType: 22, body: handshake))
        let first = decode(bytes)
        let second = decode(bytes)
        #expect(first.tlsRecords == second.tlsRecords)
        #expect(first.tlsRecordsTruncated == second.tlsRecordsTruncated)
    }

    @Test("Existing SNI/layer rendering is preserved alongside the new facts")
    func existingRenderingPreserved() {
        let bytes = PacketBuilder.tlsClientHelloFrame(
            sni: "secure.example.com", src: "10.0.0.5", dst: "93.184.216.34"
        )
        let packet = decode(bytes)
        // Unchanged behavior: SNI and the rendered Client Hello layer still decode.
        #expect(packet.sni == "secure.example.com")
        let hello = packet.layers.first { $0.proto == .tls }?
            .children.first { $0.title == "Handshake: Client Hello" }
        #expect(hello?.fields.contains(DecodedField(name: "server_name", value: "secure.example.com")) == true)
        // New behavior: a neutral ClientHello fact rides alongside without a negotiation claim.
        #expect(packet.soleClientHello?.legacyVersion == 0x0303)
    }
}
