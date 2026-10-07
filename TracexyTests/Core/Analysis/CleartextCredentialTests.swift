import Foundation
import Testing
@testable import Tracexy

/// A login secret sent unencrypted is a warning finding that names the shape
/// (HTTP Basic, FTP/POP3 PASS, IMAP LOGIN, SMTP AUTH) and never keeps the secret.
struct CleartextCredentialTests {
    // MARK: Internal

    @Test
    func detectorRecognizesEachShapeOnlyWhereItBelongs() {
        func detect(_ text: String, port: UInt16) -> CleartextCredentialKind? {
            CleartextCredentialDetector.detect(payload: Array(text.utf8), sourcePort: 50_000, destinationPort: port)
        }
        #expect(detect("GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n", port: 80) ==
            .httpBasic)
        #expect(
            detect("GET / HTTP/1.1\r\nAuthorization: Bearer abc\r\n\r\n", port: 80) == nil,
            "a bearer token is not a password"
        )
        #expect(detect("USER alice\r\nPASS secret\r\n", port: 21) == .ftp)
        #expect(detect("PASS secret\r\n", port: 110) == .pop3)
        #expect(detect("PASS secret\r\n", port: 8_080) == nil, "PASS off its standard port is not claimed")
        #expect(detect("a001 LOGIN alice secret\r\n", port: 143) == .imap)
        #expect(detect("a001 LOGIN\r\n", port: 143) == nil)
        #expect(detect("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n", port: 587) == .smtp)
        #expect(CleartextCredentialDetector.detect(
            payload: [0x16, 0x03, 0x01, 0x00],
            sourcePort: 1,
            destinationPort: 443
        ) == nil)
    }

    @Test
    func aBasicLoginIsOneWarningCitingItsFrame() throws {
        var table = ConnectionTable()
        let request = Array("GET /admin HTTP/1.1\r\nHost: example.test\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
            .utf8)
        ingest(&table, from: client, to: server, flags: [.syn], seq: 1_000, ordinal: 1)
        ingest(&table, from: server, to: client, flags: [.syn, .ack], seq: 5_000, ack: 1_001, ordinal: 2)
        ingest(&table, from: client, to: server, flags: [.ack], seq: 1_001, ack: 5_001, ordinal: 3)
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: request,
            ordinal: 4
        )
        // The same header again (a retry) reports nothing new.
        ingest(
            &table,
            from: client,
            to: server,
            flags: [.psh, .ack],
            seq: 1_001,
            ack: 5_001,
            payload: request,
            ordinal: 5
        )

        let snapshot = table.snapshot()
        let events = try #require(snapshot.summaries.first).events.filter { $0.kind == .cleartextCredential }
        #expect(events.map(\.credentialKind) == [.httpBasic])
        let finding = try #require(ConnectionAssessor().assess(snapshot).findings.first {
            $0.kind == .cleartextCredentialsObserved
        })
        #expect(finding.severity == .warning)
        #expect(finding.citations.map(\.occurrenceOrdinal) == [FrameOrdinal(4)])
        #expect(try SessionQueryParser().parse("finding == cleartextCredentials")
            == .leaf(.findingKind(.cleartextCredentials)))
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let server = IPEndpoint(ip: "203.0.113.80", port: 80)

    private func ingest(
        _ table: inout ConnectionTable,
        from source: IPEndpoint,
        to destination: IPEndpoint,
        flags: TCPFlags,
        seq: UInt32 = 0,
        ack: UInt32 = 0,
        payload: [UInt8] = [],
        ordinal: UInt64
    ) {
        var packet = DecodedPacket(timestamp: Date(timeIntervalSince1970: Double(ordinal)), originalLength: 0)
        packet.transport = .tcp
        packet.sourceEndpoint = source
        packet.destinationEndpoint = destination
        packet.fiveTuple = FiveTuple(proto: .tcp, source: source, destination: destination)
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: seq,
            acknowledgementNumber: ack,
            flags: flags,
            windowSize: 65_535,
            headerLength: 20,
            payloadSequence: flags.contains(.syn) ? seq &+ 1 : seq,
            payloadLength: payload.count,
            options: TCPOptionFacts()
        )
        packet.tcpPayloadBytes = payload
        table.ingest(packet, provenance: SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: Date(timeIntervalSince1970: Double(ordinal)),
            capturedLength: 60,
            originalLength: 60,
            linkType: 1
        ))
    }
}
