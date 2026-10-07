import Foundation
import Security
import Testing
@testable import Tracexy

// MARK: - TLSCertificateExtractionTests

/// Certificates are read from a followed stream's leading bytes only, in the order
/// sent, and only when their DER parses completely. Every absence has a named
/// reason, and an encrypted handshake is never reported as a missing certificate.
struct TLSCertificateExtractionTests {
    // MARK: Internal

    /// A leaf (`CN=www.example.test`, SAN DNS/IP) and the self-signed root that
    /// issued it. Public test certificates generated for this suite with OpenSSL;
    /// the private keys were never kept.
    static let leafDER = Array(Data(base64Encoded: """
    MIIB6zCCAZGgAwIBAgICKjswCgYIKoZIzj0EAwIwRzELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEFRyYWNleHkgRml4dHVyZXMxHTAbBgNVBAMM\
    FFRyYWNleHkgVGVzdCBSb290IENBMB4XDTI2MDYwMTAwMDAwMFoXDTI3MDYwMTAwMDAwMFowNjEZMBcGA1UECgwQRXhhbXBsZSBUZXN0IE9y\
    ZzEZMBcGA1UEAwwQd3d3LmV4YW1wbGUudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCSE6i3eMAr86JBiXE9ZSUlKs2KkvINBXGzt\
    jfRFXS09EVtynwTlCMAFCIuTZysSE/3UNE98Id5KedUd9hl8Oc+jfjB8MC8GA1UdEQQoMCaCEHd3dy5leGFtcGxlLnRlc3SCDGV4YW1wbGUu\
    dGVzdIcEwAACCjAJBgNVHRMEAjAAMB0GA1UdDgQWBBSiv3PWGXQmVRllWfY2+rzj64+s1TAfBgNVHSMEGDAWgBRzS3fgcSVRQCxTuAIRuvCj\
    Fj2q+zAKBggqhkjOPQQDAgNIADBFAiACxP8TDCX+1ThF9XZPJKzGjJF0NnumYeeJ+dH+ZHYq0gIhAMlOMphMeEFYtT8gNFj3ziTou+GxcGfB\
    IR/bYqHlvq6I
    """) ?? Data())

    static let rootDER = Array(Data(base64Encoded: """
    MIIB0TCCAXegAwIBAgICEAEwCgYIKoZIzj0EAwIwRzELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEFRyYWNleHkgRml4dHVyZXMxHTAbBgNVBAMM\
    FFRyYWNleHkgVGVzdCBSb290IENBMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowRzELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEFRy\
    YWNleHkgRml4dHVyZXMxHTAbBgNVBAMMFFRyYWNleHkgVGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtpWu6LDpSsw4\
    zLfUeh4cFcrZQC4jBf2bcg0qfTEvYVHAkjFPC7I2UpXH6TUuhYaCnZFP3NfExNREKd/POzss2aNTMFEwHQYDVR0OBBYEFHNLd+BxJVFALFO4\
    AhG68KMWPar7MB8GA1UdIwQYMBaAFHNLd+BxJVFALFO4AhG68KMWPar7MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAIJr\
    ePFsdFLIO+hxFEUyshAGXMHdVPKwSBs8BASfAP+bAiB+gNsOWYLT7cAo/oyPuRwQ1AycUmANnAnJieCUNxbIgA==
    """) ?? Data())

    // MARK: Fixture assembly

    /// ServerHello, Certificate(leaf, root), ServerHelloDone — a TLS 1.2 flight.
    static func serverFlight(split: Bool) -> [UInt8] {
        let hello = handshake(2, [0x03, 0x03] + [UInt8](repeating: 0x11, count: 32) + [0, 0xC0, 0x2B, 0])
        let certificate = handshake(11, certificateList([leafDER, rootDER]))
        let done = handshake(14, [])
        if split {
            let half = certificate.count / 2
            return record(22, hello + Array(certificate.prefix(half)))
                + record(22, Array(certificate.dropFirst(half)) + done)
        }
        return record(22, hello) + record(22, certificate) + record(22, done)
    }

    // MARK: X.509 reading

    @Test
    func leafFieldsMatchWhatOpenSSLPrinted() throws {
        let leaf = try #require(X509CertificateSummary(der: Self.leafDER))
        #expect(leaf.version == 3)
        #expect(leaf.serialNumberHex == "2A:3B")
        #expect(leaf.subject.displayString == "CN=www.example.test, O=Example Test Org")
        #expect(leaf.issuer.displayString == "CN=Tracexy Test Root CA, O=Tracexy Fixtures, C=US")
        #expect(leaf.displayName == "www.example.test")
        #expect(leaf.subjectAlternativeNames == ["www.example.test", "example.test", "192.0.2.10"])
        #expect(leaf.notBefore == Self.utc(2_026, 6, 1))
        #expect(leaf.notAfter == Self.utc(2_027, 6, 1))
        #expect(!leaf.isSelfIssued)
        #expect(leaf.fingerprintHex == "61:CC:FB:86:98:3E:03:0B:40:9E:DC:1F:F6:7B:65:99:"
            + "ED:65:94:6F:37:8D:CA:63:1B:B9:FE:CF:51:BC:AD:1A")
    }

    @Test
    func rootIsSelfIssuedAndMatchesTheSecurityFrameworkSummary() throws {
        let root = try #require(X509CertificateSummary(der: Self.rootDER))
        #expect(root.isSelfIssued)
        #expect(root.serialNumberHex == "10:01")
        #expect(root.notAfter == Self.utc(2_036, 1, 1))
        for der in [Self.rootDER, Self.leafDER] {
            let summary = try #require(X509CertificateSummary(der: der))
            let certificate = try #require(SecCertificateCreateWithData(nil, Data(der) as CFData))
            let oracle = SecCertificateCopySubjectSummary(certificate) as String?
            #expect(oracle == summary.displayName)
        }
    }

    @Test
    func pemRoundTripsTheExactBytes() throws {
        let leaf = try #require(X509CertificateSummary(der: Self.leafDER))
        let body = leaf.pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
        #expect(Data(base64Encoded: body).map(Array.init) == Self.leafDER)
        #expect(leaf.pem.split(separator: "\n").dropFirst().dropLast().allSatisfy { $0.count <= 64 })
    }

    @Test
    func malformedEncodingsAreRefusedNotGuessed() {
        #expect(X509CertificateSummary(der: []) == nil)
        #expect(X509CertificateSummary(der: Array(Self.leafDER.dropLast())) == nil)
        #expect(X509CertificateSummary(der: Self.leafDER + [0x00]) == nil)
        var badLength = Self.leafDER
        badLength[3] = 0xFF
        #expect(X509CertificateSummary(der: badLength) == nil)
        #expect(X509CertificateSummary(der: [0x30, 0x80, 0x00, 0x00]) == nil)
    }

    // MARK: Handshake walking

    @Test
    func tls12ServerFlightListsTheChainInOrder() {
        let outcome = TLSCertificateExtraction.extract(fromStreamPrefix: Self.serverFlight(split: false))
        let chain = outcome.certificates
        #expect(chain.map(\.displayName) == ["www.example.test", "Tracexy Test Root CA"])
        guard case let .certificates(_, unparsed, omitted) = outcome else {
            Issue.record("expected certificates")
            return
        }
        #expect(unparsed == 0)
        #expect(omitted == 0)
    }

    @Test
    func aCertificateMessageSplitAcrossRecordsIsReassembled() {
        let chain = TLSCertificateExtraction.extract(fromStreamPrefix: Self.serverFlight(split: true)).certificates
        #expect(chain.count == 2)
    }

    @Test
    func encryptionBeforeAnyCertificateIsNamedNotMissing() {
        let tls13Like = Self.record(22, Self.handshake(2, [UInt8](repeating: 0, count: 40)))
            + Self.record(20, [1])
            + Self.record(23, [UInt8](repeating: 0xAB, count: 60))
        #expect(TLSCertificateExtraction.extract(fromStreamPrefix: tls13Like) == .encryptedBeforeCertificate)
    }

    @Test
    func absencesKeepTheirReasons() {
        #expect(TLSCertificateExtraction.extract(fromStreamPrefix: Array("HTTP/1.1 200 OK\r\n".utf8)) == .notTLS)
        let flight = Self.serverFlight(split: false)
        #expect(TLSCertificateExtraction.extract(fromStreamPrefix: Array(flight.prefix(200))) == .incomplete)
        #expect(TLSCertificateExtraction.extract(fromStreamPrefix: [0x16, 0x03]) == .incomplete)
    }

    @Test
    func aStreamThatDoesNotStartAtItsFirstByteIsIncomplete() {
        let bytes = Self.serverFlight(split: false)
        let midstream = FollowStreamDirectionSnapshot(
            anchorSequence: 1_000,
            runs: [FollowStreamRun(sequenceAnchor: 1_500, firstCaptureOrdinal: 2, bytes: bytes)],
            retainedByteCount: bytes.count,
            observedOmittedByteCount: 0,
            matchedFrameCount: 1
        )
        #expect(TLSCertificateExtraction.extract(from: midstream) == .incomplete)
        let empty = FollowStreamDirectionSnapshot(
            anchorSequence: nil, runs: [], retainedByteCount: 0, observedOmittedByteCount: 0, matchedFrameCount: 1
        )
        #expect(TLSCertificateExtraction.extract(from: empty) == .noPayload)
    }

    @Test
    func anUnparseableEntryIsCountedAndItsNeighboursKept() {
        let body = Self.certificateList([Self.leafDER, [0x30, 0x03, 0x02, 0x01, 0x00]])
        let outcome = TLSCertificateExtraction.extract(fromStreamPrefix: Self.record(22, Self.handshake(11, body)))
        guard case let .certificates(list, unparsed, _) = outcome else {
            Issue.record("expected certificates")
            return
        }
        #expect(list.count == 1)
        #expect(unparsed == 1)
    }

    @Test
    func endToEndThroughTheFollowReader() throws {
        let flight = Self.serverFlight(split: false)
        let segments = stride(from: 0, to: flight.count, by: 400).map { offset in
            (offset, Array(flight[offset ..< min(offset + 400, flight.count)]))
        }
        let frames = segments.map { offset, bytes in
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "203.0.113.9", dst: "10.0.0.5",
                payload: PacketBuilder.tcp(
                    srcPort: 443, dstPort: 50_000, flags: 0x18, payload: bytes, sequence: 7_000 + UInt32(offset)
                )
            )
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("tlscert-\(UUID().uuidString).pcap")
        try Data(FollowDatagramReaderTests.classicPcap(frames.map { ($0, UInt32($0.count)) })).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let tuple = FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
            destination: IPEndpoint(ip: "203.0.113.9", port: 443)
        )
        let result = try FollowStreamReader(
            contentsOf: url, expectedIdentity: CaptureStreamReader(contentsOf: url).identity, tuple: tuple
        ).read()
        #expect(TLSCertificateExtraction.extract(from: result.bToA).certificates.count == 2)
        #expect(TLSCertificateExtraction.extract(from: result.aToB) == .noPayload)
    }

    /// tshark's X.509 object export is the independent oracle: it must hand out the
    /// same certificates, byte for byte, from the same frames.
    @Test(.enabled(if: WiresharkOracle.isAvailable, "Wireshark is not installed on this machine"))
    func tsharkExportsTheSameCertificateBytes() throws {
        let tool = try #require(WiresharkOracle.tsharkURL)
        let flight = Self.serverFlight(split: true)
        let frames = stride(from: 0, to: flight.count, by: 700).map { offset in
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "203.0.113.9", dst: "10.0.0.5",
                payload: PacketBuilder.tcp(
                    srcPort: 443, dstPort: 50_000, flags: 0x18,
                    payload: Array(flight[offset ..< min(offset + 700, flight.count)]),
                    sequence: 7_000 + UInt32(offset)
                )
            )
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("x509-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("flight.pcap")
        try Data(FollowDatagramReaderTests.classicPcap(frames.map { ($0, UInt32($0.count)) })).write(to: url)
        let exported = directory.appendingPathComponent("objects")
        let process = Process()
        process.executableURL = tool
        process.arguments = ["-r", url.path, "-q", "--export-objects", "x509af,\(exported.path)"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        let oracle = try Set(FileManager.default.contentsOfDirectory(atPath: exported.path).map {
            try Array(Data(contentsOf: exported.appendingPathComponent($0)))
        })

        let tuple = FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "10.0.0.5", port: 50_000),
            destination: IPEndpoint(ip: "203.0.113.9", port: 443)
        )
        let result = try FollowStreamReader(
            contentsOf: url, expectedIdentity: CaptureStreamReader(contentsOf: url).identity, tuple: tuple
        ).read()
        let ours = Set(TLSCertificateExtraction.extract(from: result.bToA).certificates.map(\.der))
        #expect(oracle.count == 2)
        #expect(ours == oracle)
    }

    // MARK: Private

    private static func utc(_ year: Int, _ month: Int, _ day: Int) -> Date {
        var components = DateComponents(year: year, month: month, day: day)
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(secondsFromGMT: 0)
        return components.date ?? .distantPast
    }

    private static func be24(_ value: Int) -> [UInt8] {
        [UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    private static func record(_ type: UInt8, _ body: [UInt8]) -> [UInt8] {
        [type, 0x03, 0x03, UInt8(body.count >> 8), UInt8(body.count & 0xFF)] + body
    }

    private static func handshake(_ type: UInt8, _ body: [UInt8]) -> [UInt8] {
        [type] + be24(body.count) + body
    }

    private static func certificateList(_ certificates: [[UInt8]]) -> [UInt8] {
        let entries = certificates.flatMap { be24($0.count) + $0 }
        return be24(entries.count) + entries
    }
}
