import Foundation
import Testing
@testable import Tracexy

/// File ▸ Export Objects ▸ Email (IMF), FTP Data and X.509 Certificates list what
/// `tshark --export-objects imf|ftp-data|x509af` saves — the same bytes under the same
/// names — in the frames Wireshark lists them at: an SMTP session with two messages
/// (one split, one dot-stuffed), FTP transfers set up by PASV, EPSV and PORT (the
/// PORT one a LIST, which Wireshark does not export), and a TLS 1.2 certificate flight.
struct CaptureObjectKindsTests {
    // MARK: Internal

    @Test
    func readsEachKindAsWireshark() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }

        let imf = try Self.scan(.imf, url)
        #expect(imf.map(\.fileName) == ["Quarterly report.eml", "Re: lunch.eml"])
        #expect(imf.map(\.host) == ["alice@example.com", "carol@example.org"])
        #expect(imf.map(\.frameOrdinal) == [14, 22])
        #expect(imf.map(\.contentType) == ["EML file", "EML file"])
        #expect(imf.map(\.body) == [Array(Self.firstMessage.utf8), Array(Self.secondMessage.utf8)])

        let ftp = try Self.scan(.ftpData, url)
        #expect(ftp.map(\.fileName) == ["docs/report.txt", "upload.bin"])
        #expect(ftp.map(\.host) == ["198.51.100.21", "192.0.2.10"])
        #expect(ftp.map(\.frameOrdinal) == [42, 55])
        #expect(ftp.map(\.body) == [Self.report, Self.upload])

        let certificates = try Self.scan(.x509, url)
        #expect(certificates.map(\.fileName) == ["2a3b.cer", "1001.cer"])
        #expect(certificates.map(\.host) == ["www.example.test", "Tracexy Test Root CA"])
        #expect(certificates.map(\.frameOrdinal) == [82, 82])
        #expect(certificates.map(\.body) == [
            TLSCertificateExtractionTests.leafDER,
            TLSCertificateExtractionTests.rootDER
        ])

        #expect(CaptureObjectScanner.savableName("Re: lunch.eml") == "Re%3a lunch.eml")
        #expect(CaptureObjectScanner.savableName("docs/report.txt") == "docs%2freport.txt")

        guard WiresharkOracle.isAvailable else {
            return
        }
        for (kind, objects) in [(CaptureObjectKind.imf, imf), (.ftpData, ftp), (.x509, certificates)] {
            let theirs = try Self.tsharkObjects(url, kind: kind)
            let ours = Dictionary(objects.map { (CaptureObjectScanner.savableName($0.fileName), $0.body) }) { $1 }
            #expect(ours == theirs, "\(kind.rawValue)")
        }
        let frames = { (filter: String) in
            try WiresharkOracle.tsharkFields(url, fields: ["frame.number"], filter: filter).compactMap { UInt64($0[0]) }
        }
        #expect(try frames("imf") == imf.compactMap(\.frameOrdinal))
        #expect(try frames("x509af.serialNumber") == [82])
        #expect(try frames("ftp-data.command == \"RETR docs/report.txt\"").first == 42)
        #expect(try frames("ftp-data.command == \"STOR upload.bin\"").first == 55)
    }

    @Test
    func ftpTiesTheFirstDataCommandToTheLatestSetup() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let control = try #require(loaded.connections.summaries
            .first { $0.tuple.a.port == 21 || $0.tuple.b.port == 21 })
        let result = try FollowStreamReader(contentsOf: url, expectedIdentity: loaded.identity, tuple: control.tuple)
            .read()
        let transfers = FTPDataObjectReader.transfers(in: result)
        #expect(transfers.map(\.command) == ["RETR docs/report.txt", "STOR upload.bin"])
        #expect(transfers.map(\.endpoints) == [
            [IPEndpoint(ip: "198.51.100.21", port: 50_000)], [IPEndpoint(ip: "198.51.100.21", port: 50_001)],
        ])
    }

    // MARK: Private

    // MARK: Fixture

    /// A TCP connection written frame by frame: handshake, pushes, and a FIN close.
    private final class Connection {
        // MARK: Lifecycle

        init(_ frames: Frames, client: IPEndpoint, server: IPEndpoint) {
            self.frames = frames
            self.client = client
            self.server = server
            frames.add(client, server, clientSequence, 0, 0x02)
            frames.add(server, client, serverSequence, clientSequence + 1, 0x12)
            clientSequence += 1
            serverSequence += 1
            frames.add(client, server, clientSequence, serverSequence, 0x10)
        }

        // MARK: Internal

        func fromClient(_ bytes: [UInt8]) {
            frames.add(client, server, clientSequence, serverSequence, 0x18, bytes)
            clientSequence += UInt32(bytes.count)
        }

        func fromServer(_ bytes: [UInt8]) {
            frames.add(server, client, serverSequence, clientSequence, 0x18, bytes)
            serverSequence += UInt32(bytes.count)
        }

        func fromClient(_ text: String) {
            fromClient(Array(text.utf8))
        }

        func fromServer(_ text: String) {
            fromServer(Array(text.utf8))
        }

        func close() {
            frames.add(client, server, clientSequence, serverSequence, 0x11)
            frames.add(server, client, serverSequence, clientSequence + 1, 0x11)
            frames.add(client, server, clientSequence + 1, serverSequence + 1, 0x10)
        }

        // MARK: Private

        private let frames: Frames
        private let client: IPEndpoint
        private let server: IPEndpoint
        private var clientSequence: UInt32 = 1_000
        private var serverSequence: UInt32 = 5_000
    }

    private final class Frames {
        var list: [[UInt8]] = []

        func add(
            _ from: IPEndpoint, _ to: IPEndpoint, _ sequence: UInt32, _ ack: UInt32, _ flags: UInt8,
            _ payload: [UInt8] = []
        ) {
            var segment = PacketBuilder.tcp(
                srcPort: from.port, dstPort: to.port, flags: flags, payload: payload, sequence: sequence
            )
            segment.replaceSubrange(8 ..< 12, with: withUnsafeBytes(of: ack.bigEndian, Array.init))
            list.append(PacketBuilder.ethernetIPv4(proto: 6, src: from.ip, dst: to.ip, payload: segment))
        }
    }

    private static let firstMessage = "From: \"Alice Example\" <alice@example.com>\r\nTo: bob@example.net\r\n"
        + "Subject: Quarterly report\r\nDate: Mon, 21 Sep 2026 10:00:00 +0000\r\n\r\nHello Bob,\r\n"
        + "the report is attached.\r\n"
    private static let secondMessage = "From: carol@example.org\r\nTo: bob@example.net\r\nSubject: Re: lunch\r\n\r\n"
        + "..a line that began with a dot\r\nsee you\r\n"
    private static let report = Array((1 ... 40).map { String(format: "line %02d of the quarterly report\r\n", $0) }
        .joined().utf8)
    private static let upload = [UInt8]((0 ... 255).map { UInt8($0) }) + (0 ... 255).map { UInt8($0) }
        + (0 ... 255).map { UInt8($0) }

    private static func scan(_ kind: CaptureObjectKind, _ url: URL) throws -> [CaptureObject] {
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let (streams, connections) = CaptureObjectScanner.inputs(kind, in: loaded.sessions, from: loaded.sessions)
        return try CaptureObjectScanner.scan(
            kind, contentsOf: url, expectedIdentity: loaded.identity, streams: streams, connections: connections,
            sourceToken: SavedCaptureStreamLoader.sourceToken(for: loaded.identity)
        ).objects
    }

    /// The files `tshark --export-objects` writes, by name.
    private static func tsharkObjects(_ url: URL, kind: CaptureObjectKind) throws -> [String: [UInt8]] {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("objects-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let process = Process()
        process.executableURL = WiresharkOracle.tsharkURL
        process.arguments = ["-r", url.path, "-q", "--export-objects", "\(kind.rawValue),\(folder.path)"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        var files: [String: [UInt8]] = [:]
        for name in try FileManager.default.contentsOfDirectory(atPath: folder.path) {
            files[name] = try [UInt8](Data(contentsOf: folder.appendingPathComponent(name)))
        }
        return files
    }

    /// Frame numbers above are those of this sequence (the same as the
    /// make-export-objects-fixture generator): SMTP 1–30, FTP 31–76, TLS 77–86.
    private static func capture() throws -> URL {
        let frames = Frames()
        let host = { (ip: String, port: UInt16) in IPEndpoint(ip: ip, port: port) }
        let smtp = Connection(frames, client: host("192.0.2.10", 50_025), server: host("198.51.100.25", 25))
        smtp.fromServer("220 mail.example.net ESMTP\r\n")
        smtp.fromClient("EHLO client.example.com\r\n")
        smtp.fromServer("250 mail.example.net\r\n")
        for (sender, message) in [("alice@example.com", firstMessage), ("carol@example.org", secondMessage)] {
            smtp.fromClient("MAIL FROM:<\(sender)>\r\n")
            smtp.fromServer("250 OK\r\n")
            smtp.fromClient("RCPT TO:<bob@example.net>\r\n")
            smtp.fromServer("250 OK\r\n")
            smtp.fromClient("DATA\r\n")
            smtp.fromServer("354 End data with <CR><LF>.<CR><LF>\r\n")
            let bytes = Array(message.utf8)
            if message == firstMessage {
                smtp.fromClient(Array(bytes.prefix(60)))
                smtp.fromClient(Array(bytes.dropFirst(60)) + Array(".\r\n".utf8))
            } else {
                smtp.fromClient(bytes + Array(".\r\n".utf8))
            }
            smtp.fromServer("250 OK queued\r\n")
        }
        smtp.fromClient("QUIT\r\n")
        smtp.fromServer("221 Bye\r\n")
        smtp.close()

        let ftp = Connection(frames, client: host("192.0.2.10", 50_021), server: host("198.51.100.21", 21))
        ftp.fromServer("220 FTP ready\r\n")
        ftp.fromClient("USER anonymous\r\n")
        ftp.fromServer("230 Anonymous access granted\r\n")
        ftp.fromClient("PASV\r\n")
        ftp.fromServer("227 Entering Passive Mode (198,51,100,21,195,80).\r\n")
        ftp.fromClient("RETR docs/report.txt\r\n")
        var data = Connection(frames, client: host("192.0.2.10", 50_100), server: host("198.51.100.21", 50_000))
        ftp.fromServer("150 Opening BINARY mode data connection\r\n")
        data.fromServer(Array(report.prefix(700)))
        data.fromServer(Array(report.dropFirst(700)))
        data.close()
        ftp.fromServer("226 Transfer complete\r\n")
        ftp.fromClient("EPSV\r\n")
        ftp.fromServer("229 Entering Extended Passive Mode (|||50001|)\r\n")
        ftp.fromClient("STOR upload.bin\r\n")
        data = Connection(frames, client: host("192.0.2.10", 50_101), server: host("198.51.100.21", 50_001))
        ftp.fromServer("150 Ok to send data\r\n")
        data.fromClient(upload)
        data.close()
        ftp.fromServer("226 Transfer complete\r\n")
        ftp.fromClient("PORT 192,0,2,10,196,10\r\n")
        ftp.fromServer("200 PORT command successful\r\n")
        ftp.fromClient("LIST\r\n")
        data = Connection(frames, client: host("198.51.100.21", 20), server: host("192.0.2.10", 50_186))
        ftp.fromServer("150 Here comes the directory listing\r\n")
        data.fromClient("-rw-r--r-- 1 ftp ftp 1400 Sep 21 10:00 report.txt\r\n")
        data.close()
        ftp.fromServer("226 Directory send OK\r\n")
        ftp.fromClient("QUIT\r\n")
        ftp.fromServer("221 Goodbye\r\n")
        ftp.close()

        let tls = Connection(frames, client: host("192.0.2.10", 50_443), server: host("198.51.100.43", 443))
        tls.fromClient(tlsRecord(
            22,
            handshake(1, [3, 3] + [UInt8](repeating: 0x22, count: 32) + [0, 0, 2, 0xC0, 0x2B, 1, 0])
        ))
        let flight = tlsRecord(22, handshake(2, [3, 3] + [UInt8](repeating: 0x11, count: 32) + [0, 0xC0, 0x2B, 0]))
            + tlsRecord(22, handshake(11, certificateList()))
            + tlsRecord(22, handshake(14, []))
        tls.fromServer(Array(flight.prefix(flight.count / 2)))
        tls.fromServer(Array(flight.dropFirst(flight.count / 2)))
        tls.close()

        let url = FileManager.default.temporaryDirectory.appendingPathComponent("objects-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.list.enumerated().map {
            CapturedFrame(
                bytes: $0.element,
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double($0.offset)),
                originalLength: $0.element.count
            )
        }, to: url)
        return url
    }

    private static func u24(_ value: Int) -> [UInt8] {
        [UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)]
    }

    private static func handshake(_ kind: UInt8, _ body: [UInt8]) -> [UInt8] {
        [kind] + u24(body.count) + body
    }

    private static func tlsRecord(_ kind: UInt8, _ body: [UInt8]) -> [UInt8] {
        [kind, 3, 3, UInt8(body.count >> 8), UInt8(body.count & 0xFF)] + body
    }

    private static func certificateList() -> [UInt8] {
        let entries = [TLSCertificateExtractionTests.leafDER, TLSCertificateExtractionTests.rootDER]
            .flatMap { u24($0.count) + $0 }
        return u24(entries.count) + entries
    }
}
