import Foundation
import Testing
@testable import Tracexy

/// `tracexy objects` lists HTTP/SMB objects and prints one with `--body` (tshark's
/// `--export-objects http|smb`); `tracexy follow` prints one TCP stream (tshark's
/// `-z follow,tcp,raw`). Both stay read-only: bytes go to standard output.
struct CommandLineExtractTests {
    // MARK: Internal

    @Test
    func objectsListAndPrintBodies() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        var text = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "objects", url.path, "--format", "csv"], output: { text += $0 }, errors: { _ in }
        ) == 0)
        #expect(text == "object,frame,host,content_type,bytes,file_name\r\n1,2,t.test,text/plain,5,a.txt\r\n"
            + "2,4,t.test,text/plain,6,b.txt\r\n")
        var body = Data()
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "objects", url.path, "--body", "2"], output: { _ in }, errors: { _ in }, data: { body += $0 }
        ) == 0)
        #expect(String(bytes: body, encoding: .utf8) == "second")
        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "objects", url.path, "--body", "3"], output: { _ in }, errors: { message += $0 }
        ) == 2)
        #expect(message.contains("from 1 to 2"))
        var typed = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "objects", url.path, "--type", "HTTP", "--format", "csv"], output: { typed += $0 },
            errors: { _ in }
        ) == 0)
        #expect(typed == text)
        var none = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "objects", url.path, "--type", "imf", "--format", "csv"], output: { none += $0 },
            errors: { _ in }
        ) == 0)
        #expect(none == "object,frame,host,content_type,bytes,file_name\r\n")
        var smb = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "objects", url.path, "--type", "smb", "--format", "csv"], output: { smb += $0 },
            errors: { _ in }
        ) == 0)
        #expect(smb == "object,frame,host,content_type,bytes,file_name\r\n")
        message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "objects", url.path, "--type", "unknown"], output: { _ in },
            errors: { message += $0 }
        ) == 2)
        #expect(message.contains("--type takes http, imf, smb, tftp, ftp-data or x509af"))

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("cli-objects-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let process = Process()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-q", "--export-objects", "http,\(folder.path)"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        #expect(try Data(contentsOf: folder.appendingPathComponent("b.txt")) == body)
    }

    @Test
    func followPrintsOneStream() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        var raw = Data()
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "follow", url.path, "--expression", "port == 80", "--format", "raw"],
            output: { _ in }, errors: { _ in }, data: { raw += $0 }
        ) == 0)
        let expected = Self.payloads.flatMap(\.self)
        #expect([UInt8](raw) == expected)
        var ascii = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "follow", url.path, "-e", "port == 80"], output: { ascii += $0 }, errors: { _ in }
        ) == 0)
        #expect(ascii.contains("GET /a.txt HTTP/1.1"))

        var message = ""
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "follow", url.path], output: { _ in }, errors: { message += $0 }
        ) == 2)
        #expect(message.contains("exactly one TCP session"))
        #expect(TracexyCommandLine.runIfRequested(
            ["Tracexy", "follow", url.path, "-e", "port == 81"], output: { _ in }, errors: { _ in }
        ) == 2)

        guard WiresharkOracle.isAvailable, let tshark = WiresharkOracle.tsharkURL else {
            return
        }
        // tshark prints each chunk as hex, the server's indented by a tab.
        let process = Process()
        let pipe = Pipe()
        process.executableURL = tshark
        process.arguments = ["-r", url.path, "-q", "-z", "follow,tcp,raw,0"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        let hex = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && $0.allSatisfy(\.isHexDigit) }
            .joined()
        let bytes = stride(from: 0, to: hex.count, by: 2).map { offset -> UInt8 in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            return UInt8(hex[start ..< hex.index(start, offsetBy: 2)], radix: 16) ?? 0
        }
        #expect(bytes == [UInt8](raw))
    }

    // MARK: Private

    private static let payloads: [[UInt8]] = [
        Array("GET /a.txt HTTP/1.1\r\nHost: t.test\r\n\r\n".utf8),
        Array("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nfirst".utf8),
        Array("GET /b.txt HTTP/1.1\r\nHost: t.test\r\n\r\n".utf8),
        Array("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nsecond".utf8),
    ]

    /// Two requests on one connection and their responses.
    private static func capture() throws -> URL {
        var clientSequence: UInt32 = 1_000
        var serverSequence: UInt32 = 5_000
        let frames = payloads.enumerated().map { index, payload in
            let client = index % 2 == 0
            let sequence = client ? clientSequence : serverSequence
            if client {
                clientSequence += UInt32(payload.count)
            } else {
                serverSequence += UInt32(payload.count)
            }
            return PacketBuilder.ethernetIPv4(
                proto: 6, src: client ? "10.0.0.5" : "203.0.113.9", dst: client ? "203.0.113.9" : "10.0.0.5",
                payload: PacketBuilder.tcp(
                    srcPort: client ? 50_000 : 80, dstPort: client ? 80 : 50_000, flags: 0x18, payload: payload,
                    sequence: sequence
                )
            )
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("cli-extract-\(UUID().uuidString).pcap")
        try Data(ReplayCorpus.classicPcapBytes(frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        })).write(to: url)
        return url
    }
}
