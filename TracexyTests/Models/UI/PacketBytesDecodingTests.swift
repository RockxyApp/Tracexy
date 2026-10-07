import Foundation
import Testing
@testable import Tracexy

/// Show Packet Bytes: each decode step, its refusal when it does not apply, and the
/// output bound that stops a small compressed payload from growing without limit.
struct PacketBytesDecodingTests {
    // MARK: Internal

    @Test
    func textSteps() throws {
        #expect(try PacketBytesDecoding.base64.decode(Array("aGVsbG8gd29ybGQ=".utf8)) == Array("hello world".utf8))
        #expect(try PacketBytesDecoding.base64.decode(Array("aGVsbG8".utf8)) == Array("hello".utf8), "unpadded")
        #expect(try PacketBytesDecoding.percent.decode(Array("a%20b+c%2F".utf8)) == Array("a b c/".utf8))
        #expect(try PacketBytesDecoding.quotedPrintable.decode(Array("caf=C3=A9 =\r\nnext".utf8))
            == Array("café next".utf8))
        #expect(try PacketBytesDecoding.rot13.decode(Array("Uryyb".utf8)) == Array("Hello".utf8))
        #expect(try PacketBytesDecoding.hexText.decode(Array("48:65 6c6c 6F".utf8)) == Array("Hello".utf8))
    }

    @Test
    func refusalsSayWhy() {
        #expect(throws: PacketBytesDecoding.Failure.self) { try PacketBytesDecoding.percent.decode(Array("%zz".utf8)) }
        #expect(throws: PacketBytesDecoding.Failure.self) { try PacketBytesDecoding.hexText.decode(Array("abc".utf8)) }
        #expect(throws: PacketBytesDecoding.Failure.self) { try PacketBytesDecoding.gzip.decode(Array("plain".utf8)) }
    }

    @Test
    func compressedBodiesInflate() throws {
        let text = Array(String(repeating: "Tracexy ", count: 200).utf8)
        #expect(try PacketBytesDecoding.gzip.decode(Self.compress(text, format: "gzip")) == text)
        #expect(try PacketBytesDecoding.zlib.decode(Self.compress(text, format: "zlib")) == text)
    }

    @Test
    func outputIsBounded() throws {
        let big = [UInt8](repeating: 0x41, count: 200_000)
        let compressed = try Self.compress(big, format: "gzip")
        #expect(throws: PacketBytesDecoding.Failure.outputTooLarge(limit: 10_000)) {
            try PacketBytesDecoding.gzip.decode(compressed, limit: 10_000)
        }
    }

    @Test
    func presentationsAndSuggestions() {
        #expect(PacketBytesPresentation.json.text(for: Array(#"{"b":1,"a":[true]}"#.utf8))
            == "{\n  \"a\" : [\n    true\n  ],\n  \"b\" : 1\n}")
        #expect(PacketBytesPresentation.json.text(for: Array("not json".utf8)) == "not json")
        #expect(PacketBytesPresentation.image.text(for: [1]) == nil)
        #expect(PacketBytesInspection.decoding(forContentEncoding: "GZIP") == .gzip)
        #expect(PacketBytesInspection.decoding(forContentEncoding: "deflate") == .zlib)
        #expect(PacketBytesInspection.decoding(forContentEncoding: "br") == PacketBytesDecoding.none)
        #expect(PacketBytesInspection.presentation(forContentType: "application/json; charset=utf-8") == .json)
        #expect(PacketBytesInspection.presentation(forContentType: "image/png") == .image)
    }

    // MARK: Private

    /// Compresses with the system `gzip`/Python zlib so the test does not trust
    /// Tracexy's own encoder (it has none) to check its decoder.
    private static func compress(_ bytes: [UInt8], format: String) throws -> [UInt8] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        let wrapper = format == "gzip" ? "gzip.compress(d)" : "zlib.compress(d)"
        process.arguments = [
            "-c",
            "import sys,gzip,zlib; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(\(wrapper))"
        ]
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        try process.run()
        input.fileHandleForWriting.write(Data(bytes))
        try input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return [UInt8](data)
    }
}
