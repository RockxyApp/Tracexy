import Foundation
import Testing
@testable import Tracexy

/// An LZ4-compressed capture — as Wireshark writes with `--compress lz4`, or
/// the `lz4` tool with linked blocks and checksums — expands to the exact capture;
/// a damaged one is refused by its checksum.
struct LZ4CaptureImportTests {
    // MARK: Internal

    @Test
    func xxhash32KnownValues() {
        #expect(XXHash32.hash([][...]) == 0x02CC5D05)
        var streamed = XXHash32()
        let text = Array("Nobody inspects the spammish repetition".utf8)
        streamed.update(text[0 ..< 7])
        streamed.update(text[7...])
        #expect(streamed.digest() == XXHash32.hash(text[...]))
    }

    @Test
    func blockDecoderRefusesOutOfRangeMatches() throws {
        var decoder = LZ4BlockDecoder()
        // One literal, then a match reaching 9 bytes back into 1 byte of output.
        #expect(throws: LZ4BlockDecoder.Failure.self) {
            _ = try decoder.decode([0x10, 0x41, 0x09, 0x00][...], maximumOutput: 64, linked: false)
        }
        // "A" then match offset 1 length 4 → "AAAAA".
        let decoded = try decoder.decode([0x10, 0x41, 0x01, 0x00][...], maximumOutput: 64, linked: false)
        #expect(decoded == Array("AAAAA".utf8))
    }

    @Test(arguments: [["-B4", "-BD", "-BX"], ["-B4", "--no-frame-crc"], ["-B7"]])
    func lz4ToolFramesExpandExactly(_ options: [String]) throws {
        guard let tool = Self.lz4Tool else {
            return
        }
        try withTemporaryDirectory { directory in
            let original = directory.appendingPathComponent("capture.pcapng")
            try Self.writeCapture(to: original, frames: 3_000)
            let compressed = directory.appendingPathComponent("capture.pcapng.lz4")
            try Self.run(tool, ["-q", "-f"] + options + [original.path, compressed.path])
            let library = directory.appendingPathComponent("Library", isDirectory: true)
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let result = try CaptureImporter.importCapture(from: compressed, intoDirectory: library)
            #expect(result.lastPathComponent == "capture.pcapng")
            #expect(try Data(contentsOf: result) == Data(contentsOf: original))
        }
    }

    @Test
    func wiresharkLZ4ExpandsAndDamageIsRefused() throws {
        guard let editcap = WiresharkOracle.capinfosURL?.deletingLastPathComponent().appendingPathComponent("editcap"),
              FileManager.default.isExecutableFile(atPath: editcap.path) else
        {
            return
        }
        try withTemporaryDirectory { directory in
            let original = directory.appendingPathComponent("wire.pcapng")
            try Self.writeCapture(to: original, frames: 500)
            let compressed = directory.appendingPathComponent("wire.pcapng.lz4")
            try Self.run(editcap, ["--compress", "lz4", original.path, compressed.path])
            let library = directory.appendingPathComponent("Library", isDirectory: true)
            try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
            let expanded = try CaptureImporter.importCapture(from: compressed, intoDirectory: library)
            let loaded = try SavedCaptureStreamLoader(contentsOf: expanded).load()
            #expect(loaded.totalFrames == 500)

            var bytes = try [UInt8](Data(contentsOf: compressed))
            bytes[bytes.count / 2] ^= 0xFF
            let damaged = directory.appendingPathComponent("damaged.lz4")
            try Data(bytes).write(to: damaged)
            #expect(throws: (any Error).self) {
                _ = try CaptureImporter.importCapture(from: damaged, intoDirectory: library)
            }
        }
    }

    // MARK: Private

    private static var lz4Tool: URL? {
        ["/opt/homebrew/bin/lz4", "/usr/local/bin/lz4"].map(URL.init(fileURLWithPath:))
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    private static func writeCapture(to url: URL, frames count: Int) throws {
        var generator = SystemRandomNumberGenerator()
        let frames = (0 ..< count).map { index in
            let payload = (0 ..< 64).map { _ in UInt8.random(in: 0 ... 7, using: &generator) }
            let bytes = PacketBuilder.ethernetIPv4(
                proto: 17, src: "192.0.2.\(index % 200 + 1)", dst: "198.51.100.1",
                payload: PacketBuilder.udp(srcPort: 40_000, dstPort: 53, payload: payload)
            )
            return CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index) / 100),
                originalLength: bytes.count
            )
        }
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: frames, to: url)
    }

    private static func run(_ tool: URL, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = tool
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lz4-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}
