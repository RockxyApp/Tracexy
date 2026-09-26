import Foundation
import Testing
@testable import Tracexy

/// Capture from a named pipe carrying pcap or pcapng, as Wireshark's pipe
/// interfaces — parsed incrementally, read without the helper, stopped promptly.
struct PipeCaptureTests {
    // MARK: Internal

    @Test
    func classicPcapArrivesInAnyChunking() throws {
        let bytes = Self.classicPcap(littleEndian: true, nanoseconds: false, frames: [
            (1_800_000_000, 250_000, Self.frame(1)), (1_800_000_001, 5, Self.frame(2)),
        ])
        for chunk in [1, 7, 24, bytes.count] {
            var parser = CaptureByteStreamParser()
            var frames: [CaptureByteStreamParser.Frame] = []
            for start in stride(from: 0, to: bytes.count, by: chunk) {
                frames += try parser.append(bytes[start ..< min(start + chunk, bytes.count)])
            }
            #expect(frames.count == 2)
            #expect(frames.map(\.linkType) == [1, 1])
            #expect(frames[0].frame.bytes == Self.frame(1))
            #expect(frames[0].frame.timestamp == Date(timeIntervalSince1970: 1_800_000_000.25))
        }
    }

    @Test
    func bigEndianNanosecondPcap() throws {
        let bytes = Self.classicPcap(littleEndian: false, nanoseconds: true, frames: [
            (10, 500_000_000, Self.frame(3)),
        ])
        var parser = CaptureByteStreamParser()
        let frames = try parser.append(bytes)
        #expect(frames.count == 1)
        #expect(frames[0].frame.timestamp == Date(timeIntervalSince1970: 10.5))
        #expect(parser.format == .pcap(littleEndian: false, nanoseconds: true, linkType: 1))
    }

    @Test
    func pcapngInterfacesKeepTheirLinkTypesAndResolutions() throws {
        var bytes = Self.sectionHeader()
        bytes += Self.interfaceBlock(linkType: 1, tsresol: nil)
        bytes += Self.interfaceBlock(linkType: 101, tsresol: 9)
        bytes += Self.enhancedPacket(interface: 0, ticks: 1_800_000_000_250_000, data: Self.frame(4))
        bytes += Self.enhancedPacket(interface: 1, ticks: 1_800_000_000_500_000_000, data: [0x45, 0, 0, 20])
        bytes += Self.block(type: 5, body: [0, 0, 0, 0]) // a statistics block, skipped
        var parser = CaptureByteStreamParser()
        var frames: [CaptureByteStreamParser.Frame] = []
        for byte in bytes {
            frames += try parser.append([byte])
        }
        #expect(frames.map(\.linkType) == [1, 101])
        #expect(frames[0].frame.timestamp == Date(timeIntervalSince1970: 1_800_000_000.25))
        #expect(frames[1].frame.timestamp == Date(timeIntervalSince1970: 1_800_000_000.5))
        #expect(frames[1].frame.bytes == [0x45, 0, 0, 20])
    }

    @Test
    func notACaptureOrImpossibleLengthsFail() {
        var parser = CaptureByteStreamParser()
        #expect(throws: CaptureByteStreamParser.Failure.self) {
            try parser.append(Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8))
        }
        var header = Self.classicPcap(littleEndian: true, nanoseconds: false, frames: [])
        header += [0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0]
        var oversize = CaptureByteStreamParser()
        #expect(throws: CaptureByteStreamParser.Failure.self) { try oversize.append(header) }
    }

    @Test
    func savedInterfaceSettingsFromBeforePipesStillDecode() throws {
        let old = Data(#"{"hidden":["awdl0"],"friendlyNames":{},"comments":{}}"#.utf8)
        let settings = try JSONDecoder().decode(InterfaceSettings.self, from: old)
        #expect(settings.hidden == ["awdl0"])
        #expect(settings.pipes.isEmpty)
        #expect(InterfaceSettings.pipePath(" /tmp//a.fifo ") == "/tmp/a.fifo")
        #expect(InterfaceSettings.pipePath("relative.fifo") == nil)
        #expect(PipeCapture.isPipe("/tmp/a.fifo"))
        #expect(!PipeCapture.isPipe("en0"))
    }

    @Test
    func readsAFIFOUntilTheWriterCloses() async throws {
        let path = try Self.makeFIFO()
        defer { unlink(path) }
        let capture = PipeCapture()
        let received = Received()
        try capture.start(
            path: path,
            onBatch: { frames, linkType in received.add(frames.count, linkType: linkType) },
            onReadFailure: { received.fail($0) },
            onEnd: { received.end() }
        )
        let bytes = Self.classicPcap(littleEndian: true, nanoseconds: false, frames: (0 ..< 300).map {
            (1_800_000_000 + UInt32($0), 0, Self.frame(UInt8($0 % 250)))
        })
        let writer = Thread {
            let descriptor = open(path, O_WRONLY)
            // Slowly, in pieces, as a remote tcpdump would.
            for start in stride(from: 0, to: bytes.count, by: 997) {
                _ = bytes[start ..< min(start + 997, bytes.count)].withUnsafeBytes {
                    write(descriptor, $0.baseAddress, $0.count)
                }
            }
            close(descriptor)
        }
        writer.start()
        for _ in 0 ..< 100 where !received.hasEnded {
            try await Task.sleep(for: .milliseconds(50))
        }
        capture.stop()
        #expect(received.hasEnded)
        #expect(received.count == 300)
        #expect(received.linkTypes == [1])
        #expect(received.failure == nil)
    }

    /// Start on a pipe, fold what the writer sends, stop when it closes — no helper.
    @MainActor
    @Test
    func coordinatorCapturesFromAPipe() async throws {
        let path = try Self.makeFIFO()
        defer { unlink(path) }
        let isolation = ProjectIsolationEnvironment(name: "pipe-capture")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.captureInterface = path
        coordinator.startCapture()
        #expect(coordinator.isCapturing)
        #expect(coordinator.captureSourceName == (path as NSString).lastPathComponent)
        let bytes = Self.classicPcap(littleEndian: true, nanoseconds: false, frames: (0 ..< 20).map {
            (1_800_000_000 + UInt32($0), 0, PacketBuilder.ethernetIPv4(
                proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.udp(srcPort: 40_000 + UInt16($0), dstPort: 9, payload: [1])
            ))
        })
        Thread {
            let descriptor = open(path, O_WRONLY)
            _ = bytes.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
            close(descriptor)
        }.start()
        for _ in 0 ..< 100 where coordinator.isCapturing || coordinator.sessions.count < 20 {
            try await Task.sleep(for: .milliseconds(50))
        }
        #expect(!coordinator.isCapturing)
        #expect(coordinator.sessions.count == 20)
        #expect(coordinator.captureError == nil)
    }

    @Test
    func stopsPromptlyWithNoWriter() throws {
        let path = try Self.makeFIFO()
        defer { unlink(path) }
        let capture = PipeCapture()
        try capture.start(path: path, onBatch: { _, _ in }, onReadFailure: { _ in }, onEnd: {})
        Thread.sleep(forTimeInterval: 0.2)
        let started = Date()
        capture.stop()
        #expect(Date().timeIntervalSince(started) < 1)
        #expect(throws: PipeCapture.Failure.self) {
            try capture.start(
                path: "/tmp/no-such-\(UUID().uuidString).fifo",
                onBatch: { _, _ in },
                onReadFailure: { _ in },
                onEnd: {}
            )
        }
    }

    // MARK: Private

    private final class Received: @unchecked Sendable {
        // MARK: Internal

        var count: Int {
            lock.withLock { frames }
        }

        var linkTypes: Set<UInt32> {
            lock.withLock { types }
        }

        var hasEnded: Bool {
            lock.withLock { ended }
        }

        var failure: String? {
            lock.withLock { message }
        }

        func add(_ number: Int, linkType: UInt32) {
            lock.withLock {
                frames += number
                types.insert(linkType)
            }
        }

        func fail(_ text: String) {
            lock.withLock { message = text }
        }

        func end() {
            lock.withLock { ended = true }
        }

        // MARK: Private

        private let lock = NSLock()
        private var frames = 0
        private var types: Set<UInt32> = []
        private var ended = false
        private var message: String?
    }

    private static func makeFIFO() throws -> String {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("pipe-\(UUID().uuidString).fifo").path
        try #require(mkfifo(path, 0o600) == 0)
        return path
    }

    private static func frame(_ marker: UInt8) -> [UInt8] {
        PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "198.51.100.7",
            payload: PacketBuilder.udp(srcPort: 40_000, dstPort: 9, payload: [marker])
        )
    }

    private static func u32(_ value: UInt32, little: Bool) -> [UInt8] {
        let bytes = (0 ..< 4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
        return little ? bytes : bytes.reversed()
    }

    private static func classicPcap(
        littleEndian little: Bool,
        nanoseconds: Bool,
        frames: [(UInt32, UInt32, [UInt8])]
    )
        -> [UInt8]
    {
        let magic: UInt32 = nanoseconds ? 0xA1B23C4D : 0xA1B2C3D4
        let version: [UInt8] = little ? [2, 0, 4, 0] : [0, 2, 0, 4]
        var bytes = u32(magic, little: little) + version + u32(0, little: little) + u32(0, little: little)
            + u32(65_535, little: little) + u32(1, little: little)
        for (seconds, fraction, frame) in frames {
            bytes += u32(seconds, little: little) + u32(fraction, little: little)
            bytes += u32(UInt32(frame.count), little: little) + u32(UInt32(frame.count), little: little) + frame
        }
        return bytes
    }

    private static func block(type: UInt32, body: [UInt8]) -> [UInt8] {
        let padded = body + [UInt8](repeating: 0, count: (4 - body.count % 4) % 4)
        let length = UInt32(12 + padded.count)
        return u32(type, little: true) + u32(length, little: true) + padded + u32(length, little: true)
    }

    private static func sectionHeader() -> [UInt8] {
        block(
            type: 0x0A0D0D0A,
            body: u32(0x1A2B3C4D, little: true) + [1, 0, 0, 0]
                + [UInt8](repeating: 0xFF, count: 8)
        )
    }

    private static func interfaceBlock(linkType: UInt16, tsresol: UInt8?) -> [UInt8] {
        var body: [UInt8] = [UInt8(linkType & 0xFF), UInt8(linkType >> 8), 0, 0] + u32(65_535, little: true)
        if let tsresol {
            body += [9, 0, 1, 0, tsresol, 0, 0, 0] + [0, 0, 0, 0]
        }
        return block(type: 1, body: body)
    }

    private static func enhancedPacket(interface: UInt32, ticks: UInt64, data: [UInt8]) -> [UInt8] {
        block(
            type: 6,
            body: u32(interface, little: true) + u32(UInt32(ticks >> 32), little: true)
                + u32(UInt32(ticks & 0xFFFFFFFF), little: true) + u32(UInt32(data.count), little: true)
                + u32(UInt32(data.count), little: true) + data
        )
    }
}
