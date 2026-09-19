import Foundation
import Testing
@testable import Tracexy

// MARK: - LargeCaptureOpenBenchmarkTests

/// An **opt-in, informational** saved-open benchmark for large captures.
///
/// It writes a synthetic classic pcap of a configurable size (many distinct
/// five-tuples so the session map, not the frame count, is the stressed bound),
/// opens it through `SavedCaptureStreamLoader`, and prints wall time, frames/s,
/// session count and the process's resident-memory delta. Like
/// `ReplayBenchmarkTests`, nothing here asserts a timing threshold; the standard
/// run performs only a cheap schedule assertion. Enable with the
/// `TRACEXY_RUN_BENCHMARKS` compilation condition; size the file with
/// `TRACEXY_BENCHMARK_MEGABYTES` (default 256).
struct LargeCaptureOpenBenchmarkTests {
    // MARK: Internal

    @Test
    func openLargeSyntheticCapture() throws {
        guard Self.isOptedIn else {
            #expect(Self.defaultMegabytes > 0)
            return
        }
        let megabytes = Int(ProcessInfo.processInfo.environment["TRACEXY_BENCHMARK_MEGABYTES"] ?? "")
            ?? Self.defaultMegabytes
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-bench-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let frames = try Self.writeSynthetic(to: url, megabytes: megabytes)

        let before = Self.residentBytes()
        let clock = ContinuousClock()
        var result: SavedCaptureLoadResult?
        let elapsed = try clock.measure {
            result = try SavedCaptureStreamLoader(contentsOf: url).load()
        }
        let after = Self.residentBytes()
        let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        let loaded = try #require(result)
        print(
            """
            [benchmark] saved open: \(megabytes) MiB, \(frames) frames, \(loaded.sessions.count) sessions, \
            \(String(format: "%.2f", seconds)) s, \(String(
                format: "%.0f",
                Double(frames) / max(seconds, 0.001)
            )) frames/s, \
            RSS delta \(Self.formatBytes(after &- before))
            """
        )
        #expect(loaded.totalFrames == frames)
    }

    // MARK: Private

    private static let defaultMegabytes = 256

    private static var isOptedIn: Bool {
        #if TRACEXY_RUN_BENCHMARKS
        true
        #else
        false
        #endif
    }

    /// Stream a classic little-endian microsecond pcap of DNS-sized UDP frames.
    /// Every 64th frame starts a new five-tuple; the rest repeat recent tuples, so
    /// the file has both many sessions and multi-frame sessions.
    private static func writeSynthetic(to url: URL, megabytes: Int) throws -> Int {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        var header = Data()
        header.append(contentsOf: [0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        header.append(contentsOf: [0xFF, 0xFF, 0, 0, 1, 0, 0, 0])
        try handle.write(contentsOf: header)

        let target = megabytes * 1_048_576
        var written = header.count
        var frames = 0
        var tuple = 0
        var buffer = Data()
        buffer.reserveCapacity(1 << 20)
        var seconds: UInt32 = 1_700_000_000
        while written + buffer.count < target {
            if frames % 64 == 0 {
                tuple += 1
            }
            let key = tuple - (frames % 7)
            let ethernet = PacketBuilder.dnsQueryFrame(
                name: "b\(key & 0xFFFF).example",
                src: "10.\((key >> 16) & 0xFF).\((key >> 8) & 0xFF).\(key & 0xFF)",
                dst: "203.0.113.53",
                srcPort: UInt16(20_000 + (key % 40_000))
            )
            if frames % 1_000 == 0 {
                seconds &+= 1
            }
            var record = Data(capacity: 16 + ethernet.count)
            for value in [seconds, UInt32(frames % 1_000_000), UInt32(ethernet.count), UInt32(ethernet.count)] {
                record.append(contentsOf: withUnsafeBytes(of: value.littleEndian, Array.init))
            }
            record.append(contentsOf: ethernet)
            buffer.append(record)
            frames += 1
            if buffer.count >= 1 << 20 {
                try handle.write(contentsOf: buffer)
                written += buffer.count
                buffer.removeAll(keepingCapacity: true)
            }
        }
        if !buffer.isEmpty {
            try handle.write(contentsOf: buffer)
        }
        return frames
    }

    private static func residentBytes() -> Int {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? Int(info.resident_size) : 0
    }

    private static func formatBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .memory)
    }
}
