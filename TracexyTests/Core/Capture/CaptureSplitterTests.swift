import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureSplitterTests

/// File ▸ Split Capture…: one capture becomes a file set named the way
/// ``CaptureFileSet`` navigates, by frame count or by seconds, optionally shifted in
/// time; nothing is left behind when a split is refused.
struct CaptureSplitterTests {
    // MARK: Internal

    @Test
    func framesBoundaryWritesANavigableFileSet() throws {
        try withDirectory { directory in
            let source = try Self.capture(in: directory, seconds: [0, 1, 2, 3, 4])
            let out = directory.appendingPathComponent("out", isDirectory: true)
            try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
            let summary = try CaptureSplitter.split(
                source: source, into: out, prefix: "part", options: .init(boundary: .frames(2)),
                timeZone: TimeZone.gmt
            )
            #expect(summary.frameCount == 5)
            #expect(summary.files.map(\.lastPathComponent) == [
                "part_00001_20270115080000.pcapng", "part_00002_20270115080002.pcapng",
                "part_00003_20270115080004.pcapng",
            ])
            let counts = try summary.files
                .map { try SavedCaptureStreamLoader(contentsOf: $0).load().properties.totalFrames }
            #expect(counts == [2, 2, 1])
            let set = try #require(CaptureFileSet(member: summary.files[0]))
            #expect(set.count == 3)
            #expect(set.next?.url.lastPathComponent == summary.files[1].lastPathComponent)
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: out.path).filter { $0.hasPrefix(".") }
            #expect(leftovers.isEmpty)

            if WiresharkOracle.isAvailable {
                let rows = try WiresharkOracle.tsharkFields(summary.files[1], fields: ["frame.time_epoch"])
                #expect(rows.compactMap { $0.first.flatMap(Double.init) } == [1_800_000_002, 1_800_000_003])
            }
        }
    }

    @Test
    func secondsBoundaryAndTimeShift() throws {
        try withDirectory { directory in
            let source = try Self.capture(in: directory, seconds: [0, 0.5, 1.2, 2.0, 5.0])
            let summary = try CaptureSplitter.split(
                source: source, into: directory, prefix: "slice",
                options: .init(boundary: .seconds(1), timeShift: -3_600),
                timeZone: TimeZone.gmt
            )
            let counts = try summary.files
                .map { try SavedCaptureStreamLoader(contentsOf: $0).load().properties.totalFrames }
            // [0, 0.5] | [1.2, 2.0] (2.0 is 0.8 s after 1.2) | [5.0]
            #expect(counts == [2, 2, 1])
            #expect(summary.files.first?.lastPathComponent == "slice_00001_20270115070000.pcapng")
            let first = try SavedCaptureStreamLoader(contentsOf: summary.files[0]).load()
            #expect(first.sessions.first?.startTime == Date(timeIntervalSince1970: 1_800_000_000 - 3_600))
        }
    }

    @Test
    func refusalsLeaveNothingBehind() throws {
        try withDirectory { directory in
            let source = try Self.capture(in: directory, seconds: [0, 1, 2])
            #expect(throws: CaptureSplitError.invalidBoundary) {
                try CaptureSplitter.split(
                    source: source,
                    into: directory,
                    prefix: "p",
                    options: .init(boundary: .frames(0))
                )
            }
            // The second file's name is taken: nothing of the set is published.
            let taken = CaptureSplitter.fileName(
                prefix: "p", sequence: 2, time: Date(timeIntervalSince1970: 1_800_000_001), timeZone: .current
            )
            FileManager.default.createFile(atPath: directory.appendingPathComponent(taken).path, contents: Data())
            #expect(throws: CaptureSplitError.fileExists(taken)) {
                try CaptureSplitter.split(
                    source: source,
                    into: directory,
                    prefix: "p",
                    options: .init(boundary: .frames(1))
                )
            }
            let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
            #expect(Set(names) == ["source.pcap", taken])
            #expect(throws: CancellationError.self) {
                try CaptureSplitter.split(
                    source: source, into: directory, prefix: "q", options: .init(boundary: .frames(1)),
                    isCancelled: { true }
                )
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).count == 2)
        }
    }

    // MARK: Private

    private static func capture(in directory: URL, seconds: [Double]) throws -> URL {
        let url = directory.appendingPathComponent("source.pcap")
        let frames = seconds.map { second in
            let bytes = PacketBuilder.ethernetIPv4(
                proto: 6, src: "10.0.0.5", dst: "192.0.2.80",
                payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 80, flags: 0x18, payload: [1, 2, 3, 4])
            )
            return CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + second),
                originalLength: bytes.count
            )
        }
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        return url
    }

    private func withDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("split-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}

// MARK: - CaptureSplitFlowTests

@MainActor
struct CaptureSplitFlowTests {
    @Test
    func theFirstFileOfTheSetOpens() async throws {
        let environment = ProjectIsolationEnvironment(name: "split-flow")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("whole.pcap")
        let frames = (0 ..< 4).map { index in
            let bytes = PacketBuilder.ethernetIPv4(
                proto: 6, src: "10.0.0.5", dst: "192.0.2.80",
                payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 80, flags: 0x18, payload: [1, 2, 3, 4])
            )
            return CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index)),
                originalLength: bytes.count
            )
        }
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "whole", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        #expect(coordinator.canSplitCapture)

        coordinator.splitCapture(into: directory, prefix: "whole-part", options: .init(boundary: .frames(3)))
        await coordinator.waitForCaptureSplit()
        #expect(coordinator.activeSavedCapture?.url.lastPathComponent.hasPrefix("whole-part_00001_") == true)
        #expect(coordinator.savedCaptureWarning?.contains("2 files") == true)
    }
}
