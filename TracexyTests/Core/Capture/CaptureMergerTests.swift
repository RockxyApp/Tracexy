import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureMergerTests

/// File ▸ Merge Captures…: several captures become one PCAPNG in capture-time order,
/// every frame still naming the file it came from; equal times keep source order;
/// untimed frames, a destination that is a source, and one lone source are refused
/// with nothing written; tshark and capinfos read the result as intended.
struct CaptureMergerTests {
    // MARK: Internal

    @Test
    func clientAndServerCapturesMergeIntoOneTimeline() throws {
        try withDirectory { directory in
            let client = try Self.capture("client.pcap", in: directory, frames: [
                Self.frame(src: "10.0.0.5", dst: "192.0.2.80", sport: 50_000, dport: 80, at: 1.0),
                Self.frame(src: "10.0.0.5", dst: "192.0.2.80", sport: 50_000, dport: 80, at: 3.0),
            ])
            let server = try Self.capture("server.pcap", in: directory, frames: [
                Self.frame(src: "192.0.2.80", dst: "10.0.0.5", sport: 80, dport: 50_000, at: 2.0),
                Self.frame(src: "192.0.2.80", dst: "10.0.0.5", sport: 80, dport: 50_000, at: 4.0),
            ])
            let output = directory.appendingPathComponent("merged.pcapng")
            let summary = try CaptureMerger.merge(sources: [client, server], to: output)
            #expect(summary.framesPerSource == [2, 2])
            #expect(summary.writtenFrameCount == 4)
            #expect(summary.truncatedSources.isEmpty)

            let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
            #expect(loaded.format == .pcapng)
            #expect(loaded.properties.totalFrames == 4)
            // One conversation: both directions fold into the same session.
            #expect(loaded.sessions.count == 1)
            #expect(loaded.sessions.first?.bytesUp == loaded.sessions.first?.bytesDown)
            let section = try #require(loaded.properties.sections.first)
            #expect(section.interfaces.map { $0.interfaceDescription?.text } == ["client.pcap", "server.pcap"])
            #expect(section.comments.values.first?.text.contains("client.pcap") == true)

            if WiresharkOracle.isAvailable {
                let rows = try WiresharkOracle.tsharkFields(
                    output, fields: ["frame.time_epoch", "frame.interface_description"]
                )
                #expect(rows.map(\.last) == ["client.pcap", "server.pcap", "client.pcap", "server.pcap"])
                let times = rows.compactMap { $0.first.flatMap(Double.init) }
                #expect(times == times.sorted())
            }
        }
    }

    @Test
    func equalTimesKeepSourceOrderAndMixedLinkTypesGetTheirOwnInterfaces() throws {
        try withDirectory { directory in
            let ethernet = try Self.capture("a.pcap", in: directory, frames: [
                Self.frame(src: "10.0.0.5", dst: "192.0.2.80", sport: 50_000, dport: 80, at: 1.0),
            ])
            // The same packet without its Ethernet header, on the raw-IP link type.
            let rawBytes = Array(Self.frame(src: "10.0.0.6", dst: "192.0.2.80", sport: 50_001, dport: 80, at: 1.0)
                .bytes.dropFirst(14))
            let raw = directory.appendingPathComponent("b.pcap")
            try PcapWriter.write(
                linkType: LinkType.raw,
                frames: [CapturedFrame(bytes: rawBytes, timestamp: Self.time(1.0), originalLength: rawBytes.count)],
                to: raw
            )
            let output = directory.appendingPathComponent("mixed.pcapng")
            _ = try CaptureMerger.merge(sources: [raw, ethernet], to: output)
            let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
            let section = try #require(loaded.properties.sections.first)
            #expect(section.interfaces.map(\.linkType) == [LinkType.raw, LinkType.ethernet])
            #expect(loaded.sessions.count == 2)
        }
    }

    @Test
    func manyLongFileNamesStillWriteAValidSectionHeader() throws {
        try withDirectory { directory in
            let sources = try (0 ..< 25).map { index in
                try Self.capture(
                    String(repeating: "é", count: 90) + "-\(index).pcap", in: directory,
                    frames: [Self.frame(
                        src: "10.0.0.5",
                        dst: "192.0.2.80",
                        sport: 50_000,
                        dport: 80,
                        at: Double(index)
                    )]
                )
            }
            let output = directory.appendingPathComponent("many.pcapng")
            let summary = try CaptureMerger.merge(sources: sources, to: output)
            #expect(summary.writtenFrameCount == 25)
            let loaded = try SavedCaptureStreamLoader(contentsOf: output).load()
            #expect(loaded.properties.totalFrames == 25)
            let section = try #require(loaded.properties.sections.first)
            #expect(section.comments.values.first?.text.hasSuffix("from 25 files.") == true)
            #expect(section.interfaces.count == 25)
        }
    }

    @Test
    func refusalsWriteNothing() throws {
        try withDirectory { directory in
            let one = try Self.capture("one.pcap", in: directory, frames: [
                Self.frame(src: "10.0.0.5", dst: "192.0.2.80", sport: 50_000, dport: 80, at: 1.0),
            ])
            let two = try Self.capture("two.pcap", in: directory, frames: [
                Self.frame(src: "10.0.0.5", dst: "192.0.2.81", sport: 50_002, dport: 80, at: 2.0),
            ])
            let output = directory.appendingPathComponent("out.pcapng")
            #expect(throws: CaptureMergeError.needsTwoSources) {
                try CaptureMerger.merge(sources: [one], to: output)
            }
            #expect(throws: CaptureMergeError.destinationIsASource) {
                try CaptureMerger.merge(sources: [one, two], to: two)
            }
            // A PCAPNG Simple Packet Block carries no time and cannot be placed.
            let untimed = directory.appendingPathComponent("untimed.pcapng")
            try PcapngWriter.write(
                defaultLinkType: LinkType.ethernet,
                frames: [CapturedFrame(
                    bytes: Self.frame(src: "10.0.0.7", dst: "192.0.2.82", sport: 50_003, dport: 80, at: 0).bytes,
                    timestamp: nil,
                    originalLength: 54
                )],
                to: untimed
            )
            #expect(throws: CaptureMergeError.untimedFrame(source: "untimed.pcapng")) {
                try CaptureMerger.merge(sources: [one, untimed], to: output)
            }
            #expect(throws: CancellationError.self) {
                try CaptureMerger.merge(sources: [one, two], to: output, isCancelled: { true })
            }
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: directory.path)
            #expect(!leftovers.contains("out.pcapng"))
            #expect(!leftovers.contains { $0.hasSuffix(".partial") })
        }
    }

    // MARK: Private

    private static func time(_ seconds: Double) -> Date {
        Date(timeIntervalSince1970: 1_800_000_000 + seconds)
    }

    private static func frame(
        src: String, dst: String, sport: UInt16, dport: UInt16, at seconds: Double
    )
        -> CapturedFrame
    {
        let bytes = PacketBuilder.ethernetIPv4(
            proto: 6, src: src, dst: dst,
            payload: PacketBuilder.tcp(srcPort: sport, dstPort: dport, flags: 0x18, payload: [1, 2, 3, 4])
        )
        return CapturedFrame(bytes: bytes, timestamp: time(seconds), originalLength: bytes.count)
    }

    private static func capture(_ name: String, in directory: URL, frames: [CapturedFrame]) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        return url
    }

    private func withDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("merge-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }
}

// MARK: - CaptureMergeFlowTests

@MainActor
struct CaptureMergeFlowTests {
    @Test
    func mergedFileOpensAsTheCurrentCapture() async throws {
        let environment = ProjectIsolationEnvironment(name: "capture-merge")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let first = directory.appendingPathComponent("first.pcap")
        let second = directory.appendingPathComponent("second.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: first)
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: ReplayCorpus.tcpConnectionCapturedFrames(),
            to: second
        )
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        #expect(coordinator.canMergeCaptures)

        let merged = directory.appendingPathComponent("merged.pcapng")
        coordinator.mergeCaptures([first, second], to: merged)
        #expect(!coordinator.canMergeCaptures)
        await coordinator.waitForCaptureMerge()
        #expect(coordinator.canMergeCaptures)
        #expect(coordinator.captureError == nil)
        #expect(coordinator.activeSavedCapture?.url == merged)
        let expected = try SavedCaptureStreamLoader(contentsOf: merged).load().sessions.count
        #expect(coordinator.presentedSessions.count == expected)
        #expect(expected > 0)

        coordinator.mergeCaptures([first], to: directory.appendingPathComponent("lonely.pcapng"))
        await coordinator.waitForCaptureMerge()
        #expect(coordinator.captureError?.contains("at least two") == true)
    }
}
