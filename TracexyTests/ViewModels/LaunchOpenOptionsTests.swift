import Foundation
import Testing
@testable import Tracexy

/// `-Y`/`--expression` and `-g`/`--frame` for a capture opened at launch.
@MainActor
struct LaunchOpenOptionsTests {
    @Test
    func parsesExpressionAndFrame() {
        #expect(LaunchOpenOptions.parse(["Tracexy", "-Y", "tcp and port == 443", "-g", "42"])
            == LaunchOpenOptions(expression: "tcp and port == 443", frame: 42))
        #expect(LaunchOpenOptions.parse(["Tracexy", "--direct-capture", "--frame", "7"])
            == LaunchOpenOptions(expression: nil, frame: 7))
        #expect(LaunchOpenOptions.parse(["Tracexy", "-g", "0", "-Y", "  "]).isEmpty)
        #expect(LaunchOpenOptions.parse(["Tracexy", "-g"]).isEmpty)
    }

    /// `-i` names the interface or pipe and `-k` starts capturing, as Wireshark's.
    @Test
    func parsesInterfaceAndStart() {
        var expected = LaunchOpenOptions()
        expected.interface = "/tmp/remote.fifo"
        expected.startsCapture = true
        #expect(LaunchOpenOptions.parse(["Tracexy", "-i", "/tmp/remote.fifo", "-k"]) == expected)
        #expect(LaunchOpenOptions.parse(["Tracexy", "--interface", "en0"]).interface == "en0")
        // A flag is never taken as the interface's value.
        let flagOnly = LaunchOpenOptions.parse(["Tracexy", "-i", "-k"])
        #expect(flagOnly.interface == nil)
        #expect(flagOnly.startsCapture)
    }

    @Test
    func goesToTheFrameOnceListed() async throws {
        let isolation = ProjectIsolationEnvironment(name: "launch-frame")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("launch-frame.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)

        coordinator.allFrames.pendingReveal = 3
        coordinator.openSavedCapture(SavedCapture(url: url, name: "launch-frame", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        for _ in 0 ..< 100 where coordinator.allFrames.list == nil || coordinator.allFrames.isLoading {
            try await Task.sleep(for: .milliseconds(50))
        }
        let row = try #require(coordinator.allFrames.list?.rows.first { $0.ordinal == 3 })
        #expect(coordinator.allFrames.pendingReveal == nil)
        if let session = row.sessionID {
            #expect(coordinator.activeWorkspace.selectedSessionID == session)
        }
        for _ in 0 ..< 100 {
            if case .loaded = coordinator.citedFrame.state {
                break
            }
            try await Task.sleep(for: .milliseconds(50))
        }
        guard case let .loaded(evidence) = coordinator.citedFrame.state else {
            Issue.record("frame 3 should be cited: \(coordinator.citedFrame.state)")
            return
        }
        #expect(evidence.provenance.ordinal.rawValue == 3)
    }
}
