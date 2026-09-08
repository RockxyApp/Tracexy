import Foundation
import Testing
@testable import Tracexy

// MARK: - CopyPause

nonisolated private final class CopyPause: @unchecked Sendable {
    // MARK: Internal

    func pauseOnce() {
        let first = lock.withLock {
            guard !entered else {
                return false
            }
            entered = true
            continuation?.resume()
            continuation = nil
            return true
        }
        if first {
            releaseSignal.wait()
        }
    }

    func waitForEntry() async {
        await withCheckedContinuation { waiter in
            lock.withLock {
                if entered {
                    waiter.resume()
                } else {
                    continuation = waiter
                }
            }
        }
    }

    func release() {
        releaseSignal.signal()
    }

    // MARK: Private

    private let lock = NSLock()
    private let releaseSignal = DispatchSemaphore(value: 0)
    private var entered = false
    private var continuation: CheckedContinuation<Void, Never>?
}

// MARK: - CaptureImportCancellationTests

@Suite("Import worker cancellation")
struct CaptureImportCancellationTests {
    @Test("Cancelling the async operation reaches the actual detached chunk copier")
    func cancellationReachesWorker() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let library = root.appendingPathComponent("Library")
        try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("capture.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: SampleCapture.frames(now: Date()), to: source)
        let handle = try FileHandle(forWritingTo: source)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data(repeating: 0, count: 800_000))
        try handle.close()
        let original = try Data(contentsOf: source)
        let gate = CopyPause()
        let task = Task {
            try await CaptureImportOperation.copy.run(source, library) { progress in
                if progress.bytesConsumed > 0 {
                    gate.pauseOnce()
                }
            }
        }
        await gate.waitForEntry()
        task.cancel()
        gate.release()
        do {
            _ = try await task.value
            Issue.record("Cancelled copy unexpectedly published a file")
        } catch is CancellationError {
            // Expected: parent cancellation propagated through the cancellation handler.
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: library.path).isEmpty)
        #expect(try Data(contentsOf: source) == original)
    }
}
