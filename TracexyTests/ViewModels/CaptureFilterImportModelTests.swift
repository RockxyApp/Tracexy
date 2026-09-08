import Foundation
import Testing
@testable import Tracexy

// MARK: - ReadGate

/// A read body the test drives explicitly: it reports the exact moment the read
/// starts and suspends until the test finishes it. Ordering is therefore exact,
/// with no sleeps and no polling.
///
/// `respondsToCancellation: false` models the harder case — a worker that
/// completes *successfully* after it was superseded or the sheet went away — so
/// the model's own request and lifecycle guards are what the test measures,
/// rather than cancellation doing the work for them.
nonisolated private final class ReadGate: @unchecked Sendable {
    // MARK: Lifecycle

    init(respondsToCancellation: Bool = true) {
        self.respondsToCancellation = respondsToCancellation
    }

    // MARK: Internal

    var didCancel: Bool {
        lock.withLock { cancelled }
    }

    var startCount: Int {
        lock.withLock { starts }
    }

    func body() async throws -> [NamedCaptureFilter] {
        signalEntry()
        guard respondsToCancellation else {
            return try await suspend()
        }
        return try await withTaskCancellationHandler {
            try await suspend()
        } onCancel: {
            finish(.failure(CancellationError()), byCancellation: true)
        }
    }

    func waitForEntry() async {
        await withCheckedContinuation { continuation in
            let ready: Bool = lock.withLock {
                if entered {
                    return true
                }
                entryWaiter = continuation
                return false
            }
            if ready {
                continuation.resume()
            }
        }
    }

    func finish(_ result: Result<[NamedCaptureFilter], any Error>, byCancellation: Bool = false) {
        let pending: CheckedContinuation<[NamedCaptureFilter], any Error>? = lock.withLock {
            if byCancellation {
                cancelled = true
            }
            guard outcome == nil else {
                return nil
            }
            outcome = result
            let waiting = waiter
            waiter = nil
            return waiting
        }
        pending?.resume(with: result)
    }

    // MARK: Private

    private let lock = NSLock()
    private let respondsToCancellation: Bool

    private var starts = 0
    private var cancelled = false
    private var entered = false
    private var entryWaiter: CheckedContinuation<Void, Never>?
    private var outcome: Result<[NamedCaptureFilter], any Error>?
    private var waiter: CheckedContinuation<[NamedCaptureFilter], any Error>?

    private func signalEntry() {
        let pending: CheckedContinuation<Void, Never>? = lock.withLock {
            starts += 1
            entered = true
            let waiting = entryWaiter
            entryWaiter = nil
            return waiting
        }
        pending?.resume()
    }

    private func suspend() async throws -> [NamedCaptureFilter] {
        try await withCheckedThrowingContinuation { continuation in
            let ready: Result<[NamedCaptureFilter], any Error>? = lock.withLock {
                if let outcome {
                    return outcome
                }
                waiter = continuation
                return nil
            }
            if let ready {
                continuation.resume(with: ready)
            }
        }
    }
}

// MARK: - ReadCursor

nonisolated private final class ReadCursor: @unchecked Sendable {
    // MARK: Internal

    func next(upperBound: Int) -> Int {
        lock.withLock {
            let current = min(index, upperBound)
            index += 1
            return current
        }
    }

    // MARK: Private

    private let lock = NSLock()
    private var index = 0
}

private func scriptedRead(_ gates: [ReadGate]) -> CaptureFilterListRead {
    let cursor = ReadCursor()
    return CaptureFilterListRead { _ in
        try await gates[cursor.next(upperBound: gates.count - 1)].body()
    }
}

private func fileURL(_ name: String) -> URL {
    URL(fileURLWithPath: "/tmp/\(name)")
}

// MARK: - CaptureFilterImportModelTests

@MainActor
@Suite("Capture filter import coordination")
struct CaptureFilterImportModelTests {
    @Test("A superseded read cannot publish its entries even when it succeeds")
    func supersededRead() async {
        let first = ReadGate(respondsToCancellation: false)
        let second = ReadGate(respondsToCancellation: false)
        let model = CaptureFilterImportModel(read: scriptedRead([first, second]))

        model.load(from: fileURL("cfilters"))
        await first.waitForEntry()
        model.load(from: fileURL("other-cfilters"))
        await second.waitForEntry()

        first.finish(.success([NamedCaptureFilter(line: 1, name: "Stale", expression: "tcp")]))
        second.finish(.success([NamedCaptureFilter(line: 1, name: "Fresh", expression: "udp port 53")]))
        await model.waitForReads()

        #expect(model.filters.map(\.name) == ["Fresh"])
        #expect(model.sourceName == "other-cfilters")
        #expect(model.phase == .loaded)
        #expect(model.selectedFilterID == nil)
        #expect(!model.canApply)
    }

    @Test("Cancelling a read reaches the worker and publishes nothing")
    func cancelledRead() async {
        let gate = ReadGate()
        let model = CaptureFilterImportModel(read: scriptedRead([gate]))

        model.load(from: fileURL("cfilters"))
        await gate.waitForEntry()
        #expect(model.isLoading)
        #expect(!model.canApply)

        model.cancelRead()
        await model.waitForReads()

        #expect(gate.didCancel)
        #expect(model.phase == .idle)
        #expect(model.filters.isEmpty)
        #expect(model.sourceName == nil)
        #expect(model.applicableExpression() == nil)
    }

    @Test("A read that returns after the sheet closes can neither show nor apply")
    func deactivatedRead() async {
        let gate = ReadGate(respondsToCancellation: false)
        let model = CaptureFilterImportModel(read: scriptedRead([gate]))

        model.load(from: fileURL("cfilters"))
        await gate.waitForEntry()
        model.deactivate()
        gate.finish(.success([NamedCaptureFilter(line: 1, name: "Late", expression: "tcp port 443")]))
        await model.waitForReads()

        #expect(model.filters.isEmpty)
        #expect(model.phase == .idle)
        #expect(model.sourceName == nil)
        #expect(!model.canApply)
        #expect(model.applicableExpression() == nil)

        // A chooser that returns after dismissal must not start new work either.
        model.load(from: fileURL("cfilters"))
        #expect(model.phase == .idle)
        #expect(model.sourceName == nil)
        #expect(gate.startCount == 1)
    }

    @Test("A failed read is explicit and never applicable")
    func failedRead() async {
        let gate = ReadGate()
        let model = CaptureFilterImportModel(read: scriptedRead([gate]))

        model.load(from: fileURL("cfilters"))
        await gate.waitForEntry()
        gate.finish(.failure(CaptureFilterList.Failure.notRegularFile))
        await model.waitForReads()

        let message = model.errorMessage ?? ""
        #expect(message.contains("cfilters"))
        #expect(message.contains("regular capture-filter text file"))
        #expect(model.filters.isEmpty)
        #expect(!model.canApply)
        #expect(model.applicableExpression() == nil)
    }

    @Test("Known non-capture configuration files are refused before any read", arguments: [
        "dfilters", "dfilter_buttons", "colorfilters", "preferences", "recent", "disabled_protos",
    ])
    func rejectedFileName(_ name: String) {
        let gate = ReadGate()
        let model = CaptureFilterImportModel(read: scriptedRead([gate]))

        model.load(from: fileURL(name))

        let message = model.errorMessage ?? ""
        #expect(message.contains(name))
        #expect(message.contains("cfilters"))
        #expect(gate.startCount == 0)
        #expect(model.filters.isEmpty)
        #expect(!model.canApply)
        #expect(model.applicableExpression() == nil)
    }

    @Test("Only the selected entry of a loaded list is applicable")
    func selectionGatesApply() async {
        let gate = ReadGate()
        let model = CaptureFilterImportModel(read: scriptedRead([gate]))

        model.load(from: fileURL("cfilters"))
        await gate.waitForEntry()
        gate.finish(.success([
            NamedCaptureFilter(line: 2, name: "Web", expression: "tcp port 443"),
            NamedCaptureFilter(line: 4, name: "DNS", expression: "udp port 53"),
        ]))
        await model.waitForReads()

        #expect(model.phase == .loaded)
        #expect(!model.canApply)

        model.selectedFilterID = 99
        #expect(model.selectedFilter == nil)
        #expect(!model.canApply)

        model.selectedFilterID = 4
        #expect(model.canApply)
        #expect(model.applicableExpression() == "udp port 53")

        // Deactivation retires an already-selected expression too.
        model.deactivate()
        #expect(model.applicableExpression() == nil)
    }

    @Test("The default read loads an actual capture-filter file off the main actor")
    func defaultReadLoadsFile() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("cfilters")
        try Data("# personal filters\n\"Web\" tcp port 443\n\"DNS\" udp port 53\n".utf8).write(to: url)

        let model = CaptureFilterImportModel()
        model.load(from: url)
        await model.waitForReads()

        #expect(model.phase == .loaded)
        #expect(model.filters.map(\.name) == ["Web", "DNS"])
        #expect(model.sourceName == "cfilters")

        model.selectedFilterID = model.filters.last?.id
        #expect(model.applicableExpression() == "udp port 53")
    }

    @Test("The default read reports a directory as an unusable source")
    func defaultReadRejectsDirectory() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let model = CaptureFilterImportModel()
        model.load(from: root)
        await model.waitForReads()

        #expect(model.filters.isEmpty)
        #expect(!model.canApply)
        #expect(model.errorMessage?.contains("regular capture-filter text file") == true)
    }
}
