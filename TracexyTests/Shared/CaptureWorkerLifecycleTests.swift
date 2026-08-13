import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureWorkerLifecycleTests

@Suite("CaptureWorkerLifecycle (race-free capture teardown)")
struct CaptureWorkerLifecycleTests {
    @Test("stop() waits for the worker to run its own teardown, off the caller thread")
    func stopWaitsForWorkerOwnedTeardown() {
        let lifecycle = CaptureWorkerLifecycle()
        let probe = TeardownProbe()
        let callerThread = Thread.current

        lifecycle.start(name: "test.lifecycle.teardown") { isRunning in
            while isRunning() {
                Thread.sleep(forTimeInterval: 0.005)
            }
            // Stands in for closing the pcap handle: teardown runs after the loop
            // exits, on the worker thread — never the caller's.
            probe.record(thread: Thread.current)
        }
        #expect(lifecycle.isRunning)

        lifecycle.stop()

        // stop() returned only after the worker body — including teardown — ran.
        #expect(probe.didRunTeardown)
        // And that teardown happened on the worker thread, proving the handle is
        // never closed from the caller's thread mid-read.
        #expect(probe.ranOnCaller(callerThread) == false)
        #expect(lifecycle.isRunning == false)
    }

    @Test("start/stop are idempotent")
    func startStopAreIdempotent() {
        let lifecycle = CaptureWorkerLifecycle()
        lifecycle.stop() // no-op before any start

        lifecycle.start(name: "test.lifecycle.idempotent") { isRunning in
            while isRunning() {
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        lifecycle.stop()
        lifecycle.stop() // second stop is a no-op, not a hang or crash
        #expect(lifecycle.isRunning == false)
    }

    @Test("Concurrent stop() callers all block until worker teardown completes")
    func concurrentStopBlocksUntilTeardownReleased() {
        let lifecycle = CaptureWorkerLifecycle()
        // The worker signals when it has entered teardown, then blocks there until
        // the test explicitly releases it — deterministically holding teardown open
        // while both stop() callers are parked.
        let teardownReached = DispatchSemaphore(value: 0)
        let releaseTeardown = DispatchSemaphore(value: 0)

        lifecycle.start(name: "test.lifecycle.concurrent-stop") { isRunning in
            while isRunning() {
                Thread.sleep(forTimeInterval: 0.001)
            }
            teardownReached.signal()
            releaseTeardown.wait() // teardown stays open until the test allows it
        }

        // Two concurrent stoppers; each signals only once its stop() returns.
        let firstReturned = DispatchSemaphore(value: 0)
        let secondReturned = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            lifecycle.stop()
            firstReturned.signal()
        }
        Thread.detachNewThread {
            lifecycle.stop()
            secondReturned.signal()
        }

        // Wait until the worker is inside its (blocked) teardown, so both stoppers
        // are now parked on the completion latch.
        #expect(teardownReached.wait(timeout: .now() + 2) == .success)

        // Neither stop() may return while teardown is still blocked — this is the
        // regression guard: a second concurrent stop must not short-circuit.
        #expect(firstReturned.wait(timeout: .now() + 0.1) == .timedOut)
        #expect(secondReturned.wait(timeout: .now() + 0.1) == .timedOut)

        // Release teardown: both stoppers must now unblock.
        releaseTeardown.signal()
        #expect(firstReturned.wait(timeout: .now() + 2) == .success)
        #expect(secondReturned.wait(timeout: .now() + 2) == .success)
        #expect(lifecycle.isRunning == false)
    }
}

// MARK: - TeardownProbe

/// Thread-safe capture of where and whether the worker teardown ran.
private final class TeardownProbe: @unchecked Sendable {
    // MARK: Internal

    var didRunTeardown: Bool {
        lock.lock()
        defer { lock.unlock() }
        return teardownThread != nil
    }

    func record(thread: Thread) {
        lock.lock()
        defer { lock.unlock() }
        teardownThread = thread
    }

    func ranOnCaller(_ caller: Thread) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return teardownThread === caller
    }

    // MARK: Private

    private let lock = NSLock()
    private var teardownThread: Thread?
}
