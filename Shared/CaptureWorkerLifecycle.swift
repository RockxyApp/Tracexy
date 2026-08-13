import Foundation

// MARK: - CaptureWorkerLifecycle

/// Race-free start/stop for a single background capture worker.
///
/// A libpcap read loop and its handle must be torn down carefully: closing the
/// handle from the caller's thread while the worker is mid-`pcap_next_ex` frees
/// the handle under the reader and crashes with `EXC_BAD_ACCESS` inside
/// `pcap_read_bpf`. The safe shape is: the caller *requests* stop and waits; the
/// worker thread owns the loop, and only the worker closes the handle — after
/// the loop has fully exited — then signals completion.
///
/// This type is that shape, and nothing else. The worker body is supplied as a
/// closure that loops while `isRunning()` is true and performs its own teardown
/// (closing the handle, a final stats read) before returning. `stop()` flips the
/// flag and blocks until the body returns, so the caller never races the reader
/// and the teardown always happens on the worker thread.
///
/// It lives in `Shared` (compiled into app + helper) so the helper's
/// `PcapCapture` uses the *same* primitive the test bundle exercises directly —
/// the helper target itself isn't importable by the tests.
nonisolated final class CaptureWorkerLifecycle: @unchecked Sendable {
    // MARK: Internal

    /// Whether a worker is currently running. Reads under the lock.
    var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }

    /// Starts `body` on a fresh background thread. Any previous worker is stopped
    /// first, so start is idempotent-safe against a leftover worker.
    ///
    /// `body` must loop while its `isRunning` argument returns true and perform
    /// its own teardown before returning; the completion signal fires only once
    /// `body` returns, which is what makes `stop()` a real barrier.
    func start(
        name: String,
        stackSize: Int = 1 << 20,
        body: @escaping @Sendable (_ isRunning: @escaping @Sendable () -> Bool) -> Void
    ) {
        stop()
        let completion = Completion()
        lock.lock()
        running = true
        current = completion
        lock.unlock()

        let worker = Thread {
            body { [weak self] in self?.isRunning ?? false }
            // Fires once the body returns (after its own teardown). A manual-reset
            // latch: every current and future waiter is released, not just one.
            completion.markDone()
        }
        worker.name = name
        worker.stackSize = stackSize
        lock.lock()
        thread = worker
        lock.unlock()
        worker.start()
    }

    /// Requests stop and blocks until the worker body has returned (after its own
    /// teardown). Idempotent, and safe under concurrency: *every* concurrent
    /// caller blocks until teardown completes — none returns early on the strength
    /// of another caller having flipped the running flag first.
    func stop() {
        lock.lock()
        // Gate on the completion latch, not on `running`: a second concurrent
        // stop must still wait for teardown even after the first flipped `running`
        // to false. `current` is cleared only once the worker has finished.
        guard let completion = current else {
            lock.unlock()
            return
        }
        running = false
        lock.unlock()

        // Wait outside the lock: the worker's final flush may still take the
        // caller's surrounding locks, and we must not hold ours while blocking.
        completion.wait()

        lock.lock()
        // Only the caller that still sees *this* worker's latch clears it, so a
        // subsequent start()'s fresh latch is never stomped by a lagging waiter.
        if current === completion {
            current = nil
            thread = nil
        }
        lock.unlock()
    }

    // MARK: Private

    /// A manual-reset completion latch: `markDone()` releases all waiters, and any
    /// waiter arriving after it is already done returns immediately. Unlike a
    /// count-1 semaphore, this admits arbitrarily many concurrent `stop()` waiters.
    private final class Completion: @unchecked Sendable {
        // MARK: Internal

        func wait() {
            condition.lock()
            while !done {
                condition.wait()
            }
            condition.unlock()
        }

        func markDone() {
            condition.lock()
            done = true
            condition.broadcast()
            condition.unlock()
        }

        // MARK: Private

        private let condition = NSCondition()
        private var done = false
    }

    private let lock = NSLock()
    private var running = false
    private var thread: Thread?
    /// The current worker's completion latch; `stop()` waits on it. Set on start,
    /// cleared once the worker has finished, so its lifetime spans teardown.
    private var current: Completion?
}
