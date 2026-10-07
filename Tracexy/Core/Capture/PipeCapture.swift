import Foundation

// MARK: - PipeCapture

/// Capture from a named pipe (a FIFO made with `mkfifo`) carrying a pcap or pcapng
/// stream — Wireshark's pipe interfaces, the bridge for
/// `ssh host tcpdump -U -w - > /tmp/remote.fifo`. Read in this process with no
/// helper and no privilege: the bytes are whatever the writer sends, parsed by
/// ``CaptureByteStreamParser``. The capture filter does not apply; filter where
/// the capture is taken.
///
/// The pipe is opened non-blocking and polled with a 100 ms timeout, so Stop
/// returns promptly even while no writer has connected or nothing arrives.
nonisolated final class PipeCapture: @unchecked Sendable {
    // MARK: Internal

    struct Failure: Error { let message: String }

    /// Interface names never start with "/", so a path names a pipe.
    static func isPipe(_ interface: String?) -> Bool {
        interface?.hasPrefix("/") == true
    }

    /// Why `path` cannot be read as a pipe right now, or `nil` when it can.
    static func problem(with path: String) -> String? {
        var info = stat()
        guard stat(path, &info) == 0 else {
            return String(localized: "No pipe exists at \(path). Create it with mkfifo, then start the writer.")
        }
        guard info.st_mode & S_IFMT == S_IFIFO else {
            return String(localized: "\(path) is not a named pipe. Open a capture file with File ▸ Open instead.")
        }
        return nil
    }

    /// Starts reading `path`. `onBatch` fires on the worker thread with frames of
    /// one link type; `onReadFailure` once if the stream is unreadable or not a
    /// capture; `onEnd` once when the writer closes the pipe after sending data.
    func start(
        path: String,
        onBatch: @escaping @Sendable ([CapturedFrame], UInt32) -> Void,
        onReadFailure: @escaping @Sendable (String) -> Void,
        onEnd: @escaping @Sendable () -> Void
    )
        throws
    {
        stop()
        if let problem = Self.problem(with: path) {
            throw Failure(message: problem)
        }
        let descriptor = open(path, O_RDONLY | O_NONBLOCK)
        guard descriptor >= 0 else {
            throw Failure(message: String(cString: strerror(errno)))
        }
        setRunning(true)
        let done = DispatchSemaphore(value: 0)
        finished = done
        let worker = Thread { [weak self] in
            self?.loop(descriptor: descriptor, onBatch: onBatch, onReadFailure: onReadFailure, onEnd: onEnd)
            close(descriptor)
            done.signal()
        }
        worker.name = "com.amunx.tracexy.pipe-capture"
        worker.start()
    }

    /// Stops reading and waits for the worker to close the pipe. Idempotent.
    func stop() {
        lock.lock()
        let wasRunning = running
        running = false
        lock.unlock()
        guard wasRunning else {
            return
        }
        finished?.wait()
        finished = nil
    }

    // MARK: Private

    private let lock = NSLock()
    private var running = false
    private var finished: DispatchSemaphore?

    private var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }

    private func setRunning(_ value: Bool) {
        lock.lock()
        running = value
        lock.unlock()
    }

    private func loop(
        descriptor: Int32,
        onBatch: @Sendable ([CapturedFrame], UInt32) -> Void,
        onReadFailure: @Sendable (String) -> Void,
        onEnd: @Sendable () -> Void
    ) {
        var parser = CaptureByteStreamParser()
        var pending: [CapturedFrame] = []
        var pendingLinkType: UInt32?
        var lastFlush = Date()
        var hasReadData = false
        var chunk = [UInt8](repeating: 0, count: 256 * 1_024)
        func flush() {
            if let linkType = pendingLinkType, !pending.isEmpty {
                onBatch(pending, linkType)
            }
            pending = []
            lastFlush = Date()
        }
        while isRunning {
            // `poll` only waits: on macOS it does not report a FIFO's writer going
            // away, so every pass also tries a non-blocking read.
            var poller = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            if poll(&poller, 1, 100) < 0, errno != EINTR {
                flush()
                onReadFailure(String(cString: strerror(errno)))
                return
            }
            let count = chunk.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
            if count < 0, errno != EAGAIN, errno != EINTR {
                flush()
                onReadFailure(String(cString: strerror(errno)))
                return
            }
            if count == 0 {
                // Before any data this only means no writer has opened the pipe
                // yet; after data it means the writer closed it.
                if hasReadData {
                    flush()
                    onEnd()
                    return
                }
                Thread.sleep(forTimeInterval: 0.1)
            }
            if count > 0 {
                hasReadData = true
                do {
                    for item in try parser.append(chunk[0 ..< count]) {
                        if item.linkType != pendingLinkType {
                            flush()
                            pendingLinkType = item.linkType
                        }
                        pending.append(item.frame)
                    }
                } catch {
                    flush()
                    onReadFailure((error as? CaptureByteStreamParser.Failure)?.message ?? "\(error)")
                    return
                }
            }
            if pending.count >= 512 || Date().timeIntervalSince(lastFlush) >= 0.1 {
                flush()
            }
        }
        flush()
    }
}
