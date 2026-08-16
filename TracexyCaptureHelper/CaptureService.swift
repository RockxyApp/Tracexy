import Foundation
import OSLog

final class CaptureService: NSObject, TracexyHelperProtocol {
    // MARK: Internal

    static let shared = CaptureService()

    /// The helper's staging buffer capacity. When the app falls behind draining,
    /// the oldest frames are evicted and counted (see `BoundedFrameBuffer`); the
    /// count rides out in every drain batch so the loss is never silent.
    static let bufferCapacity = 40_000

    var isCapturing: Bool {
        lock.lock()
        defer { lock.unlock() }
        return capture != nil
    }

    func getHelperInfo(withReply reply: @escaping (String, Int, Int) -> Void) {
        // Report the helper's *actual* bundle version so the app can detect an
        // outdated installed helper and offer an update (sibling-app parity).
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "0.0.0"
        let build = Int(info?["CFBundleVersion"] as? String ?? "0") ?? 0
        reply(version, build, HelperProtocolVersion.current)
    }

    func startCapture(configuration: CaptureConfiguration, withReply reply: @escaping (Bool, String) -> Void) {
        // Serialize the whole start/stop lifecycle on a *separate* operation lock,
        // so a start can't interleave with a stop (e.g. assigning `capture` after
        // a concurrent stop cleared it). This lock is only ever held by lifecycle
        // operations — never by the callbacks or `fetchFrames`, which take the
        // state/buffer `lock`. We also never hold the state lock while blocking in
        // `PcapCapture.stop()`, so the worker's teardown never deadlocks a drain.
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }

        // Stop any prior capture race-free BEFORE taking the buffer lock: the
        // worker's blocking teardown must never run under the state lock.
        let previous: PcapCapture? = {
            lock.lock()
            defer { lock.unlock() }
            let existing = capture
            capture = nil
            return existing
        }()
        previous?.stop()

        do {
            let session = try PcapCapture()
            // Capture boundary: reset the buffer and its cumulative drop count, and
            // clear stale accounting, so a fresh capture starts from zero.
            lock.lock()
            buffer.reset()
            latestStats = nil
            statsAvailable = false
            lock.unlock()

            // `start` validates the configuration, opens the handle, and compiles
            // any BPF synchronously: it throws on an out-of-bounds value, an
            // interface that can't be opened, or a bad filter (so we never report a
            // started capture that isn't running or silently ignored its filter),
            // and otherwise returns the real link type before the first frame —
            // reported immediately so a savefile is faithful from frame 0.
            let linkType = try session.start(configuration: configuration, onBatch: { [weak self] frames in
                guard let self else {
                    return
                }
                self.lock.lock()
                if let link = frames.first?.linkType {
                    self.captureLinkType = link
                }
                self.buffer.append(contentsOf: frames)
                self.lock.unlock()
            }, onStatistics: { [weak self] sample in
                guard let self else {
                    return
                }
                self.lock.lock()
                self.latestStats = sample
                self.statsAvailable = sample != nil
                self.lock.unlock()
            })

            lock.lock()
            capture = session
            captureLinkType = linkType
            lock.unlock()
            Self.logger.info("started capture on \(configuration.interface, privacy: .public)")
            reply(true, "")
        } catch let error as PcapCapture.Failure {
            reply(false, error.message)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func stopCapture(withReply reply: @escaping (FrameBatchMessage) -> Void) {
        // Serialize against start/stop on the operation lock (see startCapture).
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }

        // Detach the session under the state lock, then stop it *outside* that
        // lock: its teardown blocks until the worker exits, and holding the state
        // lock across that wait would stall the onBatch callback running on the
        // worker thread.
        let session: PcapCapture? = {
            lock.lock()
            defer { lock.unlock() }
            let existing = capture
            capture = nil
            return existing
        }()
        session?.stop()

        // Atomically drain the worker's final flush and final pcap_stats sample
        // into the stop reply. A separate stop→fetch sequence could race the next
        // start and drain the wrong capture generation.
        lock.lock()
        let finalBatch = FrameBatchMessage(
            frames: buffer.drain(),
            bufferDroppedCount: buffer.droppedCount,
            captureLinkType: captureLinkType,
            stats: statsAvailable ? latestStats : nil
        )
        buffer.reset()
        latestStats = nil
        statsAvailable = false
        lock.unlock()
        reply(finalBatch)
    }

    func fetchFrames(withReply reply: @escaping (FrameBatchMessage) -> Void) {
        lock.lock()
        let drained = buffer.drain()
        let dropped = buffer.droppedCount
        let stats = statsAvailable ? latestStats : nil
        let link = captureLinkType
        lock.unlock()
        reply(FrameBatchMessage(
            frames: drained,
            bufferDroppedCount: dropped,
            captureLinkType: link,
            stats: stats
        ))
    }

    /// The owning app disconnected — stop capturing and discard the returned
    /// final batch, because no authenticated client remains to receive it.
    func handleConnectionInvalidated(processID _: Int32) {
        stopCapture { _ in }
    }

    // MARK: Private

    private static let logger = Logger(subsystem: TracexyIdentity.current.logSubsystem, category: "CaptureService")

    /// Serializes start/stop *operations* so they can't interleave. Distinct from
    /// `lock` (which guards the buffer/stats state and is taken by callbacks and
    /// `fetchFrames`); a blocking `PcapCapture.stop()` is only ever awaited under
    /// this lock, never the state lock.
    private let lifecycleLock = NSLock()
    private let lock = NSLock()
    private var capture: PcapCapture?
    private var buffer = BoundedFrameBuffer<CapturedFrameMessage>(capacity: CaptureService.bufferCapacity)
    /// Latest `pcap_stats` sample, or `nil` when accounting is unavailable.
    private var latestStats: HelperCaptureStats?
    private var statsAvailable = false
    /// Representative outer DLT of the running capture, for a faithful savefile.
    private var captureLinkType: UInt32 = 1
}
