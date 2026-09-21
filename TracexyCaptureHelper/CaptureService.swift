import Foundation
import OSLog

final class CaptureService: NSObject {
    // MARK: Internal

    static let shared = CaptureService()

    /// The helper's staging buffer capacity. When the app falls behind draining,
    /// the oldest frames are evicted and counted (see `BoundedFrameBuffer`); the
    /// count rides out in every drain batch so the loss is never silent.
    static let bufferCapacity = 40_000

    /// Freeze the running executable identity before an app update can replace
    /// the bytes at this daemon's path.
    @discardableResult
    static func prepareExecutableIdentityForLaunch() -> Bool {
        runningHelperInfo.buildNumber > 0
            && runningHelperInfo.protocolVersion > 0
            && runningExecutableIdentity.isWellFormed
    }

    func getHelperInfo(withReply reply: @escaping (String, Int, Int) -> Void) {
        // Report the metadata frozen at process launch. Reading Bundle.main
        // after an in-place app update could make an old process claim the new
        // bundle's versions even though its executable bytes have not changed.
        let info = Self.runningHelperInfo
        reply(info.binaryVersion, info.buildNumber, info.protocolVersion)
    }

    func getExecutableIdentity(
        withReply reply: @escaping (String, String, Int32, String, Int, Int) -> Void
    ) {
        let identity = Self.runningExecutableIdentity
        reply(
            identity.executableDigest,
            identity.launchIdentity,
            identity.processIdentifier,
            identity.executablePath,
            identity.buildNumber,
            identity.protocolVersion
        )
    }

    func prepareForExecutableRefresh(withReply reply: @escaping (Bool) -> Void) {
        lifecycleLock.lock()
        let canRefresh: Bool = {
            lock.lock()
            defer { lock.unlock() }
            guard capture == nil, !processExitPending else {
                return false
            }
            processExitPending = true
            return true
        }()
        lifecycleLock.unlock()

        guard canRefresh else {
            reply(false)
            return
        }

        // Acknowledge before exiting so the app can distinguish a delivered
        // refresh from an XPC interruption. No new capture can start after the
        // pending flag is set.
        reply(true)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.15) {
            Foundation.exit(0)
        }
    }

    func startCapture(
        ownerID: UUID,
        configuration: CaptureConfiguration,
        withReply reply: @escaping (Bool, String) -> Void
    ) {
        // Serialize the whole start/stop lifecycle on a *separate* operation lock,
        // so a start can't interleave with a stop (e.g. assigning `capture` after
        // a concurrent stop cleared it). This lock is only ever held by lifecycle
        // operations — never by the callbacks or `fetchFrames`, which take the
        // state/buffer `lock`. We also never hold the state lock while blocking in
        // `PcapCapture.stop()`, so the worker's teardown never deadlocks a drain.
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }

        lock.lock()
        let refreshPending = processExitPending
        let existingOwnerID = captureOwnerID
        lock.unlock()
        guard !refreshPending else {
            reply(false, "The helper is restarting after an app update.")
            return
        }
        guard existingOwnerID == nil || existingOwnerID == ownerID else {
            reply(false, "Another authenticated app connection owns the active capture.")
            return
        }

        // Stop any prior capture race-free BEFORE taking the buffer lock: the
        // worker's blocking teardown must never run under the state lock.
        let previous: PcapCapture? = {
            lock.lock()
            defer { lock.unlock() }
            let existing = capture
            capture = nil
            captureOwnerID = nil
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
            readFailure = nil
            // Claim ownership before the worker can emit its first callback.
            // `fetchFrames` does not take the lifecycle lock, so leaving this
            // nil until `start` returned would let another accepted connection
            // drain the first batch during startup.
            captureOwnerID = ownerID
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
            }, onReadFailure: { [weak self] message in
                guard let self else {
                    return
                }
                // Keep the failure with the buffered tail: the next fetch or stop
                // reply carries both, so the app sees every frame that arrived
                // before the source failed and the reason it stopped.
                self.lock.lock()
                self.readFailure = message
                self.lock.unlock()
                Self.logger.error("capture read failed: \(message, privacy: .public)")
            })

            lock.lock()
            capture = session
            captureLinkType = linkType
            lock.unlock()
            Self.logger.info("started capture on \(configuration.interface, privacy: .public)")
            reply(true, "")
        } catch let error as PcapCapture.Failure {
            clearStartingOwner(ownerID)
            reply(false, error.message)
        } catch {
            clearStartingOwner(ownerID)
            reply(false, error.localizedDescription)
        }
    }

    func stopCapture(ownerID: UUID, withReply reply: @escaping (FrameBatchMessage) -> Void) {
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
            guard captureOwnerID == nil || captureOwnerID == ownerID else {
                return nil
            }
            let existing = capture
            capture = nil
            captureOwnerID = nil
            return existing
        }()
        if session == nil {
            lock.lock()
            let ownedByAnotherConnection = captureOwnerID != nil && captureOwnerID != ownerID
            lock.unlock()
            if ownedByAnotherConnection {
                reply(Self.emptyBatch(readFailure: "The active capture belongs to another app connection."))
                return
            }
        }
        session?.stop()

        // Atomically drain the worker's final flush and final pcap_stats sample
        // into the stop reply. A separate stop→fetch sequence could race the next
        // start and drain the wrong capture generation.
        lock.lock()
        let finalBatch = FrameBatchMessage(
            frames: buffer.drain(),
            bufferDroppedCount: buffer.droppedCount,
            captureLinkType: captureLinkType,
            stats: statsAvailable ? latestStats : nil,
            readFailure: readFailure
        )
        buffer.reset()
        latestStats = nil
        statsAvailable = false
        readFailure = nil
        lock.unlock()
        reply(finalBatch)
    }

    func fetchFrames(ownerID: UUID, withReply reply: @escaping (FrameBatchMessage) -> Void) {
        lock.lock()
        guard captureOwnerID == nil || captureOwnerID == ownerID else {
            lock.unlock()
            reply(Self.emptyBatch(readFailure: "The active capture belongs to another app connection."))
            return
        }
        let drained = buffer.drain()
        let dropped = buffer.droppedCount
        let stats = statsAvailable ? latestStats : nil
        let link = captureLinkType
        let failure = readFailure
        lock.unlock()
        reply(FrameBatchMessage(
            frames: drained,
            bufferDroppedCount: dropped,
            captureLinkType: link,
            stats: stats,
            readFailure: failure
        ))
    }

    /// The owning app disconnected — stop capturing and discard the returned
    /// final batch, because no authenticated client remains to receive it.
    func handleConnectionInvalidated(ownerID: UUID, processID _: Int32) {
        stopCapture(ownerID: ownerID) { _ in }
    }

    /// Atomically closes the lifecycle gate before an idle exit. Once this
    /// returns true, a concurrent Start request is rejected instead of racing
    /// the process termination.
    func prepareForIdleExit() -> Bool {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        lock.lock()
        defer { lock.unlock() }
        guard capture == nil, !processExitPending else {
            return false
        }
        processExitPending = true
        return true
    }

    // MARK: Private

    private static let logger = Logger(subsystem: TracexyIdentity.current.logSubsystem, category: "CaptureService")

    private static let runningHelperInfo: HelperInfo = {
        let info = Bundle.main.infoDictionary
        return HelperInfo(
            binaryVersion: info?["CFBundleShortVersionString"] as? String ?? "0.0.0",
            buildNumber: Int(info?["CFBundleVersion"] as? String ?? "0") ?? 0,
            protocolVersion: HelperProtocolVersion.value(in: info)
        )
    }()

    private static let runningExecutableIdentity: HelperExecutableIdentity = {
        let path = HelperExecutableLocation.currentProcessExecutablePath()
        let digest = (try? HelperExecutableDigest.sha256Hex(atPath: path)) ?? ""
        return HelperExecutableIdentity(
            executableDigest: digest,
            launchIdentity: UUID().uuidString,
            processIdentifier: ProcessInfo.processInfo.processIdentifier,
            executablePath: path,
            buildNumber: runningHelperInfo.buildNumber,
            protocolVersion: runningHelperInfo.protocolVersion
        )
    }()

    /// Serializes start/stop *operations* so they can't interleave. Distinct from
    /// `lock` (which guards the buffer/stats state and is taken by callbacks and
    /// `fetchFrames`); a blocking `PcapCapture.stop()` is only ever awaited under
    /// this lock, never the state lock.
    private let lifecycleLock = NSLock()
    private let lock = NSLock()
    private var capture: PcapCapture?
    private var captureOwnerID: UUID?
    private var processExitPending = false
    private var buffer = BoundedFrameBuffer<CapturedFrameMessage>(capacity: CaptureService.bufferCapacity)
    /// Latest `pcap_stats` sample, or `nil` when accounting is unavailable.
    private var latestStats: HelperCaptureStats?
    private var statsAvailable = false
    /// libpcap's reason when the worker's read loop ended on its own. Delivered
    /// with the next batch reply and cleared at every capture boundary.
    private var readFailure: String?
    /// Representative outer DLT of the running capture, for a faithful savefile.
    private var captureLinkType: UInt32 = 1

    private static func emptyBatch(readFailure: String?) -> FrameBatchMessage {
        FrameBatchMessage(
            frames: [],
            bufferDroppedCount: 0,
            captureLinkType: 1,
            stats: nil,
            readFailure: readFailure
        )
    }

    private func clearStartingOwner(_ ownerID: UUID) {
        lock.lock()
        defer { lock.unlock() }
        if capture == nil, captureOwnerID == ownerID {
            captureOwnerID = nil
        }
    }
}
