import Foundation
import OSLog

final class CaptureService: NSObject, TracexyHelperProtocol {
    // MARK: Internal

    static let shared = CaptureService()

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

    func startCapture(interface: String, withReply reply: @escaping (Bool, String) -> Void) {
        do {
            let session = try PcapCapture()
            session.start(interface: interface, onBatch: { [weak self] frames, link in
                guard let self else {
                    return
                }
                self.lock.lock()
                self.linkType = Int(link)
                self.buffer.append(contentsOf: frames)
                if self.buffer.count > 40_000 {
                    self.buffer.removeFirst(self.buffer.count - 40_000)
                }
                self.lock.unlock()
            }, onError: { message in
                Self.logger.error("capture error: \(message, privacy: .public)")
            })
            lock.lock()
            capture = session
            lock.unlock()
            Self.logger.info("started capture on \(interface, privacy: .public)")
            reply(true, "")
        } catch {
            reply(false, "\(error)")
        }
    }

    func stopCapture(withReply reply: @escaping () -> Void) {
        lock.lock()
        capture?.stop()
        capture = nil
        buffer.removeAll(keepingCapacity: false)
        lock.unlock()
        reply()
    }

    func fetchFrames(withReply reply: @escaping ([Data], Int) -> Void) {
        lock.lock()
        let drained = buffer
        buffer.removeAll(keepingCapacity: true)
        let link = linkType
        lock.unlock()
        reply(drained, link)
    }

    /// The owning app disconnected — stop capturing and clear state.
    func handleConnectionInvalidated(processID: Int32) {
        stopCapture {}
    }

    // MARK: Private

    private static let logger = Logger(subsystem: TracexyIdentity.current.logSubsystem, category: "CaptureService")

    private let lock = NSLock()
    private var capture: PcapCapture?
    private var buffer: [Data] = []
    private var linkType = 1
}
