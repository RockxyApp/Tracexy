import Foundation
import os

// MARK: - CaptureServiceConnection

/// One exported object per authenticated XPC connection. Capture ownership is
/// tied to this object's stable ID so an unrelated connection invalidation
/// cannot stop or drain another connection's active session.
private final class CaptureServiceConnection: NSObject, TracexyHelperProtocol {
    // MARK: Lifecycle

    init(processID: Int32) {
        self.processID = processID
    }

    // MARK: Internal

    let ownerID = UUID()
    let processID: Int32

    func getHelperInfo(withReply reply: @escaping (String, Int, Int) -> Void) {
        CaptureService.shared.getHelperInfo(withReply: reply)
    }

    func getExecutableIdentity(
        withReply reply: @escaping (String, String, Int32, String, Int, Int) -> Void
    ) {
        CaptureService.shared.getExecutableIdentity(withReply: reply)
    }

    func prepareForExecutableRefresh(withReply reply: @escaping (Bool) -> Void) {
        CaptureService.shared.prepareForExecutableRefresh(withReply: reply)
    }

    func startCapture(configuration: CaptureConfiguration, withReply reply: @escaping (Bool, String) -> Void) {
        CaptureService.shared.startCapture(ownerID: ownerID, configuration: configuration, withReply: reply)
    }

    func stopCapture(withReply reply: @escaping (FrameBatchMessage) -> Void) {
        CaptureService.shared.stopCapture(ownerID: ownerID, withReply: reply)
    }

    func fetchFrames(withReply reply: @escaping (FrameBatchMessage) -> Void) {
        CaptureService.shared.fetchFrames(ownerID: ownerID, withReply: reply)
    }

    func invalidate() {
        CaptureService.shared.handleConnectionInvalidated(ownerID: ownerID, processID: processID)
    }
}

// MARK: - HelperDelegate

/// NSXPCListenerDelegate that validates incoming connections and sets up the exported service.
final class HelperDelegate: NSObject, NSXPCListenerDelegate {
    // MARK: Internal

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    )
        -> Bool
    {
        guard ConnectionValidator.isValidCaller(connection) else {
            Self.logger.warning("Rejected XPC connection from untrusted caller (pid: \(connection.processIdentifier))")
            return false
        }

        Self.logger.info("Accepted XPC connection from pid \(connection.processIdentifier)")
        IdleExitMonitor.resetIdleTimer()

        let processID = connection.processIdentifier
        let exportedObject = CaptureServiceConnection(processID: processID)
        connection.exportedInterface = TracexyHelperInterface.make()
        connection.exportedObject = exportedObject

        connection.invalidationHandler = { [exportedObject] in
            Self.logger.warning("XPC connection invalidated for pid \(processID)")
            exportedObject.invalidate()
        }

        connection.interruptionHandler = {
            Self.logger.info("XPC connection interrupted (transient, not restoring proxy)")
        }

        connection.resume()
        return true
    }

    // MARK: Private

    private static let logger = Logger(subsystem: TracexyIdentity.current.logSubsystem, category: "HelperDelegate")
}
