import Foundation
import OSLog

let identity = TracexyIdentity.current
let logger = Logger(subsystem: identity.logSubsystem, category: "main")

logger.info("TracexyCaptureHelper starting on \(identity.helperMachServiceName, privacy: .public)")

// Capture both the executable bytes and this process's own signing facts before
// an app update can replace the on-disk bundle while this daemon remains alive.
if !CaptureService.prepareExecutableIdentityForLaunch() {
    logger.error("SECURITY: helper executable identity could not be captured")
}

if !CallerValidation.captureLaunchSigningProfile() {
    logger.error("SECURITY: helper launch signing profile could not be captured; callers will be refused")
}

let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: identity.helperMachServiceName)
listener.delegate = delegate
listener.resume()

IdleExitMonitor.start()
RunLoop.current.run()
