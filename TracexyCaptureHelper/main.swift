import Foundation
import OSLog

let identity = TracexyIdentity.current
let logger = Logger(subsystem: identity.logSubsystem, category: "main")

logger.info("TracexyCaptureHelper starting on \(identity.helperMachServiceName, privacy: .public)")

let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: identity.helperMachServiceName)
listener.delegate = delegate
listener.resume()

IdleExitMonitor.start()
RunLoop.current.run()
