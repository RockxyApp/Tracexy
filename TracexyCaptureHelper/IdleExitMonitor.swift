import Foundation

enum IdleExitMonitor {
    // MARK: Internal

    static func start() {
        queue.async { schedule() }
    }

    static func resetIdleTimer() {
        lock.lock()
        lastActivity = Date()
        lock.unlock()
    }

    // MARK: Private

    private static let queue = DispatchQueue(label: "com.amunx.tracexy.helper.idle-exit")
    private static let idleTimeout: TimeInterval = 5 * 60
    private static let lock = NSLock()
    private static var lastActivity = Date()

    private static func schedule() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 30, repeating: 30)
        timer.setEventHandler { checkAndExit() }
        timer.resume()
        RunLoop.current.run()
    }

    private static func checkAndExit() {
        lock.lock()
        let idle = Date().timeIntervalSince(lastActivity)
        lock.unlock()
        guard idle > idleTimeout, !CaptureService.shared.isCapturing else {
            return
        }
        exit(0)
    }
}
