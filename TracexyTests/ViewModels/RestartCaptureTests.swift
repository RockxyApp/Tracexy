import Foundation
import Testing
@testable import Tracexy

/// Capture ▸ Restart acts only on a running capture, and Capture ▸ Refresh
/// Interfaces asks interface lists to read the system again.
@MainActor
struct RestartCaptureTests {
    @Test
    func restartNeedsARunningCaptureAndRefreshBumpsTheToken() async {
        let isolation = ProjectIsolationEnvironment(name: "restart-capture")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        #expect(!coordinator.canRestartCapture)
        let generation = coordinator.startGeneration
        coordinator.restartCapture()
        #expect(!coordinator.isStarting)
        #expect(coordinator.startGeneration == generation)
        #expect(coordinator.captureError == nil)

        let token = coordinator.interfaceListToken
        coordinator.refreshInterfaces()
        #expect(coordinator.interfaceListToken == token + 1)
    }
}
