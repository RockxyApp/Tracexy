import Foundation
import Testing
@testable import Tracexy

/// When libpcap stops reading on its own (the interface went away), the capture
/// must settle like an explicit Stop and say why — never stay "Capturing" while
/// nothing arrives.
@MainActor
@Suite("Capture source failure")
struct CaptureSourceFailureTests {
    @Test("A source read failure stops the active capture and reports the reason")
    func readFailureStopsAndReports() async {
        let environment = ProjectIsolationEnvironment(name: "source-failure")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.isCapturing = true // State-only: no backend was started.
        let token = coordinator.startGeneration

        coordinator.captureSourceDidFail("en0: The interface went down", captureToken: token)

        #expect(!coordinator.isCapturing)
        #expect(!coordinator.isStarting)
        #expect(coordinator.captureError?.contains("The interface went down") == true)
        // The stop retired the capture generation, as an explicit Stop does.
        #expect(coordinator.startGeneration != token)
    }

    @Test("A stale failure token from a retired capture changes nothing")
    func staleFailureIsIgnored() async {
        let environment = ProjectIsolationEnvironment(name: "source-failure-stale")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.isCapturing = true
        defer { coordinator.isCapturing = false }
        let stale = coordinator.startGeneration - 1

        coordinator.captureSourceDidFail("late report", captureToken: stale)

        #expect(coordinator.isCapturing)
        #expect(coordinator.captureError == nil)
    }
}
