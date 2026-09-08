import Foundation
import Testing
@testable import Tracexy

// MARK: - ProjectRecoveryBoundaryTests

/// The explicit destructive helper reset (Settings → Helper → Force Reset)
/// destroys the XPC connection a running or stopping capture depends on, so the
/// final drain that capture owes can never be completed by a reply. These tests
/// drive the *app-side* hook only: no helper is installed, no privileged operation
/// runs, no device is opened and no network traffic is captured. Everything is a
/// synthetic engine epoch, a real file-backed spool inside a throwaway environment,
/// and a deferred tail that is modelled as a late callback.
///
/// The contract under test: the obsolete owed operation is terminated as *failed*,
/// the accepted prefix is finalized under the exact epoch and stopped generation
/// the operation recorded and written to History as `incomplete`, the current
/// Project stays recoverable, and nothing here ever claims the missing tail
/// arrived.
@MainActor
@Suite("Destructive helper reset boundary")
struct ProjectRecoveryBoundaryTests {
    // MARK: Internal

    @Test("A pending stop whose helper reply is lost is finalized as an incomplete prefix")
    func pendingStopIsFinalizedWithoutClaimingTheTail() async throws {
        let environment = ProjectIsolationEnvironment(name: "recovery-pending-stop")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let projectA = coordinator.projectStore.activeProjectID

        // A confirmed capture: this Project's own engine epoch and spool hold the
        // prefix, and one durable History identity was minted at start.
        let captureToken = coordinator.startGeneration
        let spool = coordinator.liveCaptureSpool
        coordinator.resetSessionEngineForSavedCapture(token: captureToken)
        await coordinator.ingestChain?.value
        let frames = SampleCapture.frames(now: Self.epoch)
        coordinator.isCapturing = true
        coordinator.beginLiveHistoryLifetime(captureGeneration: captureToken)
        coordinator.ingest(frames, linkType: LinkType.ethernet)
        await coordinator.ingestChain?.value
        let expectedSessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        #expect(!expectedSessions.isEmpty)

        // Stop reached the backend and minted its boundary; the helper's final reply
        // is the thing the reset is about to make unreachable.
        coordinator.startGeneration &+= 1
        let stoppedToken = coordinator.startGeneration
        coordinator.freezeLiveHistoryLifetime(captureGeneration: captureToken, stoppedGeneration: stoppedToken)
        coordinator.isCapturing = false
        let frozen = try #require(coordinator.frozenHistoryLifetime)
        coordinator.beginFinalCaptureDrain(stoppedToken: stoppedToken, captureToken: captureToken)
        #expect(coordinator.isFinalDrainPending)
        #expect(coordinator.captureStartBlockedMessage != nil)

        coordinator.prepareForDestructiveHelperReset()
        await coordinator.ingestChain?.value
        await coordinator.waitForHistory()

        // The obsolete operation is retired, so the app is usable again.
        #expect(!coordinator.isFinalDrainPending)
        #expect(coordinator.captureStartBlockedMessage == nil)
        // Truthfully, not as a success.
        #expect(coordinator.captureError != nil)
        #expect(coordinator.historyCaptures.count == 1)
        #expect(coordinator.historyCaptures.first?.record.completeness == .incomplete)
        // The recoverable prefix is finalized, never discarded to unblock the app.
        #expect(coordinator.stoppedCaptureReadyGeneration == coordinator.startGeneration)
        #expect(coordinator.startGeneration != stoppedToken)
        #expect(coordinator.sessions.map(\.id) == expectedSessions.map(\.id))
        #expect(coordinator.historyCaptures.first?.id == frozen.captureID)
        coordinator.selectHistoryCapture(frozen.captureID)
        await coordinator.waitForHistory()
        #expect(coordinator.historySessions.count == expectedSessions.count)
        #expect(coordinator.liveCaptureSpool === spool)
        let spooled = try await spool.capture()
        #expect(spooled.frames.map(\.bytes) == frames.map(\.bytes))
        // The Project is left exactly where it was, and recoverable.
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.projectTransitionStatus == .idle)
    }

    @Test("A stop parked before its stopped token is minted resolves the same operation")
    func stopWithoutAStoppedTokenIsResolvedOnTheSameOperation() async throws {
        let environment = ProjectIsolationEnvironment(name: "recovery-unminted-stop")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let captureToken = coordinator.startGeneration
        coordinator.resetSessionEngineForSavedCapture(token: captureToken)
        await coordinator.ingestChain?.value
        coordinator.beginLiveHistoryLifetime(captureGeneration: captureToken)
        coordinator.isCapturing = true

        // Exactly what `stopCapture()` does when a destructive helper fetch is still
        // in flight: the drain is owed before a stopped generation exists.
        coordinator.isStarting = false
        coordinator.beginFinalCaptureDrain(stoppedToken: nil, captureToken: captureToken)
        let owedOperation = try #require(coordinator.pendingFinalDrainOperationID)

        coordinator.prepareForDestructiveHelperReset()
        // The boundary minted here resolves the operation already owed rather than
        // opening a second one a stale completion could satisfy.
        #expect(coordinator.pendingFinalDrainOperationID == owedOperation)
        #expect(!coordinator.isCapturing)
        await coordinator.ingestChain?.value
        await coordinator.waitForHistory()

        #expect(!coordinator.isFinalDrainPending)
        #expect(coordinator.historyCaptures.count == 1)
        #expect(coordinator.historyCaptures.first?.record.completeness == .incomplete)
        #expect(coordinator.captureError != nil)
    }

    @Test("A transition parked on the lost drain fails outgoing and retries after finalization")
    func failedTransitionStaysOutgoingAndRetriesAfterFinalization() async throws {
        let environment = ProjectIsolationEnvironment(name: "recovery-retry")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        // Only the reset may release this boundary; no bounded wait can.
        coordinator.projectTransitionDrainTimeout = .seconds(30)
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let projectB = try #require(await Self.created(coordinator, named: "Bravo"))
        #expect(await Self.switched(coordinator, to: projectA))

        let captureToken = coordinator.startGeneration
        coordinator.resetSessionEngineForSavedCapture(token: captureToken)
        await coordinator.ingestChain?.value
        coordinator.startGeneration &+= 1
        let stoppedToken = coordinator.startGeneration
        coordinator.beginFinalCaptureDrain(stoppedToken: stoppedToken, captureToken: captureToken)

        #expect(coordinator.switchToProject(id: projectB.id))
        await Task.yield()
        #expect(coordinator.projectTransitionStatus.isPending)

        coordinator.prepareForDestructiveHelperReset()
        // The parked transition is failed, never silently switched or completed.
        #expect(await !coordinator.waitForProjectTransition())
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.projectTransitionStatus.failureMessage != nil)
        #expect(coordinator.retryableProjectTransition != nil)

        await coordinator.ingestChain?.value
        #expect(!coordinator.isFinalDrainPending)

        // An explicit retry may proceed now that the prefix is finalized.
        coordinator.retryProjectTransition()
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.projectStore.activeProjectID == projectB.id)
    }

    @Test("A late completion from the reset capture cannot release a newer stop")
    func lateCompletionCannotReleaseANewerStop() async throws {
        let environment = ProjectIsolationEnvironment(name: "recovery-late-tail")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let captureToken = coordinator.startGeneration
        coordinator.resetSessionEngineForSavedCapture(token: captureToken)
        await coordinator.ingestChain?.value
        coordinator.startGeneration &+= 1
        let resetStoppedToken = coordinator.startGeneration
        coordinator.beginFinalCaptureDrain(stoppedToken: resetStoppedToken, captureToken: captureToken)
        let resetOperation = try #require(coordinator.pendingFinalDrainOperationID)

        coordinator.prepareForDestructiveHelperReset()
        await coordinator.ingestChain?.value
        #expect(!coordinator.isFinalDrainPending)

        // A later capture stops and owes its own, different boundary.
        coordinator.startGeneration &+= 1
        let newStoppedToken = coordinator.startGeneration
        coordinator.beginFinalCaptureDrain(stoppedToken: newStoppedToken, captureToken: resetStoppedToken)
        #expect(coordinator.pendingFinalDrainOperationID != resetOperation)

        // The deferred tail of the reset capture finally arrives. It belongs to a
        // retired operation, so it releases nothing.
        coordinator.completeFinalCaptureDrain(stoppedToken: resetStoppedToken)
        #expect(coordinator.isFinalDrainPending)
        #expect(coordinator.pendingFinalDrainOperationID != resetOperation)

        coordinator.completeFinalCaptureDrain(stoppedToken: newStoppedToken)
        #expect(!coordinator.isFinalDrainPending)
    }

    @Test("Idle helper maintenance stops, republishes and writes nothing")
    func idleHelperMaintenanceIsInert() async {
        let environment = ProjectIsolationEnvironment(name: "recovery-idle")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        coordinator.sessions = [Self.summary(host: "a.example")]
        let generation = coordinator.startGeneration
        #expect(!coordinator.isFinalDrainPending)

        coordinator.prepareForDestructiveHelperReset()
        await coordinator.ingestChain?.value
        await coordinator.waitForHistory()

        // No boundary was minted, so no parked engine snapshot was republished and
        // no terminal History was written for a capture that never stopped.
        #expect(coordinator.startGeneration == generation)
        #expect(coordinator.sessions.map(\.host) == ["a.example"])
        #expect(coordinator.stoppedCaptureReadyGeneration == nil)
        #expect(!coordinator.isFinalDrainPending)
        #expect(!coordinator.isCapturing)
        #expect(coordinator.captureError == nil)
        #expect(coordinator.historyAvailability == .idle)
        #expect(coordinator.historyCaptures.isEmpty)
    }

    // MARK: Private

    private static let epoch = Date(timeIntervalSince1970: 1_700_000_000)

    private static func switched(_ coordinator: MainContentCoordinator, to id: UUID) async -> Bool {
        guard coordinator.switchToProject(id: id) else {
            return false
        }
        return await coordinator.waitForProjectTransition()
    }

    private static func created(
        _ coordinator: MainContentCoordinator,
        named name: String
    )
        async -> Project?
    {
        guard let project = coordinator.createProject(named: name),
              await coordinator.waitForProjectTransition() else
        {
            return nil
        }
        return project
    }

    private static func summary(host: String) -> SessionSummary {
        SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_000),
            duration: 5,
            processName: "curl",
            host: host,
            sourceEndpoint: "10.0.0.1:5000",
            destinationEndpoint: "93.184.216.34:443",
            protocolStack: [.tcp, .tls],
            status: .ok,
            latencyMilliseconds: 12.5,
            bytesUp: 100,
            bytesDown: 200
        )
    }
}
