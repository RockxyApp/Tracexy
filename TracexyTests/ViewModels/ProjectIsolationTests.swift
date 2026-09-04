import Foundation
import Testing
@testable import Tracexy

// MARK: - ProjectIsolationTests

/// Behavior tests for complete Project isolation. Every coordinator here is built
/// on an isolated storage root and defaults namespace, so no assertion depends on
/// (or disturbs) a production path or the shared `UserDefaults` domain.
///
/// A Project change is durable-first and therefore asynchronous: starting one only
/// means it was accepted and validated. Every test awaits
/// ``MainContentCoordinator/waitForProjectTransition()`` before asserting on the
/// destination, because that is the moment the catalog was written and the runtime
/// published.
@MainActor
@Suite("Project isolation")
struct ProjectIsolationTests {
    // MARK: Internal

    // MARK: Sessions, evidence and the live spool

    @Test("Each Project keeps its own sessions across A → B → A")
    func sessionsAreProjectScoped() async throws {
        let environment = ProjectIsolationEnvironment(name: "sessions")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let sessionA = Self.summary(host: "a.example")
        coordinator.sessions = [sessionA]

        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        #expect(coordinator.sessions.isEmpty)
        let sessionB = Self.summary(host: "b.example")
        coordinator.sessions = [sessionB]

        #expect(await Self.switched(coordinator, to: projectA))
        #expect(coordinator.sessions.map(\.host) == ["a.example"])

        #expect(await Self.switched(coordinator, to: projectB.id))
        #expect(coordinator.sessions.map(\.host) == ["b.example"])
    }

    @Test("Selection and structured query drafts survive a round trip")
    func selectionAndQueryDraftsAreRestored() async throws {
        let environment = ProjectIsolationEnvironment(name: "selection")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let session = Self.summary(host: "selected.example")
        coordinator.sessions = [session]
        coordinator.workspaces.activeWorkspace.selectedSessionID = session.id
        coordinator.workspaces.activeWorkspace.filterText = "handshake"

        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        #expect(coordinator.workspaces.activeWorkspace.selectedSessionID == nil)
        #expect(coordinator.workspaces.activeWorkspace.filterText.isEmpty)

        #expect(await Self.switched(coordinator, to: projectA))
        // Runtime selection is preserved because the Project keeps its real
        // workspace instance; it is not rehydrated from the portable snapshot.
        #expect(coordinator.workspaces.activeWorkspace.selectedSessionID == session.id)
        #expect(coordinator.workspaces.activeWorkspace.filterText == "handshake")
        #expect(projectB.id != projectA)
    }

    /// The Project boundary is not a capture boundary. A parked Project keeps the
    /// *structured* Investigation state its workspaces own — the editable draft and
    /// the accepted query with its matched rows — because that is user work, not
    /// capture-local state that a new source invalidates.
    @Test("Structured Investigation drafts and accepted results survive a round trip")
    func investigationDraftsAndResultsSurviveAProjectRoundTrip() async throws {
        let environment = ProjectIsolationEnvironment(name: "investigation")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let matching = Self.summary(host: "auth.example")
        let other = Self.summary(host: "cdn.example")
        coordinator.sessions = [matching, other]
        coordinator.adoptInvestigation(InvestigationSnapshot(
            sessions: [matching, other],
            connections: .empty,
            datagramEvidence: .empty,
            tlsEvidence: .empty,
            connectionAnalysis: .empty,
            datagramAnalysis: .empty
        ))

        let workspaceA = coordinator.workspaces.activeWorkspace
        let draft = InvestigationQueryDraft(
            combination: .all,
            rows: [InvestigationQueryDraftRow(predicate: .hostContains("auth"))]
        )
        coordinator.applyInvestigationQuery(draft, in: workspaceA)
        await coordinator.waitForInvestigationQuery(in: workspaceA)
        #expect(workspaceA.acceptedInvestigationDraft == draft)
        #expect(workspaceA.investigationMatchedSessionIDs == [matching.id])

        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        // B starts genuinely empty; nothing of A's query leaked into it.
        #expect(coordinator.workspaces.activeWorkspace.acceptedInvestigationDraft == nil)
        #expect(coordinator.workspaces.activeWorkspace.investigationMatchedSessionIDs.isEmpty)

        #expect(await Self.switched(coordinator, to: projectA))
        let restored = coordinator.workspaces.activeWorkspace
        #expect(restored.investigationDraft == draft)
        #expect(restored.acceptedInvestigationDraft == draft)
        #expect(restored.investigationMatchedSessionIDs == [matching.id])
        await coordinator.waitForInvestigationQuery(in: restored)
        #expect(!restored.isEvaluatingInvestigationQuery)
        #expect(projectB.id != projectA)
    }

    @Test("Clearing capture data in B leaves A's sessions and spool intact")
    func clearingBLeavesAIntact() async throws {
        let environment = ProjectIsolationEnvironment(name: "clear")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        coordinator.sessions = [Self.summary(host: "a.example")]
        let spoolA = coordinator.liveCaptureSpool
        try await spoolA.reset(epoch: 1)
        _ = try await spoolA.append(
            [Self.frame(payload: 0xA1)],
            defaultLinkType: LinkType.ethernet,
            epoch: 1
        )

        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        #expect(coordinator.liveCaptureSpool !== spoolA)
        coordinator.sessions = [Self.summary(host: "b.example")]
        // A start/reset boundary in B must not touch A's evidence.
        coordinator.clearSessions()
        await coordinator.ingestChain?.value

        #expect(await Self.switched(coordinator, to: projectA))
        #expect(coordinator.sessions.map(\.host) == ["a.example"])
        let recovered = try await coordinator.liveCaptureSpool.capture()
        #expect(recovered.frames.count == 1)
        #expect(recovered.frames.first?.bytes.first == 0xA1)
        #expect(projectB.id != projectA)
    }

    // MARK: Settings

    @Test("Capture, privacy and retention settings are per Project")
    func settingsArePerProject() async throws {
        let environment = ProjectIsolationEnvironment(name: "settings")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let defaultsA = coordinator.activeProjectDefaults
        defaultsA.set(CaptureFilterMode.custom.rawValue, forKey: SettingsKeys.captureFilterMode)
        defaultsA.set("tcp port 443", forKey: SettingsKeys.bpfExpression)
        defaultsA.set(50_000, forKey: SettingsKeys.retainPackets)
        defaultsA.set(true, forKey: SettingsKeys.maskIPs)
        defaultsA.set(AutoClear.hour1.rawValue, forKey: SettingsKeys.autoClear)
        coordinator.configureHistoryAutoClear(.hour1)
        await coordinator.waitForHistory()

        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        let defaultsB = coordinator.activeProjectDefaults
        #expect(defaultsB !== defaultsA)
        // A brand-new Project starts from safe defaults, and never falls through
        // to another Project's — or the shared domain's — values.
        #expect(coordinator.readinessCaptureConfiguration.bpf == nil)
        #expect(coordinator.readinessRetentionCapacity == CaptureSettingsResolver.defaultRetainPackets)
        #expect(!PrivacySettingsResolver.exportPolicy(defaults: defaultsB).maskIPAddresses)
        #expect(HistoryRetentionSettingsResolver.autoClear(defaults: defaultsB) == .never)
        #expect(coordinator.historyAutoClear == .never)
        // While stopped, readiness describes the *active* Project's current
        // defaults. No configuration retained from a capture that ran in another
        // Project may keep describing a source here.
        #expect(!coordinator.isCapturing)
        let expectedConfiguration = CaptureSettingsResolver.configuration(
            interface: coordinator.captureInterface,
            defaults: defaultsB
        )
        let actualConfiguration = coordinator.readinessCaptureConfiguration
        #expect(actualConfiguration.interface == expectedConfiguration.interface)
        #expect(actualConfiguration.snapLength == expectedConfiguration.snapLength)
        #expect(actualConfiguration.promiscuous == expectedConfiguration.promiscuous)
        #expect(actualConfiguration.bpf == expectedConfiguration.bpf)

        #expect(await Self.switched(coordinator, to: projectA))
        #expect(coordinator.readinessCaptureConfiguration.bpf == "tcp port 443")
        #expect(coordinator.readinessRetentionCapacity == 50_000)
        #expect(PrivacySettingsResolver.exportPolicy(defaults: coordinator.activeProjectDefaults).maskIPAddresses)
        #expect(coordinator.historyAutoClear == .hour1)
        #expect(projectB.id != projectA)
    }

    @Test("Pins, Focus Sets, muted noise and hidden sources are per Project")
    func libraryPreferencesArePerProject() async throws {
        let environment = ProjectIsolationEnvironment(name: "prefs")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        coordinator.togglePinHost("pinned.example")
        coordinator.saveFocusSet(FocusSet(name: "Auth", rules: [SessionFilterRule()]))
        coordinator.toggleMuteHost("noisy.example")
        coordinator.hideSourceApp("Finder")

        _ = try #require(await Self.created(coordinator, named: "Second"))
        #expect(coordinator.pinnedHosts.isEmpty)
        #expect(coordinator.focusSets.isEmpty)
        #expect(coordinator.mutedHosts.isEmpty)
        #expect(coordinator.hiddenSourceApps.isEmpty)

        #expect(await Self.switched(coordinator, to: projectA))
        #expect(coordinator.pinnedHosts == ["pinned.example"])
        #expect(coordinator.focusSets.map(\.name) == ["Auth"])
        #expect(coordinator.mutedHosts.contains("noisy.example"))
        #expect(coordinator.hiddenSourceApps.contains("Finder"))
    }

    // MARK: History and the saved-capture Library

    @Test("History writes, reads and Clear stay inside one Project")
    func historyIsPerProject() async throws {
        let environment = ProjectIsolationEnvironment(name: "history")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let storeA = try #require(coordinator.sessionStore)
        Self.writeTerminalCapture(into: coordinator, host: "a.example")
        await coordinator.waitForHistory()
        #expect(coordinator.historyCaptures.count == 1)

        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        let storeB = try #require(coordinator.sessionStore)
        #expect(storeB !== storeA)
        coordinator.refreshHistory()
        await coordinator.waitForHistory()
        #expect(coordinator.historyCaptures.isEmpty)

        Self.writeTerminalCapture(into: coordinator, host: "b.example")
        await coordinator.waitForHistory()
        #expect(coordinator.historyCaptures.count == 1)

        // Clearing B's History must not delete A's row.
        coordinator.clearAllHistory()
        await coordinator.waitForHistory()
        #expect(coordinator.historyCaptures.isEmpty)

        #expect(await Self.switched(coordinator, to: projectA))
        coordinator.refreshHistory()
        await coordinator.waitForHistory()
        #expect(coordinator.historyCaptures.count == 1)
        let retainedCaptureID = try #require(coordinator.historyCaptures.first?.id)
        let sessions = try await storeA.sessions(captureID: retainedCaptureID, after: nil, limit: 10)
        #expect(sessions.sessions.first?.host == "a.example")
        #expect(projectB.id != projectA)
    }

    @Test("Each Project has its own managed capture Library folder")
    func savedCaptureLibraryIsPerProject() async throws {
        let environment = ProjectIsolationEnvironment(name: "library")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let directoryA = try #require(coordinator.capturesDirectory())
        try Data([0]).write(to: directoryA.appendingPathComponent("Capture A.pcapng"))
        coordinator.refreshSavedCaptures()
        #expect(coordinator.savedCaptures.map(\.name) == ["Capture A"])

        _ = try #require(await Self.created(coordinator, named: "Second"))
        let directoryB = try #require(coordinator.capturesDirectory())
        #expect(directoryB != directoryA)
        #expect(coordinator.savedCaptures.isEmpty)

        #expect(await Self.switched(coordinator, to: projectA))
        #expect(coordinator.savedCaptures.map(\.name) == ["Capture A"])
    }

    /// Before hydration the runtime carries no Project identity, so it must not
    /// resolve — let alone create or scan — any capture Library. Doing so would
    /// touch the pre-Projects folder before its owner is durably bound.
    @Test("No capture Library is resolved or scanned before Projects hydrate")
    func libraryIsNotScannedBeforeHydration() async {
        let environment = ProjectIsolationEnvironment(name: "bootlibrary")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()

        #expect(coordinator.capturesDirectory() == nil)
        #expect(coordinator.savedCaptures.isEmpty)
        coordinator.refreshSavedCaptures()
        #expect(coordinator.savedCaptures.isEmpty)

        await coordinator.hydrateProjectsOnLaunch()
        #expect(coordinator.capturesDirectory() != nil)
    }

    // MARK: Legacy ownership

    @Test("A v1 catalog assigns one stable legacy owner that survives relaunch")
    func legacyOwnerIsAssignedOnceAndSurvivesRelaunch() async throws {
        let environment = ProjectIsolationEnvironment(name: "legacy", persistsCatalog: true)
        defer { environment.tearDown() }

        let first = environment.makeCoordinator()
        await first.hydrateProjectsOnLaunch()
        let owner = try #require(first.projectStore.legacyDataOwnerProjectID)
        #expect(owner == first.projectStore.activeProjectID)
        let legacyHistoryURL = try #require(first.activeRuntime.location?.historyDatabaseURL)
        #expect(!legacyHistoryURL.path.contains("Projects/"))

        // A second Project must not be given the pre-Projects locations.
        let second = try #require(await Self.created(first, named: "Second"))
        let scopedHistoryURL = try #require(first.activeRuntime.location?.historyDatabaseURL)
        #expect(scopedHistoryURL.path.contains(second.id.uuidString))
        await first.flushProjectStateForTermination()

        // "Relaunch": a fresh coordinator over the same on-disk catalog.
        let relaunched = environment.makeCoordinator()
        await relaunched.hydrateProjectsOnLaunch()
        #expect(relaunched.projectStore.legacyDataOwnerProjectID == owner)
        #expect(relaunched.projectStore.activeProjectID == second.id)

        // Deleting the owner must not hand the legacy data to anyone else.
        #expect(relaunched.deleteProject(id: owner))
        #expect(await relaunched.waitForProjectTransition())
        #expect(relaunched.projectStore.legacyDataOwnerProjectID == owner)
        #expect(!relaunched.projectStore.projects.contains { $0.id == owner })
    }

    @Test("A Project whose settings store fails keeps the outgoing Project active")
    func settingsFailureStaysFailClosed() async throws {
        let environment = ProjectIsolationEnvironment(name: "failclosed")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let owner = coordinator.projectStore.legacyDataOwnerProjectID
        let sessionA = Self.summary(host: "a.example")
        coordinator.sessions = [sessionA]

        // Refuse storage for any new Project: creation must not silently succeed.
        environment.provider.failsSettingsForNewProjects = true
        let candidate = try #require(coordinator.createProject(named: "Second"))
        let started = await coordinator.waitForProjectTransition()
        #expect(!started)

        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.activeRuntime.projectID == projectA)
        #expect(coordinator.sessions.map(\.host) == ["a.example"])
        #expect(coordinator.projectTransitionStatus.failureMessage != nil)
        // The unusable Project was never published, so there is nothing to roll
        // back out of the catalog.
        #expect(coordinator.projectStore.projects.count == 1)
        #expect(!coordinator.projectStore.projects.contains { $0.id == candidate.id })
        // A failed transition must never reassign the pre-Projects data.
        #expect(coordinator.projectStore.legacyDataOwnerProjectID == owner)
        // The catalog is unfrozen again, so the app is not wedged.
        #expect(coordinator.projectStore.isMutable)
    }

    /// The destination of an active-Project deletion is resolved *before* the
    /// deletion is published. A destination whose storage cannot be opened must
    /// therefore leave both Projects in the catalog — the old path deleted first
    /// and then had nothing left to fall back to.
    @Test("An active delete whose destination cannot be prepared deletes nothing")
    func activeDeleteWithUnpreparableDestinationDeletesNothing() async throws {
        let environment = ProjectIsolationEnvironment(name: "deletefail", persistsCatalog: true)
        defer { environment.tearDown() }

        let first = environment.makeCoordinator()
        await first.hydrateProjectsOnLaunch()
        let projectA = first.projectStore.activeProjectID
        let projectB = try #require(await Self.created(first, named: "Second"))
        await first.flushProjectStateForTermination()

        // Relaunch with B active, so A has no runtime bucket in this app session.
        let relaunched = environment.makeCoordinator()
        await relaunched.hydrateProjectsOnLaunch()
        #expect(relaunched.projectStore.activeProjectID == projectB.id)

        // A's storage is refused, so deleting B has nowhere safe to land.
        environment.provider.failingSettingsProjectIDs = [projectA]
        #expect(relaunched.deleteProject(id: projectB.id))
        let deleted = await relaunched.waitForProjectTransition()
        #expect(!deleted)

        #expect(relaunched.projectStore.activeProjectID == projectB.id)
        #expect(relaunched.projectStore.projects.count == 2)
        #expect(relaunched.projectStore.projects.contains { $0.id == projectB.id })
        #expect(relaunched.projectStore.projects.contains { $0.id == projectA })
        #expect(relaunched.projectTransitionStatus.failureMessage != nil)
        #expect(relaunched.retryableProjectTransition != nil)
        #expect(relaunched.projectStore.isMutable)
    }

    /// A catalog change is published only after it has been written. A refused
    /// write leaves the user on the Project they were on, with the catalog intact
    /// and the change retryable.
    @Test("A refused catalog write publishes nothing and stays retryable")
    func refusedCatalogWritePublishesNothing() async throws {
        let environment = ProjectIsolationEnvironment(name: "catalogsave")
        defer { environment.tearDown() }
        // Refuse exactly the two-Project candidate: the create transition's own
        // write, never the single-Project workspace flush ahead of it.
        let repository = ControllableProjectCatalogRepository(refusingSaveWithProjectCount: 2)
        environment.catalogRepository = repository
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        coordinator.sessions = [Self.summary(host: "a.example")]

        _ = try #require(coordinator.createProject(named: "Second"))
        let committed = await coordinator.waitForProjectTransition()
        #expect(!committed)
        let refusals = await repository.refusedSaveCount
        #expect(refusals == 1)
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.projectStore.projects.count == 1)
        #expect(coordinator.sessions.map(\.host) == ["a.example"])
        #expect(coordinator.projectTransitionStatus.failureMessage != nil)
        #expect(coordinator.retryableProjectTransition != nil)

        // Nothing diverged from disk, so the store stays mutable and the retry is
        // a real retry rather than a wedged catalog.
        #expect(coordinator.projectStore.isMutable)
        await repository.refuseSaveWithProjectCount(nil)
        coordinator.retryProjectTransition()
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.projectStore.projects.count == 2)
        #expect(coordinator.projectStore.activeProjectID != projectA)
        #expect(coordinator.sessions.isEmpty)

        #expect(await Self.switched(coordinator, to: projectA))
        #expect(coordinator.sessions.map(\.host) == ["a.example"])
    }

    // MARK: The one lifecycle path

    @Test("Switching while capturing asks first; Cancel leaves the Project untouched")
    func capturingSwitchRequiresConfirmation() async throws {
        let environment = ProjectIsolationEnvironment(name: "confirm")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        #expect(await Self.switched(coordinator, to: projectA))
        coordinator.sessions = [Self.summary(host: "a.example")]
        coordinator.isCapturing = true

        #expect(!coordinator.switchToProject(id: projectB.id))
        #expect(coordinator.pendingProjectSwitchConfirmation != nil)
        #expect(coordinator.projectStore.activeProjectID == projectA)

        coordinator.cancelPendingProjectSwitch()
        #expect(coordinator.pendingProjectSwitchConfirmation == nil)
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.isCapturing)
        #expect(coordinator.sessions.count == 1)
    }

    @Test("Confirming waits for an already-stopping capture before the Project changes")
    func confirmedSwitchDrainsFirst() async throws {
        let environment = ProjectIsolationEnvironment(name: "drain")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        #expect(await Self.switched(coordinator, to: projectA))
        coordinator.sessions = [Self.summary(host: "a.example")]
        coordinator.isCapturing = true

        #expect(!coordinator.switchToProject(id: projectB.id))
        // Model Stop reaching the backend while the confirmation was open. No
        // real helper or capture device is touched by this deterministic test.
        coordinator.isCapturing = false
        coordinator.startGeneration &+= 1
        coordinator.beginFinalCaptureDrain(stoppedToken: coordinator.startGeneration)
        coordinator.confirmPendingProjectSwitch()
        // The transition is parked on the capture's final drain: nothing has moved.
        #expect(coordinator.projectTransitionStatus.isPending)
        #expect(coordinator.projectStore.activeProjectID == projectA)
        await Task.yield()
        // Stand in for the helper's final batch folding and publishing.
        coordinator.completeFinalCaptureDrain(stoppedToken: coordinator.startGeneration)
        let finished = await coordinator.waitForProjectTransition()
        #expect(finished)

        #expect(!coordinator.isCapturing)
        #expect(!coordinator.isFinalDrainPending)
        #expect(coordinator.projectStore.activeProjectID == projectB.id)
        #expect(coordinator.sessions.isEmpty)

        #expect(await Self.switched(coordinator, to: projectA))
        #expect(coordinator.sessions.map(\.host) == ["a.example"])
    }

    /// A completion carrying a superseded stopped generation is not this stop's
    /// boundary, so it releases nothing. Releasing every parked waiter on any
    /// completion would let a transition swap the spool mid-drain.
    @Test("A stale final-drain completion does not release the parked transition")
    func staleFinalDrainCompletionReleasesNothing() async throws {
        let environment = ProjectIsolationEnvironment(name: "stale")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        // The boundary here is released by hand, never by the bounded wait.
        coordinator.projectTransitionDrainTimeout = .seconds(30)
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        #expect(await Self.switched(coordinator, to: projectA))
        coordinator.sessions = [Self.summary(host: "a.example")]

        // A stop that still owes an exact final batch, without touching the helper.
        let stoppedToken = coordinator.startGeneration &+ 1
        coordinator.beginFinalCaptureDrain(stoppedToken: stoppedToken)
        #expect(coordinator.isFinalDrainPending)

        #expect(coordinator.switchToProject(id: projectB.id))
        await Task.yield()
        #expect(coordinator.projectTransitionStatus.isPending)

        // A superseded capture's completion must not resume this boundary.
        coordinator.completeFinalCaptureDrain(stoppedToken: stoppedToken &- 1)
        await Task.yield()
        #expect(coordinator.isFinalDrainPending)
        #expect(coordinator.projectTransitionStatus.isPending)
        #expect(coordinator.projectStore.activeProjectID == projectA)

        // The exact boundary does.
        coordinator.completeFinalCaptureDrain(stoppedToken: stoppedToken)
        #expect(await coordinator.waitForProjectTransition())
        #expect(!coordinator.isFinalDrainPending)
        #expect(coordinator.projectStore.activeProjectID == projectB.id)
    }

    @Test("A drain that never completes stays on the outgoing Project and offers a retry")
    func drainTimeoutKeepsOutgoingProject() async throws {
        let environment = ProjectIsolationEnvironment(name: "timeout")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        #expect(await Self.switched(coordinator, to: projectA))
        coordinator.sessions = [Self.summary(host: "a.example")]
        // A stop that is already owed a final helper batch which never arrives.
        coordinator.beginFinalCaptureDrain(stoppedToken: coordinator.startGeneration)

        #expect(coordinator.switchToProject(id: projectB.id))
        let finished = await coordinator.waitForProjectTransition()
        #expect(!finished)
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.sessions.map(\.host) == ["a.example"])
        #expect(coordinator.projectTransitionStatus.failureMessage != nil)
        #expect(coordinator.retryableProjectTransition != nil)
        // The catalog is unfrozen, so the retry below is not blocked by the freeze.
        #expect(coordinator.projectStore.isMutable)
    }

    /// The timed-out transition stays on the outgoing Project, but the stop still
    /// owes the same boundary. A retry must park on *that* boundary rather than
    /// opening a second one that a stale completion could satisfy.
    @Test("Retrying a timed-out transition awaits the same drain boundary")
    func retryAwaitsTheSameDrainBoundary() async throws {
        let environment = ProjectIsolationEnvironment(name: "retrydrain")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        #expect(await Self.switched(coordinator, to: projectA))
        let stoppedToken = coordinator.startGeneration &+ 1
        coordinator.beginFinalCaptureDrain(stoppedToken: stoppedToken)

        #expect(coordinator.switchToProject(id: projectB.id))
        let timedOut = await coordinator.waitForProjectTransition()
        #expect(!timedOut)
        #expect(coordinator.isFinalDrainPending)

        // The retry parks on the *same* owed boundary, so it is released by hand.
        coordinator.projectTransitionDrainTimeout = .seconds(30)
        coordinator.retryProjectTransition()
        await Task.yield()
        #expect(coordinator.projectTransitionStatus.isPending)
        #expect(coordinator.projectStore.activeProjectID == projectA)

        coordinator.completeFinalCaptureDrain(stoppedToken: stoppedToken)
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.projectStore.activeProjectID == projectB.id)
        #expect(!coordinator.isFinalDrainPending)
    }

    @Test("Capture start is refused while a Project transition is pending")
    func captureStartIsBlockedDuringTransition() async {
        let environment = ProjectIsolationEnvironment(name: "startblock")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()

        // Before hydration the runtime is unbound, so intake is refused outright.
        #expect(coordinator.captureStartBlockedMessage != nil)
        coordinator.startCapture()
        #expect(!coordinator.isStarting)
        #expect(coordinator.captureError != nil)

        await coordinator.hydrateProjectsOnLaunch()
        #expect(coordinator.captureStartBlockedMessage == nil)

        // A stop that still owes a final batch defers the transition, and no
        // capture may begin inside that window.
        coordinator.beginFinalCaptureDrain(stoppedToken: coordinator.startGeneration)
        #expect(coordinator.createProject(named: "Second") != nil)
        #expect(coordinator.projectTransitionStatus.isPending)
        #expect(coordinator.captureStartBlockedMessage != nil)
        coordinator.startCapture()
        #expect(!coordinator.isStarting)
        _ = await coordinator.waitForProjectTransition()
    }

    @Test("Deleting the active Project uses the same boundary and preserves its data")
    func deletingActiveProjectUsesTheSameBoundary() async throws {
        let environment = ProjectIsolationEnvironment(name: "delete")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        coordinator.sessions = [Self.summary(host: "a.example")]
        let projectB = try #require(await Self.created(coordinator, named: "Second"))
        let directoryB = try #require(coordinator.capturesDirectory())
        try Data([0]).write(to: directoryB.appendingPathComponent("Capture B.pcapng"))

        #expect(coordinator.deleteProject(id: projectB.id))
        #expect(await coordinator.waitForProjectTransition())
        #expect(coordinator.projectStore.activeProjectID == projectA)
        #expect(coordinator.sessions.map(\.host) == ["a.example"])
        // The deleted Project's captures are preserved on disk, not removed.
        #expect(FileManager.default.fileExists(
            atPath: directoryB.appendingPathComponent("Capture B.pcapng").path
        ))
    }

    @Test("A History write started in A lands in A even when a switch follows immediately")
    func delayedHistoryWriteLandsInItsOwnProject() async throws {
        let environment = ProjectIsolationEnvironment(name: "delayedhistory")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let projectA = coordinator.projectStore.activeProjectID
        let storeA = try #require(coordinator.sessionStore)
        Self.writeTerminalCapture(into: coordinator, host: "a.example")
        // Change Projects without awaiting the write. The pending terminal write
        // defers the transition, so it must land against A's own database.
        _ = try #require(coordinator.createProject(named: "Second"))
        #expect(coordinator.projectTransitionStatus.isPending)
        let finished = await coordinator.waitForProjectTransition()
        #expect(finished)
        let storeB = try #require(coordinator.sessionStore)
        #expect(coordinator.projectStore.activeProjectID != projectA)

        let inA = try await storeA.captures(after: nil, limit: 10)
        let inB = try await storeB.captures(after: nil, limit: 10)
        #expect(inA.captures.count == 1)
        #expect(inB.captures.isEmpty)
    }

    // MARK: Private

    // MARK: Transition helpers

    /// Start a switch and await the durable completion the change now requires.
    private static func switched(_ coordinator: MainContentCoordinator, to id: UUID) async -> Bool {
        guard coordinator.switchToProject(id: id) else {
            return false
        }
        return await coordinator.waitForProjectTransition()
    }

    /// Start a creation and await its durable completion, returning the Project
    /// only when it actually became active.
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

    // MARK: Fixtures

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

    private static func frame(payload: UInt8) -> CapturedFrame {
        CapturedFrame(
            bytes: [payload] + [UInt8](repeating: 0, count: 63),
            timestamp: Date(timeIntervalSince1970: 1_000),
            originalLength: 64,
            linkType: LinkType.ethernet
        )
    }

    private static func writeTerminalCapture(into coordinator: MainContentCoordinator, host: String) {
        coordinator.frozenHistoryLifetime = FrozenHistoryLifetime(
            captureID: UUID(),
            startedAt: Date(timeIntervalSince1970: 1),
            endedAt: Date(timeIntervalSince1970: 2),
            stoppedGeneration: coordinator.startGeneration
        )
        coordinator.persistTerminalLiveHistory(
            sessions: [summary(host: host)],
            stoppedGeneration: coordinator.startGeneration,
            completeness: .complete
        )
    }
}
