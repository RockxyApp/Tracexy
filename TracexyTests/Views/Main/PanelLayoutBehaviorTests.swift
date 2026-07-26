import Foundation
import Testing
@testable import Tracexy

@MainActor
struct PanelLayoutBehaviorTests {
    // MARK: Internal

    @Test("There is no right dock — the right column is a separate object")
    func inspectorLayoutHasNoRightCase() {
        #expect(InspectorLayout.allCases.count == 2)
        #expect(InspectorLayout.allCases.contains(.hidden))
        #expect(InspectorLayout.allCases.contains(.bottom))
        #expect(InspectorLayout(rawValue: "right") == nil)
    }

    @Test("The right inspector has exactly two modes: Details and AI Assistant")
    func contextDockHasTwoModes() {
        #expect(ContextDockTab.allCases == [.details, .aiAssistant])
        #expect(ContextDockTab.details.title == "Details")
        #expect(ContextDockTab.aiAssistant.title == "AI Assistant")
        // The prior Insight/Related/Security cases are gone.
        #expect(ContextDockTab(rawValue: "insight") == nil)
        #expect(ContextDockTab(rawValue: "related") == nil)
    }

    @Test("A fresh workspace opens the right inspector on Details")
    func contextDockDefaultsToDetails() {
        let workspace = WorkspaceState(title: "Test")
        #expect(workspace.contextDockTab == .details)
    }

    @Test("A fresh workspace opens with both panels closed")
    func defaultsAreClosed() {
        let env = makeEnvironment()
        defer { env.teardown() }
        let coordinator = MainContentCoordinator(layoutPreferences: env.preferences)

        #expect(coordinator.inspectorLayout == .hidden)
        #expect(!coordinator.isContextDockVisible)
    }

    @Test("Selecting a session reveals the evidence inspector but never the dock")
    func firstSelectionRevealsEvidenceOnly() {
        let env = makeEnvironment()
        defer { env.teardown() }
        let coordinator = MainContentCoordinator(layoutPreferences: env.preferences)

        coordinator.select(Self.makeSession())

        #expect(coordinator.inspectorLayout == .bottom)
        #expect(!coordinator.isContextDockVisible)
    }

    @Test("Hiding the inspector by hand stops it reopening, and persists")
    func manualHideWins() {
        let env = makeEnvironment()
        defer { env.teardown() }
        let coordinator = MainContentCoordinator(layoutPreferences: env.preferences)
        let session = Self.makeSession()

        coordinator.select(session)
        #expect(coordinator.inspectorLayout == .bottom)

        coordinator.toggleInspectorBottom()
        #expect(coordinator.inspectorLayout == .hidden)

        // A later selection must not undo the user's decision.
        coordinator.select(Self.makeSession())
        #expect(coordinator.inspectorLayout == .hidden)

        // …and the decision survives a relaunch.
        let relaunched = MainContentCoordinator(layoutPreferences: env.preferences)
        relaunched.select(Self.makeSession())
        #expect(relaunched.inspectorLayout == .hidden)
    }

    @Test("The two panels toggle independently — neither closes the other")
    func panelsAreIndependent() {
        let env = makeEnvironment()
        defer { env.teardown() }
        let coordinator = MainContentCoordinator(layoutPreferences: env.preferences)

        coordinator.toggleContextDock()
        #expect(coordinator.isContextDockVisible)
        #expect(coordinator.inspectorLayout == .hidden)

        coordinator.toggleInspectorBottom()
        #expect(coordinator.isContextDockVisible)
        #expect(coordinator.inspectorLayout == .bottom)

        coordinator.toggleContextDock()
        #expect(!coordinator.isContextDockVisible)
        #expect(coordinator.inspectorLayout == .bottom)
    }

    @Test("Both panels are closed at launch even when they were left open")
    func launchAlwaysStartsClosed() {
        let env = makeEnvironment()
        defer { env.teardown() }
        let coordinator = MainContentCoordinator(layoutPreferences: env.preferences)

        coordinator.toggleContextDock()
        coordinator.toggleInspectorBottom()
        #expect(coordinator.isContextDockVisible)
        #expect(coordinator.inspectorLayout == .bottom)

        // The app must open on the traffic, not on two panes describing a
        // selection that does not exist yet.
        let relaunched = MainContentCoordinator(layoutPreferences: env.preferences)
        #expect(!relaunched.isContextDockVisible)
        #expect(relaunched.inspectorLayout == .hidden)
    }

    @Test("A remembered layout is deferred to the first selection, not discarded")
    func rememberedLayoutReturnsOnSelection() {
        let env = makeEnvironment()
        defer { env.teardown() }
        let coordinator = MainContentCoordinator(layoutPreferences: env.preferences)

        coordinator.toggleContextDock()
        coordinator.toggleInspectorBottom()

        let relaunched = MainContentCoordinator(layoutPreferences: env.preferences)
        #expect(!relaunched.isContextDockVisible)

        // Starting closed must not cost the user their layout — the moment
        // there is something to describe, both come back.
        relaunched.select(Self.makeSession())
        #expect(relaunched.isContextDockVisible)
        #expect(relaunched.inspectorLayout == .bottom)
    }

    @Test("A dock the user never opened stays shut, even once a session is selected")
    func dockIsNeverRevealedUnasked() {
        let env = makeEnvironment()
        defer { env.teardown() }
        let coordinator = MainContentCoordinator(layoutPreferences: env.preferences)

        coordinator.select(Self.makeSession())

        // The dock earns its width only by being asked for.
        #expect(!coordinator.isContextDockVisible)
    }

    @Test("Re-opening the inspector by hand restores automatic reveal")
    func manualReopenCancelsDismissal() {
        let env = makeEnvironment()
        defer { env.teardown() }
        let coordinator = MainContentCoordinator(layoutPreferences: env.preferences)

        coordinator.select(Self.makeSession())
        coordinator.toggleInspectorBottom() // hide — stops auto-reveal
        coordinator.toggleInspectorBottom() // show again — asks for it back

        // Without this, "closed at launch" and "dismissed for good" combine into
        // a trap: the user would have to re-open the inspector every launch.
        let relaunched = MainContentCoordinator(layoutPreferences: env.preferences)
        #expect(relaunched.inspectorLayout == .hidden)
        relaunched.select(Self.makeSession())
        #expect(relaunched.inspectorLayout == .bottom)
    }

    // MARK: Private

    private struct Environment {
        let preferences: WorkspaceLayoutPreferences
        let teardown: () -> Void
    }

    private static func makeSession(host: String = "api.example.com") -> SessionSummary {
        SessionSummary(
            id: UUID(),
            startTime: Date(),
            duration: 0.14,
            processName: "MyApp",
            host: host,
            sourceEndpoint: "192.168.1.42:52344",
            destinationEndpoint: "93.184.16.34:443",
            protocolStack: [.tcp, .tls],
            status: .ok,
            latencyMilliseconds: 142,
            bytesUp: 2_048,
            bytesDown: 36_864
        )
    }

    /// An isolated defaults suite so tests never touch the user's real settings.
    private func makeEnvironment(function: String = #function) -> Environment {
        let suiteName = "com.amunx.tracexy.tests.\(function).\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            fatalError("could not create a scratch defaults suite")
        }
        return Environment(
            preferences: WorkspaceLayoutPreferences(defaults: defaults),
            teardown: { defaults.removePersistentDomain(forName: suiteName) }
        )
    }
}
