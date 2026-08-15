import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Session search command")
struct SessionSearchCommandTests {
    // MARK: Internal

    @Test("Find routes to Sessions and makes the existing search field usable")
    func revealsSessionSearch() throws {
        let environment = try makeCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        workspace.sidebarSelection = .overview
        workspace.isFilterBarVisible = false
        workspace.isSearchEnabled = false

        coordinator.beginSessionSearch()

        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.isFilterBarVisible)
        #expect(workspace.isSearchEnabled)
        #expect(workspace.searchFocusRequest != nil)
    }

    @Test("Every Find request receives a fresh focus identity")
    func repeatedRequestsRefocus() throws {
        let environment = try makeCoordinator()
        defer { environment.teardown() }
        let coordinator = environment.coordinator

        coordinator.beginSessionSearch()
        let firstRequest = coordinator.activeWorkspace.searchFocusRequest
        coordinator.beginSessionSearch()

        #expect(firstRequest != nil)
        #expect(coordinator.activeWorkspace.searchFocusRequest != firstRequest)
    }

    // MARK: Private

    private struct Environment {
        let coordinator: MainContentCoordinator
        let teardown: () -> Void
    }

    private func makeCoordinator(function: String = #function) throws -> Environment {
        let suiteName = "com.amunx.tracexy.tests.\(function).\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        let coordinator = MainContentCoordinator(
            layoutPreferences: WorkspaceLayoutPreferences(defaults: defaults)
        )
        return Environment(coordinator: coordinator) {
            defaults.removePersistentDomain(forName: suiteName)
        }
    }
}
