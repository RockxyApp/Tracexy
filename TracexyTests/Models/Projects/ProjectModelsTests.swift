import Foundation
import Testing
@testable import Tracexy

@Suite("Project catalog domain")
struct ProjectModelsTests {
    // MARK: Internal

    @Test("Names normalize canonically and fold accents, width and case for uniqueness")
    func unicodeNormalizationAndUniqueness() throws {
        #expect(try ProjectNameNormalization.normalize("  Cafe\u{301}  ") == "Café")

        let first = Self.project(name: "Résumé")
        let second = Self.project(name: "ＲＥＳＵＭＥ")
        let catalog = ProjectCatalog(projects: [first, second], activeProjectID: first.id)
        #expect(throws: ProjectCatalogValidationError.self) {
            _ = try catalog.normalizedValidated()
        }
    }

    @Test("Unsafe Unicode format controls are rejected while join controls remain valid")
    func unsafeUnicodeIsRejected() throws {
        #expect(throws: ProjectNameNormalizationError.containsControlCharacter) {
            _ = try ProjectNameNormalization.normalize("Visible\u{202E}hidden")
        }
        #expect(try ProjectNameNormalization.normalize("می\u{200C}روم") == "می\u{200C}روم")
    }

    @Test("Workspace configuration round-trips without selection or investigation state")
    @MainActor
    func workspaceRoundTripExcludesEphemeralState() {
        let workspace = WorkspaceState(title: "DNS Review")
        workspace.navigatorMode = .focus
        workspace.sidebarSelection = .dns
        workspace.inspectorLayout = .bottom
        workspace.contextDockTab = .aiAssistant
        workspace.sessionGrouping = .host
        workspace.filterText = "example.test"
        workspace.categoryFilters = [.dns, .errors]
        workspace.filterRules = [
            SessionFilterRule(field: .host, filterOperator: .contains, value: "example"),
        ]
        workspace.selectedSessionID = UUID()
        workspace.acceptedInvestigationDraft = InvestigationQueryDraft()

        let snapshot = ProjectWorkspaceSnapshot(capturing: workspace)
        let restored = snapshot.hydrateWorkspaceState(
            maxFilterRules: 64,
            allowsAutomaticInspectorReveal: false
        )

        #expect(restored.id == workspace.id)
        #expect(restored.navigatorMode == .focus)
        #expect(restored.sidebarSelection == .dns)
        #expect(restored.inspectorLayout == .bottom)
        #expect(restored.contextDockTab == .aiAssistant)
        #expect(restored.sessionGrouping == .host)
        #expect(restored.categoryFilters == [.dns, .errors])
        #expect(restored.selectedSessionID == nil)
        #expect(restored.acceptedInvestigationDraft == nil)
    }

    @Test("Unknown raw discriminators hydrate with conservative UI fallbacks")
    @MainActor
    func unknownRawValuesFallBackSafely() {
        let snapshot = ProjectWorkspaceSnapshot(
            title: "Imported",
            sidebarSelection: "future-view",
            navigatorMode: "future-mode",
            inspectorTab: "future-tab",
            inspectorLayout: "future-layout",
            contextDockTab: "future-dock",
            sessionGrouping: "future-grouping",
            searchField: "future-field",
            categoryFilters: ["dns", "future-category"],
            filterRules: [
                ProjectFilterRuleSnapshot(
                    connector: "future-connector",
                    field: "future-rule-field",
                    filterOperator: "future-operator",
                    value: "kept"
                ),
            ]
        )
        let workspace = snapshot.hydrateWorkspaceState(
            maxFilterRules: 64,
            allowsAutomaticInspectorReveal: nil
        )
        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.navigatorMode == .browse)
        #expect(workspace.inspectorTab == .timeline)
        #expect(workspace.inspectorLayout == .hidden)
        #expect(workspace.contextDockTab == .details)
        #expect(workspace.sessionGrouping == .none)
        #expect(workspace.searchField == .allFields)
        #expect(workspace.categoryFilters == [.dns])
        #expect(workspace.filterRules[0].connector == .and)
        #expect(workspace.filterRules[0].field == .host)
        #expect(workspace.filterRules[0].filterOperator == .contains)
    }

    // MARK: Private

    private static func project(name: String) -> Project {
        let workspace = ProjectWorkspaceSnapshot(title: "Live", isClosable: false)
        return Project(name: name, workspaces: [workspace], activeWorkspaceID: workspace.id)
    }
}
