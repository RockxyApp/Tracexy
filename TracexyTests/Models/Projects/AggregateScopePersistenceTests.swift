import Foundation
import Testing
@testable import Tracexy

/// The aggregate narrowing a user left a workspace in is filter *intent*, so it
/// belongs in the Project catalog beside the host/client/IP scope — and it has to
/// arrive there without breaking a catalog or `.tracexyproject` written before
/// these fields existed. A missing key must cost a user no Projects.
@Suite("Aggregate scope persistence")
struct AggregateScopePersistenceTests {
    // MARK: Internal

    @Test("The aggregate scope round-trips, and nothing ephemeral rides along")
    @MainActor
    func aggregateScopeRoundTrips() {
        let workspace = WorkspaceState(title: "Flow Review")
        workspace.aggregateProtocolFilters = [.tls, .http2]
        workspace.aggregateRequiresFindings = true
        workspace.aggregateDestinationFilter = "93.184.16.34"
        workspace.hostFilter = "api.example.com"
        // Capture-local state that must never reach a transferable document.
        workspace.selectedSessionID = UUID()
        workspace.sessionScopeReturnStack = [
            SessionScopeReturnPoint(workspace: workspace, startGeneration: 3),
        ]

        let snapshot = ProjectWorkspaceSnapshot(capturing: workspace)
        // Written in a fixed order so two identical workspaces produce identical
        // documents.
        #expect(snapshot.aggregateProtocolFilters == ["http2", "tls"])
        #expect(snapshot.aggregateDestinationFilter == "93.184.16.34")

        let restored = snapshot.hydrateWorkspaceState(
            maxFilterRules: 64,
            allowsAutomaticInspectorReveal: false
        )
        #expect(restored.aggregateProtocolFilters == [.tls, .http2])
        #expect(restored.aggregateRequiresFindings)
        #expect(restored.aggregateDestinationFilter == "93.184.16.34")
        #expect(restored.hostFilter == "api.example.com")
        #expect(restored.selectedSessionID == nil)
        #expect(restored.sessionScopeReturnStack.isEmpty)
    }

    @Test("An unused aggregate scope writes no keys at all")
    @MainActor
    func anUnusedAggregateScopeIsAbsentFromTheDocument() throws {
        let workspace = WorkspaceState(title: "Live")
        let snapshot = ProjectWorkspaceSnapshot(capturing: workspace)
        #expect(snapshot.aggregateProtocolFilters == nil)
        #expect(snapshot.aggregateDestinationFilter == nil)

        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(snapshot))
        let json = try #require(object as? [String: Any])
        // A workspace that never drilled in produces exactly the document an
        // older build would have.
        #expect(json["aggregateProtocolFilters"] == nil)
        #expect(json["aggregateDestinationFilter"] == nil)
        #expect(json["aggregateRequiresFindings"] == nil)
    }

    @Test("A document written before these fields existed still decodes, with no new filter")
    @MainActor
    func documentsMissingTheKeysStillDecode() throws {
        let workspace = WorkspaceState(title: "Live")
        workspace.aggregateProtocolFilters = [.tls]
        workspace.aggregateDestinationFilter = "93.184.16.34"
        let encoded = try JSONEncoder().encode(ProjectWorkspaceSnapshot(capturing: workspace))
        let object = try JSONSerialization.jsonObject(with: encoded)
        var json = try #require(object as? [String: Any])
        json.removeValue(forKey: "aggregateProtocolFilters")
        json.removeValue(forKey: "aggregateDestinationFilter")

        let older = try JSONSerialization.data(withJSONObject: json)
        let decoded = try JSONDecoder().decode(ProjectWorkspaceSnapshot.self, from: older)

        #expect(decoded.aggregateProtocolFilters == nil)
        #expect(decoded.aggregateDestinationFilter == nil)
        let restored = decoded.hydrateWorkspaceState(
            maxFilterRules: 64,
            allowsAutomaticInspectorReveal: nil
        )
        #expect(restored.aggregateProtocolFilters.isEmpty)
        #expect(restored.aggregateDestinationFilter == nil)
        #expect(!restored.hasActiveFilters)
        #expect(!restored.aggregateRequiresFindings)
    }

    @Test("Unknown protocol names are dropped and an oversized set is clamped on hydration")
    @MainActor
    func hydrationIsConservativeAndBounded() {
        let snapshot = ProjectWorkspaceSnapshot(
            title: "Imported",
            aggregateProtocolFilters: ["tls", "future-protocol", "udp"]
        )
        let restored = snapshot.hydrateWorkspaceState(
            maxFilterRules: 64,
            allowsAutomaticInspectorReveal: nil
        )
        // A name this build cannot recognize contributes nothing rather than a
        // guessed filter.
        #expect(restored.aggregateProtocolFilters == [.tls, .udp])

        let oversized = ProjectWorkspaceSnapshot(
            title: "Oversized",
            aggregateProtocolFilters: Array(
                repeating: "tls",
                count: ProjectLimits.maximumAggregateProtocolFilters + 40
            )
        )
        let clamped = oversized.hydrateWorkspaceState(
            maxFilterRules: 64,
            allowsAutomaticInspectorReveal: nil
        )
        #expect(clamped.aggregateProtocolFilters == [.tls])
    }

    @Test("Validation bounds the array and both string fields")
    func validationRejectsOversizedAggregateScope() {
        let tooMany = Self.catalog(
            aggregateProtocolFilters: Array(
                repeating: "tls",
                count: ProjectLimits.maximumAggregateProtocolFilters + 1
            )
        )
        #expect(throws: ProjectCatalogValidationError.self) {
            _ = try tooMany.normalizedValidated()
        }

        let overlongName = Self.catalog(
            aggregateProtocolFilters: [String(repeating: "a", count: ProjectLimits.maximumStringLength + 1)]
        )
        #expect(throws: ProjectCatalogValidationError.stringTooLong(
            field: "aggregateProtocolFilters",
            limit: ProjectLimits.maximumStringLength
        )) {
            _ = try overlongName.normalizedValidated()
        }

        let overlongDestination = Self.catalog(
            aggregateDestinationFilter: String(repeating: "9", count: ProjectLimits.maximumStringLength + 1)
        )
        #expect(throws: ProjectCatalogValidationError.stringTooLong(
            field: "aggregateDestinationFilter",
            limit: ProjectLimits.maximumStringLength
        )) {
            _ = try overlongDestination.normalizedValidated()
        }

        // The bounded case still validates.
        let accepted = Self.catalog(
            aggregateProtocolFilters: ["tls", "http2"],
            aggregateDestinationFilter: "93.184.16.34"
        )
        #expect(throws: Never.self) {
            _ = try accepted.normalizedValidated()
        }
    }

    // MARK: Private

    private static func catalog(
        aggregateProtocolFilters: [String]? = nil,
        aggregateDestinationFilter: String? = nil
    )
        -> ProjectCatalog
    {
        let workspace = ProjectWorkspaceSnapshot(
            title: "Live",
            isClosable: false,
            aggregateProtocolFilters: aggregateProtocolFilters,
            aggregateDestinationFilter: aggregateDestinationFilter
        )
        let project = Project(
            name: "Aggregate",
            workspaces: [workspace],
            activeWorkspaceID: workspace.id
        )
        return ProjectCatalog(projects: [project], activeProjectID: project.id)
    }
}
