import Foundation
import Testing
@testable import Tracexy

@Suite("Workspace presentation contract")
struct WorkspacePresentationContractTests {
    // MARK: Internal

    @Test("Monitor navigation is exactly Overview, Sessions, Flow Map, in that order")
    func monitorOrder() {
        #expect(SidebarSection.monitor.items == [.overview, .sessions, .flow])
    }

    @Test("Toolbar update badge keeps the approved capsule geometry")
    func updateBadgeMetrics() {
        #expect(Theme.Metrics.toolbarControlHeight == 32)
        #expect(Theme.Metrics.updateBadgeHeight == 24)
        #expect(Theme.Metrics.updateBadgeHorizontalPadding == 9)
        #expect(Theme.Metrics.updateBadgeStrokeWidth == 0.75)
    }

    @Test("Overview stays inside the workspace when the native sidebar is open")
    func overviewUsesTheWorkspaceViewport() throws {
        let source = try readProjectFile("Tracexy/Views/Overview/OverviewView.swift")

        #expect(source.contains("GeometryReader { proxy in"))
        #expect(source.contains("proxy.size.width >= Self.wideDashboardMinimumWidth"))
        #expect(source.contains("proxy.size.width - Theme.Metrics.spacingL * 2"))
    }

    @Test("Overview summarizes findings and leaves evidence to Sessions")
    func overviewDoesNotDuplicateTheFindingList() throws {
        let source = try readProjectFile("Tracexy/Views/Overview/OverviewView.swift")

        #expect(source.contains("findingSummaryBar"))
        #expect(source.contains("Review \\(all.count.formatted()) in Sessions"))
        #expect(!source.contains("findingPreviewLimit"))
        #expect(!source.contains("findingRow("))
        #expect(!source.contains("Open evidence"))
    }

    @Test("Details uses stacked inspector tables instead of List sections")
    func detailsUsesInspectorTables() throws {
        let details = try readProjectFile("Tracexy/Views/Inspector/ContextDockView.swift")
        let table = try readProjectFile("Tracexy/Views/Inspector/ContextInspectorTable.swift")

        #expect(details.contains("ScrollView {"))
        #expect(details.contains("ContextInspectorTable(title: \"Assessment\")"))
        #expect(details.contains("ContextInspectorFieldTable("))
        #expect(!details.contains("List {"))
        #expect(!details.contains(".listStyle"))

        #expect(table.contains("Color(nsColor: .controlBackgroundColor)"))
        #expect(table.contains("Color(nsColor: .textBackgroundColor)"))
        #expect(table.contains("lineWidth: 0.5"))
        #expect(table.contains("struct ContextInspectorFieldRow"))
        #expect(table.contains("struct ContextInspectorInsightRow"))
        #expect(table.contains("struct ContextInspectorFullRow"))
    }

    @Test("Session search keeps the Rockxy control rhythm with Tracexy field semantics")
    func sessionSearchUsesResponsiveNativeControls() throws {
        let source = try readProjectFile("Tracexy/Views/Sessions/SessionFilterBar.swift")

        #expect(source.contains("ViewThatFits(in: .horizontal)"))
        #expect(source.contains("pickerWidth: 130, showsAddFieldTitle: true"))
        #expect(source.contains("pickerWidth: 100, showsAddFieldTitle: false"))
        #expect(source.contains(".frame(minWidth: 220, maxWidth: .infinity)"))
        #expect(source.contains("Label(\"Add Field\", systemImage: \"plus\")"))
        #expect(source.contains(".accessibilityLabel(\"Search field\")"))
        #expect(source.contains(".accessibilityLabel(\"Add field\")"))
    }

    @Test("Security is a toolbar-only quick filter over the scalable session workflow")
    func securityUsesSessionQuickFilter() throws {
        let root = try readProjectFile("Tracexy/Views/Main/RootView.swift")
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")
        let sidebarItems = try readProjectFile("Tracexy/Models/UI/SidebarItem.swift")
        let filters = try readProjectFile("Tracexy/Views/Sessions/SessionFilterBar.swift")

        #expect(!root.contains("SecurityFindingsView(coordinator:"))
        #expect(!sidebar.contains("securityQuickFilterRow"))
        #expect(!sidebarItems.contains("case security"))
        #expect(!sidebarItems.contains(".security]"))
        #expect(filters.contains("systemImage: category == .security ? \"exclamationmark.shield\" : nil"))
    }

    @Test("AI Assistant uses a truthful conversation shell")
    func assistantUsesConversationShell() throws {
        let source = try readProjectFile("Tracexy/Views/Inspector/AIAssistantDockView.swift")

        #expect(source.contains("conversationHeader"))
        #expect(source.contains("attachedContextHeader"))
        #expect(source.contains("conversationTranscript"))
        #expect(source.contains("promptComposer"))
        #expect(source.contains("New Conversation"))
        #expect(source.contains("Select a session to add context"))
        #expect(source.contains("Ask Tracexy AI Assistant…"))
        #expect(source.contains("Label(\"Not connected\", systemImage: \"cpu\")"))
        #expect(source.contains("Label(\"Read-only\", systemImage: \"lock.shield\")"))
        #expect(!source.contains("sampleMessages"))
        #expect(!source.contains("streamingText"))
    }

    // MARK: Private

    private enum ResolveError: Error {
        case rootNotFound
    }

    private func readProjectFile(_ relativePath: String) throws -> String {
        let root = try resolveProjectRoot()
        return try String(contentsOf: root.appendingPathComponent(relativePath), encoding: .utf8)
    }

    private func resolveProjectRoot() throws -> URL {
        var url = URL(fileURLWithPath: #filePath)
        while url.lastPathComponent != "TracexyTests", url.path != "/" {
            url.deleteLastPathComponent()
        }
        guard url.lastPathComponent == "TracexyTests" else {
            throw ResolveError.rootNotFound
        }
        url.deleteLastPathComponent()
        return url
    }
}
