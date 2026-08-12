import Foundation
import Testing
@testable import Tracexy

@Suite("Workspace presentation contract")
struct WorkspacePresentationContractTests {
    // MARK: Internal

    @Test("Toolbar update badge keeps the approved capsule geometry")
    func updateBadgeMetrics() {
        #expect(Theme.Metrics.toolbarControlHeight == 32)
        #expect(Theme.Metrics.updateBadgeHeight == 24)
        #expect(Theme.Metrics.updateBadgeHorizontalPadding == 9)
        #expect(Theme.Metrics.updateBadgeStrokeWidth == 0.75)
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
