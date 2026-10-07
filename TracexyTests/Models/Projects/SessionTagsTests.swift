import Foundation
import Testing
@testable import Tracexy

/// Color tags on sessions — per capture scope, persisted with the Project,
/// carried from a live run to its saved file, bounded, and usable as `tag == red`.
@MainActor
struct SessionTagsTests {
    @Test
    func tagsArePerScopePersistedAndCarried() throws {
        let suite = "session-tags-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let store = InvestigationNotesStore()
        store.bind(to: defaults)
        let session = UUID()
        let live = InvestigationNoteScope.liveRun()
        store.scope = live
        #expect(store.setTag(.red, on: [session], enabled: true))
        #expect(store.setTag(.blue, on: [session], enabled: true))
        #expect(store.tags(onSession: session) == [.red, .blue])
        #expect(store.currentTagNames[session] == ["red", "blue"])

        // Another capture's scope does not see them.
        store.scope = InvestigationNoteScope(rawValue: "capture:other:1")
        #expect(store.tags(onSession: session).isEmpty)

        // Saving the live run carries them to the file's scope.
        let saved = InvestigationNoteScope(rawValue: "capture:abc:10")
        store.move(from: live, to: saved)
        store.scope = saved
        #expect(store.tags(onSession: session) == [.red, .blue])

        // Persisted: a fresh store bound to the same suite reads them back.
        let reloaded = InvestigationNotesStore()
        reloaded.bind(to: defaults)
        reloaded.scope = saved
        #expect(reloaded.tags(onSession: session) == [.red, .blue])
        #expect(reloaded.setTag(.red, on: [session], enabled: false))
        #expect(reloaded.tags(onSession: session) == [.blue])
    }

    @Test
    func noScopeRefuses() {
        let store = InvestigationNotesStore()
        #expect(!store.setTag(.green, on: [UUID()], enabled: true))
        #expect(store.lastRefusal == .noCaptureScope)
    }

    @Test
    func tagExpression() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("tag == Red") == .leaf(.tagEquals("red")))
        #expect(try parser.parse("tag in {red, blue}") == .any([.leaf(.tagEquals("red")), .leaf(.tagEquals("blue"))]))
        #expect(throws: SessionQueryParseError.self) { try parser.parse("tag == magenta") }

        let tagged = SessionSummary(
            id: UUID(), startTime: nil, duration: nil, processName: nil, host: "a", sourceEndpoint: "—",
            destinationEndpoint: "—", protocolStack: [.tcp], status: .ok, latencyMilliseconds: nil,
            bytesUp: 1, bytesDown: 1
        )
        var other = tagged
        other = SessionSummary(
            id: UUID(), startTime: nil, duration: nil, processName: nil, host: "b", sourceEndpoint: "—",
            destinationEndpoint: "—", protocolStack: [.tcp], status: .ok, latencyMilliseconds: nil,
            bytesUp: 1, bytesDown: 1
        )
        let snapshot = InvestigationSnapshot(
            fold: SessionFoldSnapshot(
                sessions: [tagged, other], connections: .empty, datagramEvidence: .empty, tlsEvidence: .empty,
                segmentSeries: .empty
            )
        )
        let engine = InvestigationQueryEngine()
        let compiled = try engine.compile(parser.parse("tag == red"))
        let result = try InvestigationQueryEngine.$sessionTags.withValue([tagged.id: ["red"]]) {
            try engine.evaluate(compiled, over: snapshot)
        }
        #expect(result.matched.map(\.host) == ["a"])
        #expect(result.indeterminate.isEmpty)
    }
}
