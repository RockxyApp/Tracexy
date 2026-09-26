import Foundation
import Testing
@testable import Tracexy

// MARK: - InvestigationNotesTests

/// Notes are the investigator's own words: kept per capture, bounded without ever
/// evicting one, written through to the Project suite, and carried from a live run
/// to the file it was saved as.
@MainActor
final class InvestigationNotesTests {
    // MARK: Internal

    @Test
    func writeReadReplaceAndClear() {
        let (store, _) = makeStore()
        store.scope = Self.captureA
        let target = InvestigationNoteTarget.session(Self.session)

        #expect(store.setText("Resolver timed out twice", for: target))
        #expect(store.text(for: target) == "Resolver timed out twice")
        #expect(store.hasNote(onSession: Self.session))

        #expect(store.setText("Resolver timed out three times", for: target))
        #expect(store.notes.count == 1)
        #expect(store.text(for: target) == "Resolver timed out three times")

        #expect(store.setText("   \n", for: target))
        #expect(store.notes.isEmpty)
        #expect(!store.hasNote(onSession: Self.session))
    }

    @Test
    func theSameSessionIdInAnotherCaptureHasItsOwnNote() {
        let (store, _) = makeStore()
        let target = InvestigationNoteTarget.session(Self.session)
        store.scope = Self.captureA
        store.setText("Seen in capture A", for: target)

        store.scope = Self.captureB
        #expect(store.text(for: target).isEmpty)
        #expect(store.annotatedSessionIDs.isEmpty)

        store.scope = Self.captureA
        #expect(store.text(for: target) == "Seen in capture A")
    }

    @Test
    func noCaptureMeansNoNote() {
        let (store, _) = makeStore()
        #expect(!store.setText("orphan", for: .session(Self.session)))
        #expect(store.lastRefusal == .noCaptureScope)
        #expect(store.notes.isEmpty)
    }

    @Test
    func anExplicitScopeWritesBackToTheCaptureTheEditorOpenedOn() {
        let (store, _) = makeStore()
        store.scope = Self.captureB
        store.setText("written while A was on screen", for: .session(Self.session), in: Self.captureA)
        #expect(store.text(for: .session(Self.session)).isEmpty)
        #expect(store.text(for: .session(Self.session), in: Self.captureA) == "written while A was on screen")
    }

    @Test
    func boundsCutLongTextAndRefuseANewNoteWithoutEvicting() {
        let (store, _) = makeStore()
        store.scope = Self.captureA
        let long = String(repeating: "x", count: InvestigationNotesStore.maximumCharacters + 10)
        store.setText(long, for: .session(Self.session))
        #expect(store.text(for: .session(Self.session)).count == InvestigationNotesStore.maximumCharacters)

        for _ in 1 ..< InvestigationNotesStore.maximumNotes {
            store.setText("n", for: .session(UUID()))
        }
        #expect(store.notes.count == InvestigationNotesStore.maximumNotes)
        let refused = UUID()
        #expect(!store.setText("one too many", for: .session(refused)))
        #expect(store.lastRefusal == .projectFull(limit: InvestigationNotesStore.maximumNotes))
        #expect(store.notes.count == InvestigationNotesStore.maximumNotes)
        #expect(store.text(for: .session(Self.session)).count == InvestigationNotesStore.maximumCharacters)
        // Editing an existing note is still allowed at the bound.
        #expect(store.setText("edited", for: .session(Self.session)))
    }

    @Test
    func notesPersistThroughTheProjectSuite() {
        let (store, defaults) = makeStore()
        store.scope = Self.captureA
        let finding = UUID()
        store.setText("Session note", for: .session(Self.session))
        store.setText("Finding note", for: .finding(id: finding, sessionID: Self.session))

        let reloaded = InvestigationNotesStore()
        reloaded.bind(to: defaults)
        reloaded.scope = Self.captureA
        let notes = reloaded.notes(onSession: Self.session)
        #expect(notes.map(\.text) == ["Session note", "Finding note"])
        #expect(notes.first?.target == .session(Self.session))
        #expect(reloaded.text(for: .finding(id: finding, sessionID: Self.session)) == "Finding note")
    }

    @Test
    func aSavedLiveRunCarriesItsNotesAndKeepsTheFilesOwn() {
        let (store, defaults) = makeStore()
        let live = InvestigationNoteScope.liveRun()
        #expect(live.isLiveRun)
        store.scope = live
        store.setText("from the live run", for: .session(Self.session))
        store.setText("clashes", for: .session(Self.other))
        store.scope = Self.captureA
        store.setText("already on the file", for: .session(Self.other))

        store.move(from: live, to: Self.captureA)
        #expect(store.text(for: .session(Self.session)) == "from the live run")
        #expect(store.text(for: .session(Self.other)) == "already on the file")
        #expect(!store.notes.contains { $0.scope == live })

        let reloaded = InvestigationNotesStore()
        reloaded.bind(to: defaults)
        #expect(reloaded.notes.count == 2)
    }

    @Test
    func contentIdentitySurvivesACopyAndSeparatesDifferentFiles() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("notes-scope-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let original = directory.appendingPathComponent("a.pcap")
        let copy = directory.appendingPathComponent("renamed copy.pcap")
        let different = directory.appendingPathComponent("b.pcap")
        try Data([1, 2, 3, 4, 5]).write(to: original)
        try FileManager.default.copyItem(at: original, to: copy)
        try Data([1, 2, 3, 4, 6]).write(to: different)

        let scope = try InvestigationNoteScope.capture(at: original)
        #expect(try InvestigationNoteScope.capture(at: copy) == scope)
        #expect(try InvestigationNoteScope.capture(at: different) != scope)
        #expect(!scope.isLiveRun)
    }

    // MARK: Private

    private static let session = UUID()
    private static let other = UUID()
    private static let captureA = InvestigationNoteScope(rawValue: "capture:a:1")
    private static let captureB = InvestigationNoteScope(rawValue: "capture:b:1")

    /// The scratch domains this test made, removed when it ends.
    private var suites: [String] = []

    deinit {
        for suite in suites {
            TestPreferences.remove(suite)
        }
    }

    private func makeStore() -> (InvestigationNotesStore, UserDefaults) {
        let suite = "com.amunx.tracexy.tests.notes.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite) ?? .standard
        TestPreferences.remove(suite)
        suites.append(suite)
        let store = InvestigationNotesStore()
        store.bind(to: defaults)
        return (store, defaults)
    }
}
