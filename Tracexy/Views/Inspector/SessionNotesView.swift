import SwiftUI

// MARK: - SessionNotesView

/// **Notes** in the Details dock: what the investigator wrote about this session
/// and about any finding on it. Notes belong to the capture they were written
/// about and to the active Project; they are saved as the investigator types and
/// travel only in an explicit session export.
struct SessionNotesView: View {
    // MARK: Internal

    let store: InvestigationNotesStore
    let session: SessionSummary
    let findings: [Finding]
    let unavailableReason: String?

    var body: some View {
        ContextInspectorTable(title: "Notes") {
            if let unavailableReason {
                ContextInspectorFullRow {
                    Text(unavailableReason)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                ContextInspectorFullRow {
                    NoteEditor(
                        store: store,
                        target: .session(session.id),
                        prompt: "Add a note about this session",
                        accessibilityName: "Note on this session"
                    )
                }
                ForEach(findingEditors, id: \.id) { finding in
                    Divider()
                    ContextInspectorFullRow {
                        VStack(alignment: .leading, spacing: 4) {
                            Label(finding.title, systemImage: finding.severity.systemImage)
                                .font(Theme.Typography.captionMedium)
                                .foregroundStyle(.secondary)
                            NoteEditor(
                                store: store,
                                target: .finding(id: finding.id, sessionID: session.id),
                                prompt: "Add a note about this finding",
                                accessibilityName: "Note on \(finding.title)"
                            )
                        }
                    }
                }
                if !findingsWithoutEditor.isEmpty {
                    Divider()
                    ContextInspectorFullRow {
                        Menu("Note a Finding") {
                            ForEach(findingsWithoutEditor, id: \.id) { finding in
                                Button(finding.title) {
                                    openedFindingIDs.insert(finding.id)
                                }
                            }
                        }
                        .controlSize(.small)
                        .fixedSize()
                        .help("Write a note about one of the findings on this session")
                    }
                }
                if case let .projectFull(limit) = store.lastRefusal {
                    ContextInspectorFullRow {
                        Label(
                            "This Project already holds \(limit.formatted()) notes. Clear one to add another.",
                            systemImage: "exclamationmark.triangle"
                        )
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .onChange(of: session.id) { _, _ in
            openedFindingIDs = []
        }
    }

    // MARK: Private

    @State private var openedFindingIDs: Set<UUID> = []

    /// Findings shown with an editor: those with a note, and those the user chose.
    private var findingEditors: [Finding] {
        findings.filter { finding in
            openedFindingIDs.contains(finding.id)
                || !store.text(for: .finding(id: finding.id, sessionID: session.id)).isEmpty
        }
    }

    private var findingsWithoutEditor: [Finding] {
        let shown = Set(findingEditors.map(\.id))
        return findings.filter { !shown.contains($0.id) }
    }
}

// MARK: - NoteEditor

/// One note's text. Typing edits a local draft; the draft is written to the store
/// a moment after typing stops, and immediately when the editor goes away, so a
/// long note is not re-encoded on every keystroke and nothing typed is lost.
private struct NoteEditor: View {
    // MARK: Internal

    let store: InvestigationNotesStore
    let target: InvestigationNoteTarget
    let prompt: String
    let accessibilityName: String

    var body: some View {
        ZStack(alignment: .topLeading) {
            TextEditor(text: $draft)
                .font(Theme.Typography.body)
                .scrollContentBackground(.hidden)
                .frame(minHeight: 44, maxHeight: 160)
                .accessibilityLabel(accessibilityName)
            if draft.isEmpty {
                Text(prompt)
                    .font(Theme.Typography.body)
                    .foregroundStyle(.tertiary)
                    .padding(.leading, 5)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }
        }
        .padding(4)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
        .onAppear {
            loadedScope = store.scope
            draft = store.text(for: target, in: loadedScope)
            loadedTarget = target
        }
        .onChange(of: target) { oldTarget, newTarget in
            commit(to: oldTarget)
            loadedScope = store.scope
            draft = store.text(for: newTarget, in: loadedScope)
            loadedTarget = newTarget
        }
        .task(id: draft) {
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled, loadedTarget == target else {
                return
            }
            commit(to: target)
        }
        .onDisappear {
            if loadedTarget == target {
                commit(to: target)
            }
        }
        .help("Saved in this Project with this capture as you type")
    }

    // MARK: Private

    @State private var draft = ""
    @State private var loadedTarget: InvestigationNoteTarget?
    /// The capture this editor was opened on. Writes go back there even if the
    /// workspace has moved to another capture by the time they land.
    @State private var loadedScope: InvestigationNoteScope?

    private func commit(to target: InvestigationNoteTarget) {
        guard let loadedScope else {
            return
        }
        store.setText(draft, for: target, in: loadedScope)
    }
}
