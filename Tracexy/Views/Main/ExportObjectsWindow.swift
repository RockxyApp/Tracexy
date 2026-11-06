import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - ExportObjectsWindow

/// File ▸ Export Objects: the HTTP bodies, FTP/SMB files, email messages or certificates
/// in the capture, as Wireshark's Export Objects lists them, one kind at a time. Save
/// the selected object, or all of them into a folder; double-click to open its session.
struct ExportObjectsWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var state = coordinator.exportObjects
        let objects = state.visibleObjects
        Group {
            if state.isLoading {
                VStack(spacing: Theme.Metrics.spacingM) {
                    if let progress = state.progress, progress.total > 0 {
                        ProgressView(value: Double(progress.done), total: Double(progress.total))
                            .frame(width: 240)
                        Text("Reading streams (\(progress.done.formatted()) of \(progress.total.formatted()))")
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        ProgressView("Reading streams…").controlSize(.small)
                    }
                    Button("Cancel") { state.cancel(clearLists: false) }
                        .controlSize(.small)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error = state.error {
                ContentUnavailableView(
                    "Objects Unavailable", systemImage: "doc.on.doc", description: Text(error)
                )
            } else if state.unreadKinds.contains(state.kind) {
                ContentUnavailableView(
                    "Objects Not Read",
                    systemImage: "doc.on.doc",
                    description: Text("This read stopped before it finished. Rescan to list these objects.")
                )
            } else if objects.isEmpty {
                ContentUnavailableView(
                    "No Objects",
                    systemImage: "doc.on.doc",
                    description: Text(state.search.isEmpty ? emptyReason(state.kind) : String(
                        localized: "No object matches the search."
                    ))
                )
            } else {
                table(objects)
            }
        }
        .searchable(text: $state.search, placement: .toolbar, prompt: "File name, host or content type")
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .top) {
            HStack {
                Picker("Objects", selection: Binding(
                    get: { state.kind },
                    set: { coordinator.loadExportObjects($0) }
                )) {
                    ForEach(CaptureObjectKind.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .accessibilityIdentifier("exportObjects.kind")
                .help("Which kind of object to list, as Wireshark's Export Objects submenu")
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
            .padding(.vertical, Theme.Metrics.spacingS)
        }
        .tracexySafeAreaBar(edge: .bottom) {
            footer(objects, state: state)
        }
        .frame(minWidth: 700, minHeight: 360)
        .onAppear { coordinator.loadExportObjects(state.kind) }
    }

    // MARK: Private

    private struct SaveAllProgress: Equatable {
        let done: Int
        let total: Int
    }

    /// What the off-main-actor writer reports back while it saves.
    private enum SaveAllEvent: Sendable {
        case progress(done: Int)
        case finished(saved: Int, firstError: String?)
        case cancelled(saved: Int)
    }

    @State private var selection: CaptureObject.ID?
    @State private var notice: String?
    @State private var saveAllProgress: SaveAllProgress?
    @State private var saveAllTask: Task<Void, Never>?

    private func table(_ objects: [CaptureObject]) -> some View {
        Table(objects, selection: $selection) {
            TableColumn("Frame") { object in
                Text(object.frameOrdinal.map { $0.formatted() } ?? "—").monospacedDigit()
            }
            .width(min: 45, ideal: 60)
            TableColumn("Host") { object in
                Text(object.host).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 90, ideal: 130)
            TableColumn("Content Type") { object in
                Text(object.contentType).lineLimit(1).foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 110)
            TableColumn("Size") { object in
                Text(ByteUnits.string(Int64(object.body.count))).monospacedDigit()
            }
            .width(min: 55, ideal: 65)
            TableColumn("File Name") { object in
                Text(object.fileName).lineLimit(1).truncationMode(.middle)
                    .accessibilityIdentifier("exportObjects.fileName")
            }
            .width(min: 100, ideal: 180)
            TableColumn("Evidence") { object in
                if object.contributingFrames.isEmpty {
                    Text("—").foregroundStyle(.secondary)
                } else {
                    Menu("\(object.contributingFrames.count) frames") {
                        ForEach(object.contributingFrames, id: \.ordinal.rawValue) { provenance in
                            Button("Frame \(provenance.ordinal.rawValue.formatted())") {
                                inspect(object, provenance: provenance)
                            }
                            .accessibilityIdentifier("exportObjects.frame.\(provenance.ordinal.rawValue)")
                        }
                    }
                    .accessibilityIdentifier("exportObjects.evidence")
                    .help("Inspect a frame that contributed to this file")
                }
            }
            .width(min: 80, ideal: 100)
        }
        .contextMenu(forSelectionType: CaptureObject.ID.self) { ids in
            if let object = objects.first(where: { $0.id == ids.first }) {
                Button("Save…") { save(object) }
                Button("Show Session") { reveal(object) }
            }
        } primaryAction: { ids in
            if let object = objects.first(where: { $0.id == ids.first }) {
                reveal(object)
            }
        }
    }

    private func footer(_ objects: [CaptureObject], state: CaptureObjectListState) -> some View {
        let selected = objects.first { $0.id == selection }
        let saving = saveAllProgress
        return HStack(spacing: Theme.Metrics.spacingM) {
            if let saving {
                ProgressView(value: Double(saving.done), total: Double(max(1, saving.total)))
                    .frame(width: 120)
                Text("Saving \(saving.done.formatted()) of \(saving.total.formatted()) objects")
                    .lineLimit(1)
                    .accessibilityIdentifier("exportObjects.saveAllProgress")
            } else if let notice {
                Text(notice).lineLimit(1)
            } else if let list = state.list {
                Text(summary(list, shown: objects.count)).lineLimit(1)
            }
            Spacer()
            if saving != nil {
                Button("Cancel") { cancelSaveAll() }
                    .accessibilityIdentifier("exportObjects.saveAllCancel")
            }
            Button("Save…") {
                if let selected {
                    save(selected)
                }
            }
            .accessibilityIdentifier("exportObjects.saveSelected")
            .disabled(selected == nil || saving != nil)
            Button("Save All…") { saveAll(objects) }
                .disabled(objects.isEmpty || saving != nil)
                .accessibilityIdentifier("exportObjects.saveAll")
            Button("Rescan") { coordinator.loadExportObjects(state.kind, force: true) }
                .disabled(state.isLoading || saving != nil)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    /// The one workspace window, found the way the GeoIP sheet finds its host: by
    /// the managed workspace toolbar, then AppKit's own main window.
    private static func workspaceWindow() -> NSWindow? {
        let visible = NSApp.windows.filter { $0.isVisible && $0.sheetParent == nil && !($0 is NSPanel) }
        return visible.first { $0.toolbar?.identifier == NativeWorkspaceToolbar.toolbarIdentifier }
            ?? NSApp.mainWindow
            ?? visible.first { $0.canBecomeMain }
    }

    /// Selecting the session changes nothing the user can see while this window is
    /// in front, so the workspace window is brought forward with the selection.
    private static func activateWorkspaceWindow() {
        guard let window = workspaceWindow() else {
            return
        }
        NSApp.activate()
        window.makeKeyAndOrderFront(nil)
    }

    private static func saveAllNotice(saved: Int, total: Int, firstError: String?, cancelled: Bool) -> String {
        if cancelled {
            return String(
                localized: "Cancelled after saving \(saved.formatted()) of \(total.formatted()) objects."
            )
        }
        if let firstError {
            return String(
                localized: "Saved \(saved.formatted()) of \(total.formatted()) objects. Couldn’t save the rest: \(firstError)"
            )
        }
        return String(localized: "Saved \(saved.formatted()) objects.")
    }

    /// Writes every object body on a detached task. One object that can’t be
    /// written does not stop the others, and cancellation stops between objects.
    private static func writeObjects(
        _ objects: [CaptureObject], into folder: URL
    )
        -> AsyncStream<SaveAllEvent>
    {
        AsyncStream { continuation in
            let writer = Task.detached(priority: .userInitiated) {
                var taken = Set((try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [])
                var saved = 0
                var firstError: String?
                for (index, object) in objects.enumerated() {
                    if Task.isCancelled {
                        continuation.yield(.cancelled(saved: saved))
                        continuation.finish()
                        return
                    }
                    let name = CaptureObjectScanner.uniqueName(
                        CaptureObjectScanner.savableName(object.fileName), taken: taken
                    )
                    taken.insert(name)
                    do {
                        try Data(object.body)
                            .write(to: folder.appendingPathComponent(name), options: .withoutOverwriting)
                        saved += 1
                    } catch {
                        firstError = firstError ?? error.localizedDescription
                    }
                    // Progress is reported in small batches: one hop per object
                    // would cost more than the write for a long list of small ones.
                    if (index + 1).isMultiple(of: 8) || index + 1 == objects.count {
                        continuation.yield(.progress(done: index + 1))
                    }
                }
                continuation.yield(.finished(saved: saved, firstError: firstError))
                continuation.finish()
            }
            continuation.onTermination = { _ in writer.cancel() }
        }
    }

    private func emptyReason(_ kind: CaptureObjectKind) -> String {
        switch kind {
        case .ftpData:
            String(localized: "No FTP file transfer in this capture could be matched to its data connection.")
        case .http:
            String(localized: "No HTTP/1 response in this capture carried a body that was read to its end.")
        case .imf:
            String(localized: "No SMTP session in this capture sent a message that was read to its end.")
        case .smb:
            String(localized: "No complete SMB file with verified byte coverage and a final size was observed.")
        case .tftp:
            String(localized: "No TFTP transfer in this capture reached its last block with every block present.")
        case .x509:
            String(
                localized: "No TLS handshake in this capture sent a certificate in the clear. TLS 1.3 sends them encrypted."
            )
        }
    }

    private func summary(_ list: CaptureObjectList, shown: Int) -> String {
        var text = String(localized: "\(shown.formatted()) of \(list.objects.count.formatted()) objects")
        if list.skippedStreamCount > 0 {
            text += String(localized: "; \(list.skippedStreamCount.formatted()) more streams not read")
        }
        if list.ambiguousStreamCount > 0 {
            text +=
                String(localized: "; \(list.ambiguousStreamCount.formatted()) FTP streams lacked a proven packet order")
        }
        if list.omittedObjectCount > 0 {
            text += String(localized: "; \(list.omittedObjectCount.formatted()) objects past the size limit")
        }
        return text
    }

    private func reveal(_ object: CaptureObject) {
        guard coordinator.revealExportedObject(object) else {
            notice = String(localized: "This object's session is not in view in the main window.")
            return
        }
        notice = nil
        Self.activateWorkspaceWindow()
    }

    private func inspect(_ object: CaptureObject, provenance: SessionFrameProvenance) {
        guard coordinator.revealExportedObject(object) else {
            notice = String(localized: "This object's session is not in view in the main window.")
            return
        }
        coordinator.inspectCitedFrame(sessionID: object.sessionID, provenance: provenance)
        notice = nil
        Self.activateWorkspaceWindow()
    }

    private func save(_ object: CaptureObject) {
        guard coordinator.presentRawExportAcknowledgement(formatName: "Object body") else {
            return
        }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = CaptureObjectScanner.savableName(object.fileName)
        panel.canCreateDirectories = true
        panel.message = String(localized: "Saves the object exactly as it was sent; nothing is opened or run.")
        #if DEBUG
        if CommandLine.arguments.contains("--smb-export-objects-ui-test"),
           let directory = ProcessInfo.processInfo.environment["TRACEXY_SMB_UI_TEST_SAVE_DIRECTORY"]
        {
            panel.directoryURL = URL(fileURLWithPath: directory, isDirectory: true)
        }
        #endif
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        do {
            try Data(object.body).write(to: url, options: .atomic)
            notice = nil
        } catch {
            notice = String(localized: "Couldn’t save: \(error.localizedDescription)")
        }
    }

    private func saveAll(_ objects: [CaptureObject]) {
        guard coordinator.presentRawExportAcknowledgement(formatName: "Object body") else {
            return
        }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = String(localized: "Save Here")
        panel.message = String(localized: "Choose a folder for the \(objects.count.formatted()) objects.")
        guard panel.runModal() == .OK, let folder = panel.url else {
            return
        }
        startSaveAll(objects, into: folder)
    }

    /// Writing happens off the main actor, one object at a time, reporting progress
    /// back here; the synchronous loop this replaced froze the window for the whole
    /// save with no progress and no way out.
    private func startSaveAll(_ objects: [CaptureObject], into folder: URL) {
        let total = objects.count
        notice = nil
        saveAllProgress = SaveAllProgress(done: 0, total: total)
        saveAllTask = Task { @MainActor in
            var saved = 0
            var firstError: String?
            // Cancelling this task ends the stream without any further event, so
            // only an explicit `finished` counts as a complete save.
            var finished = false
            for await event in Self.writeObjects(objects, into: folder) {
                switch event {
                case let .progress(done):
                    saveAllProgress = SaveAllProgress(done: done, total: total)
                case let .finished(count, error):
                    saved = count
                    firstError = error
                    finished = true
                case let .cancelled(count):
                    saved = count
                }
            }
            saveAllProgress = nil
            saveAllTask = nil
            notice = Self.saveAllNotice(saved: saved, total: total, firstError: firstError, cancelled: !finished)
        }
    }

    private func cancelSaveAll() {
        saveAllTask?.cancel()
    }
}
