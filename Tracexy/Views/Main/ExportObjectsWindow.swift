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

    @State private var selection: CaptureObject.ID?
    @State private var notice: String?

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
        return HStack(spacing: Theme.Metrics.spacingM) {
            if let notice {
                Text(notice).lineLimit(1)
            } else if let list = state.list {
                Text(summary(list, shown: objects.count)).lineLimit(1)
            }
            Spacer()
            Button("Save…") {
                if let selected {
                    save(selected)
                }
            }
            .accessibilityIdentifier("exportObjects.saveSelected")
            .disabled(selected == nil)
            Button("Save All…") { saveAll(objects) }
                .disabled(objects.isEmpty)
                .accessibilityIdentifier("exportObjects.saveAll")
            Button("Rescan") { coordinator.loadExportObjects(state.kind, force: true) }
                .disabled(state.isLoading)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
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
        if list.omittedObjectCount > 0 {
            text += String(localized: "; \(list.omittedObjectCount.formatted()) objects past the size limit")
        }
        return text
    }

    private func reveal(_ object: CaptureObject) {
        notice = coordinator.revealExportedObject(object)
            ? nil
            : String(localized: "This object's session is not in view in the main window.")
    }

    private func inspect(_ object: CaptureObject, provenance: SessionFrameProvenance) {
        guard coordinator.revealExportedObject(object) else {
            notice = String(localized: "This object's session is not in view in the main window.")
            return
        }
        coordinator.inspectCitedFrame(sessionID: object.sessionID, provenance: provenance)
        notice = nil
    }

    private func save(_ object: CaptureObject) {
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
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = String(localized: "Save Here")
        panel.message = String(localized: "Choose a folder for the \(objects.count.formatted()) objects.")
        guard panel.runModal() == .OK, let folder = panel.url else {
            return
        }
        var taken = Set((try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? [])
        do {
            for object in objects {
                let name = CaptureObjectScanner.uniqueName(
                    CaptureObjectScanner.savableName(object.fileName), taken: taken
                )
                taken.insert(name)
                try Data(object.body).write(to: folder.appendingPathComponent(name), options: .withoutOverwriting)
            }
            notice = String(localized: "Saved \(objects.count.formatted()) objects.")
        } catch {
            notice = String(localized: "Couldn’t save: \(error.localizedDescription)")
        }
    }
}
