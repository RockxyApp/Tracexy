import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - PacketBytesWindow

/// Show Packet Bytes: one run of captured bytes — a frame, a selected field, or an
/// HTTP body — decoded (Base64, gzip, deflate, percent, quoted-printable, ROT-13,
/// hex digits) and shown as text, pretty JSON, a hex dump, a C array or an image,
/// with an optional byte range, as Wireshark's dialog of the same name.
struct PacketBytesWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        Group {
            if let subject = coordinator.packetBytesInspection.subject {
                content(subject)
            } else {
                ContentUnavailableView(
                    "No Bytes Chosen",
                    systemImage: "doc.text.magnifyingglass",
                    description: Text(
                        "Choose Show Bytes… in the Layers facet, or Show Body… on an HTTP exchange in the Stream facet."
                    )
                )
            }
        }
        .frame(minWidth: showsFrameDetails ? 720 : 560, minHeight: 360)
        .alert("Couldn’t Save Rendering", isPresented: Binding(
            get: { renderingSaveError != nil },
            set: {
                if !$0 {
                    renderingSaveError = nil
                }
            }
        )) {
            Button("OK") { renderingSaveError = nil }
        } message: {
            Text(renderingSaveError ?? "The rendering could not be saved.")
        }
        .onDisappear {
            renderingSaveRequest = UUID()
            isSavingRendering = false
        }
        .onChange(of: coordinator.packetBytesInspection.revision, initial: true) { _, _ in
            if let subject = coordinator.packetBytesInspection.subject {
                decoding = subject.suggestedDecoding
                presentation = subject.suggestedPresentation
                rangeStart = 0
                rangeEnd = subject.bytes.count
                selectedLayerRange = nil
                collapsedLayers = []
                fieldQuery = ""
                isLayerTreeFocused = false
                hiddenByteOwnerMessage = nil
                byteRevealToken &+= 1
            }
        }
    }

    // MARK: Private

    @State private var decoding: PacketBytesDecoding = .none
    @State private var presentation: PacketBytesPresentation = .text
    @State private var rangeStart = 0
    @State private var rangeEnd = 0
    @State private var selectedLayerRange: Range<Int>?
    @State private var collapsedLayers: Set<String> = []
    @State private var fieldQuery = ""
    @FocusState private var isLayerTreeFocused: Bool
    @State private var hiddenByteOwnerMessage: String?
    @State private var byteRevealToken = 0
    @State private var isSavingRendering = false
    @State private var renderingSaveError: String?
    @State private var renderingSaveRequest = UUID()

    private var showsFrameDetails: Bool {
        guard let subject = coordinator.packetBytesInspection.subject else {
            return false
        }
        return !subject.layers.isEmpty && presentation == .hexDump && decoding == .none
    }

    private var layerFilterControl: some View {
        HStack(spacing: 5) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary).font(.system(size: Theme.Icon.small))
            TextField("Filter Fields", text: $fieldQuery)
                .textFieldStyle(.plain)
                .font(Theme.Typography.caption)
                .accessibilityLabel("Filter decoded fields")
            if !fieldQuery.isEmpty {
                Button { fieldQuery = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .accessibilityLabel("Clear field filter")
                    .help("Clear the field filter")
            }
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .tracexyContentSurface(in: Capsule(style: .continuous))
        .padding(.horizontal, Theme.Metrics.spacingM)
    }

    private func content(_ subject: PacketBytesSubject) -> some View {
        let start = min(max(0, rangeStart), subject.bytes.count)
        let end = min(max(start, rangeEnd), subject.bytes.count)
        let input = Array(subject.bytes[start ..< end])
        let decoded = Result { () throws(PacketBytesDecoding.Failure) -> [UInt8] in try decoding.decode(input) }
        return VStack(spacing: 0) {
            controls(subject)
                .padding(Theme.Metrics.spacingL)
            Divider()
            switch decoded {
            case let .success(bytes):
                if !subject.layers.isEmpty, presentation == .hexDump, decoding == .none,
                   start == 0, end == subject.bytes.count
                {
                    frameDetails(subject)
                } else {
                    output(bytes)
                }
            case let .failure(failure):
                ContentUnavailableView(
                    "Can’t Decode as \(decoding.title)",
                    systemImage: "exclamationmark.triangle",
                    description: Text(Self.message(failure))
                )
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(
                inputCount: input.count, decoded: try? decoded.get(), title: subject.title,
                subject: subject, start: start, end: end,
                isFullFrameDetails: !subject.layers.isEmpty && presentation == .hexDump && decoding == .none
                    && start == 0 && end == subject.bytes.count
            )
        }
    }

    private func frameDetails(_ subject: PacketBytesSubject) -> some View {
        let layers = DecodedLayerSearchProjection.filter(subject.layers, query: fieldQuery)
        return ScrollViewReader { proxy in
            HSplitView {
                VStack(spacing: 0) {
                    layerFilterControl
                        .padding(Theme.Metrics.spacingM)
                    if let hiddenByteOwnerMessage {
                        Label(hiddenByteOwnerMessage, systemImage: "eye.slash")
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, Theme.Metrics.spacingM)
                            .padding(.bottom, Theme.Metrics.spacingS)
                            .accessibilityLabel(hiddenByteOwnerMessage)
                    }
                    Divider()
                    if layers.isEmpty {
                        ContentUnavailableView(
                            "No Matching Fields",
                            systemImage: "magnifyingglass",
                            description: Text("No decoded layer, field name or value contains ‘\(fieldQuery)’.")
                        )
                    } else {
                        ScrollView {
                            DecodedLayerTree(
                                layers: layers, selectedRange: selectedLayerRange, collapsed: $collapsedLayers,
                                onSelect: { range in
                                    selectedLayerRange = range == selectedLayerRange ? nil : range
                                    hiddenByteOwnerMessage = nil
                                    isLayerTreeFocused = true
                                },
                                allowsFieldFilters: false
                            )
                            .padding(Theme.Metrics.spacingL)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .focusable()
                        .focused($isLayerTreeFocused)
                        .focusEffectDisabled()
                        .onKeyPress(keys: [.upArrow, .downArrow, .leftArrow, .rightArrow]) { press in
                            navigate(press, layers: layers, proxy: proxy)
                        }
                        .onKeyPress(.return, phases: .down) { press in
                            guard press.modifiers.isEmpty else {
                                return .ignored
                            }
                            return navigate(.toggleLayer, layers: layers)
                        }
                    }
                }
                .frame(minWidth: 260)
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Frame protocol details")
                .onChange(of: fieldQuery) {
                    selectedLayerRange = nil
                    hiddenByteOwnerMessage = nil
                    isLayerTreeFocused = false
                }
                .onChange(of: selectedLayerRange) {
                    if let selectedLayerRange {
                        proxy.scrollTo(DecodedLayerTree.rowID(selectedLayerRange), anchor: .center)
                    }
                }
                .onChange(of: byteRevealToken) {
                    if let selectedLayerRange {
                        proxy.scrollTo(DecodedLayerTree.rowID(selectedLayerRange), anchor: .center)
                    }
                }
                ScrollView {
                    PacketBytesPane(
                        bytes: subject.bytes, highlight: selectedLayerRange,
                        onShowBytes: { bytes in
                            coordinator.packetBytesInspection.show(PacketBytesSubject(
                                title: String(localized: "\(subject.title) — Selected Bytes"), bytes: bytes
                            ))
                        },
                        layers: subject.layers,
                        onSelectRange: { range in
                            selectedLayerRange = range
                            hiddenByteOwnerMessage = nil
                            isLayerTreeFocused = false
                        },
                        onRevealByteOwner: { index, owner in
                            revealByteOwner(owner, byte: index, displayedLayers: layers)
                        },
                        dumpStyle: Binding(
                            get: { coordinator.packetDetailOptions.byteDumpStyle },
                            set: { coordinator.packetDetailOptions.byteDumpStyle = $0 }
                        ),
                        onScrollToRow: { proxy.scrollTo($0, anchor: .center) },
                        sourceIdentity: "subject-\(coordinator.packetBytesInspection.revision)"
                    )
                    .padding(Theme.Metrics.spacingM)
                    .frame(minWidth: 360)
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel("Frame bytes")
                }
            }
        }
    }

    private func controls(_ subject: PacketBytesSubject) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text(subject.title)
                .font(Theme.Typography.bodyEmphasis)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(subject.title)
            HStack(spacing: Theme.Metrics.spacingL) {
                Picker("Decode as", selection: $decoding) {
                    ForEach(PacketBytesDecoding.allCases) { step in
                        Text(step.title).tag(step)
                    }
                }
                .fixedSize()
                Picker("Show as", selection: $presentation) {
                    ForEach(PacketBytesPresentation.allCases) { kind in
                        Text(kind.title).tag(kind)
                    }
                }
                .fixedSize()
                Spacer(minLength: 0)
                HStack(spacing: Theme.Metrics.spacingS) {
                    Text("Bytes")
                        .foregroundStyle(.secondary)
                    TextField("Start", value: $rangeStart, format: .number)
                        .frame(width: 64)
                        .help("First byte of the range to decode (0-based)")
                    Text("to")
                        .foregroundStyle(.secondary)
                    TextField("End", value: $rangeEnd, format: .number)
                        .frame(width: 64)
                        .help("End of the range to decode (exclusive); the whole run is 0 to \(subject.bytes.count)")
                }
                .textFieldStyle(.roundedBorder)
                .controlSize(.small)
            }
        }
    }

    @ViewBuilder
    private func output(_ bytes: [UInt8]) -> some View {
        if presentation == .image {
            if let image = NSImage(data: Data(bytes)) {
                ScrollView([.horizontal, .vertical]) {
                    Image(nsImage: image)
                        .accessibilityLabel(
                            "Decoded image, \(Int(image.size.width)) by \(Int(image.size.height)) points"
                        )
                        .padding(Theme.Metrics.spacingL)
                }
            } else {
                ContentUnavailableView(
                    "Not an Image",
                    systemImage: "photo",
                    description: Text("These bytes are not an image format macOS can read.")
                )
            }
        } else {
            ScrollView {
                Text(presentation.text(for: bytes) ?? "")
                    .font(Theme.Typography.mono)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Theme.Metrics.spacingL)
            }
        }
    }

    private func footer(
        inputCount: Int, decoded: [UInt8]?, title: String, subject: PacketBytesSubject, start: Int, end: Int,
        isFullFrameDetails: Bool
    )
        -> some View
    {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(decoded.map { "\(inputCount.formatted()) bytes in, \($0.count.formatted()) bytes out" }
                ?? "\(inputCount.formatted()) bytes in")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
            if presentation == .json, let decoded, !PacketBytesPresentation.isJSON(decoded) {
                Text("Not valid JSON, shown as text")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Copy") {
                guard let decoded else {
                    return
                }
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(
                    renderingText(decoded, isFullFrameDetails: isFullFrameDetails) ?? "", forType: .string
                )
            }
            .disabled(decoded == nil || presentation == .image)
            Button("Save Rendering…") {
                guard let decoded else {
                    return
                }
                saveRendering(
                    decoded, subject: subject, start: start, end: end, isFullFrameDetails: isFullFrameDetails
                )
            }
            .disabled(decoded == nil || presentation == .image || isSavingRendering)
            .help("Save the text currently shown, encoded as UTF-8")
            Button("Save As…") {
                if let decoded {
                    save(decoded, suggestedName: title)
                }
            }
            .disabled(decoded == nil)
            .help("Save decoded bytes exactly, before any text rendering")
            if isSavingRendering {
                ProgressView().controlSize(.small).accessibilityLabel("Preparing rendering")
            }
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private static func message(_ failure: PacketBytesDecoding.Failure) -> String {
        switch failure {
        case let .notApplicable(reason): reason
        case let .outputTooLarge(limit):
            String(localized: "Decoding would produce more than \(ByteUnits.string(Int64(limit))); it was stopped.")
        }
    }

    private static func contentType(for fileExtension: String) -> UTType {
        switch fileExtension {
        case "json": .json
        case "c": UTType(filenameExtension: "c") ?? .plainText
        default: .plainText
        }
    }

    private func revealByteOwner(
        _ owner: DecodedByteMap.Hit, byte: Int, displayedLayers: [DecodedLayer]
    ) {
        guard DecodedByteMap.owner(ofByte: byte, in: displayedLayers) == owner else {
            hiddenByteOwnerMessage = "Selected field is hidden by Filter Fields. Clear the query, then click the byte again."
            return
        }
        collapsedLayers.subtract(owner.path.dropLast())
        hiddenByteOwnerMessage = nil
        isLayerTreeFocused = false
        byteRevealToken &+= 1
    }

    private func navigate(
        _ press: KeyPress, layers: [DecodedLayer], proxy: ScrollViewProxy
    )
        -> KeyPress.Result
    {
        guard isLayerTreeFocused else {
            return .ignored
        }
        let arrow: DecodeTreeNavigation.Arrow = switch press.key {
        case .upArrow: .up
        case .downArrow: .down
        case .leftArrow: .left
        default: .right
        }
        let key = DecodeTreeNavigation.key(
            for: arrow, command: press.modifiers.contains(.command), shift: press.modifiers.contains(.shift)
        )
        guard let outcome = DecodeTreeNavigation.press(
            key, layers: layers, selection: selectedLayerRange, collapsed: collapsedLayers
        ) else {
            return .ignored
        }
        collapsedLayers = outcome.collapsed
        selectedLayerRange = outcome.selection
        if let selection = outcome.selection {
            proxy.scrollTo(DecodedLayerTree.rowID(selection), anchor: .center)
        }
        return .handled
    }

    private func navigate(
        _ key: DecodeTreeNavigation.Key, layers: [DecodedLayer]
    )
        -> KeyPress.Result
    {
        guard isLayerTreeFocused,
              let outcome = DecodeTreeNavigation.press(
                  key, layers: layers, selection: selectedLayerRange, collapsed: collapsedLayers
              ) else
        {
            return .ignored
        }
        collapsedLayers = outcome.collapsed
        selectedLayerRange = outcome.selection
        return .handled
    }

    private func save(_ bytes: [UInt8], suggestedName: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "bytes.bin"
        panel.allowedContentTypes = [.data]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        try? Data(bytes).write(to: url, options: .atomic)
    }

    private func saveRendering(
        _ bytes: [UInt8], subject: PacketBytesSubject, start: Int, end: Int, isFullFrameDetails: Bool
    ) {
        let request = UUID()
        renderingSaveRequest = request
        isSavingRendering = true
        renderingSaveError = nil
        let selectedPresentation = presentation
        let selectedDecoding = decoding
        let selectedDumpStyle = isFullFrameDetails ? coordinator.packetDetailOptions.byteDumpStyle : nil
        let revision = coordinator.packetBytesInspection.revision
        let projectID = coordinator.projectStore.activeProjectID

        Task {
            do {
                let data = try await Task.detached(priority: .userInitiated) {
                    try PacketBytesRenderingSave.outputData(
                        bytes, presentation: selectedPresentation, byteDumpStyle: selectedDumpStyle
                    )
                }.value
                guard renderingSaveRequest == request else {
                    return
                }
                guard renderingScopeIsCurrent(
                    subject: subject, revision: revision, projectID: projectID, start: start, end: end,
                    selectedDecoding: selectedDecoding, selectedPresentation: selectedPresentation,
                    selectedDumpStyle: selectedDumpStyle, isFullFrameDetails: isFullFrameDetails
                ) else {
                    renderingSaveError = "The inspected bytes or view changed while preparing the rendering. Choose Save Rendering again."
                    isSavingRendering = false
                    return
                }

                let jsonIsValid = selectedPresentation == .json && PacketBytesPresentation.isJSON(bytes)
                let fileExtension: String = switch selectedPresentation {
                case .text,
                     .utf16LittleEndian,
                     .utf16BigEndian,
                     .hexDump: "txt"
                case .json: jsonIsValid ? "json" : "txt"
                case .cArray: "c"
                case .image: "txt"
                }
                let panel = NSSavePanel()
                panel.nameFieldStringValue = "bytes.\(fileExtension)"
                panel.allowedContentTypes = [Self.contentType(for: fileExtension)]
                panel.canCreateDirectories = true
                guard panel.runModal() == .OK, let url = panel.url else {
                    guard renderingSaveRequest == request else {
                        return
                    }
                    isSavingRendering = false
                    return
                }
                guard renderingSaveRequest == request else {
                    return
                }
                guard renderingScopeIsCurrent(
                    subject: subject, revision: revision, projectID: projectID, start: start, end: end,
                    selectedDecoding: selectedDecoding, selectedPresentation: selectedPresentation,
                    selectedDumpStyle: selectedDumpStyle, isFullFrameDetails: isFullFrameDetails
                ) else {
                    renderingSaveError = "The inspected bytes or view changed while the save panel was open. Choose Save Rendering again."
                    isSavingRendering = false
                    return
                }
                try await Task.detached(priority: .utility) {
                    try data.write(to: url, options: .atomic)
                }.value
                guard renderingSaveRequest == request else {
                    return
                }
                isSavingRendering = false
            } catch {
                guard renderingSaveRequest == request else {
                    return
                }
                renderingSaveError = error.localizedDescription
                isSavingRendering = false
            }
        }
    }

    private func renderingScopeIsCurrent(
        subject: PacketBytesSubject, revision: Int, projectID: UUID, start: Int, end: Int,
        selectedDecoding: PacketBytesDecoding, selectedPresentation: PacketBytesPresentation,
        selectedDumpStyle: ByteDumpStyle?, isFullFrameDetails: Bool
    )
        -> Bool
    {
        let byteCount = coordinator.packetBytesInspection.subject?.bytes.count ?? 0
        let currentStart = min(max(0, rangeStart), byteCount)
        let currentEnd = min(max(currentStart, rangeEnd), byteCount)
        return coordinator.packetBytesInspection.revision == revision
            && coordinator.packetBytesInspection.subject == subject
            && coordinator.projectStore.activeProjectID == projectID
            && currentStart == start && currentEnd == end
            && decoding == selectedDecoding && presentation == selectedPresentation
            && (!isFullFrameDetails || coordinator.packetDetailOptions.byteDumpStyle == selectedDumpStyle)
            && isFullFrameDetails == (!subject.layers.isEmpty && presentation == .hexDump && decoding == .none
                && currentStart == 0 && currentEnd == subject.bytes.count)
    }

    private func renderingText(_ bytes: [UInt8], isFullFrameDetails: Bool) -> String? {
        PacketBytesRenderingSave.text(
            for: bytes, presentation: presentation,
            byteDumpStyle: isFullFrameDetails ? coordinator.packetDetailOptions.byteDumpStyle : nil
        )
    }
}
