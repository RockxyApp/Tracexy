import SwiftUI

// MARK: - FrameFindBar

/// Find Packet for View ▸ All Frames, as Wireshark's find bar: a string, hex bytes or
/// a regular expression in frame bytes or details, or a typed Frame Expression.
/// Next and Previous step through the stable capture, paging the list when needed.
struct FrameFindBar: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    let selection: CaptureFrameRow.ID?
    let onSelect: (UInt64) -> Void
    let onClose: () -> Void

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Picker("Find", selection: $mode) {
                Text("String").tag(Mode.string)
                Text("Hex").tag(Mode.hex)
                Text("Regex").tag(Mode.regex)
                Text("Expression").tag(Mode.expression)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("Find text, hex bytes, a regular expression, or a Tracexy Frame Expression")
            Picker("In", selection: $query.target) {
                Text("Bytes").tag(FrameSearchQuery.Target.bytes)
                Text("Details").tag(FrameSearchQuery.Target.details)
            }
            .fixedSize()
            .accessibilityLabel(Text("Look in"))
            .help("Look in each frame's bytes, or in its layers and fields as Layers shows them")
            .disabled(mode == .expression)
            if mode != .expression, query.kind == .string, query.target == .bytes {
                Picker("String encoding", selection: $query.stringEncoding) {
                    ForEach(FrameSearchQuery.StringEncoding.allCases, id: \.self) { encoding in
                        Text(encoding.title).tag(encoding)
                    }
                }
                .pickerStyle(.menu)
                .fixedSize()
                .accessibilityLabel(Text("String encoding"))
                .help("Search UTF-8, UTF-16 little-endian, UTF-16 big-endian, or all three")
            }
            TextField("Find in frames", text: $query.text, prompt: Text(prompt))
                .textFieldStyle(.roundedBorder)
                .font(mode == .string ? Theme.Typography.body : Theme.Typography.mono)
                .frame(minWidth: 160)
                .onSubmit { step(forward: true) }
            Toggle("Match Case", isOn: $query.caseSensitive)
                .toggleStyle(.checkbox)
                .disabled(mode == .hex || mode == .expression)
            Button("Previous", systemImage: "chevron.up") { step(forward: false) }
                .labelStyle(.iconOnly)
                .help("Previous matching frame")
                .disabled(isSearching || coordinator.allFrames.isLoading)
            Button("Next", systemImage: "chevron.down") { step(forward: true) }
                .labelStyle(.iconOnly)
                .help("Next matching frame")
                .disabled(isSearching || coordinator.allFrames.isLoading)
                .keyboardShortcut("g", modifiers: .command)
            Text(status)
                .help(status)
                .accessibilityLabel(Text(status))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .frame(minWidth: 90, alignment: .leading)
            Spacer(minLength: 0)
            Button("Done") { onClose() }
                .keyboardShortcut(.cancelAction)
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .onDisappear {
            searchRequestID &+= 1
            search?.cancel()
            isSearching = false
        }
        .onChange(of: query) { _, _ in resetSearch() }
        .onChange(of: mode) { _, newMode in
            switch newMode {
            case .string: query.kind = .string
            case .hex: query.kind = .hex
            case .regex: query.kind = .regex
            case .expression: break
            }
            resetSearch()
        }
        .onChange(of: coordinator.startGeneration) { _, _ in resetSearch() }
        .onChange(of: coordinator.projectStore.activeProjectID) { _, _ in resetSearch() }
        .onChange(of: selection) { _, selected in
            if mode == .expression, let selected, selected != lastAnchor {
                lastAnchor = nil
                searchRequestID &+= 1
                search?.cancel()
                search = nil
                isSearching = false
            }
        }
    }

    // MARK: Private

    private enum Mode: Hashable {
        case string
        case hex
        case regex
        case expression
    }

    private struct SearchSummary {
        let query: FrameSearchQuery
        let mode: Mode
        let count: Int
        let unknown: Int
        let completeness: CaptureLoadCompleteness
    }

    @State private var mode = Mode.string
    @State private var query = FrameSearchQuery(kind: .string, target: .bytes, text: "")
    @State private var lastResult: SearchSummary?
    @State private var lastAnchor: UInt64?
    @State private var isSearching = false
    @State private var message: String?
    @State private var search: Task<Void, Never>?
    @State private var searchRequestID = 0

    private var prompt: String {
        switch mode {
        case .string: String(localized: "Text to find")
        case .hex: "16 03 01"
        case .regex: String(localized: "Regular expression")
        case .expression: "dns.response or tcp.flags.reset"
        }
    }

    private var status: String {
        if isSearching {
            return String(localized: "Searching…")
        }
        if let message {
            return message
        }
        guard let lastResult, lastResult.query == query, lastResult.mode == mode else {
            return ""
        }
        let scope = lastResult.completeness == .complete
            ? String(localized: "in capture") : String(localized: "in complete frames; truncated tail")
        let matches = lastResult.count < 1 ? String(localized: "No match \(scope)")
            : String(localized: "\(lastResult.count.formatted()) \(scope)")
        guard lastResult.mode == .expression else {
            return matches
        }
        return String(localized: "\(matches); \(lastResult.unknown.formatted()) unknown")
    }

    private func resetSearch() {
        searchRequestID &+= 1
        search?.cancel()
        search = nil
        isSearching = false
        message = nil
        lastAnchor = nil
        lastResult = nil
    }

    private func step(forward: Bool) {
        searchRequestID &+= 1
        let requestID = searchRequestID
        search?.cancel()
        search = nil
        let expression: FrameExpression?
        do {
            if mode == .expression {
                var parser = FrameExpressionParser()
                expression = try parser.parse(query.text)
            } else {
                _ = try query.matcher()
                expression = nil
            }
        } catch {
            isSearching = false
            if let error = error as? FrameExpressionError {
                message = String(localized: "Expression error at character \(error.position): \(error.reason)")
            } else {
                message = (error as? FrameSearchQuery.Invalid)?.message
            }
            return
        }
        message = nil
        isSearching = true
        let asked = query
        let askedMode = mode
        let current = mode == .expression ? lastAnchor ?? selection : selection
        let selected = selection
        let listID = coordinator.allFrames.requestID
        search = Task {
            do {
                let ordinal: UInt64?
                let count: Int
                let unknown: Int
                let completeness: CaptureLoadCompleteness
                if let expression {
                    let result = try await coordinator.findAdjacentFrame(
                        matching: expression, after: current, forward: forward
                    )
                    ordinal = result.ordinal
                    count = result.matchCount
                    unknown = result.unknownCount
                    completeness = result.completeness
                } else {
                    let result = try await coordinator.findAdjacentFrame(
                        matching: asked, after: current, forward: forward
                    )
                    ordinal = result.ordinal
                    count = result.matchCount
                    unknown = 0
                    completeness = result.completeness
                }
                guard requestID == searchRequestID else {
                    return
                }
                isSearching = false
                guard !Task.isCancelled, asked == query, askedMode == mode,
                      askedMode != .expression || selected == selection,
                      listID == coordinator.allFrames.requestID else
                {
                    return
                }
                lastResult = SearchSummary(
                    query: asked, mode: askedMode, count: count, unknown: unknown, completeness: completeness
                )
                if let ordinal {
                    if askedMode == .expression {
                        lastAnchor = ordinal
                    }
                    onSelect(ordinal)
                }
            } catch is CancellationError {
                if requestID == searchRequestID {
                    isSearching = false
                }
            } catch {
                guard requestID == searchRequestID else {
                    return
                }
                isSearching = false
                message = (error as? FrameSearchQuery.Invalid)?.message
                    ?? String(localized: "Couldn’t search the frames: \(error.localizedDescription)")
            }
        }
    }
}
