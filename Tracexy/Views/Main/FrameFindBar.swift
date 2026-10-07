import SwiftUI

// MARK: - FrameFindBar

/// Find Packet for View ▸ All Frames, as Wireshark's find bar: a string, hex bytes or
/// a regular expression, in each frame's bytes or its decoded details. Next and
/// Previous step through the matching frames the list shows and wrap around.
struct FrameFindBar: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator
    /// The frames the list shows, in order.
    let rows: [CaptureFrameRow]
    @Binding var selection: CaptureFrameRow.ID?
    @Binding var revealToken: Int

    let onClose: () -> Void

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            Picker("Find", selection: $query.kind) {
                Text("String").tag(FrameSearchQuery.Kind.string)
                Text("Hex").tag(FrameSearchQuery.Kind.hex)
                Text("Regex").tag(FrameSearchQuery.Kind.regex)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .help("Find a string, hex bytes such as 16 03 01, or a regular expression")
            Picker("In", selection: $query.target) {
                Text("Bytes").tag(FrameSearchQuery.Target.bytes)
                Text("Details").tag(FrameSearchQuery.Target.details)
            }
            .fixedSize()
            .accessibilityLabel(Text("Look in"))
            .help("Look in each frame's bytes, or in its layers and fields as Layers shows them")
            TextField("Find in frames", text: $query.text, prompt: Text(prompt))
                .textFieldStyle(.roundedBorder)
                .font(query.kind == .string ? Theme.Typography.body : Theme.Typography.mono)
                .frame(minWidth: 160)
                .onSubmit { step(forward: true) }
            Toggle("Match Case", isOn: $query.caseSensitive)
                .toggleStyle(.checkbox)
                .disabled(query.kind == .hex)
            Button("Previous", systemImage: "chevron.up") { step(forward: false) }
                .labelStyle(.iconOnly)
                .help("Previous matching frame")
                .disabled(isSearching)
            Button("Next", systemImage: "chevron.down") { step(forward: true) }
                .labelStyle(.iconOnly)
                .help("Next matching frame")
                .disabled(isSearching)
                .keyboardShortcut("g", modifiers: .command)
            Text(status)
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
        .onDisappear { search?.cancel() }
    }

    /// The next matching frame after `current` among `rows` (before it when going
    /// back), wrapping around; `nil` when none of the matches is shown.
    static func step(
        from current: UInt64?,
        forward: Bool,
        matches: Set<UInt64>,
        rows: [CaptureFrameRow]
    )
        -> UInt64?
    {
        let shown = rows.map(\.ordinal).filter(matches.contains)
        guard let first = shown.first, let last = shown.last else {
            return nil
        }
        guard let current else {
            return forward ? first : last
        }
        return forward ? shown.first { $0 > current } ?? first : shown.last { $0 < current } ?? last
    }

    // MARK: Private

    @State private var query = FrameSearchQuery(kind: .string, target: .bytes, text: "")
    @State private var matches: (query: FrameSearchQuery, frames: Set<UInt64>)?
    @State private var isSearching = false
    @State private var message: String?
    @State private var search: Task<Void, Never>?

    private var prompt: String {
        switch query.kind {
        case .string: String(localized: "Text to find")
        case .hex: "16 03 01"
        case .regex: String(localized: "Regular expression")
        }
    }

    private var status: String {
        if isSearching {
            return String(localized: "Searching…")
        }
        if let message {
            return message
        }
        guard let matches, matches.query == query else {
            return ""
        }
        let shown = rows.map(\.ordinal).filter(matches.frames.contains)
        guard !shown.isEmpty else {
            return matches.frames.isEmpty ? String(localized: "No match")
                : String(localized: "\(matches.frames.count.formatted()) found, none in this list")
        }
        guard let selection, let index = shown.firstIndex(of: selection) else {
            return shown
                .count == 1 ? String(localized: "1 match") : String(localized: "\(shown.count.formatted()) matches")
        }
        return String(localized: "\(index + 1) of \(shown.count.formatted())")
    }

    private func step(forward: Bool) {
        if let matches, matches.query == query {
            move(forward: forward, in: matches.frames)
            return
        }
        do {
            _ = try query.matcher()
        } catch {
            message = (error as? FrameSearchQuery.Invalid)?.message
            return
        }
        message = nil
        isSearching = true
        let asked = query
        search?.cancel()
        search = Task {
            defer { isSearching = false }
            do {
                let frames = try await coordinator.findFrames(matching: asked)
                guard !Task.isCancelled, asked == query else {
                    return
                }
                matches = (asked, Set(frames))
                move(forward: forward, in: Set(frames))
            } catch is CancellationError {
                return
            } catch {
                message = (error as? FrameSearchQuery.Invalid)?.message
                    ?? String(localized: "Couldn’t search the frames: \(error.localizedDescription)")
            }
        }
    }

    private func move(forward: Bool, in frames: Set<UInt64>) {
        guard let next = Self.step(from: selection, forward: forward, matches: frames, rows: rows) else {
            return
        }
        selection = next
        revealToken &+= 1
    }
}
