import AppKit
import SwiftUI

// MARK: - PacketBytesPane

/// The hex dump of one frame with Find (hex bytes or text) and Copy Bytes — the
/// whole frame, or the field selected in the decode tree when there is one.
struct PacketBytesPane: View {
    // MARK: Internal

    let bytes: [UInt8]
    var highlight: Range<Int>?
    /// Opens Show Packet Bytes on these bytes (or the highlighted field's).
    var onShowBytes: (([UInt8]) -> Void)?
    /// The frame's decode tree: pointing at a byte names the field it belongs to,
    /// and clicking it selects that field through `onSelectRange`.
    var layers: [DecodedLayer] = []
    var onSelectRange: ((Range<Int>) -> Void)?
    /// The byte and exact decoded owner after a user clicks in the dump.
    var onRevealByteOwner: ((Int, DecodedByteMap.Hit) -> Void)?
    /// The byte under the pointer, for a pointer line the host pins in view.
    var onHoverByte: ((Int?) -> Void)?
    /// Show as: hexadecimal or bits. `nil` hides the choice.
    var dumpStyle: Binding<ByteDumpStyle>?
    /// Scrolls the owning vertical bytes view to a dump-row identifier.
    var onScrollToRow: ((String) -> Void)?
    /// Identifies the selected frame or detached subject independently of byte equality.
    var sourceIdentity: String?

    var body: some View {
        let found = PacketBytesSearch.matches(query, in: bytes, caseSensitive: isCaseSensitive)
        let activeMatch = activeMatchIndex.flatMap { found.ranges.indices.contains($0) ? found.ranges[$0] : nil }
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            HStack(spacing: Theme.Metrics.spacingM) {
                TextField("Find bytes", text: $query, prompt: Text("Hex bytes or text"))
                    .textFieldStyle(.roundedBorder)
                    .controlSize(.small)
                    .frame(maxWidth: 220)
                    .help(
                        "Hex-byte pairs search bytes regardless of this option. Other text searches its UTF-8 bytes; hex-only text such as CAFE is interpreted as hex."
                    )
                if !query.trimmingCharacters(in: .whitespaces).isEmpty {
                    Text(Self.countLabel(found.ranges.count, truncated: found.truncated))
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                        .accessibilityLabel(Self.countLabel(found.ranges.count, truncated: found.truncated))
                }
                Spacer(minLength: 0)
                if let dumpStyle {
                    Picker("Show as", selection: dumpStyle) {
                        ForEach(ByteDumpStyle.allCases) { Text($0.title).tag($0) }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .controlSize(.small)
                    .fixedSize()
                    .help("Show each byte as hexadecimal or as bits")
                }
                if let onShowBytes {
                    Button("Show Bytes…") {
                        onShowBytes(selectedBytes)
                    }
                    .buttonStyle(.link)
                    .controlSize(.small)
                    .help(highlight == nil
                        ? "Decode this frame's bytes (Base64, gzip, deflate…) and show them as text, JSON or an image"
                        : "Decode the selected field's bytes and show them as text, JSON or an image")
                }
                Menu("Copy Bytes") {
                    ForEach(PacketBytesFormat.allCases) { format in
                        Button(format.menuTitle) {
                            copy(format)
                        }
                    }
                }
                .menuStyle(.borderlessButton)
                .controlSize(.small)
                .fixedSize()
                .help(highlight == nil
                    ? "Copy this frame's bytes"
                    : "Copy the selected field's bytes")
            }
            if !query.trimmingCharacters(in: .whitespaces).isEmpty {
                HStack(spacing: Theme.Metrics.spacingM) {
                    Toggle("Case Sensitive", isOn: $isCaseSensitive)
                        .toggleStyle(.checkbox)
                        .font(Theme.Typography.caption)
                        .help("Match text bytes with exact ASCII letter case; hexadecimal byte searches are unchanged")
                    matchNavigation(found)
                }
            }
            if layers.isEmpty {
                HexDumpView(bytes: bytes, highlight: highlight, matches: found.ranges, activeMatch: activeMatch)
                    .environment(\.byteDumpStyle, selectedDumpStyle)
            } else {
                ScrollView(.horizontal) {
                    linkedDump(found.ranges, activeMatch: activeMatch)
                }
            }
        }
        .onChange(of: query) { _, _ in activeMatchIndex = nil }
        .onChange(of: bytes) { _, _ in activeMatchIndex = nil }
        .onChange(of: selectedDumpStyle) { _, _ in activeMatchIndex = nil }
        .onChange(of: sourceIdentity) { _, _ in activeMatchIndex = nil }
        .onChange(of: isCaseSensitive) { _, _ in activeMatchIndex = nil }
    }

    // MARK: Private

    @State private var query = ""
    @State private var activeMatchIndex: Int?
    @State private var isCaseSensitive = false
    @Environment(\.byteDumpStyle) private var environmentDumpStyle

    private var selectedDumpStyle: ByteDumpStyle {
        dumpStyle?.wrappedValue ?? environmentDumpStyle
    }

    /// The highlighted field's bytes, or the whole frame.
    private var selectedBytes: [UInt8] {
        let range = highlight.flatMap { $0.clamped(to: 0 ..< bytes.count) } ?? (0 ..< bytes.count)
        return Array(bytes[range])
    }

    private func linkedDump(_ matches: [Range<Int>], activeMatch: Range<Int>?) -> some View {
        HexDumpView(
            bytes: bytes, highlight: highlight, matches: matches, activeMatch: activeMatch,
            onHoverByte: { onHoverByte?($0) },
            onClickByte: { index in
                if let owner = DecodedByteMap.owner(ofByte: index, in: layers) {
                    onSelectRange?(owner.range)
                    onRevealByteOwner?(index, owner)
                }
            }
        )
        .environment(\.byteDumpStyle, selectedDumpStyle)
    }

    private func matchNavigation(_ found: (ranges: [Range<Int>], truncated: Bool)) -> some View {
        let position = activeMatchIndex.map { $0 + 1 }
        let total = "\(found.ranges.count.formatted())\(found.truncated ? "+" : "")"
        return HStack(spacing: Theme.Metrics.spacingS) {
            Button {
                moveMatch(by: -1, ranges: found.ranges)
            } label: {
                Image(systemName: "chevron.up")
            }
            .buttonStyle(.plain)
            .disabled(found.ranges.isEmpty)
            .accessibilityLabel("Previous byte match")
            .help("Go to the previous byte match; wraps at the start")

            Button {
                moveMatch(by: 1, ranges: found.ranges)
            } label: {
                Image(systemName: "chevron.down")
            }
            .buttonStyle(.plain)
            .disabled(found.ranges.isEmpty)
            .accessibilityLabel("Next byte match")
            .help(found.truncated
                ? "Go to the next retained byte match; only the first 256 matches are available"
                : "Go to the next byte match; wraps at the end")

            Text(position.map { "Match \($0) of \(total)" } ?? "\(total) retained matches")
                .font(Theme.Typography.micro)
                .monospacedDigit()
                .lineLimit(1)
        }
    }

    private static func countLabel(_ count: Int, truncated: Bool) -> String {
        switch (count, truncated) {
        case (0, _): "No match"
        case (1, false): "1 match"
        case (_, true): "\(count.formatted())+ matches"
        default: "\(count.formatted()) matches"
        }
    }

    private func moveMatch(by offset: Int, ranges: [Range<Int>]) {
        guard !ranges.isEmpty else {
            activeMatchIndex = nil
            return
        }
        let next: Int = if let activeMatchIndex {
            (activeMatchIndex + offset + ranges.count) % ranges.count
        } else {
            offset < 0 ? ranges.count - 1 : 0
        }
        activeMatchIndex = next
        onScrollToRow?(HexDumpView.rowID(forByte: ranges[next].lowerBound, style: selectedDumpStyle))
    }

    private func copy(_ format: PacketBytesFormat) {
        let range = highlight.flatMap { $0.clamped(to: 0 ..< bytes.count) } ?? (0 ..< bytes.count)
        let value = format.clipboardValue(for: bytes[range], startOffset: range.lowerBound)
        NSPasteboard.general.clearContents()
        switch value {
        case let .text(text):
            NSPasteboard.general.setString(text, forType: .string)
        case let .data(data, type):
            NSPasteboard.general.setData(data, forType: NSPasteboard.PasteboardType(type))
        }
    }
}
