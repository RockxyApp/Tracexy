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
    /// The byte under the pointer, for a pointer line the host pins in view.
    var onHoverByte: ((Int?) -> Void)?
    /// Show as: hexadecimal or bits. `nil` hides the choice.
    var dumpStyle: Binding<ByteDumpStyle>?

    var body: some View {
        let found = PacketBytesSearch.matches(query, in: bytes)
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            HStack(spacing: Theme.Metrics.spacingM) {
                TextField("Find bytes", text: $query, prompt: Text("Hex bytes or text"))
                    .textFieldStyle(.roundedBorder)
                    .controlSize(.small)
                    .frame(maxWidth: 220)
                    .help("Type hex bytes such as “16 03 01” or text; matches are highlighted")
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
            if layers.isEmpty {
                HexDumpView(bytes: bytes, highlight: highlight, matches: found.ranges)
            } else {
                ScrollView(.horizontal) {
                    linkedDump(found.ranges)
                }
            }
        }
    }

    // MARK: Private

    @State private var query = ""

    /// The highlighted field's bytes, or the whole frame.
    private var selectedBytes: [UInt8] {
        let range = highlight.flatMap { $0.clamped(to: 0 ..< bytes.count) } ?? (0 ..< bytes.count)
        return Array(bytes[range])
    }

    private func linkedDump(_ matches: [Range<Int>]) -> some View {
        HexDumpView(
            bytes: bytes, highlight: highlight, matches: matches,
            onHoverByte: { onHoverByte?($0) },
            onClickByte: { index in
                if let owner = DecodedByteMap.owner(ofByte: index, in: layers) {
                    onSelectRange?(owner.range)
                }
            }
        )
    }

    private static func countLabel(_ count: Int, truncated: Bool) -> String {
        switch (count, truncated) {
        case (0, _): "No match"
        case (1, false): "1 match"
        case (_, true): "\(count.formatted())+ matches"
        default: "\(count.formatted()) matches"
        }
    }

    private func copy(_ format: PacketBytesFormat) {
        let range = highlight.flatMap { $0.clamped(to: 0 ..< bytes.count) } ?? (0 ..< bytes.count)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(format.text(for: bytes[range], startOffset: range.lowerBound), forType: .string)
    }
}
