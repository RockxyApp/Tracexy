import AppKit
import SwiftUI

// MARK: - DecodedLayerTree

/// A selectable decode tree (Eth → IP → TCP → TLS → handshake). Tapping a layer
/// header or a field reports its byte range so the hex pane can highlight it.
struct DecodedLayerTree: View {
    // MARK: Internal

    let layers: [DecodedLayer]
    let selectedRange: Range<Int>?
    /// Layers folded shut, by title — remembered per protocol while the selection
    /// moves between packets, as Wireshark remembers its expanded subtrees.
    @Binding var collapsed: Set<String>

    let onSelect: (Range<Int>?) -> Void
    /// Apply as Filter / Prepare as Filter: the term, how it joins, and whether to apply.
    var onFilter: (String, DecodedFieldFilter.Combination, Bool) -> Void = { _, _, _ in }
    /// Apply as Column's list of columns, when the tree offers it.
    var columnOptions: PacketDetailOptions?
    var depth = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(layers) { layer in
                VStack(alignment: .leading, spacing: 2) {
                    layerHeader(layer)
                    if !collapsed.contains(layer.title) {
                        ForEach(Array(layer.fields.enumerated()), id: \.offset) { _, decodedField in
                            fieldRow(decodedField, in: layer)
                        }
                        if !layer.children.isEmpty {
                            DecodedLayerTree(
                                layers: layer.children, selectedRange: selectedRange, collapsed: $collapsed,
                                onSelect: onSelect, onFilter: onFilter, columnOptions: columnOptions,
                                depth: depth + 1
                            )
                            .padding(.leading, 14)
                        }
                    }
                }
            }
        }
    }

    /// Every layer title in `layers`, nested ones included.
    static func titles(_ layers: [DecodedLayer]) -> Set<String> {
        layers.reduce(into: Set<String>()) { result, layer in
            result.insert(layer.title)
            result.formUnion(titles(layer.children))
        }
    }

    /// The scroll identity of the rows that own `range`.
    static func rowID(_ range: Range<Int>) -> String {
        "bytes-\(range.lowerBound)-\(range.upperBound)"
    }

    // MARK: Private

    @Environment(\.packetTextZoom) private var zoom
    @Environment(\.openWindow) private var openWindow

    private func layerHeader(_ layer: DecodedLayer) -> some View {
        let isCollapsed = collapsed.contains(layer.title)
        // The disclosure button sits beside the selectable header, not inside it,
        // so a click or accessibility press on it folds the layer and nothing else.
        return HStack(spacing: 2) {
            Button {
                toggle(layer.title)
            } label: {
                Image(systemName: "chevron.right")
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(isCollapsed ? 0 : 90))
                    .frame(width: 16, height: 16)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(isCollapsed
                ? String(localized: "Expand \(layer.title)")
                : String(localized: "Collapse \(layer.title)"))
            HStack(spacing: 6) {
                Text(layer.title).font(Theme.Typography.bodyMedium)
                    .foregroundStyle(Theme.color(for: layer.proto))
                if !layer.summary.isEmpty {
                    Text(layer.summary).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 1).padding(.horizontal, 4)
            .background(rowBackground(layer.byteRange), in: RoundedRectangle(cornerRadius: 4))
            .contentShape(Rectangle())
            // Tap still selects the byte range for the hex pane; the context menu is
            // an additive right-click affordance and leaves that behavior untouched.
            .onTapGesture { onSelect(layer.byteRange) }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isButton)
            .accessibilityAction { onSelect(layer.byteRange) }
            .contextMenu {
                Button(isCollapsed ? "Expand Subtree" : "Collapse Subtree") {
                    toggle(layer.title)
                }
                Button("Expand All") {
                    collapsed.removeAll()
                }
                Button("Collapse All") {
                    collapsed.formUnion(Self.titles(layers))
                }
                Divider()
                Button("Copy Layer Summary", systemImage: "doc.on.doc") {
                    copy(DecodedClipboardText.layerSummary(layer))
                }
                if let term = DecodedFieldFilter.term(for: layer.proto) {
                    Divider()
                    FieldFilterMenus(term: term, action: onFilter)
                }
            }
        }
        .id(layer.byteRange.map(Self.rowID))
    }

    private func fieldRow(_ field: DecodedField, in layer: DecodedLayer) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(field.name).font(Theme.Typography.zoomed(.subheadline, zoom: zoom)).foregroundStyle(.secondary)
                .frame(width: 128 + CGFloat(zoom) * 8, alignment: .leading)
            Text(field.value).font(Theme.Typography.zoomed(.subheadline, zoom: zoom, monospaced: true))
            Spacer(minLength: 0)
        }
        .padding(.leading, 15).padding(.trailing, 4).padding(.vertical, 1)
        .background(rowBackground(field.byteRange), in: RoundedRectangle(cornerRadius: 4))
        .id(field.byteRange.map(Self.rowID))
        .contentShape(Rectangle())
        .onTapGesture { onSelect(field.byteRange) }
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { onSelect(field.byteRange) }
        .contextMenu {
            Button("Copy Value", systemImage: "doc.on.doc") {
                copy(DecodedClipboardText.value(field))
            }
            Button("Copy Field Name", systemImage: "textformat") {
                copy(DecodedClipboardText.name(field))
            }
            Button("Copy \u{201C}Name: Value\u{201D}", systemImage: "text.append") {
                copy(DecodedClipboardText.nameValue(field))
            }
            if let term = DecodedFieldFilter.term(proto: layer.proto, field: field.name, value: field.value) {
                Divider()
                FieldFilterMenus(term: term, action: onFilter)
            }
            if let columnOptions {
                ApplyAsColumnButton(key: FieldKey(proto: layer.proto, name: field.name), options: columnOptions)
            }
            Divider()
            Button("Show Value Distribution", systemImage: "chart.bar.doc.horizontal") {
                FieldValueDistributionController.shared.field = FieldKey(proto: layer.proto, name: field.name)
                openWindow(id: TracexyApp.valueDistributionWindowID)
            }
            if FieldPlot.number(field.value) != nil {
                Button("Plot Over Time", systemImage: "chart.xyaxis.line") {
                    FieldPlotController.shared.field = FieldKey(proto: layer.proto, name: field.name)
                    openWindow(id: TracexyApp.fieldPlotWindowID)
                }
            }
        }
    }

    private func toggle(_ title: String) {
        if collapsed.remove(title) == nil {
            collapsed.insert(title)
        }
    }

    private func rowBackground(_ range: Range<Int>?) -> Color {
        guard let range, range == selectedRange else {
            return .clear
        }
        return Color.accentColor.opacity(0.18)
    }

    /// The only side effect of the copy actions: the text formatting itself lives
    /// in the pure ``DecodedClipboardText`` so it stays independently testable.
    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
