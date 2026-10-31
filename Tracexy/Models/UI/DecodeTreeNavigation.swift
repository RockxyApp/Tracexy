import Foundation

// MARK: - DecodeTreeNavigation

/// Keyboard movement through the Layers decode tree, as Wireshark's packet details
/// pane moves: ↑ and ↓ step through the rows shown, ← folds the selected layer or
/// goes to the layer a row belongs to, → unfolds the selected layer or enters it, and
/// ⌘→ / ⌘← unfold or fold every layer. Rows are identified by their byte range; a row
/// with none cannot be selected.
nonisolated enum DecodeTreeNavigation {
    // MARK: Internal

    enum Key: Sendable, Equatable {
        case up
        case down
        case toggleLayer
        case left
        case right
        case expandSubtree
        case collapseSubtree
        case expandAll
        case collapseAll
    }

    enum Arrow: Sendable {
        case up
        case down
        case left
        case right
    }

    struct Row: Equatable, Sendable {
        let range: Range<Int>
        /// The layer this row heads, or `nil` for a field.
        let layer: String?
        /// The layer this row sits in.
        let parent: String?
    }

    /// What a key press does: the range to select and the folded layers after it.
    struct Outcome: Equatable, Sendable {
        let selection: Range<Int>?
        let collapsed: Set<String>
    }

    static func key(for arrow: Arrow, command: Bool, shift: Bool) -> Key {
        switch arrow {
        case .up: .up
        case .down: .down
        case .left: command ? .collapseAll : (shift ? .collapseSubtree : .left)
        case .right: command ? .expandAll : (shift ? .expandSubtree : .right)
        }
    }

    /// The rows shown, top to bottom.
    static func rows(_ layers: [DecodedLayer], collapsed: Set<String>, parent: String? = nil) -> [Row] {
        layers.flatMap { layer -> [Row] in
            var rows = layer.byteRange.map { [Row(range: $0, layer: layer.title, parent: parent)] } ?? []
            guard !collapsed.contains(layer.title) else {
                return rows
            }
            rows += layer.fields.compactMap { field in
                field.byteRange.map { Row(range: $0, layer: nil, parent: layer.title) }
            }
            return rows + Self.rows(layer.children, collapsed: collapsed, parent: layer.title)
        }
    }

    static func press(
        _ key: Key,
        layers: [DecodedLayer],
        selection: Range<Int>?,
        collapsed: Set<String>
    )
        -> Outcome?
    {
        let shown = rows(layers, collapsed: collapsed)
        switch key {
        case .toggleLayer:
            guard let row = shown.first(where: { $0.range == selection }),
                  let layer = row.layer else
            {
                return nil
            }
            let updated = collapsed.contains(layer)
                ? collapsed.subtracting([layer])
                : collapsed.union([layer])
            return Outcome(selection: selection, collapsed: updated)
        case .expandSubtree,
             .collapseSubtree:
            guard let row = shown.first(where: { $0.range == selection }), row.layer != nil,
                  let layer = layer(with: row.range, in: layers) else
            {
                return nil
            }
            let subtreeTitles = titles([layer])
            let updated = key == .expandSubtree
                ? collapsed.subtracting(subtreeTitles)
                : collapsed.union(subtreeTitles)
            return Outcome(selection: selection, collapsed: updated)
        case .expandAll:
            return Outcome(selection: selection, collapsed: [])
        case .collapseAll:
            let all = titles(layers)
            let heads = rows(layers, collapsed: all)
            let owner = shown.first { $0.range == selection }
            let kept = heads.first { $0.layer != nil && ($0.range == selection || $0.layer == owner?.parent) }
            return Outcome(selection: kept?.range ?? heads.first?.range, collapsed: all)
        case .up,
             .down:
            guard let index = shown.firstIndex(where: { $0.range == selection }) else {
                return (key == .down ? shown.first : shown.last)
                    .map { Outcome(selection: $0.range, collapsed: collapsed) }
            }
            let next = key == .down ? index + 1 : index - 1
            guard shown.indices.contains(next) else {
                return nil
            }
            return Outcome(selection: shown[next].range, collapsed: collapsed)
        case .left:
            guard let row = shown.first(where: { $0.range == selection }) else {
                return nil
            }
            if let layer = row.layer, !collapsed.contains(layer) {
                return Outcome(selection: selection, collapsed: collapsed.union([layer]))
            }
            guard let parent = shown.first(where: { $0.layer != nil && $0.layer == row.parent }) else {
                return nil
            }
            return Outcome(selection: parent.range, collapsed: collapsed)
        case .right:
            guard let row = shown.first(where: { $0.range == selection }), let layer = row.layer else {
                return nil
            }
            if collapsed.contains(layer) {
                return Outcome(selection: selection, collapsed: collapsed.subtracting([layer]))
            }
            guard let index = shown.firstIndex(of: row), shown.indices.contains(index + 1),
                  shown[index + 1].parent == layer else
            {
                return nil
            }
            return Outcome(selection: shown[index + 1].range, collapsed: collapsed)
        }
    }

    // MARK: Private

    private static func titles(_ layers: [DecodedLayer]) -> Set<String> {
        layers.reduce(into: Set<String>()) { result, layer in
            result.insert(layer.title)
            result.formUnion(titles(layer.children))
        }
    }

    private static func layer(with range: Range<Int>, in layers: [DecodedLayer]) -> DecodedLayer? {
        for layer in layers {
            if layer.byteRange == range {
                return layer
            }
            if let child = Self.layer(with: range, in: layer.children) {
                return child
            }
        }
        return nil
    }
}
