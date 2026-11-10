import Foundation

// MARK: - DecodedClipboardText

/// Pure, side-effect-free clipboard formatting for the decode tree's contextual
/// copy actions. Kept out of the view so the exact text each menu item produces
/// is unit-testable, and so the view is left with only the pasteboard call.
///
/// Every string here is derived solely from values already present on the
/// decoded `DecodedField`/`DecodedLayer` — nothing is inferred, fetched, or
/// fabricated. Names and values are emitted verbatim.
enum DecodedClipboardText {
    /// A field's value alone (the "Copy Value" action).
    static func value(_ field: DecodedField) -> String {
        field.value
    }

    /// A field's name alone (the "Copy Field Name" action).
    static func name(_ field: DecodedField) -> String {
        field.name
    }

    /// A field as `Name: Value`, the form most useful to paste into notes or a
    /// bug report (the `Copy "Name: Value"` action).
    static func nameValue(_ field: DecodedField) -> String {
        "\(field.name): \(field.value)"
    }

    /// The layer header exactly as shown in the tree: its title, plus the summary
    /// when one is present. Field values keep their own deliberate copy actions.
    static func layerSummary(_ layer: DecodedLayer) -> String {
        layer.summary.isEmpty ? layer.title : "\(layer.title): \(layer.summary)"
    }

    /// The clicked layer and only its currently expanded displayed descendants.
    /// Siblings and fields absent from the supplied display projection are never read.
    static func visibleSubtree(_ layer: DecodedLayer, collapsed: Set<String>) -> String {
        var lines: [String] = []

        func appendLines(_ text: String, prefix: String, continuation: String) {
            let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
                .replacingOccurrences(of: "\r", with: "\n")
            let parts = normalized.components(separatedBy: "\n")
            for (index, part) in parts.enumerated() {
                lines.append((index == 0 ? prefix : continuation) + part)
            }
        }

        func append(_ current: DecodedLayer, depth: Int) {
            let indentation = String(repeating: "  ", count: depth)
            appendLines(layerSummary(current), prefix: indentation, continuation: indentation)
            guard !collapsed.contains(current.title) else {
                return
            }
            for field in current.fields {
                let fieldIndentation = indentation + "  "
                appendLines(
                    field.value, prefix: "\(fieldIndentation)\(field.name): ",
                    continuation: fieldIndentation + "  "
                )
            }
            for child in current.children {
                append(child, depth: depth + 1)
            }
        }

        append(layer, depth: 0)
        return lines.joined(separator: "\n")
    }
}
