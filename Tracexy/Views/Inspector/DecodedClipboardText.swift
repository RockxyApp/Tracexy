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
}
