import SwiftUI

// MARK: - FieldFilterMenus

/// The decode tree's Apply as Filter and Prepare as Filter submenus, each with
/// Wireshark's six ways of joining the term to the expression in the editor.
struct FieldFilterMenus: View {
    // MARK: Internal

    let term: String
    let action: (String, DecodedFieldFilter.Combination, Bool) -> Void

    var body: some View {
        Menu("Apply as Filter", systemImage: "line.3.horizontal.decrease.circle") {
            items(applying: true)
        }
        Menu("Prepare as Filter", systemImage: "square.and.pencil") {
            items(applying: false)
        }
    }

    // MARK: Private

    private func items(applying: Bool) -> some View {
        ForEach(DecodedFieldFilter.Combination.allCases) { combination in
            Button(combination.title) {
                action(term, combination, applying)
            }
        }
    }
}

// MARK: - ApplyAsColumnButton

/// Wireshark's Apply as Column: shows the field's value in a View ▸ All Frames
/// column (opening it), or removes the column it already has.
struct ApplyAsColumnButton: View {
    // MARK: Internal

    let key: FieldKey
    let options: PacketDetailOptions

    var body: some View {
        let isColumn = options.frameColumns.contains(key)
        Button(isColumn ? "Remove Column" : "Apply as Column", systemImage: "rectangle.split.3x1") {
            options.toggleFrameColumn(key)
            if !isColumn {
                openWindow(id: TracexyApp.allFramesWindowID)
            }
        }
        .disabled(!isColumn && options.frameColumns.count >= PacketDetailOptions.maximumFrameColumns)
    }

    // MARK: Private

    @Environment(\.openWindow) private var openWindow
}
