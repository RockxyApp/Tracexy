import SwiftUI

// MARK: - KeyboardShortcutsView

/// Help ▸ Keyboard Shortcuts: the menu commands that have a key, grouped the way
/// the menus group them. Read-only; every command is also in the menu bar.
struct KeyboardShortcutsView: View {
    var body: some View {
        Form {
            ForEach(KeyboardShortcutReference.groups) { group in
                Section(group.title) {
                    ForEach(group.entries) { entry in
                        LabeledContent(entry.command) {
                            Text(entry.keys)
                                .font(Theme.Typography.mono)
                                .foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 380, idealWidth: 420, minHeight: 420)
    }
}
