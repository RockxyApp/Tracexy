import AppKit
import SwiftUI

// Native bottom safe-area bar for the sidebar: a capture menu beside the
// expanding search field, matching Finder/Xcode navigator chrome.

// MARK: - SidebarBottomBar

struct SidebarBottomBar<AddMenu: View>: View {
    @Binding var searchText: String

    /// Menu items shown under the "+" button (Save Current / Import…).
    @ViewBuilder var addMenu: () -> AddMenu

    var body: some View {
        // The shared footer primitive owns the row height, the sidebar material
        // and the top seam, so this bar aligns with the workspace and inspector
        // footers. It contributes only local sidebar search + the captures menu.
        WorkspaceFooterBar(surface: .sidebar) {
            HStack(spacing: Theme.Metrics.spacingM) {
                Menu {
                    addMenu()
                } label: {
                    Image(systemName: "plus")
                        .font(.system(size: Theme.Icon.medium))
                        .frame(width: 24, height: 28)
                        .contentShape(Rectangle())
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Save or import a capture")
                .accessibilityLabel("Save or import a capture")

                NativeSidebarSearchField(text: $searchText)
                    .frame(maxWidth: .infinity, minHeight: 28)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
        }
    }
}

// MARK: - NativeSidebarSearchField

private struct NativeSidebarSearchField: NSViewRepresentable {
    // MARK: Internal

    @MainActor
    final class Coordinator: NSObject, NSSearchFieldDelegate {
        // MARK: Lifecycle

        init(text: Binding<String>) {
            self.text = text
        }

        // MARK: Internal

        var text: Binding<String>

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSearchField else {
                return
            }
            text.wrappedValue = field.stringValue
        }
    }

    @Binding var text: String

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = String(localized: "Search")
        field.toolTip = String(localized: "Search sidebar")
        field.controlSize = .regular
        field.focusRingType = .exterior
        field.sendsWholeSearchString = false
        field.sendsSearchStringImmediately = true
        field.delegate = context.coordinator
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.setAccessibilityLabel(String(localized: "Search sidebar"))
        configure(field)
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.text = $text
        if field.stringValue != text {
            field.stringValue = text
        }
        configure(field)
    }

    // MARK: Private

    private func configure(_ field: NSSearchField) {
        field.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        guard let cell = field.cell as? NSSearchFieldCell else {
            return
        }
        cell.searchButtonCell?.image = NSImage(
            systemSymbolName: "line.3.horizontal.decrease.circle",
            accessibilityDescription: String(localized: "Search")
        )
    }
}
