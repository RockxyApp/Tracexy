import AppKit
import SwiftUI

// Native bottom safe-area bar for the sidebar: a capture menu beside the
// expanding search field, matching Finder/Xcode navigator chrome.

// MARK: - SidebarFilterFocusAction

/// Moves keyboard focus into the sidebar's filter field for the focused window.
///
/// The footer cannot publish this itself: `NativeWorkspaceSplitView` re-hosts the
/// sidebar in its own `NSHostingController`, which starts a SwiftUI graph outside
/// the `WindowGroup`'s scene, so a `focusedSceneValue` sent from inside the sidebar
/// never reaches the app's `Commands`. The scene publishes the action instead, and
/// the action finds the real `NSSearchField` through AppKit, where the split view
/// controller's hosting boundary does not exist.
struct SidebarFilterFocusAction {
    // MARK: Internal

    /// Set on the search field so this action can find it again across the
    /// AppKit hosting boundary.
    static let fieldIdentifier = "tracexy.sidebar.filter-field"

    /// - Returns: `true` when a filter field was found and took first responder.
    /// Whether the route can work at all right now. The command is listed
    /// always, so it must go disabled when it cannot act rather than look
    /// available and quietly do nothing.
    @MainActor var canFocus: Bool {
        guard let (window, _) = Self.locateField() else {
            return false
        }
        return window.attachedSheet == nil
    }

    /// - Returns: `true` when a filter field was found and took first responder.
    @MainActor
    @discardableResult
    func focus() -> Bool {
        // The field's own window, not NSApp.keyWindow. Key belongs to whatever
        // is frontmost, which is routinely a sheet or a panel, while the
        // workspace holds main instead.
        guard let (window, field) = Self.locateField() else {
            return false
        }
        // A modal sheet owns key and will not give it up, so first responder
        // behind it would look focused while the keystrokes went nowhere.
        guard window.attachedSheet == nil else {
            return false
        }
        if !window.isKeyWindow {
            window.makeKeyAndOrderFront(nil)
        }
        return window.makeFirstResponder(field)
    }

    // MARK: Private

    /// Breadth-first so the footer's field is reached without recursing through
    /// the whole session table first.
    /// The window that actually contains the field, so the caller never has to
    /// assume it is the key one.
    @MainActor
    private static func locateField() -> (NSWindow, NSSearchField)? {
        for window in NSApp.windows {
            if let root = window.contentView, let field = filterField(in: root) {
                return (window, field)
            }
        }
        return nil
    }

    @MainActor
    private static func filterField(in root: NSView) -> NSSearchField? {
        var queue = [root]
        var index = 0
        while index < queue.count {
            let view = queue[index]
            index += 1
            if let field = view as? NSSearchField,
               field.accessibilityIdentifier() == fieldIdentifier
            {
                return field
            }
            queue.append(contentsOf: view.subviews)
        }
        return nil
    }
}

// MARK: - SidebarFilterFocusKey

private struct SidebarFilterFocusKey: FocusedValueKey {
    typealias Value = SidebarFilterFocusAction
}

extension FocusedValues {
    /// Non-nil only while the main workspace scene is focused, so
    /// View ▸ Filter Sidebar disables itself in every auxiliary window.
    var focusSidebarFilter: SidebarFilterFocusAction? {
        get { self[SidebarFilterFocusKey.self] }
        set { self[SidebarFilterFocusKey.self] = newValue }
    }
}

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
        // How View ▸ Filter Sidebar finds this field; it does not change the
        // label VoiceOver reads.
        field.setAccessibilityIdentifier(SidebarFilterFocusAction.fieldIdentifier)
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
