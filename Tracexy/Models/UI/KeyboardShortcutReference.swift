import Foundation

// MARK: - KeyboardShortcutReference

/// The app's menu shortcuts, as Help ▸ Keyboard Shortcuts lists them. One list, kept
/// honest by a contract test that finds each command and its key in the menu source,
/// so the reference cannot drift from what the menus actually do.
enum KeyboardShortcutReference {
    struct Entry: Hashable, Identifiable {
        let command: String
        /// The key as macOS menus print it, e.g. "⌥⌘I".
        let keys: String

        var id: String {
            command
        }
    }

    struct Group: Hashable, Identifiable {
        let title: String
        let entries: [Entry]

        var id: String {
            title
        }
    }

    static let groups: [Group] = [
        Group(title: "Capture", entries: [
            Entry(command: "Start Capture", keys: "⌘E"),
            Entry(command: "Restart Capture", keys: "⇧⌘R"),
            Entry(command: "Open…", keys: "⌘O"),
            Entry(command: "Import into Library…", keys: "⌥⌘O"),
            Entry(command: "Close Capture", keys: "⇧⌘W"),
            Entry(command: "Reload", keys: "⌘R"),
            Entry(command: "Get Info", keys: "⌘I"),
        ]),
        Group(title: "Investigate", entries: [
            Entry(command: "Find", keys: "⌘F"),
            Entry(command: "Investigate Sessions…", keys: "⌥⌘I"),
            Entry(command: "Next Session With a Finding", keys: "⌥⌘↓"),
            Entry(command: "Previous Session With a Finding", keys: "⌥⌘↑"),
            Entry(command: "Findings", keys: "⌥⌘E"),
            Entry(command: "Set Time Reference", keys: "⌘T"),
            Entry(command: "All Frames", keys: "⌥⌘A"),
            Entry(command: "Zoom In", keys: "⌘+"),
            Entry(command: "Zoom Out", keys: "⌘-"),
            Entry(command: "Actual Size", keys: "⌘0"),
            Entry(command: "Back to Previous Scope", keys: "⌘["),
            Entry(command: "Forward to Next Scope", keys: "⌘]"),
        ]),
        Group(title: "Projects and Settings", entries: [
            Entry(command: "New Project…", keys: "⇧⌘N"),
            Entry(command: "Settings…", keys: "⌘,"),
            Entry(command: "Tracexy User Guide", keys: "⌘?"),
        ]),
    ]
}
