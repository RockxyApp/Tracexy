import Foundation
import Testing
@testable import Tracexy

/// Help ▸ Keyboard Shortcuts must say exactly what the menus do: every listed command
/// is a menu button in the app's command source, bound to the listed key.
struct KeyboardShortcutReferenceTests {
    // MARK: Internal

    @Test
    func everyEntryMatchesTheMenuSource() throws {
        let sources = try ["Tracexy/TracexyApp.swift", "Tracexy/Views/Projects/ProjectPresentation.swift"]
            .map(readProjectFile)
        for entry in KeyboardShortcutReference.groups.flatMap(\.entries) {
            let expected = try #require(Self.parse(entry.keys), "\(entry.keys) must parse")
            let found = sources.contains { source in
                Self.shortcut(following: entry.command, in: source) == expected
            }
            #expect(found, "\(entry.command) is not bound to \(entry.keys) in the menu source")
        }
    }

    @Test
    func startAndStopShareOneCommand() {
        #expect(KeyboardShortcutReference.groups.flatMap(\.entries).contains { $0.command == "Start Capture" })
    }

    // MARK: Private

    private struct Shortcut: Equatable {
        let key: String
        let modifiers: Set<String>
    }

    private static let symbols: [Character: String] = ["⌘": "command", "⌥": "option", "⇧": "shift", "⌃": "control"]
    private static let namedKeys: [String: String] = ["↓": ".downArrow", "↑": ".upArrow"]

    /// "⌥⌘I" → key "i", modifiers {command, option}.
    private static func parse(_ keys: String) -> Shortcut? {
        var modifiers: Set<String> = []
        var key = ""
        for character in keys {
            if let modifier = symbols[character] {
                modifiers.insert(modifier)
            } else {
                key.append(character)
            }
        }
        guard !key.isEmpty else {
            return nil
        }
        return Shortcut(key: namedKeys[key] ?? "\"\(key.lowercased())\"", modifiers: modifiers)
    }

    /// The `.keyboardShortcut(...)` within a few lines after the button whose title is
    /// `command` (a literal, or the scope actions' `title` constants).
    private static func shortcut(following command: String, in source: String) -> Shortcut? {
        let lines = source.components(separatedBy: "\n")
        let marker = switch command {
        case SessionScopeReturnAction.title: "SessionScopeReturnAction.title"
        case SessionScopeForwardAction.title: "SessionScopeForwardAction.title"
        default: "\"\(command)\""
        }
        guard let start = lines.firstIndex(where: { $0.contains("Button(") && $0.contains(marker) }) else {
            return nil
        }
        for line in lines[start ..< min(start + 8, lines.count)] where line.contains(".keyboardShortcut(") {
            let inner = line.components(separatedBy: ".keyboardShortcut(").last ?? ""
            let parts = inner.components(separatedBy: ", modifiers:")
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let modifierText = parts.count > 1 ? parts[1] : ""
            let modifiers = Set(["command", "option", "shift", "control"].filter { modifierText.contains(".\($0)") })
            return Shortcut(key: key, modifiers: modifiers)
        }
        return nil
    }

    private func readProjectFile(_ relativePath: String) throws -> String {
        var url = URL(fileURLWithPath: #filePath)
        while url.lastPathComponent != "TracexyTests", url.path != "/" {
            url.deleteLastPathComponent()
        }
        url.deleteLastPathComponent()
        return try String(contentsOf: url.appendingPathComponent(relativePath), encoding: .utf8)
    }
}
