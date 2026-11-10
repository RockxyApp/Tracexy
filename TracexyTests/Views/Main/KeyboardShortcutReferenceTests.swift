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
                Self.shortcuts(following: entry.command, in: source).contains(expected)
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

    /// Every `.keyboardShortcut(...)` found within a few lines after an occurrence
    /// of `command` — a title literal, or the scope actions' `title` constants.
    ///
    /// The title is not required to sit on the `Button(` line itself. A command
    /// whose label is a view rather than a string writes its titles inside the
    /// trailing `label:` closure, which is still the button's own declaration and
    /// still directly above its shortcut; requiring `Button(` read that form as
    /// an unbound command. Every occurrence is tried, so a title that also
    /// appears elsewhere in the file cannot mask the binding.
    private static func shortcuts(following command: String, in source: String) -> [Shortcut] {
        let lines = source.components(separatedBy: "\n")
        let marker = switch command {
        case SessionScopeReturnAction.title: "SessionScopeReturnAction.title"
        case SessionScopeForwardAction.title: "SessionScopeForwardAction.title"
        default: "\"\(command)\""
        }
        return lines.indices.filter { lines[$0].contains(marker) }.compactMap { start in
            for line in lines[start ..< min(start + 8, lines.count)]
                where line.contains(".keyboardShortcut(")
            {
                let inner = line.components(separatedBy: ".keyboardShortcut(").last ?? ""
                let parts = inner.components(separatedBy: ", modifiers:")
                let key = parts[0].trimmingCharacters(in: .whitespaces)
                let modifierText = parts.count > 1 ? parts[1] : ""
                let modifiers = Set(
                    ["command", "option", "shift", "control"].filter { modifierText.contains(".\($0)") }
                )
                return Shortcut(key: key, modifiers: modifiers)
            }
            return nil
        }
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
