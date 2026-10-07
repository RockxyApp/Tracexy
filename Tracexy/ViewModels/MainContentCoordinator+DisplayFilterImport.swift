import AppKit
import Foundation
import UniformTypeIdentifiers

// MARK: - DisplayFilterImportResult

/// What importing a Wireshark `dfilters` file did: the filters saved as Session
/// Expressions, the ones that do not translate and why, and any the library had
/// no room for.
struct DisplayFilterImportResult: Equatable {
    struct Imported: Equatable {
        let name: String
        let expression: String
        let approximate: Bool
    }

    struct Refused: Equatable {
        let name: String
        let reason: String
    }

    var imported: [Imported] = []
    var refused: [Refused] = []
    var notSavedForCapacity = 0

    /// A short account for the alert shown after an import.
    var summary: String {
        var lines: [String] = []
        let total = imported.count + refused.count + notSavedForCapacity
        lines.append("Saved \(imported.count) of \(total) display filters as Session Expressions.")
        let approximate = imported.filter(\.approximate).map(\.name)
        if !approximate.isEmpty {
            lines.append("Read as findings — check that they mean what you want: "
                + ListFormatter.localizedString(byJoining: approximate.prefix(6).map { "“\($0)”" }) + ".")
        }
        for refusal in refused.prefix(8) {
            lines.append("“\(refusal.name)”: \(refusal.reason)")
        }
        if refused.count > 8 {
            lines.append("\(refused.count - 8) more did not translate.")
        }
        if notSavedForCapacity > 0 {
            lines.append("\(notSavedForCapacity) were not saved because this Project already holds "
                + "\(SessionExpressionLibrary.maximumSaved) saved expressions.")
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - Import

@MainActor
extension MainContentCoordinator {
    /// Investigate Sessions ▸ Saved ▸ Import Wireshark Display Filters…
    func presentDisplayFilterImport() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = String(
            localized: "Choose a Wireshark display-filter list (“dfilters”). Filters that describe sessions become saved Session Expressions."
        )
        panel.prompt = String(localized: "Import")
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        let alert = NSAlert()
        do {
            let result = try importWiresharkDisplayFilters(from: url)
            alert.messageText = String(localized: "Display Filters Imported")
            alert.informativeText = result.summary
        } catch {
            alert.alertStyle = .warning
            alert.messageText = String(localized: "Couldn’t Import Display Filters")
            alert.informativeText = Self.displayFilterListMessage(error)
        }
        alert.runModal()
    }

    /// The panel-free route for tests: read, translate and save.
    func importWiresharkDisplayFilters(from url: URL) throws -> DisplayFilterImportResult {
        let entries = try CaptureFilterList.load(from: url)
        var result = DisplayFilterImportResult()
        for entry in entries {
            switch DisplayFilterTranslator.translate(entry.expression) {
            case let .translated(expression, approximate):
                if expressionLibrary.save(expression, named: entry.name) {
                    result.imported.append(.init(name: entry.name, expression: expression, approximate: approximate))
                } else {
                    result.notSavedForCapacity += 1
                }
            case let .untranslatable(reason):
                result.refused.append(.init(name: entry.name, reason: reason))
            }
        }
        return result
    }

    /// The list reader speaks of capture filters; say display filters here.
    private static func displayFilterListMessage(_ error: Error) -> String {
        guard let failure = error as? CaptureFilterList.Failure else {
            return error.localizedDescription
        }
        return switch failure {
        case .empty: "This file contains no named display filters."
        case .tooLarge: "The display-filter list exceeds 256 KiB."
        case .tooManyEntries: "The display-filter list contains more than 256 entries."
        case let .invalidLine(line): "Line \(line) must contain a quoted name and a filter of up to 1,024 characters."
        default: failure.localizedDescription.replacingOccurrences(of: "capture-filter", with: "display-filter")
        }
    }
}
