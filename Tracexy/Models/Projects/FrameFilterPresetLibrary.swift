import Foundation
import Observation

// MARK: - SavedFrameFilter

/// A named Tracexy Frame Expression. Its grammar is intentionally distinct from
/// Wireshark display filters and Session Expressions.
nonisolated struct SavedFrameFilter: Codable, Hashable, Sendable, Identifiable {
    // MARK: Lifecycle

    init(id: UUID = UUID(), name: String, expression: String) {
        self.id = id
        self.name = name
        self.expression = expression
    }

    // MARK: Internal

    let id: UUID
    var name: String
    var expression: String
}

// MARK: - SavedFrameFilterEnvelope

private struct SavedFrameFilterEnvelope: Codable {
    static let current = SavedFrameFilterEnvelope(
        formatVersion: 1,
        grammarID: "tracexy.frame-expression",
        grammarVersion: 1,
        filters: []
    )

    let formatVersion: Int
    let grammarID: String
    let grammarVersion: Int
    var filters: [SavedFrameFilter]
}

// MARK: - FrameFilterPresetLibrary

/// Named presets stored only in the active Project's preferences. Loading a preset
/// edits the draft; applying it remains an explicit action in All Frames.
@MainActor
@Observable
final class FrameFilterPresetLibrary {
    // MARK: Internal

    nonisolated static let maximumFilters = 40
    nonisolated static let maximumNameCharacters = 80
    nonisolated static let maximumEncodedBytes = 128 * 1_024

    private(set) var filters: [SavedFrameFilter] = []
    private(set) var storageAvailable = true

    nonisolated static func isValid(_ filter: SavedFrameFilter) -> Bool {
        let name = filter.name.trimmingCharacters(in: .whitespacesAndNewlines)
        let expression = filter.expression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= maximumNameCharacters,
              !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }),
              !expression.isEmpty, expression.utf8.count <= 512 else
        {
            return false
        }
        var parser = FrameExpressionParser()
        return (try? parser.parse(expression)) != nil
    }

    func bind(projectID: UUID?, defaults: UserDefaults) {
        self.projectID = projectID
        self.defaults = defaults
        let key = ProjectScopedSettingsKeys.savedFrameFilters
        guard let data = defaults.data(forKey: key) else {
            filters = []
            storageAvailable = true
            return
        }
        guard data.count <= Self.maximumEncodedBytes,
              let envelope = try? JSONDecoder().decode(SavedFrameFilterEnvelope.self, from: data),
              envelope.formatVersion == 1,
              envelope.grammarID == "tracexy.frame-expression",
              envelope.grammarVersion == 1,
              envelope.filters.count <= Self.maximumFilters,
              envelope.filters.allSatisfy(Self.isValid),
              Set(envelope.filters.map(\.id)).count == envelope.filters.count,
              Set(envelope.filters.map { $0.name.lowercased() }).count == envelope.filters.count else
        {
            UnreadableStoredValue.preserve(data, key: key, in: defaults)
            filters = []
            storageAvailable = false
            return
        }
        filters = envelope.filters
        storageAvailable = true
    }

    /// Adds or replaces a preset by case-insensitive name. `expectedProjectID`
    /// prevents a sheet opened in one Project from writing into another.
    @discardableResult
    func save(name: String, expression: String, expectedProjectID: UUID?) -> Bool {
        guard storageAvailable, projectID == expectedProjectID, defaults != nil else {
            return false
        }
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanExpression = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        let candidate = SavedFrameFilter(name: cleanName, expression: cleanExpression)
        guard Self.isValid(candidate) else {
            return false
        }
        let previous = filters
        if let index = filters.firstIndex(where: { $0.name.caseInsensitiveCompare(cleanName) == .orderedSame }) {
            filters[index] = SavedFrameFilter(id: filters[index].id, name: cleanName, expression: cleanExpression)
        } else {
            guard filters.count < Self.maximumFilters,
                  !filters.contains(where: { $0.id == candidate.id }) else
            {
                return false
            }
            filters.append(candidate)
        }
        if persist() {
            return true
        }
        filters = previous
        return false
    }

    @discardableResult
    func remove(_ id: UUID, expectedProjectID: UUID?) -> Bool {
        guard storageAvailable, projectID == expectedProjectID, defaults != nil else {
            return false
        }
        let previous = filters
        filters.removeAll { $0.id == id }
        if persist() {
            return true
        }
        filters = previous
        return false
    }

    @discardableResult
    func replaceAll(_ updated: [SavedFrameFilter], expectedProjectID: UUID?) -> Bool {
        guard storageAvailable, projectID == expectedProjectID, defaults != nil,
              updated.count <= Self.maximumFilters,
              updated.allSatisfy(Self.isValid),
              Set(updated.map(\.id)).count == updated.count,
              Set(updated.map { $0.name.lowercased() }).count == updated.count else
        {
            return false
        }
        let previous = filters
        filters = updated
        if persist() {
            return true
        }
        filters = previous
        return false
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?
    @ObservationIgnored private var projectID: UUID?

    private func persist() -> Bool {
        guard let defaults else {
            return false
        }
        let envelope = SavedFrameFilterEnvelope.current.with(filters: filters)
        guard let data = try? JSONEncoder().encode(envelope), data.count <= Self.maximumEncodedBytes else {
            return false
        }
        defaults.set(data, forKey: ProjectScopedSettingsKeys.savedFrameFilters)
        return true
    }
}

private extension SavedFrameFilterEnvelope {
    func with(filters: [SavedFrameFilter]) -> Self {
        Self(formatVersion: formatVersion, grammarID: grammarID, grammarVersion: grammarVersion, filters: filters)
    }
}
