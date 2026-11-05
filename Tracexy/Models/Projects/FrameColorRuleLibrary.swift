import Foundation
import Observation

// MARK: - FrameColorRule

/// A Project-local ordered packet color rule using Tracexy's bounded grammar.
nonisolated struct FrameColorRule: Codable, Hashable, Sendable, Identifiable {
    // MARK: Lifecycle

    init(
        id: UUID = UUID(), name: String, expression: String,
        foregroundRGB: UInt32, backgroundRGB: UInt32, isEnabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.expression = expression
        self.foregroundRGB = foregroundRGB
        self.backgroundRGB = backgroundRGB
        self.isEnabled = isEnabled
    }

    // MARK: Internal

    let id: UUID
    var name: String
    var expression: String
    /// Packed 0xRRGGBB sRGB value.
    var foregroundRGB: UInt32
    /// Packed 0xRRGGBB sRGB value.
    var backgroundRGB: UInt32
    var isEnabled: Bool
}

// MARK: - FrameColorRuleEvaluation

nonisolated struct FrameColorRuleEvaluation: Sendable {
    let ruleByOrdinal: [UInt64: UUID]
    let unknownOrdinals: Set<UInt64>

    /// Nil means the task was cancelled mid-pass. Up to 200,000 rows times 32
    /// rules is 6.4M evaluations, and paging cancels and restarts this, so a pass
    /// that ignored cancellation would keep a core busy for a page nobody is
    /// looking at any more.
    static func evaluate(_ rules: [FrameColorRule], rows: [CaptureFrameRow]) -> Self? {
        var parser = FrameExpressionParser()
        let parsed = rules.compactMap { rule -> (UUID, FrameExpression)? in
            guard rule.isEnabled, FrameColorRuleLibrary.isValid(rule),
                  let expression = try? parser.parse(rule.expression) else
            {
                return nil
            }
            return (rule.id, expression)
        }
        var matches: [UInt64: UUID] = [:]
        var unknown = Set<UInt64>()
        for (index, row) in rows.enumerated() {
            if index.isMultiple(of: 1_024), Task.isCancelled {
                return nil
            }
            for (id, expression) in parsed {
                switch expression.evaluate(row.filterFacts) {
                case .yes:
                    matches[row.ordinal] = id
                case .unknown:
                    unknown.insert(row.ordinal)
                case .no:
                    continue
                }
                break
            }
        }
        return Self(ruleByOrdinal: matches, unknownOrdinals: unknown)
    }
}

// MARK: - FrameColorRuleEnvelope

private struct FrameColorRuleEnvelope: Codable {
    static let current = Self(formatVersion: 1, grammarID: "tracexy.frame-expression", grammarVersion: 1, rules: [])

    let formatVersion: Int
    let grammarID: String
    let grammarVersion: Int
    var rules: [FrameColorRule]

    func replacingRules(_ rules: [FrameColorRule]) -> Self {
        Self(formatVersion: formatVersion, grammarID: grammarID, grammarVersion: grammarVersion, rules: rules)
    }
}

// MARK: - FrameColorRuleLibrary

/// Ordered color rules persist only in the active Project's preference suite.
@MainActor
@Observable
final class FrameColorRuleLibrary {
    // MARK: Internal

    nonisolated static let maximumRules = 32
    nonisolated static let maximumNameCharacters = 80
    nonisolated static let maximumEncodedBytes = 96 * 1_024

    private(set) var rules: [FrameColorRule] = []
    private(set) var storageAvailable = true

    nonisolated static func isValid(_ rule: FrameColorRule) -> Bool {
        let name = rule.name.trimmingCharacters(in: .whitespacesAndNewlines)
        let expression = rule.expression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= maximumNameCharacters,
              !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }),
              !expression.isEmpty, expression.utf8.count <= 512,
              rule.foregroundRGB <= 0xFFFFFF, rule.backgroundRGB <= 0xFFFFFF,
              contrastRatio(rule.foregroundRGB, rule.backgroundRGB) >= 4.5 else
        {
            return false
        }
        var parser = FrameExpressionParser()
        return (try? parser.parse(expression)) != nil
    }

    nonisolated static func duplicate(_ rule: FrameColorRule, among rules: [FrameColorRule]) -> FrameColorRule? {
        guard rules.count < maximumRules, rules.contains(where: { $0.id == rule.id }) else {
            return nil
        }
        let existingNames = Set(rules.map { normalizedName($0.name) })
        let base = rule.name.trimmingCharacters(in: .whitespacesAndNewlines)
        var suffix = 1
        while suffix <= maximumRules + 1 {
            let ending = suffix == 1 ? " Copy" : " Copy \(suffix)"
            let availableCharacters = max(0, maximumNameCharacters - ending.count)
            let candidate = String(base.prefix(availableCharacters)) + ending
            if !existingNames.contains(normalizedName(candidate)) {
                return FrameColorRule(
                    name: candidate, expression: rule.expression,
                    foregroundRGB: rule.foregroundRGB, backgroundRGB: rule.backgroundRGB,
                    isEnabled: rule.isEnabled
                )
            }
            suffix += 1
        }
        return nil
    }

    func bind(projectID: UUID?, defaults: UserDefaults) {
        self.projectID = projectID
        self.defaults = defaults
        let key = ProjectScopedSettingsKeys.savedFrameColorRules
        guard let data = defaults.data(forKey: key) else {
            rules = []
            storageAvailable = true
            return
        }
        guard data.count <= Self.maximumEncodedBytes,
              let envelope = try? JSONDecoder().decode(FrameColorRuleEnvelope.self, from: data),
              envelope.formatVersion == 1, envelope.grammarID == "tracexy.frame-expression",
              envelope.grammarVersion == 1, envelope.rules.count <= Self.maximumRules,
              envelope.rules.allSatisfy(Self.isValid),
              Set(envelope.rules.map(\.id)).count == envelope.rules.count,
              Set(envelope.rules.map { $0.name.lowercased() }).count == envelope.rules.count else
        {
            UnreadableStoredValue.preserve(data, key: key, in: defaults)
            rules = []
            storageAvailable = false
            return
        }
        rules = envelope.rules
        storageAvailable = true
    }

    @discardableResult
    func replaceAll(_ updated: [FrameColorRule], expectedProjectID: UUID?) -> Bool {
        guard storageAvailable, projectID == expectedProjectID, defaults != nil,
              updated.count <= Self.maximumRules, updated.allSatisfy(Self.isValid),
              Set(updated.map(\.id)).count == updated.count,
              Set(updated.map { $0.name.lowercased() }).count == updated.count else
        {
            return false
        }
        let previous = rules
        rules = updated
        guard persist() else {
            rules = previous
            return false
        }
        return true
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?
    @ObservationIgnored private var projectID: UUID?

    nonisolated private static func normalizedName(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    nonisolated private static func contrastRatio(_ lhs: UInt32, _ rhs: UInt32) -> Double {
        func luminance(_ rgb: UInt32) -> Double {
            let channels = [16, 8, 0].map { shift -> Double in
                let value = Double((rgb >> shift) & 0xFF) / 255
                return value <= 0.04045 ? value / 12.92 : pow((value + 0.055) / 1.055, 2.4)
            }
            return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
        }
        let values = [luminance(lhs), luminance(rhs)].sorted(by: >)
        return (values[0] + 0.05) / (values[1] + 0.05)
    }

    private func persist() -> Bool {
        guard let defaults,
              let data = try? JSONEncoder().encode(FrameColorRuleEnvelope.current.replacingRules(rules)),
              data.count <= Self.maximumEncodedBytes else
        {
            return false
        }
        defaults.set(data, forKey: ProjectScopedSettingsKeys.savedFrameColorRules)
        return true
    }
}
