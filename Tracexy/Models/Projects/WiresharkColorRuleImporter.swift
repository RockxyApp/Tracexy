import CoreFoundation
import Foundation

// MARK: - WiresharkColorRuleImportResult

nonisolated struct WiresharkColorRuleImportResult: Sendable {
    let rules: [FrameColorRule]
    let skipped: [String]
    let sourceRuleCount: Int
}

// MARK: - WiresharkColorRuleImportError

nonisolated enum WiresharkColorRuleImportError: Error, Equatable {
    case fileTooLarge
    case malformedFile
    case tooManyRules
}

// MARK: - WiresharkColorRuleImporter

/// Imports only Wireshark coloring rules whose filters are supported by
/// Tracexy's Frame Expression grammar. It never reads Wireshark profile paths.
nonisolated enum WiresharkColorRuleImporter {
    // MARK: Internal

    static let maximumFileBytes = 1_048_576
    static let maximumSourceRules = 256

    static func parse(_ data: Data) throws -> WiresharkColorRuleImportResult {
        guard data.count <= maximumFileBytes else {
            throw WiresharkColorRuleImportError.fileTooLarge
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw WiresharkColorRuleImportError.malformedFile
        }
        let normalizedText = text.hasPrefix("\u{FEFF}") ? String(text.dropFirst()) : text
        let trimmed = normalizedText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw WiresharkColorRuleImportError.malformedFile
        }
        if trimmed.first == "[" || trimmed.first == "{" || trimmed.hasPrefix("//") || trimmed.hasPrefix("/*") {
            return try parseJSONC(normalizedText)
        }
        return try parseLegacyColorFilters(normalizedText)
    }

    // MARK: Private

    private static func parseJSONC(_ text: String) throws -> WiresharkColorRuleImportResult {
        guard let jsonc = stripJSONCCommentsAndTrailingCommas(text),
              let root = try? JSONSerialization.jsonObject(with: jsonc),
              let records = root as? [Any] else
        {
            throw WiresharkColorRuleImportError.malformedFile
        }
        guard records.count <= maximumSourceRules else {
            throw WiresharkColorRuleImportError.tooManyRules
        }

        var accepted: [FrameColorRule] = []
        var skipped: [String] = []
        for (index, rawRecord) in records.enumerated() {
            guard let record = rawRecord as? [String: Any], record.count == 1,
                  let (name, rawRule) = record.first,
                  let fields = rawRule as? [String: Any] else
            {
                skipped.append("Rule \(index + 1): expected one named rule object.")
                continue
            }
            guard let expression = fields["filter"] as? String else {
                skipped.append("\(shortName(name)): missing a string filter.")
                continue
            }
            guard let foregroundText = fields["foreground"] as? String,
                  let foreground = rgb(foregroundText) else
            {
                skipped.append("\(shortName(name)): invalid foreground color; expected #RRGGBB or RRGGBB.")
                continue
            }
            guard let backgroundText = fields["background"] as? String,
                  let background = rgb(backgroundText) else
            {
                skipped.append("\(shortName(name)): invalid background color; expected #RRGGBB or RRGGBB.")
                continue
            }
            guard let enabledNumber = fields["enabled"] as? NSNumber,
                  CFGetTypeID(enabledNumber) == CFBooleanGetTypeID() else
            {
                skipped.append("\(shortName(name)): enabled must be a boolean.")
                continue
            }
            let rule = FrameColorRule(
                name: name, expression: expression, foregroundRGB: foreground,
                backgroundRGB: background, isEnabled: enabledNumber.boolValue
            )
            if let reason = validationFailure(rule) {
                skipped.append("\(shortName(name)): \(reason)")
                continue
            }
            accepted.append(rule)
        }
        return WiresharkColorRuleImportResult(rules: accepted, skipped: skipped, sourceRuleCount: records.count)
    }

    private static func parseLegacyColorFilters(_ text: String) throws -> WiresharkColorRuleImportResult {
        var accepted: [FrameColorRule] = []
        var skipped: [String] = []
        var sourceRuleCount = 0
        for (lineIndex, sourceLine) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            let line = sourceLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#") else {
                continue
            }
            sourceRuleCount += 1
            guard sourceRuleCount <= maximumSourceRules else {
                throw WiresharkColorRuleImportError.tooManyRules
            }
            guard line.first == "@" else {
                skipped.append("Line \(lineIndex + 1): invalid legacy rule syntax.")
                continue
            }
            let components = line.split(separator: "@", maxSplits: 3, omittingEmptySubsequences: false)
            guard components.count == 4,
                  let colors = legacyColors(String(components[3])) else
            {
                skipped.append("Line \(lineIndex + 1): invalid legacy rule syntax or colors.")
                continue
            }
            let name = String(components[1])
            let expression = String(components[2])
            let rule = FrameColorRule(
                name: name, expression: expression, foregroundRGB: colors.foreground,
                backgroundRGB: colors.background
            )
            if let reason = validationFailure(rule) {
                skipped.append("\(name.isEmpty ? "Line \(lineIndex + 1)" : shortName(name)): \(reason)")
                continue
            }
            accepted.append(rule)
        }
        guard sourceRuleCount > 0 else {
            throw WiresharkColorRuleImportError.malformedFile
        }
        return WiresharkColorRuleImportResult(rules: accepted, skipped: skipped, sourceRuleCount: sourceRuleCount)
    }

    private static func legacyColors(_ text: String) -> (background: UInt32, foreground: UInt32)? {
        guard text.first == "[", let firstClose = text.firstIndex(of: "]") else {
            return nil
        }
        let backgroundText = String(text[...firstClose])
        let foregroundText = String(text[text.index(after: firstClose)...])
        guard let backgroundComponents = legacyComponents(backgroundText),
              let foregroundComponents = legacyComponents(foregroundText) else
        {
            return nil
        }
        return (pack(backgroundComponents), pack(foregroundComponents))
    }

    private static func legacyComponents(_ text: String) -> [UInt16]? {
        guard text.first == "[", text.last == "]" else {
            return nil
        }
        let body = text.dropFirst().dropLast()
        let parts = body.split(separator: ",", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            return nil
        }
        let values = parts.compactMap { UInt16(String($0).trimmingCharacters(in: .whitespaces)) }
        return values.count == 3 ? values : nil
    }

    private static func pack(_ components: [UInt16]) -> UInt32 {
        let rgb = components.map { (UInt32($0) * 255 + 32_767) / 65_535 }
        return (rgb[0] << 16) | (rgb[1] << 8) | rgb[2]
    }

    private static func rgb(_ text: String) -> UInt32? {
        let digits = text.hasPrefix("#") ? String(text.dropFirst()) : text
        guard digits.count == 6, let value = UInt32(digits, radix: 16) else {
            return nil
        }
        return value
    }

    private static func validationFailure(_ rule: FrameColorRule) -> String? {
        var parser = FrameExpressionParser()
        do {
            _ = try parser.parse(rule.expression)
        } catch let error as FrameExpressionError {
            return "filter is outside the supported Frame Expression subset (\(error.reason), position \(error.position))."
        } catch {
            return "filter is outside the supported Frame Expression subset."
        }
        guard FrameColorRuleLibrary.isValid(rule) else {
            return "invalid rule name or foreground/background contrast below 4.5:1."
        }
        return nil
    }

    private static func shortName(_ name: String) -> String {
        name.unicodeScalars.prefix(FrameColorRuleLibrary.maximumNameCharacters).map {
            CharacterSet.controlCharacters.contains($0) ? " " : String($0)
        }.joined()
    }

    private static func stripJSONCCommentsAndTrailingCommas(_ source: String) -> Data? {
        let bytes = Array(source.utf8)
        var uncommented: [UInt8] = []
        uncommented.reserveCapacity(bytes.count)
        var index = 0
        var inString = false
        var escaped = false
        var lineComment = false
        var blockComment = false
        while index < bytes.count {
            let byte = bytes[index]
            let next = index + 1 < bytes.count ? bytes[index + 1] : 0
            if lineComment {
                if byte == 10 || byte == 13 {
                    lineComment = false
                    uncommented.append(byte)
                } else {
                    uncommented.append(32)
                }
            } else if blockComment {
                if byte == 42, next == 47 {
                    uncommented.append(contentsOf: [32, 32])
                    index += 1
                    blockComment = false
                } else {
                    uncommented.append(byte == 10 || byte == 13 ? byte : 32)
                }
            } else if inString {
                uncommented.append(byte)
                if escaped {
                    escaped = false
                } else if byte == 92 {
                    escaped = true
                } else if byte == 34 {
                    inString = false
                }
            } else if byte == 34 {
                inString = true
                uncommented.append(byte)
            } else if byte == 47, next == 47 {
                uncommented.append(contentsOf: [32, 32])
                index += 1
                lineComment = true
            } else if byte == 47, next == 42 {
                uncommented.append(contentsOf: [32, 32])
                index += 1
                blockComment = true
            } else {
                uncommented.append(byte)
            }
            index += 1
        }
        guard !inString, !blockComment else {
            return nil
        }

        var output: [UInt8] = []
        output.reserveCapacity(uncommented.count)
        inString = false
        escaped = false
        for (position, byte) in uncommented.enumerated() {
            if inString {
                output.append(byte)
                if escaped {
                    escaped = false
                } else if byte == 92 {
                    escaped = true
                } else if byte == 34 {
                    inString = false
                }
            } else if byte == 34 {
                inString = true
                output.append(byte)
            } else if byte == 44 {
                var lookahead = position + 1
                while lookahead < uncommented.count,
                      uncommented[lookahead] == 32 || uncommented[lookahead] == 9
                      || uncommented[lookahead] == 10 || uncommented[lookahead] == 13
                {
                    lookahead += 1
                }
                if lookahead < uncommented.count,
                   uncommented[lookahead] != 93, uncommented[lookahead] != 125
                {
                    output.append(byte)
                }
            } else {
                output.append(byte)
            }
        }
        return Data(output)
    }
}
