import Foundation

// MARK: - GeoIPExpressionBuiltIns

/// `$geoip_country(…)`, `$geoip_city(…)`, `$geoip_asn(…)` and `$geoip_org(…)` in a
/// Session Expression: the sessions with an address the chosen databases place
/// there.
///
/// The public grammar has no location fields, so each use expands to the addresses
/// of the open capture that match, written as `ip in {…}`: the database's network
/// when it covers no private or special range, else the address itself. Private
/// addresses are never looked up, so they never match. A use nothing matches
/// expands to a term no session satisfies.
nonisolated struct GeoIPExpressionBuiltIns: ExpressionMacroBuiltIns {
    // MARK: Internal

    /// One located address of the capture.
    nonisolated struct Entry: Hashable, Sendable {
        let address: IPAddressValue
        let location: GeoIPLocation
    }

    enum Name: String, CaseIterable {
        case country = "geoip_country"
        case city = "geoip_city"
        case asn = "geoip_asn"
        case organization = "geoip_org"
    }

    /// Values per `ip in {…}` set; the parser's own limit.
    static let valuesPerSet = SessionQueryParser.maximumSetValues
    /// A term no session satisfies: no session has both no bytes and some.
    static let matchesNothing = "bytes <= 0 and bytes >= 1"

    let entries: [Entry]

    /// The use of `name` that finds sessions with `value`, for menus.
    static func use(_ name: Name, value: String) -> String {
        let plain = value.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && (scalar.properties.isAlphabetic || ("0" ... "9").contains(scalar) || scalar == "-")
        }
        if plain {
            return "$\(name.rawValue)(\(value))"
        }
        let escaped = value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        return "$\(name.rawValue)(\"\(escaped)\")"
    }

    /// The expression for the addresses in `matched`.
    static func expression(for matched: [Entry]) -> String {
        var terms = Set<String>()
        for entry in matched {
            if let prefix = entry.location.networkPrefix,
               let network = GeoIPNetwork.publicCIDR(entry.address, prefix: prefix)
            {
                terms.insert(network)
            } else if let text = GeoIPNetwork.text(entry.address.bytes, family: entry.address.family) {
                terms.insert(text)
            }
        }
        guard !terms.isEmpty else {
            return matchesNothing
        }
        let sorted = terms.sorted()
        return stride(from: 0, to: sorted.count, by: valuesPerSet).map { start in
            let chunk = sorted[start ..< min(start + valuesPerSet, sorted.count)]
            return "ip in {\(chunk.joined(separator: ", "))}"
        }
        .joined(separator: " or ")
    }

    func expansion(of name: String, values: [String]) -> ExpressionMacroBuiltInExpansion? {
        guard let builtIn = Name(rawValue: name) else {
            return nil
        }
        guard values.count == 1, let value = Self.unquoted(values[0]), !value.isEmpty else {
            return .wrongValueCount(expected: 1)
        }
        let matched = entries.filter { Self.matches($0.location, builtIn, value: value) }
        return .text(Self.expression(for: matched))
    }

    // MARK: Private

    private static func matches(_ location: GeoIPLocation, _ name: Name, value: String) -> Bool {
        let options: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive]
        switch name {
        case .country:
            return [location.countryCode, location.country].contains { candidate in
                candidate.map { $0.compare(value, options: options) == .orderedSame } ?? false
            }
        case .city:
            return location.city.map { $0.compare(value, options: options) == .orderedSame } ?? false
        case .asn:
            var digits = Substring(value)
            if digits.lowercased().hasPrefix("as") {
                digits = digits.dropFirst(2)
            }
            guard let number = UInt32(digits) else {
                return false
            }
            return location.asNumber == number
        case .organization:
            return location.asOrganization?.range(of: value, options: options) != nil
        }
    }

    /// A value as written, without surrounding quotes and with `\"` and `\\` undone.
    private static func unquoted(_ value: String) -> String? {
        guard value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") else {
            return value
        }
        var output = ""
        var escaped = false
        for character in value.dropFirst().dropLast() {
            if escaped {
                output.append(character)
                escaped = false
            } else if character == "\\" {
                escaped = true
            } else {
                output.append(character)
            }
        }
        return escaped ? nil : output
    }
}
