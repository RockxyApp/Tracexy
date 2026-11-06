import Foundation

nonisolated enum WiresharkHostsImporter {
    struct Result: Equatable {
        let names: [String: String]
        let malformedLines: Int
        let ignoredAliases: Int
        let truncatedNames: Int
        let repeatedAddresses: Int
        let conflictingAddresses: Int
    }

    enum ImportError: Error, Equatable {
        case fileTooLarge
        case tooManyLines
        case tooManyAddresses
        case noUsableEntries
    }

    static let maximumFileBytes = 256 * 1_024
    static let maximumLines = 10_000
    static let maximumAddresses = AddressNameBook.maximumEntries

    /// Parses the standard hosts-file shape used by Wireshark. For one IP with
    /// multiple aliases, the first hostname is imported; additional aliases are
    /// counted because the Project address book intentionally stores one label/IP.
    static func parse(_ data: Data) throws -> Result {
        guard data.count <= maximumFileBytes else {
            throw ImportError.fileTooLarge
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw ImportError.noUsableEntries
        }
        let normalizedText = text.hasPrefix("\u{FEFF}") ? String(text.dropFirst()) : text
        let lines = normalizedText.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
        guard lines.count <= maximumLines else {
            throw ImportError.tooManyLines
        }
        var names: [String: String] = [:]
        var malformedLines = 0
        var ignoredAliases = 0
        var truncatedNames = 0
        var repeatedAddresses = 0
        var conflictingAddresses = 0
        for line in lines {
            let content = line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
            let fields = content.split(whereSeparator: \.isWhitespace)
            guard !fields.isEmpty else {
                continue
            }
            guard fields.count >= 2,
                  let address = IPAddressValue(parsing: String(fields[0])) else
            {
                malformedLines += 1
                continue
            }
            let key = address.compressedText.lowercased()
            let fullName = String(fields[1])
            guard !fullName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                malformedLines += 1
                continue
            }
            let name = String(fullName.prefix(AddressNameBook.maximumNameCharacters))
            if name.count < fullName.count {
                truncatedNames += 1
            }
            if let existing = names[key] {
                repeatedAddresses += 1
                if existing != name {
                    conflictingAddresses += 1
                }
            }
            names[key] = name
            ignoredAliases += max(0, fields.count - 2)
            guard names.count <= maximumAddresses else {
                throw ImportError.tooManyAddresses
            }
        }
        guard !names.isEmpty else {
            throw ImportError.noUsableEntries
        }
        return Result(
            names: names,
            malformedLines: malformedLines,
            ignoredAliases: ignoredAliases,
            truncatedNames: truncatedNames,
            repeatedAddresses: repeatedAddresses,
            conflictingAddresses: conflictingAddresses
        )
    }
}
