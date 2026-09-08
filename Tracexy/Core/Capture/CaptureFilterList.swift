import Darwin
import Foundation

// MARK: - NamedCaptureFilter

/// A named capture expression from an explicitly selected filter-list document.
/// These are BPF capture expressions, never session or display-filter rules.
nonisolated struct NamedCaptureFilter: Identifiable, Equatable, Sendable {
    let line: Int
    let name: String
    let expression: String

    var id: Int {
        line
    }
}

// MARK: - CaptureFilterList

/// The documented quoted-name + expression text format used by cfilters.
/// Parsing never evaluates an expression, resolves hosts, or starts a capture.
nonisolated enum CaptureFilterList {
    // MARK: Internal

    enum Failure: Error, Equatable, LocalizedError {
        case tooLarge
        case invalidText
        case invalidLine(Int)
        case tooManyEntries
        case empty
        case unreadable
        case notRegularFile

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case .tooLarge: "The capture-filter list exceeds 256 KiB."
            case .invalidText: "Choose a UTF-8 capture-filter list without control characters."
            case let .invalidLine(line): "Line \(line) must contain a quoted name and a BPF expression of up to 1,024 characters."
            case .tooManyEntries: "The capture-filter list contains more than 256 entries."
            case .empty: "This file contains no named capture filters."
            case .unreadable: "The capture-filter list could not be read. Choose it again."
            case .notRegularFile: "Choose a regular capture-filter text file."
            }
        }
    }

    static let maximumBytes = 262_144
    static let maximumEntries = 256
    static let maximumNameLength = 128

    /// Bounded descriptor-based read. O_NONBLOCK prevents a selected FIFO from
    /// hanging before its file kind can be checked; no source is ever modified.
    static func load(from url: URL) throws -> [NamedCaptureFilter] {
        let descriptor = url.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDONLY | O_NONBLOCK | O_CLOEXEC) } ?? -1
        }
        guard descriptor >= 0 else {
            throw Failure.unreadable
        }
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else {
            throw Failure.unreadable
        }
        guard metadata.st_mode & S_IFMT == S_IFREG else {
            throw Failure.notRegularFile
        }
        guard metadata.st_size >= 0, metadata.st_size <= maximumBytes else {
            throw Failure.tooLarge
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            try Task.checkCancellation()
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR {
                    continue
                }
                throw Failure.unreadable
            }
            if count == 0 {
                break
            }
            guard data.count + count <= maximumBytes else {
                throw Failure.tooLarge
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        try Task.checkCancellation()
        return try parse(data)
    }

    static func parse(_ data: Data) throws -> [NamedCaptureFilter] {
        guard data.count <= maximumBytes else {
            throw Failure.tooLarge
        }
        guard var text = String(data: data, encoding: .utf8) else {
            throw Failure.invalidText
        }
        if text.first == "\u{FEFF}" {
            text.removeFirst()
        }
        guard !text.unicodeScalars.contains(where: {
            CharacterSet.controlCharacters.contains($0) && $0 != "\n" && $0 != "\r" && $0 != "\t"
        }) else {
            throw Failure.invalidText
        }
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        var entries: [NamedCaptureFilter] = []
        for (index, raw) in lines.enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }
            guard !line.contains("\r"), entries.count < maximumEntries else {
                throw entries.count >= maximumEntries ? Failure.tooManyEntries : Failure.invalidLine(index + 1)
            }
            try entries.append(parseLine(line, number: index + 1))
        }
        guard !entries.isEmpty else {
            throw Failure.empty
        }
        return entries
    }

    // MARK: Private

    private static func parseLine(_ line: String, number: Int) throws -> NamedCaptureFilter {
        guard line.first == "\"" else {
            throw Failure.invalidLine(number)
        }
        var cursor = line.index(after: line.startIndex)
        var name = ""
        var closed = false
        while cursor < line.endIndex {
            let character = line[cursor]
            cursor = line.index(after: cursor)
            if character == "\"" {
                closed = true
                break
            }
            if character == "\\" {
                guard cursor < line.endIndex, line[cursor] == "\\" || line[cursor] == "\"" else {
                    throw Failure.invalidLine(number)
                }
                name.append(line[cursor])
                cursor = line.index(after: cursor)
            } else {
                name.append(character)
            }
            guard name.count <= maximumNameLength else {
                throw Failure.invalidLine(number)
            }
        }
        guard closed, cursor < line.endIndex, line[cursor].isWhitespace,
              !name.trimmingCharacters(in: .whitespaces).isEmpty else
        {
            throw Failure.invalidLine(number)
        }
        let expression = String(line[cursor...]).trimmingCharacters(in: .whitespaces)
        guard !expression.isEmpty, expression.count <= CaptureConfiguration.maxBPFLength else {
            throw Failure.invalidLine(number)
        }
        return NamedCaptureFilter(line: number, name: name, expression: expression)
    }
}
