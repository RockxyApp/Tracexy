import Foundation

// MARK: - CaptureFileSet

/// A ring-buffer file set as `dumpcap`/`tcpdump -w` with rotation write it:
/// `<prefix>_<NNNNN>_<YYYYMMDDHHMMSS>.<ext>`. Members share prefix and extension
/// and live in one directory; ordering is by the sequence number, then the
/// timestamp, so "next" and "previous" are stable however the directory lists.
nonisolated struct CaptureFileSet: Sendable, Equatable {
    // MARK: Lifecycle

    /// Parse the set `url` belongs to, listing its siblings on disk. `nil` when the
    /// name does not follow the pattern or the directory cannot be read.
    init?(member url: URL) {
        guard let key = Self.key(for: url) else {
            return nil
        }
        let directory = url.deletingLastPathComponent()
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else {
            return nil
        }
        var members: [Member] = []
        for name in names {
            let candidate = directory.appendingPathComponent(name)
            guard let other = Self.key(for: candidate), other.prefix == key.prefix, other.ext == key.ext else {
                continue
            }
            members.append(Member(url: candidate, sequence: other.sequence, timestamp: other.timestamp))
            if members.count >= Self.maxMembers {
                break
            }
        }
        members.sort { lhs, rhs in
            lhs.sequence != rhs.sequence ? lhs.sequence < rhs.sequence : lhs.timestamp < rhs.timestamp
        }
        guard let index = members.firstIndex(where: { $0.url.isSameFileSystemPath(as: url) }) else {
            return nil
        }
        self.members = members
        currentIndex = index
        prefix = key.prefix
    }

    // MARK: Internal

    nonisolated struct Member: Sendable, Equatable {
        let url: URL
        let sequence: Int
        let timestamp: String
    }

    /// Directory listings beyond this many members are cut; a set this large is
    /// navigated by number, not by menu.
    static let maxMembers = 10_000

    let members: [Member]
    let currentIndex: Int
    let prefix: String

    var current: Member {
        members[currentIndex]
    }

    var next: Member? {
        members.indices.contains(currentIndex + 1) ? members[currentIndex + 1] : nil
    }

    var previous: Member? {
        members.indices.contains(currentIndex - 1) ? members[currentIndex - 1] : nil
    }

    var count: Int {
        members.count
    }

    /// Whether `url` is named like a file-set member, without touching the disk.
    static func isMemberName(_ url: URL) -> Bool {
        key(for: url) != nil
    }

    // MARK: Private

    private static func key(for url: URL) -> (prefix: String, sequence: Int, timestamp: String, ext: String)? {
        let name = url.deletingPathExtension().lastPathComponent
        let ext = url.pathExtension.lowercased()
        guard ["pcap", "pcapng", "cap", "ntar"].contains(ext) else {
            return nil
        }
        let parts = name.split(separator: "_", omittingEmptySubsequences: false)
        guard parts.count >= 3 else {
            return nil
        }
        let timestamp = String(parts[parts.count - 1])
        let sequenceText = String(parts[parts.count - 2])
        guard timestamp.count == 14, timestamp.allSatisfy(\.isNumber),
              sequenceText.count == 5, sequenceText.allSatisfy(\.isNumber),
              let sequence = Int(sequenceText) else
        {
            return nil
        }
        let prefix = parts[0 ..< parts.count - 2].joined(separator: "_")
        guard !prefix.isEmpty else {
            return nil
        }
        return (prefix, sequence, timestamp, ext)
    }
}
