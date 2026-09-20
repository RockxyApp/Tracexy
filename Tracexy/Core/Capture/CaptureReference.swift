import CryptoKit
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - CaptureReference

/// A Library item that points at a capture *in place* instead of holding a
/// managed copy. It is persisted as a small JSON sidecar
/// (`<name>.tracexyref`) inside the Project's captures folder, so each Project
/// keeps its own references and Trash semantics stay per Project.
///
/// A reference records the path, the descriptor identity the readers already use
/// for offset validation, and a digest of the file's leading bytes. Together
/// these let Tracexy tell "same file" from "moved file" from "different file"
/// without ever trusting a path alone, and without reading the whole capture.
nonisolated struct CaptureReference: Codable, Sendable, Hashable {
    // MARK: Lifecycle

    init(path: String, displayName: String, identity: PcapFileIdentity, headDigest: String, addedAt: Date) {
        formatVersion = Self.currentFormatVersion
        self.path = path
        self.displayName = displayName
        self.identity = identity
        self.headDigest = headDigest
        self.addedAt = addedAt
    }

    // MARK: Internal

    /// How a candidate file compares with the reference.
    nonisolated enum Match: Sendable, Equatable {
        /// Same path, same identity: nothing changed.
        case identical
        /// Same leading bytes and size but a different path or descriptor identity:
        /// the file was moved or copied. Carries the identity to store.
        case relocated(PcapFileIdentity)
        /// Different content.
        case mismatch(String)
    }

    static let currentFormatVersion = 1
    static let pathExtension = "tracexyref"
    /// How many leading bytes the digest covers. Enough to span the global
    /// header / SHB + first IDBs and the first frames.
    static let headDigestLength = 65_536
    /// Sidecars larger than this are refused before decoding.
    static let maxSidecarBytes = 16_384

    let formatVersion: Int
    let path: String
    let displayName: String
    let identity: PcapFileIdentity
    let headDigest: String
    let addedAt: Date

    var url: URL {
        URL(fileURLWithPath: path)
    }

    /// Snapshot `source` into a new reference. Reads only the leading bytes.
    static func create(for source: URL, displayName: String? = nil, now: Date = Date()) throws -> CaptureReference {
        let (identity, digest) = try snapshot(source)
        return CaptureReference(
            path: source.standardizedFileURL.path,
            displayName: displayName ?? source.deletingPathExtension().lastPathComponent,
            identity: identity,
            headDigest: digest,
            addedAt: now
        )
    }

    static func read(from sidecar: URL) throws -> CaptureReference {
        let attributes = try FileManager.default.attributesOfItem(atPath: sidecar.path)
        let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
        guard size > 0, size <= maxSidecarBytes else {
            throw CaptureReferenceError.invalidSidecar("size \(size)")
        }
        let data = try Data(contentsOf: sidecar)
        let decoder = JSONDecoder()
        // Seconds as a Double: the identity's modification instant carries
        // sub-second precision that ISO 8601 text would round away, and a rounded
        // instant would make every reopened reference look "changed".
        decoder.dateDecodingStrategy = .secondsSince1970
        let reference = try decoder.decode(CaptureReference.self, from: data)
        guard reference.formatVersion == currentFormatVersion else {
            throw CaptureReferenceError.unsupportedVersion(reference.formatVersion)
        }
        guard !reference.path.isEmpty, reference.headDigest.count == 64 else {
            throw CaptureReferenceError.invalidSidecar("fields")
        }
        return reference
    }

    /// Write atomically next to the Project's managed captures.
    func write(to sidecar: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        try data.write(to: sidecar, options: [.atomic])
    }

    /// Current availability of the referenced file, using the same identity
    /// witnesses the readers revalidate before every byte read.
    func currentAvailability() -> CaptureSourceAvailability {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return .missing
        }
        defer { try? handle.close() }
        let current = PcapFileIdentity.snapshot(of: handle)
        return current.matches(identity) ? .available : .changed
    }

    /// Compare `candidate` against this reference (for Locate… and Reload).
    func match(candidate: URL) -> Match {
        guard let (identity, digest) = try? Self.snapshot(candidate) else {
            return .mismatch(String(localized: "The file could not be read."))
        }
        if identity.matches(self.identity), candidate.standardizedFileURL.path == path {
            return .identical
        }
        guard identity.size == self.identity.size else {
            return .mismatch(String(localized: "The file is a different size from the capture this item refers to."))
        }
        guard digest == headDigest else {
            return .mismatch(String(localized: "The file’s contents don’t match the capture this item refers to."))
        }
        return .relocated(identity)
    }

    /// A copy of this reference pointing at `candidate` with its current identity.
    func relocated(to candidate: URL, identity: PcapFileIdentity) -> CaptureReference {
        CaptureReference(
            path: candidate.standardizedFileURL.path,
            displayName: displayName,
            identity: identity,
            headDigest: headDigest,
            addedAt: addedAt
        )
    }

    // MARK: Private

    private static func snapshot(_ source: URL) throws -> (PcapFileIdentity, String) {
        let handle = try FileHandle(forReadingFrom: source)
        defer { try? handle.close() }
        let identity = PcapFileIdentity.snapshot(of: handle)
        var hasher = SHA256()
        var remaining = headDigestLength
        while remaining > 0 {
            guard let chunk = try handle.read(upToCount: min(remaining, 16_384)), !chunk.isEmpty else {
                break
            }
            hasher.update(data: chunk)
            remaining -= chunk.count
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return (identity, digest)
    }
}

// MARK: - CaptureSourceAvailability

/// Whether a Library item's bytes can be read right now.
nonisolated enum CaptureSourceAvailability: Sendable, Equatable {
    /// A managed copy inside the Project Library.
    case managed
    /// A referenced file whose identity still matches.
    case available
    /// A referenced file that is not at its recorded path.
    case missing
    /// A referenced file that exists at its path but no longer matches its
    /// recorded identity (replaced, truncated, or grown).
    case changed

    // MARK: Internal

    var isReadable: Bool {
        switch self {
        case .managed,
             .available: true
        case .missing,
             .changed: false
        }
    }
}

// MARK: - CaptureReferenceError

nonisolated enum CaptureReferenceError: LocalizedError, Equatable {
    case invalidSidecar(String)
    case unsupportedVersion(Int)

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case let .invalidSidecar(detail):
            "The capture reference is damaged (\(detail))."
        case let .unsupportedVersion(version):
            "The capture reference uses format \(version), which this version of Tracexy can’t read."
        }
    }
}
