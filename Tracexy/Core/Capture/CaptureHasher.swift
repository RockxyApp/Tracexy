import CryptoKit
import Foundation

// MARK: - CaptureFileDigests

/// Whole-file digests computed on demand for the Get Info window. Never computed
/// at open: hashing a multi-gigabyte capture is a deliberate, cancellable request.
nonisolated struct CaptureFileDigests: Sendable, Equatable {
    let sha256: String
    let sha1: String
    let byteCount: UInt64
}

// MARK: - CaptureHasher

/// Chunked, cancellable SHA-256 + SHA-1 over one file, with monotonic byte
/// progress. Runs on the caller's executor (never `@MainActor`).
nonisolated enum CaptureHasher {
    static let chunkSize = 4 << 20

    static func digests(
        of url: URL,
        expectedIdentity: PcapFileIdentity? = nil,
        onProgress: (PcapStreamProgress) -> Void = { _ in },
        isCancelled: () -> Bool = { Task.isCancelled }
    )
        throws -> CaptureFileDigests
    {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let identity = PcapFileIdentity.snapshot(of: handle)
        if let expectedIdentity, !identity.matches(expectedIdentity) {
            throw CaptureHasherError.fileChanged
        }
        var sha256 = SHA256()
        var sha1 = Insecure.SHA1()
        var consumed: UInt64 = 0
        while true {
            if isCancelled() {
                throw CancellationError()
            }
            guard let chunk = try handle.read(upToCount: chunkSize), !chunk.isEmpty else {
                break
            }
            sha256.update(data: chunk)
            sha1.update(data: chunk)
            consumed += UInt64(chunk.count)
            onProgress(PcapStreamProgress(bytesConsumed: consumed, totalBytes: identity.size))
        }
        return CaptureFileDigests(
            sha256: sha256.finalize().map { String(format: "%02x", $0) }.joined(),
            sha1: sha1.finalize().map { String(format: "%02x", $0) }.joined(),
            byteCount: consumed
        )
    }
}

// MARK: - CaptureHasherError

nonisolated enum CaptureHasherError: LocalizedError, Equatable {
    case fileChanged

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case .fileChanged:
            "The file changed on disk, so its digests were not computed. Reload the capture first."
        }
    }
}
