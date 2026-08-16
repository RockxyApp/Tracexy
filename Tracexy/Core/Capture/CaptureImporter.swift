import Foundation

/// Lossless, idempotent import of an external capture file into the app's
/// managed Captures directory.
///
/// Two invariants make this safe against the "import ate the source" failure
/// mode:
///
///  * **Same-file short-circuit.** If the source already *is* the computed
///    managed destination (equivalent path, symlink, or same on-disk identity),
///    nothing is removed or copied — the file is simply reported back so the
///    caller can refresh and reopen it in place.
///  * **Copy-to-temp then atomic replace.** When a genuinely external source
///    collides with an existing managed file of the same name, the source is
///    copied to a temporary sibling first and only swapped in with an atomic
///    replace once that copy has fully succeeded. A failure removes just the
///    temporary artifact and leaves both the source and the pre-existing
///    destination untouched.
nonisolated enum CaptureImporter {
    // MARK: Internal

    /// Imports `source` into `directory`, returning the managed file URL.
    ///
    /// - Returns: the destination URL inside `directory`. On the same-file path
    ///   this is the source's own location; otherwise it is
    ///   `directory/<source filename>`.
    /// - Throws: any `FileManager` error from the copy/replace. On throw, the
    ///   source and any pre-existing destination are left intact and only the
    ///   temporary artifact (if one was created) is removed.
    @discardableResult
    static func importCapture(from source: URL, intoDirectory directory: URL) throws -> URL {
        let destination = directory.appendingPathComponent(source.lastPathComponent)

        // Already the managed file: never mutate it. This is the case that
        // previously removed the destination and then failed the copy with
        // ENOENT, destroying the only copy of the capture.
        if isSameFile(source, destination) {
            return destination
        }

        let fileManager = FileManager.default

        // No collision: a plain copy is already lossless — the source stays put
        // and nothing pre-existing can be overwritten.
        guard fileManager.fileExists(atPath: destination.path) else {
            try fileManager.copyItem(at: source, to: destination)
            return destination
        }

        // Collision with a different existing managed file. Stage the copy in a
        // temporary sibling so the existing file is only replaced once the copy
        // is complete; on any failure the existing file survives.
        let temporary = directory.appendingPathComponent(
            ".\(source.lastPathComponent).import-\(UUID().uuidString).tmp"
        )
        do {
            try fileManager.copyItem(at: source, to: temporary)
            _ = try fileManager.replaceItemAt(destination, withItemAt: temporary)
        } catch {
            try? fileManager.removeItem(at: temporary)
            throw error
        }
        return destination
    }

    // MARK: Private

    /// Whether two URLs point at the same underlying file. Compares resolved,
    /// standardized paths first (covers identical and symlinked paths), then
    /// falls back to on-disk file identity so hardlinks or otherwise-equivalent
    /// paths still count as the same file.
    private static func isSameFile(_ lhs: URL, _ rhs: URL) -> Bool {
        let resolvedLhs = lhs.resolvingSymlinksInPath().standardizedFileURL
        let resolvedRhs = rhs.resolvingSymlinksInPath().standardizedFileURL
        if resolvedLhs == resolvedRhs {
            return true
        }
        guard let idLhs = fileIdentifier(lhs), let idRhs = fileIdentifier(rhs) else {
            return false
        }
        return idLhs.isEqual(idRhs)
    }

    private static func fileIdentifier(_ url: URL) -> (any NSObjectProtocol)? {
        (try? url.resourceValues(forKeys: [.fileResourceIdentifierKey]))?.fileResourceIdentifier
    }
}
