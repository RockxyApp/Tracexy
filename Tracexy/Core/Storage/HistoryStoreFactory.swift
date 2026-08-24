import Foundation

// MARK: - HistoryStoreFactory

/// The production composition root for the terminal-history ``SessionStore``.
///
/// It resolves an identity-derived Application Support database path, ensures the
/// enclosing directory exists, and opens one writable store. Every directory,
/// open, or migration failure is isolated into a typed ``Outcome/unavailable``
/// value carrying a human-readable reason — it never throws to the app, so History
/// being unavailable can never prevent the app or the capture engine from starting.
///
/// The factory owns *only* path resolution and failure isolation. It reads no
/// settings and applies no privacy policy; the store it returns is the same pure
/// substrate the tests inject directly.
enum HistoryStoreFactory {
    // MARK: Internal

    /// The result of attempting to compose the production store.
    enum Outcome: Sendable {
        /// A migrated, writable store is ready for terminal writes and reads.
        case ready(SessionStore)
        /// History is unavailable; the reason is suitable for a History-specific
        /// error surface and never becomes a capture error.
        case unavailable(String)
    }

    /// The database path relative to the app-support directory. History lives in
    /// its own subdirectory so its WAL/SHM siblings never collide with capture
    /// files or other app data.
    static let relativeDatabasePath = "History/history.sqlite"

    /// The identity-derived Application Support database URL. During tests this
    /// resolves under a per-run temporary directory (see ``TracexyIdentity``), so a
    /// production database is never shared with or overwritten by a test.
    static func productionDatabaseURL(identity: TracexyIdentity = .current) -> URL {
        identity.appSupportPath(relativeDatabasePath)
    }

    /// Compose the production store at the identity-derived path.
    static func production(
        identity: TracexyIdentity = .current,
        fileManager: FileManager = .default
    )
        -> Outcome
    {
        make(databaseURL: productionDatabaseURL(identity: identity), fileManager: fileManager)
    }

    /// Open a writable store at `databaseURL`, isolating directory-creation and
    /// open/migration failures as ``Outcome/unavailable``.
    static func make(databaseURL: URL, fileManager: FileManager = .default) -> Outcome {
        let directory = databaseURL.deletingLastPathComponent()
        do {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            return .unavailable(
                "Couldn’t prepare the History storage folder — \(error.localizedDescription)"
            )
        }
        do {
            let store = try SessionStore(configuration: .init(location: .file(databaseURL)))
            return .ready(store)
        } catch {
            return .unavailable(
                "Couldn’t open the History database — \(errorDescription(error))"
            )
        }
    }

    // MARK: Private

    private static func errorDescription(_ error: Error) -> String {
        if let error = error as? HistoryStoreError {
            return String(describing: error)
        }
        return error.localizedDescription
    }
}
