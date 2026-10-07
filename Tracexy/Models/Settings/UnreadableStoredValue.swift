import Foundation

// MARK: - UnreadableStoredValue

/// A stored value this build could not read — written by a newer version, or
/// damaged — is set aside once under `<key>.unreadable` before the caller falls
/// back to its default, so the next save cannot silently destroy it. Opening the
/// newer version again still finds the original under its own key until then.
nonisolated enum UnreadableStoredValue {
    static func preserve(_ data: Data, key: String, in defaults: UserDefaults) {
        let backup = backupKey(for: key)
        guard defaults.object(forKey: backup) == nil else {
            return
        }
        defaults.set(data, forKey: backup)
    }

    static func backupKey(for key: String) -> String {
        key + ".unreadable"
    }
}
