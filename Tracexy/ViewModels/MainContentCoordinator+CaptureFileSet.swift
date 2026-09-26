import AppKit
import Foundation

// MARK: - CaptureFileSetSettings

/// Settings → Capture → Save as a file set, resolved for one capture start.
nonisolated enum CaptureFileSetSettings {
    /// The policy a capture starting at `startedAt` adopts, or `nil` when the
    /// Project has no file set configured. The set is written to its own folder
    /// under the Project's Captures folder, named for the start instant.
    static func policy(
        defaults: UserDefaults,
        capturesDirectory: URL,
        startedAt: Date,
        timeZone: TimeZone = .current
    )
        -> LiveCaptureSpool.FileSetPolicy?
    {
        let megabytes = max(0, defaults.integer(forKey: SettingsKeys.fileSetMegabytes))
        let minutes = max(0, defaults.integer(forKey: SettingsKeys.fileSetMinutes))
        guard megabytes > 0 || minutes > 0 else {
            return nil
        }
        return LiveCaptureSpool.FileSetPolicy(
            maxFileBytes: megabytes > 0 ? UInt64(megabytes) * 1_000_000 : nil,
            maxFileDuration: minutes > 0 ? TimeInterval(minutes * 60) : nil,
            keepFiles: max(0, defaults.integer(forKey: SettingsKeys.fileSetKeep)),
            directory: capturesDirectory
                .appendingPathComponent("File Sets", isDirectory: true)
                .appendingPathComponent(folderName(startedAt, timeZone: timeZone), isDirectory: true),
            prefix: "capture"
        )
    }

    static func folderName(_ date: Date, timeZone: TimeZone) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let parts = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        return String(
            format: "Capture %04d-%02d-%02d %02d.%02d.%02d",
            parts.year ?? 0, parts.month ?? 0, parts.day ?? 0, parts.hour ?? 0, parts.minute ?? 0, parts.second ?? 0
        )
    }
}

// MARK: - File set lifecycle

@MainActor
extension MainContentCoordinator {
    /// The active Project's managed capture Library folder, created on demand.
    ///
    /// The legacy-owner Project keeps the pre-Projects
    /// `Application Support/<namespace>/Captures`; every other Project is rooted
    /// under `Projects/<uuid>/Captures`. Nothing is copied, moved, or deleted.
    func capturesDirectory() -> URL? {
        activeCapturesDirectory
    }

    /// The policy for a capture starting now in the active Project, if configured.
    func fileSetPolicyForNewCapture(now: Date = Date()) -> LiveCaptureSpool.FileSetPolicy? {
        guard let directory = capturesDirectory() else {
            return nil
        }
        return CaptureFileSetSettings.policy(
            defaults: activeProjectDefaults, capturesDirectory: directory, startedAt: now
        )
    }

    /// Close the set once the capture's terminal publication is adopted: the open
    /// file is copied in as the last member. Ordered after queued ingests.
    func finishLiveFileSet() {
        let spool = liveCaptureSpool
        let origin = activeRuntime
        let previous = ingestChain
        ingestChain = Task { @MainActor [weak self] in
            await previous?.value
            do {
                let summary = try await spool.finishFileSet()
                guard let self, self.activeRuntime === origin, let summary else {
                    return
                }
                self.lastFileSet = summary
            } catch {
                guard let self, self.activeRuntime === origin else {
                    return
                }
                self.captureError = "The capture’s file set couldn’t be completed — \(error.localizedDescription)"
            }
        }
    }

    /// The status bar's words for a finished file set.
    var lastFileSetDescription: String? {
        guard let set = lastFileSet else {
            return nil
        }
        let files = set.files.count == 1 ? "1 file" : "\(set.files.count.formatted()) files"
        let removed = set.removedFileCount > 0 ? ", \(set.removedFileCount.formatted()) older removed" : ""
        return "saved as \(files)\(removed)"
    }

    /// File ▸ Show File Set in Finder.
    func revealLastFileSet() {
        guard let set = lastFileSet else {
            return
        }
        if let first = set.files.last {
            NSWorkspace.shared.activateFileViewerSelecting([first])
        } else {
            NSWorkspace.shared.open(set.directory)
        }
    }
}
