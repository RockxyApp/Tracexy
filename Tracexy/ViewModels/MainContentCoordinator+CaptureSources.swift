import AppKit
import Foundation

// MARK: - Capture sources: open in place, references, recents, reload

/// File ▸ Open… opens a capture *where it is* and records a reference in the
/// Project Library; File ▸ Import into Library… keeps today's managed copy. Both
/// end in the same `openSavedCapture` path, so identity checks, evidence reads,
/// Follow Stream and export do not know or care which kind of item they hold.
@MainActor
extension MainContentCoordinator {
    // MARK: Preferences

    /// Whether the Open panel's "Copy into Library" starts checked. Stored per
    /// Project, default off: opening in place is the primary action (D1).
    var copiesOpenedCapturesIntoLibrary: Bool {
        get { activeRuntime.settingsDefaults.bool(forKey: ProjectScopedSettingsKeys.copiesOpenedCapturesIntoLibrary) }
        set { activeRuntime.settingsDefaults.set(
            newValue,
            forKey: ProjectScopedSettingsKeys.copiesOpenedCapturesIntoLibrary
        ) }
    }

    // MARK: Menu routes

    /// File ▸ Open… (⌘O).
    func presentCaptureOpenPanel() {
        if let refusal = captureOpenRefusal {
            captureError = refusal
            return
        }
        let origin = activeRuntime.projectID
        let panel = CaptureOpenPanel(copiesIntoLibrary: copiesOpenedCapturesIntoLibrary)
        guard let choice = panel.run() else {
            return
        }
        guard origin == activeRuntime.projectID else {
            captureError = "Tracexy switched Projects while the Open panel was open. Open the capture again in the intended Project."
            return
        }
        copiesOpenedCapturesIntoLibrary = choice.copiesIntoLibrary
        openExternalCapture(choice.url, copiesIntoLibrary: choice.copiesIntoLibrary)
    }

    /// Open a file from outside the Library: Finder, a drop, Open Recent, or the
    /// Open panel. Direct PCAP/PCAPNG opens in place unless a copy was asked for;
    /// gzip and TCP Viewer archives always expand into a managed capture because
    /// there is no in-place form of their payload.
    func openExternalCapture(_ source: URL, copiesIntoLibrary: Bool? = nil) {
        if let refusal = captureOpenRefusal {
            captureError = refusal
            return
        }
        let copies = copiesIntoLibrary ?? copiesOpenedCapturesIntoLibrary
        let origin = activeRuntime.projectID
        let scoped = source.startAccessingSecurityScopedResource()
        externalCaptureOpenTask = Task { @MainActor [weak self] in
            defer {
                if scoped {
                    source.stopAccessingSecurityScopedResource()
                }
            }
            let recognized = await Task.detached(priority: .userInitiated) {
                Result { try CaptureImporter.recognizedFormat(of: source) }
            }.value
            guard let self, self.activeRuntime.projectID == origin else {
                return
            }
            switch recognized {
            case .success:
                if copies {
                    self.importCapture(from: source, originProjectID: origin)
                } else {
                    self.openInPlace(source)
                }
            case let .failure(error):
                if case CaptureImportError.compressed = error {
                    // A container: the importer expands it into a managed capture.
                    self.importCapture(from: source, originProjectID: origin)
                } else {
                    self.captureError = "Couldn’t open “\(source.lastPathComponent)”: \(error.localizedDescription)"
                }
            }
        }
    }

    /// Test/diagnostic seam: wait for an external open's recognition step and
    /// the saved open it started.
    func waitForExternalCaptureOpen() async {
        let task = externalCaptureOpenTask
        await task?.value
        await waitForCaptureImport()
        await waitForSavedCaptureOpen()
    }

    /// File ▸ Close Capture (⇧⌘W): the same route as the status-bar Clear.
    func closeCapture() {
        clearSessions()
    }

    var canCloseCapture: Bool {
        (isViewingSavedCapture || !sessions.isEmpty) && !isProjectBoundaryBusy && !isCaptureSourceHeld
    }

    /// File ▸ Reload (⌘R): re-read the open saved capture from disk. Enabled only
    /// when the file changed underneath the open, so the menu never offers a no-op.
    var canReloadActiveSavedCapture: Bool {
        isViewingSavedCapture && activeSavedCaptureChangedOnDisk && !isOpeningSavedCapture
            && !isProjectBoundaryBusy && !isCaptureSourceHeld
    }

    func reloadActiveSavedCapture() {
        guard canReloadActiveSavedCapture, let capture = activeSavedCapture else {
            return
        }
        if let reference = capture.reference, let sidecar = capture.sidecarURL {
            // The reference must follow the file's new identity, or every later
            // byte read would refuse it as a mismatch.
            guard let refreshed = try? CaptureReference.create(
                for: capture.url, displayName: reference.displayName, now: reference.addedAt
            ) else {
                unavailableReferencedCapture = capture
                return
            }
            do {
                try refreshed.write(to: sidecar)
            } catch {
                captureError = "Couldn’t update the reference: \(error.localizedDescription)"
                return
            }
        }
        refreshSavedCaptures()
        guard let current = savedCaptures.first(where: { $0.id == capture.id }) else {
            captureError = "“\(capture.name)” is no longer in this Project’s Library."
            return
        }
        openSavedCapture(current)
    }

    /// Re-snapshot a changed reference from the file now at its path and open it.
    /// Used by the unavailable notice; the active-capture route is ``reloadActiveSavedCapture``.
    func reloadReferencedCapture(_ capture: SavedCapture) {
        guard let reference = capture.reference, let sidecar = capture.sidecarURL else {
            return
        }
        guard let refreshed = try? CaptureReference.create(
            for: capture.url, displayName: reference.displayName, now: reference.addedAt
        ) else {
            captureError = "“\(capture.name)” can’t be read at \(capture.url.path)."
            return
        }
        do {
            try refreshed.write(to: sidecar)
        } catch {
            captureError = "Couldn’t update the reference: \(error.localizedDescription)"
            return
        }
        unavailableReferencedCapture = nil
        refreshSavedCaptures()
        if let item = savedCaptures.first(where: { $0.id == capture.id }) {
            openSavedCapture(item)
        }
    }

    // MARK: File sets

    /// The ring-buffer set the open saved capture belongs to, if its name follows
    /// the `<prefix>_<NNNNN>_<YYYYMMDDHHMMSS>` rotation pattern. Read from disk on
    /// each call so a set still being written stays current.
    var activeCaptureFileSet: CaptureFileSet? {
        guard isViewingSavedCapture, let capture = activeSavedCapture, capture.isReadable else {
            return nil
        }
        return CaptureFileSet(member: capture.url)
    }

    var canOpenNextInFileSet: Bool {
        activeCaptureFileSet?.next != nil && !isOpeningSavedCapture && !isCaptureSourceHeld && !isProjectBoundaryBusy
    }

    var canOpenPreviousInFileSet: Bool {
        activeCaptureFileSet?
            .previous != nil && !isOpeningSavedCapture && !isCaptureSourceHeld && !isProjectBoundaryBusy
    }

    /// File ▸ File Set ▸ Next File: open the next member in place (never a copy —
    /// a set can be hundreds of files).
    func openNextInFileSet() {
        guard let member = activeCaptureFileSet?.next else {
            return
        }
        openExternalCapture(member.url, copiesIntoLibrary: false)
    }

    func openPreviousInFileSet() {
        guard let member = activeCaptureFileSet?.previous else {
            return
        }
        openExternalCapture(member.url, copiesIntoLibrary: false)
    }

    // MARK: References

    /// Record `source` as an in-place reference and open it. The sidecar takes the
    /// file's own name; a name already used by another item gets a unique suffix.
    func openInPlace(_ source: URL) {
        guard let directory = capturesDirectory() else {
            return
        }
        // Opening a file that is already this Project's managed copy, or already
        // referenced, reuses the existing item rather than adding a duplicate.
        refreshSavedCaptures()
        if let existing = savedCaptures.first(where: { $0.url.isSameFileSystemPath(as: source) }) {
            noteRecentCapture(source)
            openSavedCapture(existing)
            return
        }
        do {
            let reference = try CaptureReference.create(for: source)
            let sidecar = Self.uniqueSidecarURL(
                for: reference.displayName,
                in: directory,
                taken: savedCaptures.map(\.id)
            )
            try reference.write(to: sidecar)
        } catch {
            captureError = "Couldn’t open “\(source.lastPathComponent)”: \(error.localizedDescription)"
            return
        }
        refreshSavedCaptures()
        noteRecentCapture(source)
        guard let item = savedCaptures.first(where: { $0.url.isSameFileSystemPath(as: source) }) else {
            return
        }
        openSavedCapture(item)
    }

    /// Library ▸ Locate… for a reference whose file moved: the candidate must
    /// carry the same size and leading bytes; a different file is refused.
    func locateReferencedCapture(_ capture: SavedCapture) {
        guard let reference = capture.reference, let sidecar = capture.sidecarURL else {
            return
        }
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = []
        panel.prompt = String(localized: "Choose")
        panel
            .message =
            String(
                localized: "Locate “\(capture.name)”. Tracexy checks that the file matches the capture this item refers to."
            )
        guard panel.runModal() == .OK, let candidate = panel.url else {
            return
        }
        switch reference.match(candidate: candidate) {
        case .identical:
            break
        case let .relocated(identity):
            let moved = reference.relocated(to: candidate, identity: identity)
            do {
                try moved.write(to: sidecar)
            } catch {
                captureError = "Couldn’t update the reference: \(error.localizedDescription)"
                return
            }
        case let .mismatch(reason):
            captureError = "“\(candidate.lastPathComponent)” isn’t the same capture. \(reason)"
            return
        }
        unavailableReferencedCapture = nil
        refreshSavedCaptures()
        if let item = savedCaptures.first(where: { $0.id == capture.id }) {
            openSavedCapture(item)
        }
    }

    /// Remove a reference from the Library. The referenced file is never touched;
    /// only the sidecar goes to the Trash, so the action is recoverable and needs
    /// no confirmation.
    func removeReferencedCapture(_ capture: SavedCapture) throws {
        guard let sidecar = capture.sidecarURL else {
            return
        }
        if let held = captureSourceHoldMessage {
            throw CaptureMutationError.sourceInUse(held)
        }
        guard hasHydratedProjects, !isProjectBoundaryBusy else {
            throw CocoaError(.fileWriteNoPermission)
        }
        try FileManager.default.trashItem(at: sidecar, resultingItemURL: nil)
        if activeSavedCapture?.id == capture.id {
            clearSessions()
        }
        if unavailableReferencedCapture?.id == capture.id {
            unavailableReferencedCapture = nil
        }
        refreshSavedCaptures()
    }

    /// Copy a referenced capture into the Library as a managed item (context menu).
    func copyReferencedCaptureIntoLibrary(_ capture: SavedCapture) {
        guard capture.isReferenced, capture.isReadable else {
            return
        }
        importCapture(from: capture.url, originProjectID: activeRuntime.projectID)
    }

    /// Re-check whether the open saved capture still matches the identity it was
    /// read with. Called on Library refresh and app activation.
    func noteActiveSavedCaptureAvailability() {
        guard isViewingSavedCapture, let capture = activeSavedCapture,
              let handle = try? FileHandle(forReadingFrom: capture.url) else
        {
            activeSavedCaptureChangedOnDisk = isViewingSavedCapture && activeSavedCapture != nil
            return
        }
        defer { try? handle.close() }
        let current = PcapFileIdentity.snapshot(of: handle)
        let reference = savedCaptureEvidence.values.first?.identity
        if let reference {
            activeSavedCaptureChangedOnDisk = !current.matches(reference)
        } else if let stored = capture.reference?.identity {
            activeSavedCaptureChangedOnDisk = !current.matches(stored)
        } else {
            activeSavedCaptureChangedOnDisk = false
        }
    }

    // MARK: Recents

    func noteRecentCapture(_ url: URL) {
        NSDocumentController.shared.noteNewRecentDocumentURL(url)
        refreshRecentCaptures()
    }

    func refreshRecentCaptures() {
        recentCaptureURLs = NSDocumentController.shared.recentDocumentURLs
    }

    func clearRecentCaptures() {
        NSDocumentController.shared.clearRecentDocuments(nil)
        refreshRecentCaptures()
    }

    /// File ▸ Open Recent ▸ item. A managed copy of this Project opens directly;
    /// anything else goes through the in-place route.
    func openRecentCapture(_ url: URL) {
        guard FileManager.default.fileExists(atPath: url.path) else {
            captureError = "“\(url.lastPathComponent)” can’t be found. It may have been moved or deleted."
            refreshRecentCaptures()
            return
        }
        openExternalCapture(url, copiesIntoLibrary: false)
    }

    // MARK: Private

    private var captureOpenRefusal: String? {
        if let held = captureSourceHoldMessage {
            return held
        }
        guard hasHydratedProjects, activeRuntime.projectID != nil else {
            return "Load or repair Projects before opening capture data."
        }
        guard !projectTransitionStatus.isPending else {
            return "Tracexy is switching Projects. Open the capture again in a moment."
        }
        return nil
    }

    private static func uniqueSidecarURL(for name: String, in directory: URL, taken: [URL]) -> URL {
        let takenPaths = Set(taken.map(\.standardizedFileURL.path))
        var candidate = directory.appendingPathComponent(name).appendingPathExtension(CaptureReference.pathExtension)
        var suffix = 2
        while takenPaths.contains(candidate.standardizedFileURL.path)
            || FileManager.default.fileExists(atPath: candidate.path)
        {
            candidate = directory.appendingPathComponent("\(name) \(suffix)")
                .appendingPathExtension(CaptureReference.pathExtension)
            suffix += 1
        }
        return candidate
    }
}

// MARK: - URL + file-system path identity

extension URL {
    /// Path equality after standardizing and resolving symlinks, so `/var/…` and
    /// `/private/var/…` name the same managed or referenced capture.
    nonisolated func isSameFileSystemPath(as other: URL) -> Bool {
        standardizedFileURL.resolvingSymlinksInPath().path == other.standardizedFileURL.resolvingSymlinksInPath().path
    }
}
