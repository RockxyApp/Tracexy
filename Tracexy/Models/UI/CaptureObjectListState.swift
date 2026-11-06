import Foundation

// MARK: - CaptureObjectListState

/// File ▸ Export Objects: one kind's objects at a time, read on demand from a stable
/// copy of the open capture and kept per kind. Capture-local; cleared with it.
@MainActor
@Observable
final class CaptureObjectListState {
    var kind: CaptureObjectKind = .http
    var lists: [CaptureObjectKind: CaptureObjectList] = [:]
    var isLoading = false
    /// Streams read of those to read.
    var progress: (done: Int, total: Int)?
    var error: String?
    var search = ""
    /// Kinds whose last read ended without a result — cancelled, or dropped
    /// because the capture changed underneath it. `lists[kind] == nil` on its own
    /// cannot tell that apart from "scanned, and this capture has none", so the
    /// window would state the latter about a scan that never ran.
    var unreadKinds: Set<CaptureObjectKind> = []

    @ObservationIgnored var task: Task<Void, Never>?
    @ObservationIgnored var requestID = 0

    var list: CaptureObjectList? {
        lists[kind]
    }

    /// The objects the search admits (file name, host or content type).
    var visibleObjects: [CaptureObject] {
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let objects = list?.objects else {
            return []
        }
        guard !needle.isEmpty else {
            return objects
        }
        return objects.filter {
            $0.fileName.localizedCaseInsensitiveContains(needle)
                || $0.host.localizedCaseInsensitiveContains(needle)
                || $0.contentType.localizedCaseInsensitiveContains(needle)
        }
    }

    /// Stops a read in progress; `clearLists` forgets every kind's objects.
    func cancel(clearLists: Bool) {
        task?.cancel()
        task = nil
        requestID &+= 1
        isLoading = false
        progress = nil
        error = nil
        if lists[kind] == nil {
            unreadKinds.insert(kind)
        }
        if clearLists {
            lists = [:]
            unreadKinds = Set(CaptureObjectKind.allCases)
        }
    }
}
