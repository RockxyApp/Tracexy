import Foundation

// MARK: - CaptureDisplayState

/// Coarse capture state shown in the toolbar status capsule.
enum CaptureDisplayState {
    case stopped
    case starting
    case capturing
    case error

    // MARK: Internal

    var title: String {
        switch self {
        case .stopped: String(localized: "Stopped")
        case .starting: String(localized: "Starting")
        case .capturing: String(localized: "Capturing")
        case .error: String(localized: "Error")
        }
    }
}

// MARK: - SavedCapture

/// One Library item: a managed `.pcap`/`.pcapng` copy, or a reference to a
/// capture that stays in place (`.tracexyref` sidecar). `url` is always the file
/// whose bytes are read; a reference additionally carries the sidecar and the
/// availability of its target at the last Library refresh.
struct SavedCapture: Identifiable, Hashable, Sendable {
    // MARK: Lifecycle

    init(
        url: URL,
        name: String,
        date: Date,
        byteCount: Int,
        reference: CaptureReference? = nil,
        sidecarURL: URL? = nil,
        availability: CaptureSourceAvailability = .managed
    ) {
        self.url = url
        self.name = name
        self.date = date
        self.byteCount = byteCount
        self.reference = reference
        self.sidecarURL = sidecarURL
        self.availability = availability
    }

    // MARK: Internal

    let url: URL
    let name: String
    let date: Date
    let byteCount: Int
    /// Present for an in-place reference; `nil` for a managed copy.
    let reference: CaptureReference?
    /// The `.tracexyref` sidecar for a reference; `nil` for a managed copy.
    let sidecarURL: URL?
    let availability: CaptureSourceAvailability

    /// Managed copies are identified by their file; references by their sidecar,
    /// so a relocated reference keeps its identity in the list.
    var id: URL {
        sidecarURL ?? url
    }

    var isReferenced: Bool {
        reference != nil
    }

    /// Whether the bytes can be opened right now.
    var isReadable: Bool {
        availability.isReadable
    }
}

// MARK: - DomainGroup

struct DomainGroup: Identifiable {
    let domain: String
    let ips: [String]
    let count: Int

    var id: String {
        domain
    }
}

// MARK: - AppGroup

struct AppGroup: Identifiable {
    let app: String
    let hosts: [String]
    let count: Int

    var id: String {
        app
    }
}

// MARK: - ThroughputSample

struct ThroughputSample: Identifiable {
    let id = UUID()
    let bytesPerSecond: Double
}
