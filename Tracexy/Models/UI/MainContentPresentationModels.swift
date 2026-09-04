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

/// One saved `.pcap` or `.pcapng` file listed under Saved Captures.
struct SavedCapture: Identifiable, Hashable, Sendable {
    let url: URL
    let name: String
    let date: Date
    let byteCount: Int

    var id: URL {
        url
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
