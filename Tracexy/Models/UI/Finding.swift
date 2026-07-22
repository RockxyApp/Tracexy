import SwiftUI

// MARK: - Finding

/// One severity-ranked observation surfaced in the Overview's Findings panel —
/// Tracexy's analog of Wireshark's Expert Information. Derived only from data we
/// actually decode (status, protocol stack, DNS answers, latency); never a
/// fabricated anomaly. Each finding can point back to the session it came from.
struct Finding: Identifiable, Hashable {
    let id = UUID()
    let severity: Severity
    let title: String
    let subtitle: String
    /// The session this finding was derived from, for click-to-select.
    let sessionID: UUID?
}

// MARK: Finding.Severity

extension Finding {
    /// Ranked worst→least, driving both sort order and the row's icon/color.
    enum Severity: Int, CaseIterable, Hashable {
        case error = 0
        case warning = 1
        case note = 2

        // MARK: Internal

        /// Real SF Symbol (never a colored dot — see design system).
        var systemImage: String {
            switch self {
            case .error: "xmark.octagon"
            case .warning: "exclamationmark.triangle"
            case .note: "info.circle"
            }
        }

        var tint: Color {
            switch self {
            case .error: .red
            case .warning: .orange
            case .note: .secondary
            }
        }
    }
}
