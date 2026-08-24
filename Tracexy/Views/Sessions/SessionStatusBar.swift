import Combine
import SwiftUI

// MARK: - StatusSurface

/// Which central surface the status bar sits under. Every surface gets a quiet,
/// read-only summary of the same real capture; session commands live above the
/// session list rather than in this telemetry footer.
nonisolated enum StatusSurface {
    case sessionList
    case overview
    case flow
    case history
}

// MARK: - FooterTelemetry

/// A stable, pure description of one right-hand telemetry chip.
///
/// Ordered by importance and emitted only when the underlying data exists, so the
/// footer never shows a zeroed or invented figure. `role` drives colour at render
/// time and encodes the app's status semantics: green is reserved for live
/// capture, red for session errors, orange only for material packet loss, and
/// everything else stays neutral.
nonisolated struct FooterTelemetry: Identifiable, Equatable {
    enum Kind {
        case packetDrops
        case helperDrops
        case sessionErrors
        case captureDuration
        case liveRate
        case totalBytes
        case bytesUp
        case bytesDown
        case retentionTruncation
    }

    enum Role {
        case neutral
        case warning
        case error
        case live
    }

    let kind: Kind
    /// Pre-formatted display text. Empty for `captureDuration`, which the view
    /// renders as a live ticking timer from `FooterSnapshot.captureStartedAt`.
    let text: String
    let help: String
    let systemImage: String?
    let role: Role

    var id: Kind {
        kind
    }
}

// MARK: - FooterSnapshot

/// The complete, pre-derived state the footer needs to render. Built once by the
/// owning view (`MainDetailView`) from the coordinator and handed to the
/// presentation-only `SessionStatusBar`, which never reads the coordinator itself.
nonisolated struct FooterSnapshot: Equatable {
    let summary: String
    let telemetry: [FooterTelemetry]
    /// Present only while a capture is running, so the view can drive the live
    /// duration timer without owning capture state.
    let captureStartedAt: Date?
}

// MARK: - CaptureLoss

/// The three independent loss figures a capture can accrue, grouped so the footer
/// derivation stays under a sane parameter count and — more importantly — so the
/// three stages are named and kept distinct at the call site:
///
/// - kernel/interface loss (`hasStatistics` + `totalDropped` + `isMaterialLoss`),
///   from `pcap_stats`; unknown when no statistics are available;
/// - `helperDropCount`, frames the privileged helper evicted before the app drained
///   them — capture-source loss that is *not* part of the kernel figure;
/// - `retentionEvictionCount`, frames trimmed from the local inspection window —
///   a memory bound, never captured-packet or savefile loss.
nonisolated struct CaptureLoss: Equatable {
    let hasStatistics: Bool
    let totalDropped: UInt64
    let isMaterialLoss: Bool
    let helperDropCount: UInt64
    let retentionEvictionCount: UInt64
}

// MARK: - SessionStatusBarModel

/// Pure derivations for the footer's telemetry chips and center status string.
/// Kept free of SwiftUI so both are unit-testable and every responsive
/// presentation reads from one source of truth.
nonisolated enum SessionStatusBarModel {
    // MARK: Internal

    /// The right-hand telemetry chips, ordered by importance and emitted only when
    /// their data exists: kernel/interface drops → helper-stage drops → session
    /// errors → capture duration → combined live rate → session-attributed total →
    /// directional totals → retention truncation.
    ///
    /// The three loss figures are deliberately distinct chips for three distinct
    /// stages. Kernel/interface loss (`totalDropped`) and helper-stage loss
    /// (`helperBufferDropCount`) are both capture-source loss and warn; retention
    /// truncation (`retainedFrameEvictionCount`) is a save/export memory bound and
    /// is never dressed up as captured-packet loss. Folding any of them into
    /// another would misstate where fidelity was lost.
    static func telemetry(
        isCapturing: Bool,
        loss: CaptureLoss,
        errorCount: Int,
        hasCaptureDuration: Bool,
        liveBytesPerSecond: Double?,
        totalBytes: Int,
        bytesUp: Int,
        bytesDown: Int
    )
        -> [FooterTelemetry]
    {
        var items: [FooterTelemetry] = []

        // Packet drops — only when the source reports stats and something was
        // actually lost. Material loss warns (orange); anything below the
        // threshold is shown neutrally rather than dressed up as an alarm. With no
        // statistics at all the chip is omitted, never faked as "none dropped".
        if loss.hasStatistics, loss.totalDropped > 0 {
            items.append(FooterTelemetry(
                kind: .packetDrops,
                text: "\(loss.totalDropped.formatted()) dropped",
                help: loss.isMaterialLoss
                    ? "Material packet loss — the derived numbers may understate the real traffic."
                    : "Some packets were dropped, but below the level that skews the numbers.",
                systemImage: "exclamationmark.triangle.fill",
                role: loss.isMaterialLoss ? .warning : .neutral
            ))
        }

        // Helper-stage drops — frames the privileged helper's staging buffer had
        // to evict before the app drained them. This is real capture-source loss,
        // separate from kernel/interface loss above: it can be non-zero even while
        // `pcap_stats` reports a perfect kernel capture, so it always warns rather
        // than hiding behind a green fidelity figure.
        if loss.helperDropCount > 0 {
            items.append(FooterTelemetry(
                kind: .helperDrops,
                text: "\(loss.helperDropCount.formatted()) helper drops",
                help: "Frames the capture helper dropped before reaching the app — "
                    + "capture-stage loss, not counted in the kernel fidelity figure.",
                systemImage: "exclamationmark.triangle.fill",
                role: .warning
            ))
        }

        // Session errors — labelled "session errors", never a bare "errors".
        if errorCount > 0 {
            items.append(FooterTelemetry(
                kind: .sessionErrors,
                text: errorCount == 1 ? "1 session error" : "\(errorCount.formatted()) session errors",
                help: "Sessions that ended in an error state.",
                systemImage: "xmark.octagon.fill",
                role: .error
            ))
        }

        // Elapsed capture duration — a live timer; the view renders it.
        if hasCaptureDuration {
            items.append(FooterTelemetry(
                kind: .captureDuration,
                text: "",
                help: "Elapsed time since this capture started.",
                systemImage: nil,
                role: .neutral
            ))
        }

        // Combined live rate — only while capturing and only once a sample exists.
        // A single combined figure: directional live speeds are never invented.
        if isCapturing, let bps = liveBytesPerSecond {
            items.append(FooterTelemetry(
                kind: .liveRate,
                text: "\(formatBytes(Int(bps)))/s",
                help: "Combined live throughput across both directions.",
                systemImage: "waveform.path.ecg",
                role: .live
            ))
        }

        // Session-attributed total — the sum of each session's accounted bytes,
        // explicitly not raw payload.
        if totalBytes > 0 {
            items.append(FooterTelemetry(
                kind: .totalBytes,
                text: "\(formatBytes(totalBytes)) total",
                help: "Session-attributed bytes — the sum of each session's accounted bytes, not raw payload.",
                systemImage: nil,
                role: .neutral
            ))
        }

        // Directional cumulative totals (first-observed ↑, reverse ↓). Neutral —
        // green is reserved for live capture status, so a static total never
        // borrows it.
        if bytesUp > 0 {
            items.append(FooterTelemetry(
                kind: .bytesUp,
                text: "↑ \(formatBytes(bytesUp))",
                help: "First-observed direction — cumulative bytes.",
                systemImage: nil,
                role: .neutral
            ))
        }
        if bytesDown > 0 {
            items.append(FooterTelemetry(
                kind: .bytesDown,
                text: "↓ \(formatBytes(bytesDown))",
                help: "Reverse direction — cumulative bytes.",
                systemImage: nil,
                role: .neutral
            ))
        }

        // Memory-window eviction — the immediate inspection window trimmed its
        // oldest frames to stay bounded. This is emphatically *not* capture loss:
        // sessions remain accounted for and the complete raw stream continues to
        // the disk-backed spool used by save/export. Neutral and last, so it never
        // reads as an alarm about missed traffic.
        if loss.retentionEvictionCount > 0 {
            items.append(FooterTelemetry(
                kind: .retentionTruncation,
                text: "\(loss.retentionEvictionCount.formatted()) outside memory window",
                help: "Older raw frames left the bounded inspection window — sessions and the complete "
                    + "disk-backed save remain unaffected.",
                systemImage: "tray.full",
                role: .neutral
            ))
        }

        return items
    }

    /// The center status string. Session-list summaries follow a strict
    /// hierarchy; the intelligence surfaces keep their own quiet summaries.
    static func statusText(
        surface: StatusSurface,
        totalSessions: Int,
        visibleCount: Int,
        hasSelection: Bool
    )
        -> String
    {
        switch surface {
        case .overview:
            return totalSessions == 0 ? "Capture overview · No sessions" : "Capture overview · \(totalSessions) sessions"
        case .flow:
            return totalSessions == 0 ? "Flow map · No sessions" : "Flow map · \(totalSessions) sessions"
        case .history:
            return totalSessions == 0 ? "Local History · No persisted sessions" : "Local History · \(totalSessions) persisted sessions"
        case .sessionList:
            break
        }

        if totalSessions == 0 {
            return "No sessions"
        }
        // Single-selection model: the count is derived from the flag, never a
        // hardcoded "1", so it stays honest if selection is ever cleared.
        let selectedCount = hasSelection ? 1 : 0
        let isFiltered = visibleCount != totalSessions
        if selectedCount > 0 {
            return isFiltered
                ? "\(selectedCount) selected · \(visibleCount) of \(totalSessions) shown"
                : "\(selectedCount) selected · \(totalSessions) sessions"
        }
        if isFiltered {
            return "\(visibleCount) of \(totalSessions) sessions"
        }
        return "\(totalSessions) sessions"
    }

    // MARK: Private

    private static func formatBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}

// MARK: - HistoryFooterModel

/// Honest footer copy for the bounded History page. A trailing `+` means another
/// keyset page exists; it never presents a loaded-page subtotal as a database-wide
/// exact total.
nonisolated enum HistoryFooterModel {
    static func statusText(captureCount: Int, sessionCount: Int, hasMore: Bool) -> String {
        guard captureCount > 0 else {
            return "Local History · No captures"
        }
        let suffix = hasMore ? "+" : ""
        let captureLabel = captureCount == 1 && !hasMore ? "capture" : "captures"
        let sessionLabel = sessionCount == 1 && !hasMore ? "persisted session" : "persisted sessions"
        return "\(captureCount.formatted())\(suffix) \(captureLabel) · "
            + "\(sessionCount.formatted())\(suffix) \(sessionLabel)"
    }
}

// MARK: - SessionStatusBar

/// Bottom status bar showing only the session/capture summary and health
/// telemetry. **Presentation-only**: it receives a pure snapshot and owns no
/// coordinator or workspace mutation. Commands belong to the session command bar.
struct SessionStatusBar: View {
    // MARK: Internal

    let snapshot: FooterSnapshot

    var body: some View {
        WorkspaceFooterBar(surface: .workspace) {
            HStack(spacing: 0) {
                centerSummary
                Spacer(minLength: 24)
                telemetryRow
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
        }
    }

    // MARK: Private

    private var centerSummary: some View {
        Text(snapshot.summary)
            .font(Theme.Typography.chromeSecondary)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.tail)
            .layoutPriority(2)
    }

    private var telemetryRow: some View {
        HStack(spacing: 8) {
            ForEach(snapshot.telemetry) { item in
                telemetryChip(item)
            }
        }
        .lineLimit(1)
    }

    private func telemetryChip(_ item: FooterTelemetry) -> some View {
        HStack(spacing: 3) {
            if let symbol = item.systemImage {
                Image(systemName: symbol).font(.system(size: Theme.Icon.small))
            }
            if item.kind == .captureDuration, let startedAt = snapshot.captureStartedAt {
                CaptureDurationView(startedAt: startedAt)
            } else {
                Text(item.text)
                    .font(item.role == .neutral ? Theme.Typography.chromeSecondary : Theme.Typography.chrome)
            }
        }
        .foregroundStyle(color(for: item.role))
        .help(item.help)
    }

    private func color(for role: FooterTelemetry.Role) -> Color {
        switch role {
        case .neutral: .secondary
        case .warning: Color(nsColor: .systemOrange)
        case .error: Color(nsColor: .systemRed)
        case .live: Color(nsColor: .systemGreen)
        }
    }
}

// MARK: - CaptureDurationView

/// Elapsed capture time, updating every second. Neutral by design — the parent
/// telemetry chip owns the colour.
private struct CaptureDurationView: View {
    // MARK: Internal

    let startedAt: Date

    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: "clock").font(.system(size: Theme.Icon.small))
            Text(formatted).font(Theme.Typography.chromeSecondary.monospacedDigit())
        }
        .onReceive(timer) { now = $0 }
    }

    // MARK: Private

    @State private var now = Date()

    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var formatted: String {
        let interval = max(0, Int(now.timeIntervalSince(startedAt)))
        let hours = interval / 3_600
        let minutes = (interval % 3_600) / 60
        let seconds = interval % 60
        if hours > 0 {
            return String(format: "%d:%02d:%02d", hours, minutes, seconds)
        }
        return String(format: "%d:%02d", minutes, seconds)
    }
}
