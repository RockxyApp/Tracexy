import AppKit
import SwiftUI

// MARK: - AppThemeApplier

/// Applies the user's appearance preference (system / light / dark) at the AppKit
/// level via `NSApp.appearance`, so a forced light/dark covers *everything* —
/// menus, Save/Open panels, alerts, and any AppKit-hosted or future window — not
/// only SwiftUI scene content. Mirrors the sibling app's `AppThemeApplier`.
///
/// `TracexyApp` also applies `.preferredColorScheme` to each scene; both derive
/// from the same `AppAppearance`, so they never disagree. This applier is the
/// app-wide backstop that scene modifiers alone cannot provide.
@MainActor
enum AppThemeApplier {
    static func apply(_ appearance: AppAppearance) {
        switch appearance {
        case .system: NSApp.appearance = nil
        case .light: NSApp.appearance = NSAppearance(named: .aqua)
        case .dark: NSApp.appearance = NSAppearance(named: .darkAqua)
        }
    }
}

// MARK: - Theme

enum Theme {
    // MARK: Layout metrics

    enum Metrics {
        static let sidebarMinWidth: CGFloat = 200
        static let sidebarIdealWidth: CGFloat = 240
        static let inspectorWidth: CGFloat = 320
        static let rowHeight: CGFloat = 28
        static let statusBarHeight: CGFloat = 28
        static let cornerRadius: CGFloat = 8
        static let spacingS: CGFloat = 4
        static let spacingM: CGFloat = 8
        static let spacingL: CGFloat = 12

        // Inspector docks — approved metrics (design-system.md): native
        // HSplitView (right) + VSplitView (bottom).
        static let contextDockMinWidth: CGFloat = 320
        static let contextDockIdealWidth: CGFloat = 336
        static let contextDockMaxWidth: CGFloat = 460
        static let bottomInspectorMinHeight: CGFloat = 220
        static let bottomInspectorIdealHeight: CGFloat = 250
        static let sessionTableMinWidth: CGFloat = 420
        static let sessionTableMinHeight: CGFloat = 240
        /// Below this content width the right dock is suppressed so the table
        /// isn't crushed (the sibling app gates its Context Dock the same way).
        static let contextDockGateWidth: CGFloat = 820

        // Chrome pills/chips
        static let pillCornerRadius: CGFloat = 6
        static let chipCornerRadius: CGFloat = 4
    }

    // MARK: Typography

    /// The app's whole type scale — **five sizes**, SF throughout.
    ///
    /// This exists because the alternative was measured and failed: call sites
    /// had grown nineteen distinct sizes, including 9.5, 10.5, 11.5 and 12.5.
    /// Half-point steps are invisible as *intent* and very visible as
    /// misalignment — two labels meant to read as one row would sit a hair
    /// apart, and nothing in the code said which was the mistake.
    ///
    /// A step is only worth having if it changes meaning. These do:
    ///
    /// | Token          | Size | Job                                          |
    /// |----------------|------|----------------------------------------------|
    /// | `title`        | 16   | What a panel is about — one per panel         |
    /// | `surfaceTitle` | 13   | Surface and sheet headers                     |
    /// | `body`         | 12   | Rows, fields, controls — the default          |
    /// | `caption`      | 11   | Supporting text hung off a body line          |
    /// | `micro`        | 10   | Axis ticks, badges, section headers           |
    ///
    /// Weight carries emphasis *within* a step; reach for the emphasis variant
    /// before reaching for a bigger size. Never write `.system(size:)` in a
    /// view — if something here doesn't fit, the scale is wrong and should be
    /// changed here, once.
    enum Typography {
        // Structure
        static let title = Font.system(size: 16, weight: .semibold)
        static let surfaceTitle = Font.system(size: 13, weight: .semibold)

        // Body — the default for rows, fields and controls
        static let body = Font.system(size: 12)
        static let bodyMedium = Font.system(size: 12, weight: .medium)
        static let bodyEmphasis = Font.system(size: 12, weight: .semibold)

        // Supporting text
        static let caption = Font.system(size: 11)
        static let captionMedium = Font.system(size: 11, weight: .medium)
        static let captionEmphasis = Font.system(size: 11, weight: .semibold)

        // Smallest legible step: ticks, badges, uppercase section headers
        static let micro = Font.system(size: 10)
        static let microMedium = Font.system(size: 10, weight: .medium)
        static let badge = Font.system(size: 10, weight: .semibold)
        static let sectionHeader = Font.system(size: 10, weight: .semibold)

        // Monospaced — for values read digit-by-digit (addresses, hex, bytes).
        // Sizes track the proportional scale so a mono value sits on the same
        // baseline as the label next to it.
        static let mono = Font.system(size: 12, design: .monospaced)
        static let monoSmall = Font.system(size: 11, design: .monospaced)
        static let monoMicro = Font.system(size: 10, design: .monospaced)

        /// Big read-at-a-glance figures — Overview stat tiles, onboarding
        /// headlines. Outside the five-step scale on purpose: these are display
        /// numerals, not text, and sizing them from the body scale made them
        /// look like a heading that had gone wrong.
        static let metric = Font.system(size: 26, weight: .semibold)
        static let metricRounded = Font.system(size: 26, weight: .semibold, design: .rounded)
        static let hero = Font.system(size: 28, weight: .bold)

        /// Legacy alias — table rows are plain body text.
        static let rowTitle = body
    }

    // MARK: Icon sizes

    /// SF Symbol point sizes. Symbols are optically larger than text at the same
    /// point size, so an icon paired with a label steps *down* one rung.
    enum Icon {
        /// Inline with `caption`/`micro` text — status dots, chevrons.
        static let small: CGFloat = 10
        /// Inline with `body` text — the common case.
        static let medium: CGFloat = 12
        /// Toolbar and section affordances.
        static let large: CGFloat = 15
        /// Sheet and window headers.
        static let xlarge: CGFloat = 20
        /// Empty-state and placeholder glyphs.
        static let hero: CGFloat = 28
        /// The single focal glyph of an onboarding or install sheet.
        static let heroLarge: CGFloat = 40
    }

    // MARK: Protocol accents

    static func color(for kind: ProtocolKind) -> Color {
        switch kind {
        case .ethernet,
             .other: .secondary
        case .ipv4,
             .ipv6: .teal
        case .arp: .brown
        case .icmp,
             .icmpv6: .pink
        case .tcp: .blue
        case .udp: .indigo
        case .dns: .cyan
        case .tls: .purple
        case .http: .green
        case .http2: .mint
        case .quic: .orange
        case .websocket: .pink
        }
    }

    // MARK: Session status

    /// Registry regions. Distinct hues rather than a severity ramp — no region
    /// is worse than another, they are just different destinations.
    static func color(for region: EndpointRegion) -> Color {
        switch region {
        case .northAmerica: .blue
        case .europe: .purple
        case .asiaPacific: .teal
        case .latinAmerica: .orange
        case .africa: .green
        case .local,
             .unknown: .secondary
        }
    }

    /// Grouping confidence. Deliberately not a green/amber/red severity ramp —
    /// a weak grouping is not an error, it is a claim the app is less sure of.
    static func color(for tier: ConfidenceTier) -> Color {
        switch tier {
        case .causal: .green
        case .strong: .blue
        case .weak: .orange
        }
    }

    static func color(for status: SessionStatus) -> Color {
        switch status {
        case .ok: .green
        case .warning: .orange
        case .error: .red
        }
    }

    // MARK: Latency heat (green → amber → red)

    static func latencyColor(milliseconds: Double?) -> Color {
        guard let ms = milliseconds else {
            return .secondary
        }
        switch ms {
        case ..<50: return .green
        case ..<150: return .yellow
        case ..<400: return .orange
        default: return .red
        }
    }
}
