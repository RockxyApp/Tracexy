import AppKit
import SwiftUI

// MARK: - AppThemeApplier

/// Applies the user's appearance preference (system / light / dark) at the AppKit
/// level via `NSApp.appearance`, so a forced light/dark covers *everything* —
/// menus, Save/Open panels, alerts, and any AppKit-hosted or future window — not
/// only SwiftUI scene content.
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
        static let sidebarMinWidth: CGFloat = 220
        static let sidebarIdealWidth: CGFloat = 260
        /// Cap the source list so a wide window doesn't stretch the sidebar past
        /// the point where its rows read as navigation rather than content.
        static let sidebarMaxWidth: CGFloat = 320
        static let inspectorWidth: CGFloat = 320
        static let rowHeight: CGFloat = 28
        /// Shared row height for every bottom bar — the sidebar footer, the
        /// workspace/session status bar and the right Details inspector footer —
        /// so all three meet on one baseline (see `WorkspaceFooterBar`).
        static let footerBarHeight: CGFloat = 34
        static let cornerRadius: CGFloat = 8
        static let spacingS: CGFloat = 4
        static let spacingM: CGFloat = 8
        static let spacingL: CGFloat = 12

        // Inspector docks — approved metrics (design-system.md), now seated in
        // native AppKit split items: right inspector as a semantic inspector
        // column, evidence inspector as a horizontal split below the table.
        static let contextDockMinWidth: CGFloat = 320
        static let contextDockIdealWidth: CGFloat = 336
        static let contextDockMaxWidth: CGFloat = 460
        // Minimum heights bound the native evidence-split divider; there is no
        // artificial maximum, so the divider drags freely to any height the two
        // minimums allow.
        static let bottomInspectorMinHeight: CGFloat = 220
        static let sessionTableMinWidth: CGFloat = 420
        static let sessionTableMinHeight: CGFloat = 240

        // Chrome pills/chips
        static let pillCornerRadius: CGFloat = 6
        static let chipCornerRadius: CGFloat = 4

        // Center toolbar status + software-update badge: one 32pt native control
        // with a 24pt continuous capsule inset.
        static let toolbarControlHeight: CGFloat = 32
        static let updateBadgeHeight: CGFloat = 24
        static let updateBadgeHorizontalPadding: CGFloat = 9
        static let updateBadgeStrokeWidth: CGFloat = 0.75

        // Right Details inspector tables. Named tokens keep every diagnostics
        // group on the same two-column grid in both compact and expanded docks.
        static let contextTableGroupSpacing: CGFloat = 10
        static let contextTableOuterPadding: CGFloat = 12
        static let contextTableColumnPadding: CGFloat = 10
        static let contextTableHeaderVerticalPadding: CGFloat = 7
        static let contextTableRowVerticalPadding: CGFloat = 6
        static let contextTableCornerRadius: CGFloat = 6
        static let contextTableLabelWidth: CGFloat = 90
        static let contextTableInsightLabelWidth: CGFloat = 110

        // AI Assistant dock shell. These mirror the compact native hierarchy
        // used by the Details dock: chrome rows stay fixed while the transcript
        // owns the remaining height.
        static let assistantHeaderHeight: CGFloat = 36
        static let assistantContextHeight: CGFloat = 32
        static let assistantContentPadding: CGFloat = 10
        static let assistantComposerCornerRadius: CGFloat = 10
        static let assistantPopoverWidth: CGFloat = 320
    }

    // MARK: Typography

    /// The app's whole type scale, expressed in **semantic macOS text styles**
    /// rather than hardcoded point sizes.
    ///
    /// This used to be a fixed five-size ladder (16 / 13 / 12 / 11 / 10). That
    /// killed the half-point drift it was written to kill, but it also opted the
    /// whole app out of Dynamic Type: every label was a frozen pixel count, so a
    /// user who raised their text size saw nothing move. Rebinding each token to
    /// a `Font.TextStyle` keeps the same visual hierarchy on the default macOS 14
    /// setting *and* lets one accessibility setting scale the entire app from a
    /// single source of truth.
    ///
    /// The mapping preserves the old ranking (each style's default point size on
    /// macOS is noted), so call sites inherit the same relative scale:
    ///
    /// | Token          | Text style     | ~pt | Job                              |
    /// |----------------|----------------|-----|----------------------------------|
    /// | `title`        | `.title3`      | 15  | What a panel is about            |
    /// | `surfaceTitle` | `.headline`    | 13  | Surface and sheet headers        |
    /// | `navigation`   | `.body`        | 13  | Source-list navigation rows      |
    /// | `body`         | `.callout`     | 12  | Rows, fields, controls — default |
    /// | `caption`      | `.subheadline` | 11  | Supporting text off a body line  |
    /// | `micro`        | `.caption`     | 10  | Ticks, badges, section headers   |
    ///
    /// Weight carries emphasis *within* a step; reach for the emphasis variant
    /// before reaching for a bigger size. Never write `.system(size:)` in a
    /// view — if something here doesn't fit, the scale is wrong and should be
    /// changed here, once. The only exceptions are the display metrics below.
    enum Typography {
        // Structure
        static let title = Font.title3.weight(.semibold)
        static let surfaceTitle = Font.headline

        // Navigation — source-list rows read at the native sidebar size.
        static let navigation = Font.body
        static let navigationMedium = Font.body.weight(.medium)

        // Body — the default for rows, fields and controls
        static let body = Font.callout
        static let bodyMedium = Font.callout.weight(.medium)
        static let bodyEmphasis = Font.callout.weight(.semibold)

        // Supporting text
        static let caption = Font.subheadline
        static let captionMedium = Font.subheadline.weight(.medium)
        static let captionEmphasis = Font.subheadline.weight(.semibold)

        // Smallest legible step: ticks, badges, uppercase section headers
        static let micro = Font.caption
        static let microMedium = Font.caption.weight(.medium)
        static let microEmphasis = Font.caption.weight(.semibold)
        static let badge = Font.caption.weight(.semibold)
        static let sectionHeader = Font.caption.weight(.semibold)

        /// Mode switchers — the sidebar navigator and the inspector's segmented
        /// control. Sits on the body step so a switcher reads as chrome, not text.
        static let modeSwitcher = Font.callout

        // Workspace chrome — the shared footer/status baseline. `WorkspaceFooterBar`
        // installs `chrome` as the environment font so every bottom bar inherits it;
        // `chromeAction` labels an inline footer button and `chromeSecondary` is the
        // quieter telemetry/summary text hung beside it.
        static let chrome = Font.callout
        static let chromeAction = Font.callout.weight(.medium)
        static let chromeSecondary = Font.subheadline
        static let toolbarBadge = Font.body.weight(.semibold)

        // Monospaced — for values read digit-by-digit (addresses, hex, bytes).
        // Styles track the proportional scale so a mono value sits on the same
        // baseline as the label next to it, and scale with Dynamic Type together.
        static let mono = Font.system(.callout, design: .monospaced)
        static let monoSmall = Font.system(.subheadline, design: .monospaced)
        static let monoMicro = Font.system(.caption, design: .monospaced)

        /// Big read-at-a-glance figures — Overview stat tiles, onboarding
        /// headlines. Kept as deliberate fixed sizes, outside the semantic scale:
        /// these are display numerals, not text, and sizing them from the body
        /// step made them look like a heading that had gone wrong.
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

    // MARK: Chrome (sidebar + workspace footers)

    /// Semantic surfaces for the two bottom bars, so the sidebar footer and the
    /// workspace status bar meet on one baseline and adapt to light/dark and
    /// accessibility contrast without hand-tuned colors.
    ///
    /// They are deliberately *different* materials: the sidebar footer lives
    /// inside the source-list column, so it expresses that column's own sidebar
    /// material; the workspace footer spans the (non-vibrant) content area, so it
    /// uses an opaque window background rather than a `.bar` that would tint
    /// whatever scrolls beneath it.
    enum Chrome {
        /// Sidebar footer fill. Clear on purpose: it sits over the source-list
        /// column and inherits that column's sidebar material, reading as part of
        /// the sidebar rather than a separate strip. The top hairline is the seam.
        static let sidebarFooterBackground = Color.clear

        /// Workspace footer / status-bar fill — opaque window background so the
        /// table and inspector never bleed up through it.
        static let workspaceFooterBackground = Color(nsColor: .windowBackgroundColor)

        /// Hairline between either footer and the content above it.
        static let separator = Color(nsColor: .separatorColor)
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
