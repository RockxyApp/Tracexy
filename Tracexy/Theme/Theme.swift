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
    // MARK: Internal

    static func apply(_ appearance: AppAppearance) {
        let resolvedAppearance: NSAppearance? = switch appearance {
        case .system: nil
        case .light: NSAppearance(named: .aqua)
        case .dark: NSAppearance(named: .darkAqua)
        }

        NSApp.appearance = resolvedAppearance
        refreshExistingWindowChrome(with: resolvedAppearance)

        // SwiftUI-hosted NSToolbar items can finish updating after the setting
        // action returns. A second main-loop refresh prevents an old sampled
        // Light/Dark tone from surviving inside the new window appearance.
        DispatchQueue.main.async {
            refreshExistingWindowChrome(with: resolvedAppearance)
        }
    }

    static func refreshWindowChrome(_ window: NSWindow, appearance: NSAppearance?) {
        window.appearance = appearance
        window.contentView?.appearance = nil
        window.contentView?.needsLayout = true
        window.contentView?.needsDisplay = true

        guard let toolbar = window.toolbar else {
            return
        }

        let hostedViews = (toolbar.items + (toolbar.visibleItems ?? [])).compactMap(\.view)
        for view in hostedViews {
            refreshToolbarView(view, appearance: appearance)
        }
        toolbar.validateVisibleItems()
    }

    static func refreshToolbarView(_ view: NSView, appearance: NSAppearance?) {
        view.appearance = appearance
        view.needsLayout = true
        view.needsDisplay = true
        for subview in view.subviews {
            refreshToolbarView(subview, appearance: appearance)
        }
    }

    // MARK: Private

    private static func refreshExistingWindowChrome(with appearance: NSAppearance?) {
        for window in NSApp.windows {
            refreshWindowChrome(window, appearance: appearance)
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
        static let controlSpacing: CGFloat = 6
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
        /// The selected-session identity strip, facet strip and read-only footer
        /// remain visible without squeezing the evidence body below a useful
        /// inspection height.
        static let bottomInspectorMinHeight: CGFloat = 260
        static let sessionTableMinWidth: CGFloat = 420
        static let sessionTableMinHeight: CGFloat = 240

        // Chrome pills/chips
        static let pillCornerRadius: CGFloat = 6
        static let chipCornerRadius: CGFloat = 4

        /// Center toolbar status + software-update badge: one 32pt native control
        /// with a 24pt continuous capsule inset.
        static let toolbarControlHeight: CGFloat = 32
        /// Keep capture-source text away from Project identity and centered status
        /// at narrow desktop widths. The menu and full accessible label stay intact.
        static let toolbarCompactWindowWidth: CGFloat = 1_180
        static let toolbarInterfaceLabelMaximumWidth: CGFloat = 140
        /// The label frame inside a small native glass button. Native button
        /// insets expand this to a comfortable pointer target; keeping the inner
        /// square at the approved 27pt rhythm prevents toolbar glyphs from looking
        /// oversized beside the picker and search field.
        static let sessionShelfControlLength: CGFloat = 27
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
    /// | `body`         | `.body`        | 13  | Rows, fields, controls — default |
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
        static let surfaceTitle = Font.headline.weight(.semibold)

        // Navigation — source-list rows read at the native sidebar size.
        static let navigation = Font.body
        static let navigationMedium = Font.body.weight(.medium)

        // Body — the default for rows, fields and controls
        static let body = Font.body
        static let bodyMedium = Font.body.weight(.medium)
        static let bodyEmphasis = Font.body.weight(.semibold)

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
        static let modeSwitcher = Font.body

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

    // MARK: Liquid Glass

    /// Optical tokens for functional chrome and dense adaptive content surfaces.
    /// Keeping these values together prevents each screen from inventing its own
    /// translucency, border and corner-radius recipe.
    enum Glass {
        // Sessions uses the approved two-surface control-shelf geometry: generous
        // outer breathing room, one shared sampling group and a softer 16pt
        // continuous corner. Keep these separate from generic functional bars
        // so inspector and footer chrome retain their denser native metrics.
        static let sessionShelfCornerRadius: CGFloat = 16
        static let sessionShelfOuterPadding: CGFloat = 10
        static let sessionShelfSectionSpacing: CGFloat = 7
        static let sessionShelfBottomPadding: CGFloat = 4
        static let functionalBarCornerRadius: CGFloat = 12
        static let functionalBarHorizontalInset: CGFloat = 7
        static let functionalBarVerticalInset: CGFloat = 5

        static let fallbackTintOpacity = 0.15
        static let fallbackStrokeOpacity = 0.28
        static let neutralStrokeOpacity = 0.12

        static let neutralFillOpacity = 0.06
        static let hoverFillOpacity = 0.10
        static let activeStrokeOpacity = 0.55
        static let semanticFillOpacity = 0.14
        static let semanticHoverFillOpacity = 0.20
        static let semanticStrokeOpacity = 0.34
        static let semanticHoverStrokeOpacity = 0.52

        static let contentStrokeOpacity = 0.11
        static let contentTintOpacity = 0.07
        static let contentTintStrokeOpacity = 0.20
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
        case .stun: .yellow
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
