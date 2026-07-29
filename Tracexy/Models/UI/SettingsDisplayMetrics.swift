import SwiftUI

// MARK: - SettingsDisplayMetrics

/// Layout and type metrics for Tracexy's native Settings window.
///
/// The layout/density values are constant so panes render identically regardless
/// of runtime state. The font accessors, by contrast, are bound to the semantic
/// `Theme.Typography` scale rather than frozen point sizes, so Settings text
/// scales with Dynamic Type alongside the rest of the app while keeping the
/// existing size ranking (body / one-up / secondary / metadata) intact.
struct SettingsDisplayMetrics: Equatable {
    /// Shared instance used by every Settings pane.
    static let standard = SettingsDisplayMetrics()

    let bodyFontSize: CGFloat = 12
    let secondaryFontSize: CGFloat = 11
    let metadataFontSize: CGFloat = 10

    let windowWidth: CGFloat = 820
    let windowHeight: CGFloat = 600

    let contentPadding: CGFloat = 28
    let labelWidth: CGFloat = 140
    let wideLabelWidth: CGFloat = 182
    let sectionSpacing: CGFloat = 18
    let sectionTitleSpacing: CGFloat = 7
    let cardSpacing: CGFloat = 10
    let cardHorizontalPadding: CGFloat = 18
    let cardVerticalPadding: CGFloat = 16
    let cardCornerRadius: CGFloat = 8

    /// Right-aligned label column for the compact detail grids inside a card.
    /// Narrower than `labelWidth` on purpose: a grid sits *within* a card that a
    /// `SettingsRow` has already indented, so reusing the full width would push
    /// its values off toward the middle of the pane.
    let detailLabelWidth: CGFloat = 120

    /// Leading inset that aligns un-labelled controls (checkboxes, notes) with the
    /// control column of `SettingsRow`.
    var rowLeading: CGFloat {
        labelWidth + 16
    }

    var controlHeight: CGFloat {
        max(24, bodyFontSize + 12)
    }

    var footerHeight: CGFloat {
        max(36, bodyFontSize + 24)
    }

    func fieldWidth(_ baseWidth: CGFloat) -> CGFloat {
        baseWidth
    }

    func menuWidth(_ baseWidth: CGFloat) -> CGFloat {
        baseWidth
    }

    func font(weight: Font.Weight = .regular) -> Font {
        Theme.Typography.body.weight(weight)
    }

    /// One step above body, for the heading of a card that leads with a name
    /// rather than a label — a named section title, say, rather than a field caption.
    func emphasisFont(weight: Font.Weight = .semibold) -> Font {
        Theme.Typography.surfaceTitle.weight(weight)
    }

    func monospacedFont(weight: Font.Weight = .regular) -> Font {
        Theme.Typography.mono.weight(weight)
    }

    func secondaryFont(weight: Font.Weight = .regular) -> Font {
        Theme.Typography.caption.weight(weight)
    }

    func metadataFont(weight: Font.Weight = .regular) -> Font {
        Theme.Typography.micro.weight(weight)
    }
}
