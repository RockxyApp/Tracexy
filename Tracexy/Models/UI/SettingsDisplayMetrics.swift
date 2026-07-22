import SwiftUI

// MARK: - SettingsDisplayMetrics

/// Fixed layout + type metrics for the Settings window, mirroring the sibling app's
/// classic System-Preferences look. Self-contained on purpose: unlike the sibling app's
/// metrics it takes no dependency on a live app-UI settings object — every value
/// is a constant so panes render identically regardless of runtime state.
struct SettingsDisplayMetrics: Equatable {
    /// Shared instance used by every Settings pane.
    static let standard = SettingsDisplayMetrics()

    let bodyFontSize: CGFloat = 13
    let secondaryFontSize: CGFloat = 12
    let metadataFontSize: CGFloat = 11

    let windowWidth: CGFloat = 820
    let windowHeight: CGFloat = 600

    let contentPadding: CGFloat = 28
    let labelWidth: CGFloat = 160
    let wideLabelWidth: CGFloat = 182

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
        .system(size: bodyFontSize, weight: weight)
    }

    func secondaryFont(weight: Font.Weight = .regular) -> Font {
        .system(size: secondaryFontSize, weight: weight)
    }

    func metadataFont(weight: Font.Weight = .regular) -> Font {
        .system(size: metadataFontSize, weight: weight)
    }
}
