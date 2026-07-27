import SwiftUI

// MARK: - WorkspaceChrome

/// Shared metrics for the workspace's mode switchers, so the two segmented
/// controls in different columns (the sidebar navigator and the inspector's
/// Details / AI picker) read as one control rather than two that happen to look
/// similar. Kept beside the modifier that consumes them so a change here moves
/// both switchers at once.
enum WorkspaceChrome {
    static let pickerHorizontalPadding: CGFloat = 10
    static let pickerVerticalPadding: CGFloat = Theme.Metrics.spacingM
}

// MARK: - WorkspaceSegmentedPickerStyle

/// The one segmented control used for every workspace mode switcher.
///
/// It owns the regular control size, the `modeSwitcher` font and one shared
/// padding — the three things that made the sidebar navigator and the inspector
/// picker drift apart when each site styled its own `Picker`. Call sites keep
/// their own `selection` binding and tags; only the chrome is centralised here.
private struct WorkspaceSegmentedPickerStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .pickerStyle(.segmented)
            .controlSize(.regular)
            .labelsHidden()
            .font(Theme.Typography.modeSwitcher)
            .padding(.horizontal, WorkspaceChrome.pickerHorizontalPadding)
            .padding(.vertical, WorkspaceChrome.pickerVerticalPadding)
    }
}

extension View {
    /// Apply the shared workspace segmented-picker chrome. Preserves the picker's
    /// own binding and tags; standardises size, font and padding.
    func workspaceSegmentedPicker() -> some View {
        modifier(WorkspaceSegmentedPickerStyle())
    }
}
