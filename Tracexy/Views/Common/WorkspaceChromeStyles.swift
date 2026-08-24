import AppKit
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

// MARK: - WorkspaceModeSegment

/// One icon-first destination in a native workspace mode switcher.
struct WorkspaceModeSegment<Value: Hashable> {
    let value: Value
    let title: String
    let systemImage: String
}

// MARK: - WorkspaceModeSegmentedControlCoordinator

@MainActor
final class WorkspaceModeSegmentedControlCoordinator: NSObject {
    // MARK: Lifecycle

    init(applySelection: @escaping (Int) -> Void) {
        self.applySelection = applySelection
    }

    // MARK: Internal

    var applySelection: (Int) -> Void

    @objc
    func selectionChanged(_ sender: NSSegmentedControl) {
        applySelection(sender.selectedSegment)
    }
}

// MARK: - WorkspaceModeSegmentedControl

/// Equal-width native segmented control used by the sidebar and inspector.
/// AppKit owns its capsule geometry, hover, focus ring, selection and current
/// macOS rendering instead of SwiftUI call sites hand-painting those states.
struct WorkspaceModeSegmentedControl<Value: Hashable>: NSViewRepresentable {
    // MARK: Lifecycle

    init(
        selection: Binding<Value>,
        segments: [WorkspaceModeSegment<Value>],
        accessibilityLabel: String
    ) {
        _selection = selection
        self.segments = segments
        self.accessibilityLabel = accessibilityLabel
    }

    // MARK: Internal

    @Binding var selection: Value

    let segments: [WorkspaceModeSegment<Value>]
    let accessibilityLabel: String

    func makeCoordinator() -> WorkspaceModeSegmentedControlCoordinator {
        WorkspaceModeSegmentedControlCoordinator(applySelection: selectionHandler())
    }

    func makeNSView(context: Context) -> EqualWidthSegmentedControl {
        let control = EqualWidthSegmentedControl()
        control.trackingMode = .selectOne
        control.segmentStyle = .capsule
        control.controlSize = .regular
        control.selectedSegmentBezelColor = .controlAccentColor
        control.setContentHuggingPriority(.defaultLow, for: .horizontal)
        control.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        control.target = context.coordinator
        control.action = #selector(Coordinator.selectionChanged(_:))
        update(control, coordinator: context.coordinator)
        return control
    }

    func updateNSView(_ control: EqualWidthSegmentedControl, context: Context) {
        update(control, coordinator: context.coordinator)
    }

    // MARK: Private

    private func update(
        _ control: EqualWidthSegmentedControl,
        coordinator: WorkspaceModeSegmentedControlCoordinator
    ) {
        coordinator.applySelection = selectionHandler()

        if control.segmentCount != segments.count {
            control.segmentCount = segments.count
        }

        for (index, segment) in segments.enumerated() {
            let image = NSImage(
                systemSymbolName: segment.systemImage,
                accessibilityDescription: segment.title
            )
            image?.isTemplate = true
            control.setLabel("", forSegment: index)
            control.setImage(image, forSegment: index)
            control.setImageScaling(.scaleProportionallyDown, forSegment: index)
            control.setToolTip(segment.title, forSegment: index)
            control.setEnabled(true, forSegment: index)
        }

        control.selectedSegment = segments.firstIndex { $0.value == selection } ?? -1
        control.setAccessibilityLabel(accessibilityLabel)
        control.needsLayout = true
    }

    private func selectionHandler() -> (Int) -> Void {
        let selection = $selection
        let segments = segments
        return { index in
            guard segments.indices.contains(index) else {
                return
            }
            selection.wrappedValue = segments[index].value
        }
    }
}

// MARK: - EqualWidthSegmentedControl

final class EqualWidthSegmentedControl: NSSegmentedControl {
    override var intrinsicContentSize: NSSize {
        var size = super.intrinsicContentSize
        size.width = NSView.noIntrinsicMetric
        return size
    }

    override func layout() {
        super.layout()
        guard segmentCount > 0, bounds.width > 0 else {
            return
        }
        let segmentWidth = bounds.width / CGFloat(segmentCount)
        for index in 0 ..< segmentCount where abs(width(forSegment: index) - segmentWidth) > 0.5 {
            setWidth(segmentWidth, forSegment: index)
        }
    }
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

    /// Shared layout for the native mode switchers. Rendering remains owned by
    /// `NSSegmentedControl`; this modifier only seats it within its safe-area bar.
    func workspaceModeSwitcherStyle() -> some View {
        font(Theme.Typography.modeSwitcher)
            .frame(maxWidth: .infinity, minHeight: Theme.Metrics.toolbarControlHeight)
            .padding(.horizontal, WorkspaceChrome.pickerHorizontalPadding)
            .padding(.vertical, WorkspaceChrome.pickerVerticalPadding)
    }
}
