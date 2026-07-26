import AppKit
import SwiftUI

// MARK: - NativeBottomInspectorSplitView

/// Hosts the session table and its evidence inspector in a native horizontal split-view
/// controller.
///
/// The controller stays mounted while its bottom item collapses, preserving table identity,
/// selection, scroll position, and inspector state across toolbar toggles. Divider drag is
/// bounded only by the two minimum heights, so the evidence pane can grow to whatever the
/// user drags it to.
struct NativeBottomInspectorSplitView<Primary: View, Inspector: View>: NSViewControllerRepresentable {
    // MARK: Lifecycle

    init(
        isInspectorPresented: Binding<Bool>,
        autosaveName: String,
        primaryMinimumHeight: CGFloat,
        inspectorMinimumHeight: CGFloat,
        @ViewBuilder primary: @escaping () -> Primary,
        @ViewBuilder inspector: @escaping () -> Inspector
    ) {
        _isInspectorPresented = isInspectorPresented
        self.autosaveName = autosaveName
        self.primaryMinimumHeight = primaryMinimumHeight
        self.inspectorMinimumHeight = inspectorMinimumHeight
        self.primary = primary
        self.inspector = inspector
    }

    // MARK: Internal

    // MARK: - Coordinator

    final class Coordinator {
        // MARK: Internal

        var primaryController: NSHostingController<NativeBottomDeferredContent<Primary>>?
        var inspectorController: NSHostingController<NativeBottomDeferredContent<Inspector>>?

        func recordInitialPresentation(_ isPresented: Bool) {
            lastAppliedPresentation = isPresented
        }

        func shouldApplyPresentation(_ isPresented: Bool) -> Bool {
            guard lastAppliedPresentation != isPresented else {
                return false
            }
            lastAppliedPresentation = isPresented
            return true
        }

        // MARK: Private

        private var lastAppliedPresentation: Bool?
    }

    @Binding var isInspectorPresented: Bool

    let autosaveName: String
    let primaryMinimumHeight: CGFloat
    let inspectorMinimumHeight: CGFloat
    @ViewBuilder let primary: () -> Primary
    @ViewBuilder let inspector: () -> Inspector

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSViewController(context: Context) -> NativeBottomInspectorSplitViewController {
        let primaryController = NSHostingController(
            rootView: NativeBottomDeferredContent(content: primary)
        )
        let inspectorController = NSHostingController(
            rootView: NativeBottomDeferredContent(content: inspector)
        )

        // Prevent SwiftUI ideal sizes from propagating through the split controller and
        // resizing the containing workspace window.
        primaryController.sizingOptions = []
        inspectorController.sizingOptions = []

        context.coordinator.primaryController = primaryController
        context.coordinator.inspectorController = inspectorController
        context.coordinator.recordInitialPresentation(isInspectorPresented)

        let controller = NativeBottomInspectorSplitViewController()
        controller.configure(
            primaryController: primaryController,
            inspectorController: inspectorController,
            isInspectorPresented: isInspectorPresented,
            autosaveName: autosaveName,
            primaryMinimumHeight: primaryMinimumHeight,
            inspectorMinimumHeight: inspectorMinimumHeight
        )
        updateVisibilityCallback(on: controller)
        return controller
    }

    func updateNSViewController(
        _ controller: NativeBottomInspectorSplitViewController,
        context: Context
    ) {
        // Keep both hosting roots stable for the lifetime of the native split controller.
        // Their deferred builders read observable workspace state from inside the hosting
        // hierarchy, so rows and inspector details still update without replacing rootView.
        // Replacing either root during an outer SwiftUI/AppKit constraint pass can recurse
        // through the split controller and crash under exclusive-access checks.
        updateVisibilityCallback(on: controller)
        if context.coordinator.shouldApplyPresentation(isInspectorPresented) {
            controller.setInspectorPresented(isInspectorPresented, animated: true)
        }
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        nsViewController: NativeBottomInspectorSplitViewController,
        context: Context
    )
        -> CGSize?
    {
        NativeBottomInspectorSplitSizing.resolve(
            proposal,
            naturalHeight: primaryMinimumHeight + inspectorMinimumHeight
        )
    }

    // MARK: Private

    private func updateVisibilityCallback(on controller: NativeBottomInspectorSplitViewController) {
        let presentation = $isInspectorPresented
        controller.onInspectorVisibilityChanged = { isVisible in
            guard presentation.wrappedValue != isVisible else {
                return
            }
            presentation.wrappedValue = isVisible
        }
    }
}

// MARK: - NativeBottomDeferredContent

/// Evaluates the content builder inside the hosted SwiftUI hierarchy.
///
/// This lets Observation invalidate the relevant content in place while the AppKit split
/// items and their hosting roots keep stable identities across table/filter updates.
struct NativeBottomDeferredContent<Content: View>: View {
    let content: () -> Content

    var body: some View {
        content()
    }
}

// MARK: - NativeBottomInspectorSplitSizing

enum NativeBottomInspectorSplitSizing {
    /// Fallback width used when a proposal leaves the horizontal dimension unspecified.
    static let defaultWidth: CGFloat = 800

    static func resolve(_ proposal: ProposedViewSize, naturalHeight: CGFloat) -> CGSize? {
        let resolved = proposal.replacingUnspecifiedDimensions(
            by: CGSize(width: defaultWidth, height: naturalHeight)
        )
        guard resolved.width.isFinite, resolved.height.isFinite else {
            return nil
        }
        return resolved
    }

    /// The split view can safely consume its pending initial state once both dimensions are
    /// finite and strictly positive. Collapsing or expanding into zero/insufficient bounds is
    /// what produced startup `Invalid view geometry` faults.
    static func isLayoutReady(_ bounds: CGRect) -> Bool {
        bounds.size.width.isFinite
            && bounds.size.height.isFinite
            && bounds.size.width > 0
            && bounds.size.height > 0
    }
}

// MARK: - NativeBottomInspectorSplitViewController

@MainActor
final class NativeBottomInspectorSplitViewController: NSSplitViewController {
    // MARK: Internal

    var onInspectorVisibilityChanged: ((Bool) -> Void)?

    var isInspectorPresented: Bool {
        inspectorItem.map { !$0.isCollapsed } ?? false
    }

    override func viewDidLayout() {
        super.viewDidLayout()
        guard pendingInitialVisibility != nil else {
            return
        }
        guard NativeBottomInspectorSplitSizing.isLayoutReady(splitView.bounds) else {
            // Bounds are still zero/insufficient. Retain the requested state and wait for a
            // valid layout pass rather than collapsing/expanding into negative geometry.
            return
        }
        guard let pendingInitialVisibility else {
            return
        }
        self.pendingInitialVisibility = nil
        setInspectorPresented(pendingInitialVisibility, animated: false)
        isApplyingInitialState = false
    }

    func configure(
        primaryController: NSViewController,
        inspectorController: NSViewController,
        isInspectorPresented: Bool,
        autosaveName: String,
        primaryMinimumHeight: CGFloat,
        inspectorMinimumHeight: CGFloat
    ) {
        splitView.isVertical = false
        splitView.dividerStyle = .thin

        let primaryItem = NSSplitViewItem(viewController: primaryController)
        primaryItem.minimumThickness = primaryMinimumHeight
        primaryItem.canCollapse = false
        primaryItem.holdingPriority = .defaultLow

        let inspectorItem = NSSplitViewItem(viewController: inspectorController)
        inspectorItem.minimumThickness = inspectorMinimumHeight
        inspectorItem.canCollapse = true
        inspectorItem.collapseBehavior = .useConstraints
        inspectorItem.isSpringLoaded = true
        inspectorItem.holdingPriority = .defaultHigh

        addSplitViewItem(primaryItem)
        addSplitViewItem(inspectorItem)

        // AppKit restores divider position only after both items belong to the split controller.
        splitView.autosaveName = NSSplitView.AutosaveName(autosaveName)
        self.inspectorItem = inspectorItem
        requestedInspectorVisibility = isInspectorPresented
        pendingInitialVisibility = isInspectorPresented
        observeCollapseState(of: inspectorItem)
        // Initial collapse state is deferred to the first valid layout pass. Applying it here,
        // while the controller has zero-sized bounds, risks negative startup geometry.
    }

    func setInspectorPresented(_ isPresented: Bool, animated: Bool) {
        requestedInspectorVisibility = isPresented
        guard let inspectorItem, inspectorItem.isCollapsed == isPresented else {
            return
        }

        if animated, view.window != nil {
            NSAnimationContext.runAnimationGroup { context in
                context.duration = 0.18
                inspectorItem.animator().isCollapsed = !isPresented
            }
        } else {
            inspectorItem.isCollapsed = !isPresented
        }
    }

    // MARK: Private

    private weak var inspectorItem: NSSplitViewItem?
    private var collapseObservation: NSKeyValueObservation?
    private var requestedInspectorVisibility = false
    private var pendingInitialVisibility: Bool?
    private var isApplyingInitialState = true

    private func observeCollapseState(of item: NSSplitViewItem) {
        collapseObservation = item.observe(\.isCollapsed, options: [.new]) { [weak self] _, _ in
            DispatchQueue.main.async { [weak self] in
                guard let self else {
                    return
                }
                // Read the current value after AppKit finishes the collapse transaction. A
                // queued KVO callback can otherwise publish an obsolete intermediate value and
                // immediately reverse the SwiftUI binding.
                inspectorVisibilityDidChange(isInspectorPresented)
            }
        }
    }

    private func inspectorVisibilityDidChange(_ isVisible: Bool) {
        guard !isApplyingInitialState else {
            return
        }
        guard isVisible != requestedInspectorVisibility else {
            return
        }
        requestedInspectorVisibility = isVisible
        onInspectorVisibilityChanged?(isVisible)
    }
}
