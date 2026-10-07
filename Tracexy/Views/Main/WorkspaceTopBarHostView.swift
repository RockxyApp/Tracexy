import AppKit
import SwiftUI

// MARK: - WorkspaceTopBarHostView

/// A zero-size view whose only job is to find its window and install a bar under
/// the toolbar. On macOS 26 and later the bar is a top-aligned accessory of the
/// workspace split item, so it spans the session content rather than the sidebar;
/// earlier systems use a titlebar accessory. Either way AppKit owns the layout,
/// and hiding collapses it to no height. Bars that ask for ``Placement/first``
/// sit above the others, whichever was installed first.
final class WorkspaceTopBarHostView: NSView {
    // MARK: Lifecycle

    init(height: CGFloat, placement: Placement, makeContent: @escaping @MainActor () -> NSView) {
        self.height = height
        self.placement = placement
        self.makeContent = makeContent
        super.init(frame: .zero)
        setAccessibilityElement(false)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        nil
    }

    // MARK: Internal

    enum Placement {
        /// Above every other bar.
        case first
        /// Below the bars already there.
        case last
    }

    var isBarVisible = false {
        didSet {
            guard isBarVisible != oldValue else {
                return
            }
            if isBarVisible {
                installIfNeeded()
            }
            applyVisibility()
        }
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let updateObserver {
            NotificationCenter.default.removeObserver(updateObserver)
            self.updateObserver = nil
        }
        guard let window else {
            uninstall()
            return
        }
        attempts = 0
        installIfNeeded()
        // The workspace split view can be rebuilt without this view being asked to
        // update; check again (cheaply, at most twice a second) as the window updates.
        updateObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.didUpdateNotification,
            object: window,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.windowDidUpdate()
            }
        }
    }

    func uninstall() {
        splitAccessory?.removeFromParent()
        splitAccessory = nil
        if let titlebarAccessory, let window = titlebarAccessory.view.window,
           let index = window.titlebarAccessoryViewControllers.firstIndex(of: titlebarAccessory)
        {
            window.removeTitlebarAccessoryViewController(at: index)
        }
        titlebarAccessory = nil
    }

    func installIfNeeded() {
        guard !isInstalled, let window else {
            return
        }
        uninstall()
        if #available(macOS 26.0, *) {
            guard let item = Self.workspaceItem(in: window) else {
                // The split view is built after this view appears; look again shortly.
                retryLater()
                return
            }
            let accessory = NSSplitViewItemAccessoryViewController()
            let hosting = makeHostingView()
            hosting.translatesAutoresizingMaskIntoConstraints = false
            hosting.heightAnchor.constraint(equalToConstant: height).isActive = true
            accessory.view = hosting
            accessory.isHidden = !isBarVisible
            item.insertTopAlignedAccessoryViewController(
                accessory,
                at: placement == .first ? 0 : item.topAlignedAccessoryViewControllers.count
            )
            splitAccessory = accessory
            splitItem = item
        } else {
            let accessory = NSTitlebarAccessoryViewController()
            accessory.layoutAttribute = .bottom
            let hosting = makeHostingView()
            hosting.frame = NSRect(x: 0, y: 0, width: window.frame.width, height: height)
            accessory.view = hosting
            accessory.fullScreenMinHeight = height
            accessory.isHidden = !isBarVisible
            window.insertTitlebarAccessoryViewController(
                accessory,
                at: placement == .first ? 0 : window.titlebarAccessoryViewControllers.count
            )
            titlebarAccessory = accessory
        }
    }

    // MARK: Private

    private let height: CGFloat
    private let placement: Placement
    private let makeContent: @MainActor () -> NSView
    private var splitAccessory: NSViewController?
    private var titlebarAccessory: NSTitlebarAccessoryViewController?
    private var attempts = 0
    private var updateObserver: NSObjectProtocol?
    private var lastUpdateCheck = Date.distantPast

    private weak var splitItem: NSSplitViewItem?

    /// Installed, and still in this window: the workspace can rebuild its split view
    /// (a Project change remounts it), which would leave the bar on a dead item.
    private var isInstalled: Bool {
        if let splitAccessory {
            guard let splitItem, let window,
                  splitItem.viewController.view.window === window,
                  splitAccessory.parent != nil else
            {
                return false
            }
            return true
        }
        if let titlebarAccessory {
            return titlebarAccessory.parent != nil || window?.titlebarAccessoryViewControllers
                .contains(titlebarAccessory) == true
        }
        return false
    }

    /// The workspace's centre column: the non-sidebar, non-inspector item of the
    /// window's workspace split view controller.
    private static func workspaceItem(in window: NSWindow) -> NSSplitViewItem? {
        var pending: [NSViewController] = window.contentViewController.map { [$0] } ?? []
        var visited = 0
        while let controller = pending.popLast(), visited < 500 {
            visited += 1
            if let split = controller as? NativeWorkspaceSplitViewController {
                return split.splitViewItems.first { $0.behavior == .default }
            }
            pending.append(contentsOf: controller.children)
        }
        // Not reachable through child controllers: find it through its split view.
        var views: [NSView] = window.contentView.map { [$0] } ?? []
        visited = 0
        while let view = views.popLast(), visited < 5_000 {
            visited += 1
            if let split = view as? NSSplitView, let owner = split.delegate as? NativeWorkspaceSplitViewController {
                return owner.splitViewItems.first { $0.behavior == .default }
            }
            views.append(contentsOf: view.subviews)
        }
        return nil
    }

    private func makeHostingView() -> NSView {
        let content = makeContent()
        if let hosting = content as? any HostingSizing {
            hosting.clearSizingOptions()
        }
        return content
    }

    private func windowDidUpdate() {
        let now = Date()
        guard now.timeIntervalSince(lastUpdateCheck) >= 0.5 else {
            return
        }
        lastUpdateCheck = now
        installIfNeeded()
    }

    private func retryLater() {
        guard attempts < 120 else {
            return
        }
        attempts += 1
        // 0.1 s at first, then every 0.5 s, for about a minute.
        let delay = attempts < 20 ? 0.1 : 0.5
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            self?.installIfNeeded()
        }
    }

    private func applyVisibility() {
        if #available(macOS 26.0, *), let accessory = splitAccessory as? NSSplitViewItemAccessoryViewController {
            accessory.animator().isHidden = !isBarVisible
        }
        titlebarAccessory?.animator().isHidden = !isBarVisible
    }
}

// MARK: - HostingSizing

/// Lets the host clear an `NSHostingView`'s intrinsic sizing whatever its root view
/// type is, so AppKit's accessory layout, not SwiftUI, decides the bar's size.
@MainActor
protocol HostingSizing {
    func clearSizingOptions()
}

// MARK: - NSHostingView + HostingSizing

extension NSHostingView: HostingSizing {
    func clearSizingOptions() {
        sizingOptions = []
    }
}
