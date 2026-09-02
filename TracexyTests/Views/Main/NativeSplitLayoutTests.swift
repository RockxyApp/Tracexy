import AppKit
import CoreGraphics
import Foundation
import SwiftUI
import Testing
@testable import Tracexy

/// Pure, window-free coverage for the native split containers' initial-layout math.
///
/// These verify the readiness gates and ideal-divider placement that keep the workspace
/// and evidence splits from latching a provisional, too-narrow layout or driving a pane's
/// geometry negative on the first layout pass.
struct NativeSplitLayoutTests {
    // MARK: Internal

    // MARK: Workspace split — layout readiness

    @Test("Layout is ready only for finite, strictly-positive bounds")
    func workspaceLayoutReadiness() {
        #expect(NativeWorkspaceSplitSizing.isLayoutReady(CGRect(x: 0, y: 0, width: 1_200, height: 760)))
        #expect(!NativeWorkspaceSplitSizing.isLayoutReady(.zero))
        #expect(!NativeWorkspaceSplitSizing.isLayoutReady(CGRect(x: 0, y: 0, width: 1_200, height: 0)))
    }

    @Test("A raw-negative provisional frame is rejected, not standardized to positive")
    func workspaceRejectsRawNegativeSize() {
        // CGRect.width would report +5 here; the sizing helper must read the raw size.
        let rawNegative = CGRect(x: 0, y: 0, width: -5, height: 760)
        #expect(!NativeWorkspaceSplitSizing.isLayoutReady(rawNegative))
    }

    @Test("Non-finite bounds are never ready")
    func workspaceRejectsNonFinite() {
        let infinite = CGRect(x: 0, y: 0, width: CGFloat.infinity, height: 760)
        #expect(!NativeWorkspaceSplitSizing.isLayoutReady(infinite))
    }

    // MARK: Workspace split — minimum seating

    @Test("Both panes seat only once the width covers every minimum plus dividers")
    func workspaceSeatsRequestedMinima() {
        func canSeat(_ totalWidth: CGFloat, sidebar: Bool, inspector: Bool) -> Bool {
            NativeWorkspaceSplitSizing.canSeatRequestedMinima(
                totalWidth: totalWidth,
                dividerThickness: 1,
                sidebarPresented: sidebar,
                inspectorPresented: inspector,
                sidebarMinimumWidth: 200,
                workspaceMinimumWidth: 420,
                inspectorMinimumWidth: 320
            )
        }

        // 200 + 320 + 420 + 2 dividers = 942 required for both panes.
        #expect(!canSeat(700, sidebar: true, inspector: true))
        #expect(canSeat(1_000, sidebar: true, inspector: true))
        // With the inspector collapsed the requirement drops to 200 + 420 + 1 = 621.
        #expect(canSeat(700, sidebar: true, inspector: false))
        #expect(!canSeat(0, sidebar: false, inspector: false))
    }

    // MARK: Workspace split — ideal placement

    @Test("Ideal placement seats both dividers when the window is wide enough")
    func workspaceIdealPlacementWhenWide() {
        let placement = NativeWorkspaceSplitSizing.idealPlacement(
            totalWidth: 1_200,
            dividerThickness: 1,
            sidebarPresented: true,
            inspectorPresented: true,
            sidebarIdealWidth: 240,
            inspectorIdealWidth: 336,
            sidebarMinimumWidth: 200,
            workspaceMinimumWidth: 420,
            inspectorMinimumWidth: 320
        )
        #expect(placement?.leadingDividerPosition == 240)
        #expect(placement?.trailingDividerPosition == CGFloat(1_200 - 336 - 1))
    }

    @Test("Ideal placement defers to AppKit when the window is too narrow")
    func workspaceIdealPlacementTooNarrow() {
        let placement = NativeWorkspaceSplitSizing.idealPlacement(
            totalWidth: 700,
            dividerThickness: 1,
            sidebarPresented: true,
            inspectorPresented: true,
            sidebarIdealWidth: 240,
            inspectorIdealWidth: 336,
            sidebarMinimumWidth: 200,
            workspaceMinimumWidth: 420,
            inspectorMinimumWidth: 320
        )
        #expect(placement == nil)
    }

    @Test("A collapsed pane contributes no divider position")
    func workspaceIdealPlacementWithCollapsedInspector() {
        let placement = NativeWorkspaceSplitSizing.idealPlacement(
            totalWidth: 1_200,
            dividerThickness: 1,
            sidebarPresented: true,
            inspectorPresented: false,
            sidebarIdealWidth: 240,
            inspectorIdealWidth: 336,
            sidebarMinimumWidth: 200,
            workspaceMinimumWidth: 420,
            inspectorMinimumWidth: 320
        )
        #expect(placement?.leadingDividerPosition == 240)
        #expect(placement?.trailingDividerPosition == nil)
    }

    // MARK: Bottom evidence split — sizing readiness

    @Test("Bottom split is ready only for finite, strictly-positive bounds")
    func bottomLayoutReadiness() {
        #expect(NativeBottomInspectorSplitSizing.isLayoutReady(CGRect(x: 0, y: 0, width: 800, height: 460)))
        #expect(!NativeBottomInspectorSplitSizing.isLayoutReady(.zero))
        #expect(!NativeBottomInspectorSplitSizing.isLayoutReady(CGRect(x: 0, y: 0, width: 800, height: -1)))
    }

    @Test("Bottom sizing resolves an unspecified proposal to a finite natural size")
    func bottomResolveUnspecified() {
        let resolved = NativeBottomInspectorSplitSizing.resolve(.unspecified, naturalHeight: 460)
        #expect(resolved?.height == 460)
        #expect(resolved?.width == NativeBottomInspectorSplitSizing.defaultWidth)
    }

    // MARK: Autosave identity

    @MainActor
    @Test("The workspace and evidence splits persist under distinct, non-empty autosave names")
    func autosaveNamesAreDistinct() {
        let workspace = RootView.workspaceSplitAutosaveName
        let bottom = RootView.bottomInspectorSplitAutosaveName
        #expect(!workspace.isEmpty)
        #expect(!bottom.isEmpty)
        #expect(workspace != bottom)
    }

    // MARK: Native window toolbar chrome

    @MainActor
    @Test("Main toolbar places the bordered sidebar toggle immediately before its tracking separator")
    func nativeSidebarToolbarChrome() {
        let controller = makeToolbarController()
        let toolbar = NativeWorkspaceToolbar(
            splitViewController: controller,
            configuration: NativeWorkspaceToolbarConfiguration(coordinator: MainContentCoordinator())
        )
        let window = NSWindow(contentViewController: controller)
        window.toolbar = toolbar.managedToolbar

        let identifiers = toolbar.managedToolbar.items.map(\.itemIdentifier)
        let toggleIndex = identifiers.firstIndex(
            of: NativeWorkspaceToolbar.sidebarToggleIdentifier
        )
        let trackingSeparatorIndex = identifiers.firstIndex(
            of: NativeWorkspaceToolbar.sidebarTrackingSeparatorIdentifier
        )

        // Flexible space leads, then the bordered toggle, then the tracking separator
        // bound to the sidebar's divider — the geometric contract that seats the
        // toggle above the source list.
        #expect(identifiers.first == .flexibleSpace)
        #expect(toggleIndex != nil)
        #expect(trackingSeparatorIndex == toggleIndex.map { $0 + 1 })
        if let toggleIndex {
            #expect(toolbar.managedToolbar.items[toggleIndex].isBordered)
        }
        if let trackingSeparatorIndex {
            #expect(
                toolbar.managedToolbar.items[trackingSeparatorIndex]
                    is NSTrackingSeparatorToolbarItem
            )
        }
    }

    @MainActor
    @Test("Centered capture status leaves its single border to the native toolbar item")
    func nativeCaptureStatusSurfaceOwnership() {
        let controller = makeToolbarController()
        let toolbar = NativeWorkspaceToolbar(
            splitViewController: controller,
            configuration: NativeWorkspaceToolbarConfiguration(coordinator: MainContentCoordinator())
        )
        let window = NSWindow(contentViewController: controller)
        window.toolbar = toolbar.managedToolbar

        #expect(toolbar.managedToolbar.centeredItemIdentifiers == [
            NativeWorkspaceToolbar.captureStatusIdentifier,
        ])

        let statusItem = toolbar.managedToolbar.items.first(where: {
            $0.itemIdentifier == NativeWorkspaceToolbar.captureStatusIdentifier
        })
        #expect(statusItem?.view != nil)
        #expect(statusItem?.isBordered == true)
    }

    @MainActor
    @Test("Trailing export menu stays visible beside the grouped capture and inspector actions")
    func nativeActionGroupStructure() {
        let controller = makeToolbarController()
        let toolbar = NativeWorkspaceToolbar(
            splitViewController: controller,
            configuration: NativeWorkspaceToolbarConfiguration(coordinator: MainContentCoordinator())
        )
        let window = NSWindow(contentViewController: controller)
        window.toolbar = toolbar.managedToolbar

        guard let actionsItem = toolbar.managedToolbar.items.first(where: {
            $0.itemIdentifier == NativeWorkspaceToolbar.actionsIdentifier
        }) else {
            Issue.record("Trailing actions item was not installed")
            return
        }

        let group = actionsItem as? NSToolbarItemGroup
        #expect(group != nil)
        #expect(group?.subitems.count == 3)
        #expect(group?.subitems.map(\.label) == ["Start", "Bottom Inspector", "Inspector"])

        let exportItem = toolbar.managedToolbar.items.first(where: {
            $0.itemIdentifier == NativeWorkspaceToolbar.sessionExportIdentifier
        }) as? NSMenuToolbarItem
        #expect(exportItem != nil)
        #expect(exportItem?.isBordered == false)
        #expect(exportItem?.showsIndicator == true)
        #expect(exportItem?.menu.items.map(\.title) == [
            "Export Session",
            "Export as pcap",
            "Export as pcapng",
        ])
    }

    @MainActor
    @Test("Capture action observes an immediate launch-state transition")
    func nativeCaptureActionObservesImmediateStart() async {
        let controller = makeToolbarController()
        let coordinator = MainContentCoordinator()
        let toolbar = NativeWorkspaceToolbar(
            splitViewController: controller,
            configuration: NativeWorkspaceToolbarConfiguration(coordinator: coordinator)
        )
        let window = NSWindow(contentViewController: controller)
        window.toolbar = toolbar.managedToolbar

        guard let group = toolbar.managedToolbar.items.first(where: {
            $0.itemIdentifier == NativeWorkspaceToolbar.actionsIdentifier
        }) as? NSToolbarItemGroup,
            let captureItem = group.subitems.first(where: {
                $0.itemIdentifier == NativeWorkspaceToolbar.captureActionIdentifier
            }) else
        {
            Issue.record("Capture toolbar item was not installed")
            return
        }

        toolbar.startObservingState()
        // Mirrors launch auto-start: the coordinator can become live before the
        // observation task receives its first MainActor turn.
        coordinator.isCapturing = true
        await Task.yield()

        #expect(captureItem.label == "Stop")
        #expect(captureItem.toolTip == "Stop capture")
        #expect(captureItem.image?.accessibilityDescription == "Stop")
    }

    @MainActor
    @Test("Native toolbar toggle collapses and restores the real sidebar split item")
    func nativeToolbarTogglesSidebar() {
        let controller = makeToolbarController()
        var publishedPresentations: [Bool] = []
        controller.onSidebarVisibilityChanged = {
            publishedPresentations.append($0)
        }
        let toolbar = NativeWorkspaceToolbar(
            splitViewController: controller,
            configuration: NativeWorkspaceToolbarConfiguration(coordinator: MainContentCoordinator())
        )
        let window = NSWindow(contentViewController: controller)
        window.toolbar = toolbar.managedToolbar
        guard let toggleItem = toolbar.managedToolbar.items.first(where: {
            $0.itemIdentifier == NativeWorkspaceToolbar.sidebarToggleIdentifier
        }),
            let action = toggleItem.action else
        {
            Issue.record("Sidebar toolbar item was not installed")
            return
        }

        NSApp.sendAction(action, to: toggleItem.target, from: toggleItem)
        #expect(!controller.isSidebarPresented)
        #expect(publishedPresentations.last == false)

        NSApp.sendAction(action, to: toggleItem.target, from: toggleItem)
        #expect(controller.isSidebarPresented)
        #expect(publishedPresentations.last == true)
    }

    @MainActor
    @Test("Native toolbar does not retain its workspace split controller")
    func nativeToolbarDoesNotRetainSplitController() {
        weak var releasedController: NativeWorkspaceSplitViewController?
        let toolbar: NativeWorkspaceToolbar = {
            let controller = NativeWorkspaceSplitViewController()
            releasedController = controller
            return NativeWorkspaceToolbar(
                splitViewController: controller,
                configuration: NativeWorkspaceToolbarConfiguration(coordinator: MainContentCoordinator())
            )
        }()

        #expect(releasedController == nil)
        withExtendedLifetime(toolbar) {}
    }

    // MARK: Private

    /// A laid-out three-pane workspace controller for the toolbar chrome tests.
    @MainActor
    private func makeToolbarController() -> NativeWorkspaceSplitViewController {
        let controller = NativeWorkspaceSplitViewController()
        controller.configure(
            sidebarController: NSHostingController(rootView: Color.clear),
            workspaceController: NSHostingController(rootView: Color.clear),
            inspectorController: NSHostingController(rootView: Color.clear),
            isSidebarPresented: true,
            isInspectorPresented: true,
            layout: NativeWorkspaceSplitLayout(
                autosaveName: "NativeSplitLayoutTests-\(UUID().uuidString)",
                sidebarMinimumWidth: 200,
                sidebarIdealWidth: 240,
                sidebarMaximumWidth: 350,
                workspaceMinimumWidth: 420,
                inspectorMinimumWidth: 320,
                inspectorIdealWidth: 336,
                inspectorMaximumWidth: 520
            )
        )
        controller.view.frame = CGRect(x: 0, y: 0, width: 1_300, height: 700)
        controller.view.needsLayout = true
        controller.view.layoutSubtreeIfNeeded()
        return controller
    }
}
