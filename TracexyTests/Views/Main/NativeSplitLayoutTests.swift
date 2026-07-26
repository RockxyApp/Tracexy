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
}
