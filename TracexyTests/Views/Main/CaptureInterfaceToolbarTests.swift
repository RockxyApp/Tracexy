import AppKit
import SwiftUI
import Testing
@testable import Tracexy

@MainActor
struct CaptureInterfaceToolbarTests {
    @Test("Toolbar source constraints follow a narrow-to-wide resize round trip")
    func toolbarResizeRoundTrip() async throws {
        let coordinator = MainContentCoordinator()
        let split = NativeWorkspaceSplitViewController()
        let toolbar = NativeWorkspaceToolbar(
            splitViewController: split,
            configuration: NativeWorkspaceToolbarConfiguration(coordinator: coordinator)
        )
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_320, height: 700),
            styleMask: [.titled, .resizable],
            backing: .buffered,
            defer: false
        )
        window.toolbar = toolbar.managedToolbar
        let host = try #require(toolbar.managedToolbar.items.first {
            $0.itemIdentifier == NativeWorkspaceToolbar.interfacePickerIdentifier
        }?.view as? CaptureInterfaceToolbarHost)
        #expect(host.sizingOptions.contains(.minSize))
        #expect(host.sizingOptions.contains(.maxSize))
        window.orderFront(nil)
        defer { window.orderOut(nil) }
        for width: CGFloat in [1_000, 1_320, 1_000, 1_320] {
            window.setContentSize(NSSize(width: width, height: 700))
            NotificationCenter.default.post(name: NSWindow.didResizeNotification, object: window)
            await Task.yield()
            window.contentView?.superview?.layoutSubtreeIfNeeded()
            #expect(host.rootView.isCompact == (width < Theme.Metrics.toolbarCompactWindowWidth))
            #expect(host.frame.width >= host.fittingSize.width - 1)
        }
    }

    @Test("Source control remains measurable in light, dark, and high-contrast appearances")
    func nativeAppearances() {
        let host = CaptureInterfaceToolbarHost(coordinator: MainContentCoordinator())
        for name in [
            NSAppearance.Name.aqua,
            .darkAqua,
            .accessibilityHighContrastAqua,
            .accessibilityHighContrastDarkAqua
        ] {
            host.appearance = NSAppearance(named: name)
            for compact in [false, true] {
                host.rootView.isCompact = compact
                host.layoutSubtreeIfNeeded()
                let size = host.fittingSize
                #expect(size.width.isFinite && size.width > 0)
                #expect(size.height.isFinite && size.height > 0)
            }
        }
    }

    @Test("Source label collapses at narrow widths without changing capture selection")
    func responsiveDensity() {
        let coordinator = MainContentCoordinator()
        let selectedInterface = NetworkInterfaces.available().first?.id ?? coordinator.captureInterface
        coordinator.captureInterface = selectedInterface
        let host = CaptureInterfaceToolbarHost(coordinator: coordinator)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_320, height: 700),
            styleMask: [.titled, .resizable], backing: .buffered, defer: false
        )
        window.contentView = host
        #expect(!host.rootView.isCompact)

        window.setContentSize(NSSize(width: 1_000, height: 700))
        NotificationCenter.default.post(name: NSWindow.didResizeNotification, object: window)
        #expect(host.rootView.isCompact)

        window.setContentSize(NSSize(width: Theme.Metrics.toolbarCompactWindowWidth, height: 700))
        NotificationCenter.default.post(name: NSWindow.didResizeNotification, object: window)
        #expect(!host.rootView.isCompact)
        #expect(coordinator.captureInterface == selectedInterface)
    }

    @Test("Rehosting observes only the current window")
    func windowObservationOwnership() {
        let host = CaptureInterfaceToolbarHost(coordinator: MainContentCoordinator())
        let narrow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_000, height: 700),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        let wide = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1_320, height: 700),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        narrow.contentView = host
        #expect(host.rootView.isCompact)
        narrow.contentView = nil
        wide.contentView = host
        #expect(!host.rootView.isCompact)
        NotificationCenter.default.post(name: NSWindow.didResizeNotification, object: narrow)
        #expect(!host.rootView.isCompact)
    }
}
