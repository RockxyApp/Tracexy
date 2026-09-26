import AppKit
import Testing
@testable import Tracexy

// MARK: - WorkspaceTabStripViewTests

/// The AppKit tab strip in a real titled window: what VoiceOver finds in it,
/// what pressing those elements does, and how it scrolls when tabs overflow.
/// With `TEST_RUNNER_TRACEXY_TAB_STRIP_SNAPSHOTS=<dir>` it also writes Light
/// and Dark renderings of the window's titlebar for a visual check.
@Suite("Workspace tab strip")
@MainActor
struct WorkspaceTabStripViewTests {
    // MARK: Internal

    @Test("Each tab is a radio button in a tab group, with its close button, New Tab last")
    func accessibilityElements() {
        let (window, strip, recorder) = Self.makeWindow(tabCount: 4, width: 1_000)
        defer { window.close() }

        #expect(strip.accessibilityRole() == .tabGroup)
        #expect(strip.accessibilityLabel() == "Workspace Tabs")
        let children = (strip.accessibilityChildren() ?? []).compactMap { $0 as? NSAccessibilityElement }
        let tabs = children.filter { $0.accessibilityRole() == .radioButton }
        #expect(tabs.map { $0.accessibilityLabel() ?? "" } == ["Live", "Workspace 2", "Workspace 3", "Workspace 4"])
        #expect(tabs.map { ($0.accessibilityValue() as? Int) ?? -1 } == [0, 1, 0, 0])
        #expect((strip.accessibilityTabs() ?? []).count == 4)
        // Live cannot be closed, so it has no close button.
        let closes = children
            .filter { $0.accessibilityRole() == .button && $0.accessibilityIdentifier() == "workspaceTabs.close" }
        #expect(closes.map { $0.accessibilityLabel() ?? "" } == [
            "Close Workspace 2",
            "Close Workspace 3",
            "Close Workspace 4"
        ])
        #expect(children.last?.accessibilityLabel() == "New Tab")
        #expect(!children.contains { $0.accessibilityIdentifier() == "workspaceTabs.all" })

        // Pressing does what clicking does.
        #expect(tabs[2].accessibilityPerformPress())
        #expect(closes[0].accessibilityPerformPress())
        #expect(children.last?.accessibilityPerformPress() == true)
        #expect(recorder.events == ["select Workspace 3", "close Workspace 2", "add"])

        // Tab frames sit inside the strip, side by side, left to right.
        let frames = tabs.map { $0.accessibilityFrame() }
        #expect(zip(frames, frames.dropFirst()).allSatisfy { $0.maxX <= $1.minX + 0.5 })
        Self.snapshot(window, name: "four-tabs")
    }

    @Test("Past the minimum width the strip scrolls to the active tab and offers All Tabs")
    func overflowScrollsToActiveTab() {
        let (window, strip, _) = Self.makeWindow(tabCount: 32, width: 1_000, activeIndex: 31)
        defer { window.close() }

        let children = (strip.accessibilityChildren() ?? []).compactMap { $0 as? NSAccessibilityElement }
        let tabs = children.filter { $0.accessibilityRole() == .radioButton }
        // Only the tabs in view are exposed; the active last one is among them.
        #expect(tabs.count < 32 && tabs.count >= 5)
        #expect(tabs.last?.accessibilityLabel() == "Workspace 32")
        #expect((tabs.last?.accessibilityValue() as? Int) == 1)
        #expect(!tabs.contains { $0.accessibilityLabel() == "Live" })
        // A tab partly scrolled out reports only the part the strip shows.
        let stripOnScreen = window.convertToScreen(strip.convert(strip.bounds, to: nil))
        let stripLeft = stripOnScreen.minX + WorkspaceTabStripLayout.leadingInset
        let allTabs = children.first { $0.accessibilityIdentifier() == "workspaceTabs.all" }
        #expect(tabs.allSatisfy { $0.accessibilityFrame().minX >= stripLeft - 0.5 })
        #expect(tabs.allSatisfy { $0.accessibilityFrame().maxX <= (allTabs?.accessibilityFrame().minX ?? .infinity) })
        #expect(children
            .contains { $0.accessibilityIdentifier() == "workspaceTabs.all" && $0.accessibilityRole() == .menuButton })
        Self.snapshot(window, name: "thirty-two-tabs")

        // Selecting the first tab brings it back into view.
        var model = strip.model
        model.activeID = model.tabs[0].id
        strip.model = model
        let revealed = (strip.accessibilityChildren() ?? []).compactMap { $0 as? NSAccessibilityElement }
            .filter { $0.accessibilityRole() == .radioButton }
        #expect(revealed.first?.accessibilityLabel() == "Live")
    }

    @Test("The strip is hidden until a Project has a second tab")
    func hiddenWithOneTab() {
        let anchor = WorkspaceTabStripAnchorView()
        let window = Self.titledWindow(width: 900)
        defer { window.close() }
        window.contentView?.addSubview(anchor)
        var model = WorkspaceTabStripModel()
        model.tabs = [.init(id: UUID(), title: "Live", isClosable: false)]
        model.activeID = model.tabs[0].id
        model.isEnabled = true
        anchor.apply(model: model, actions: WorkspaceTabStripActions())
        let accessory = window.titlebarAccessoryViewControllers.first { $0.view is WorkspaceTabStripView }
        #expect(accessory?.layoutAttribute == .bottom)
        #expect(accessory?.isHidden == true)

        model.tabs.append(.init(id: UUID(), title: "Workspace 2", isClosable: true))
        model.isVisible = true
        anchor.apply(model: model, actions: WorkspaceTabStripActions())
        #expect(window.titlebarAccessoryViewControllers.filter { $0.view is WorkspaceTabStripView }.count == 1)

        anchor.removeFromSuperview()
        #expect(!window.titlebarAccessoryViewControllers.contains { $0.view is WorkspaceTabStripView })
    }

    // MARK: Private

    @MainActor
    private final class Recorder {
        var events: [String] = []
    }

    private static func titledWindow(width: CGFloat) -> NSWindow {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: width, height: 300),
            styleMask: [.titled, .closable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.titlebarAppearsTransparent = true
        window.toolbar = NSToolbar(identifier: "tabStripTest")
        window.toolbarStyle = .unified
        window.titleVisibility = .hidden
        return window
    }

    private static func makeWindow(
        tabCount: Int,
        width: CGFloat,
        activeIndex: Int = 1
    )
        -> (NSWindow, WorkspaceTabStripView, Recorder)
    {
        let window = titledWindow(width: width)
        let anchor = WorkspaceTabStripAnchorView()
        window.contentView?.addSubview(anchor)
        let tabs = (0 ..< tabCount).map { index in
            WorkspaceTabStripModel.Tab(
                id: UUID(),
                title: index == 0 ? "Live" : "Workspace \(index + 1)",
                isClosable: index > 0
            )
        }
        let recorder = Recorder()
        let title = { (id: UUID) in tabs.first { $0.id == id }?.title ?? "?" }
        var actions = WorkspaceTabStripActions()
        actions.select = { recorder.events.append("select \(title($0))") }
        actions.close = { recorder.events.append("close \(title($0))") }
        actions.add = { recorder.events.append("add") }
        var model = WorkspaceTabStripModel()
        model.tabs = tabs
        model.activeID = tabs[activeIndex].id
        model.isEnabled = true
        model.isVisible = true
        anchor.apply(model: model, actions: actions)
        window.layoutIfNeeded()
        let strip = window.titlebarAccessoryViewControllers.compactMap { $0.view as? WorkspaceTabStripView }.first
        return (window, strip ?? WorkspaceTabStripView(), recorder)
    }

    /// Renders the strip over the window background, in Light and Dark. (The
    /// titlebar container is not drawn by `cacheDisplay`, so the strip is drawn alone.)
    private static func snapshot(_ window: NSWindow, name: String) {
        guard let directory = ProcessInfo.processInfo.environment["TRACEXY_TAB_STRIP_SNAPSHOTS"],
              let strip = window.titlebarAccessoryViewControllers.compactMap({ $0.view as? WorkspaceTabStripView })
              .first else
        {
            return
        }
        for (label, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            window.appearance = NSAppearance(named: appearance)
            guard let rep = strip.bitmapImageRepForCachingDisplay(in: strip.bounds),
                  let context = NSGraphicsContext(bitmapImageRep: rep) else
            {
                continue
            }
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current = context
            strip.effectiveAppearance.performAsCurrentDrawingAppearance {
                NSColor.windowBackgroundColor.setFill()
                NSRect(origin: .zero, size: rep.size).fill()
            }
            NSGraphicsContext.restoreGraphicsState()
            strip.cacheDisplay(in: strip.bounds, to: rep)
            let url = URL(fileURLWithPath: directory).appendingPathComponent("\(name)-\(label).png")
            try? rep.representation(using: .png, properties: [:])?.write(to: url)
        }
    }
}
