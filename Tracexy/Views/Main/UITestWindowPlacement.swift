#if DEBUG
import AppKit

// MARK: - UITestWindowPlacement

/// Places the app's windows on the main display while a UI test drives it.
///
/// This exists because of how XCUITest decides whether an element can be
/// clicked. On a host with a second display, a window can open on that display
/// at negative screen coordinates, and every element inside it then reports
/// `is not hittable` — the run fails on hit testing rather than on the
/// behaviour under test, and it fails differently depending on which display
/// the developer happens to have attached. Nothing here runs in a release
/// build, and nothing runs unless the launch argument is present.
@MainActor
enum UITestWindowPlacement {
    // MARK: Internal

    /// Passed by the UI-test harness; absent everywhere else.
    static let launchArgument = "--ui-test-main-screen"

    static func installIfRequested() {
        guard CommandLine.arguments.contains(launchArgument), !isInstalled else {
            return
        }
        isInstalled = true
        // Windows created before the observer went in get placed now; later
        // ones, including every auxiliary window a test opens, are placed as
        // they take key or main.
        for window in NSApp.windows {
            center(window)
        }
        for name in [
            NSWindow.didBecomeKeyNotification,
            NSWindow.didBecomeMainNotification,
        ] {
            observers.append(
                NotificationCenter.default.addObserver(
                    forName: name, object: nil, queue: .main
                ) { notification in
                    MainActor.assumeIsolated {
                        guard let window = notification.object as? NSWindow else {
                            return
                        }
                        center(window)
                    }
                }
            )
        }
    }

    // MARK: Private

    private static var isInstalled = false
    private static var observers: [NSObjectProtocol] = []

    /// The screen that holds the coordinate origin, never `NSScreen.main`.
    /// `main` is the screen of the *key* window, so a window already on a
    /// second display reports that display as main, is judged to be where it
    /// belongs, and is never moved — and every window opened after it gets
    /// centred on that second display too. The hook then produces exactly the
    /// unhittable windows it exists to prevent. The origin-holding screen is
    /// fixed regardless of which window has key.
    private static var primaryScreen: NSScreen? {
        NSScreen.screens.first { $0.frame.origin == .zero } ?? NSScreen.screens.first
    }

    /// Moves the window onto the main screen, keeping its size. A sheet is left
    /// alone: it is positioned by its parent, and moving it detaches it.
    private static func center(_ window: NSWindow) {
        guard window.parent == nil, !window.isSheet, let screen = primaryScreen else {
            return
        }
        let visible = screen.visibleFrame
        // The whole frame, not just its origin. A window whose bottom-left
        // corner sits inside the primary screen can still extend off it, and
        // the part that hangs over reports `is not hittable` all the same.
        guard !visible.contains(window.frame) else {
            return
        }
        let size = window.frame.size
        let origin = CGPoint(
            x: visible.midX - size.width / 2,
            y: visible.midY - size.height / 2
        )
        window.setFrameOrigin(origin)
    }
}
#endif
