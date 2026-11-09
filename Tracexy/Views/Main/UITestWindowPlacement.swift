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

    /// Shrinks each window to the smallest size it declares, so a test can
    /// measure the layout at the width the window actually has to survive.
    /// Several footer defects only appear there: at a window's ordinary size
    /// the row fits, and at its minimum the labels truncate or wrap.
    static let minimumSizeArgument = "--ui-test-minimum-size"

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

    /// Resizes the window to the minimum it declares, when the harness asked
    /// for it. The size comes from the window's own `contentMinSize`, which the
    /// scene's resizability sets from the view's `frame(minWidth:minHeight:)`,
    /// so nothing here repeats a number that lives in the view.
    private static func shrinkToMinimum(_ window: NSWindow) {
        guard CommandLine.arguments.contains(minimumSizeArgument) else {
            return
        }
        let minimum = window.contentMinSize
        guard minimum.width > 0, minimum.height > 0 else {
            return
        }
        guard window.contentRect(forFrameRect: window.frame).size != minimum else {
            return
        }
        window.setContentSize(minimum)
    }

    /// Moves the window onto the main screen, keeping its size. A sheet is left
    /// alone: it is positioned by its parent, and moving it detaches it.
    private static func center(_ window: NSWindow) {
        guard window.parent == nil, !window.isSheet, let screen = primaryScreen else {
            return
        }
        shrinkToMinimum(window)
        let visible = screen.visibleFrame
        // Judged by the window's centre, not by whether the whole frame fits.
        // Requiring containment looked stricter and was wrong: a window simply
        // larger than the screen never satisfies it, so the hook moved it again
        // on every key and main notification. On CI, where the display is
        // smaller than this app's default window, that re-centring ran
        // constantly and took keyboard focus with it — three sidebar-focus
        // tests failed there while passing on a larger display. A window whose
        // centre is on the primary screen is reachable, which is all this hook
        // needs to guarantee.
        guard !visible.contains(CGPoint(x: window.frame.midX, y: window.frame.midY)) else {
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
