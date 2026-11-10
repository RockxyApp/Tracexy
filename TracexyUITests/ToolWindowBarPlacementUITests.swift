import XCTest

/// Where a tool window's top bar actually sits.
///
/// A `safeAreaBar` is sized together with the content it is attached to, so a
/// window that expands its content *after* attaching the bar centres bar and
/// content as one block: the bar then floats down the window instead of sitting
/// under the titlebar, and it does so only when the content does not fill —
/// an empty state, most often, which is what a reader sees first. Measured
/// before the fix: the IP Statistics choosers at 171pt and the Service Response
/// Time picker at 107pt from their window's top, while each window's footer,
/// attached after the frame, stayed pinned.
///
/// Reading the bar's accessibility frame is the only way to catch this. The
/// window renders, every control works, and nothing fails to build.
final class ToolWindowBarPlacementUITests: XCTestCase {
    // MARK: Internal

    override func setUp() {
        continueAfterFailure = false
    }

    /// Every tool window whose first control belongs to a top bar must draw it
    /// against the titlebar, with a capture open and with none.
    @MainActor
    func testTopBarsSitUnderTheTitlebar() throws {
        let capture = try UITestCapture.write()
        defer { try? FileManager.default.removeItem(at: capture) }

        let app = launchAppWithCapture("tool-window-bars", capture: capture)
        defer { app.terminate() }

        for window in Self.windows {
            let opened = openWindow(app, menu: window.menu, item: window.item, titled: window.title)
            defer { opened.typeKey("w", modifierFlags: .command) }

            let control = opened.descendants(matching: .any)
                .matching(NSPredicate(format: "elementType IN %@", Self.barControlTypes))
                .firstMatch
            XCTAssertTrue(control.waitForExistence(timeout: 20), opened.debugDescription)

            let offset = control.frame.minY - opened.frame.minY
            XCTAssertLessThan(
                offset, Self.titlebarAllowance,
                "\(window.title): its top bar is \(Int(offset))pt below the window's top edge. "
                    + "A bar drawn against the titlebar lands within \(Int(Self.titlebarAllowance))pt; "
                    + "further down means the bar was attached before the content was expanded, "
                    + "so the two are being centred together."
            )
        }
    }

    // MARK: Private

    private struct ToolWindow {
        let menu: String
        let item: String
        let title: String
    }

    /// The titlebar plus the bar's own top padding. The measured good value is
    /// 44pt and the measured bad values were 107pt and 171pt, so this separates
    /// them with room for a taller titlebar or a larger text size.
    private static let titlebarAllowance: CGFloat = 80

    /// A segmented picker reports as a radio button, a pull-down as a pop-up
    /// button; both are what these bars hold.
    private static let barControlTypes: [UInt] = [
        XCUIElement.ElementType.radioButton.rawValue,
        XCUIElement.ElementType.popUpButton.rawValue,
    ]

    private static let windows = [
        ToolWindow(menu: "Statistics", item: "IP Statistics", title: "IP Statistics"),
        ToolWindow(menu: "Statistics", item: "Service Response Time", title: "Service Response Time"),
        ToolWindow(menu: "Capture", item: "Decode As…", title: "Decode As"),
    ]
}
