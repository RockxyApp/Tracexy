import XCTest

/// Whether a menu item's enabled state follows the state it is gated on.
///
/// A command's `.disabled(...)` is computed while the `Commands` body runs and
/// baked into the item. If that body is not re-evaluated when the state it read
/// changes, the item keeps the enablement it was built with — and because a
/// disabled `Button` also kills its own keyboard shortcut, the command becomes
/// unreachable by either route rather than merely looking wrong.
///
/// These read the menu **opened**, by clicking it, rather than querying the
/// accessibility tree of a closed `NSMenu`: the two are not known to be the
/// same measurement, and only the opened one is what the user acts on.
final class CommandMenuRefreshUITests: XCTestCase {
    // MARK: Internal

    override func setUp() {
        continueAfterFailure = false
    }

    /// View ▸ Actual Size is disabled exactly while the packet text is already
    /// at actual size, so zooming in must make it usable. Nothing the app's own
    /// `body` reads changes when the zoom changes, which is the case this is
    /// here to catch.
    @MainActor
    func testZoomingInMakesActualSizeUsable() throws {
        let capture = try UITestCapture.write()
        defer { try? FileManager.default.removeItem(at: capture) }

        let app = launchAppWithCapture("command-refresh-zoom", capture: capture)
        defer { app.terminate() }

        let atActualSize = try XCTUnwrap(
            openedMenuItemIsEnabled(app, menu: "View", item: "Actual Size"),
            "View ▸ Actual Size must exist: \(app.menuBars.debugDescription)"
        )
        XCTAssertFalse(
            atActualSize,
            "The packet text starts at actual size, so the command must start disabled"
        )

        app.typeKey("+", modifierFlags: .command)

        XCTAssertTrue(
            waitUntil(15) { openedMenuItemIsEnabled(app, menu: "View", item: "Actual Size") == true },
            "After ⌘+ the text is no longer at actual size, so Actual Size must become usable — "
                + "a disabled item also disables ⌘0, leaving no way back"
        )
    }

    /// File ▸ Export Marked Packet Dissections… is gated on there being a
    /// marked frame. Marking one changes only the frame list, which the app's
    /// own `body` does not read.
    @MainActor
    func testMarkingAFrameMakesTheMarkedExportUsable() throws {
        let capture = try UITestCapture.write()
        defer { try? FileManager.default.removeItem(at: capture) }

        let app = launchAppWithCapture("command-refresh-marks", capture: capture)
        defer { app.terminate() }

        let window = openWindow(app, menu: "View", item: "All Frames", titled: "All Frames")
        let rows = window.outlines.firstMatch.outlineRows
        XCTAssertTrue(waitUntil(45) { rows.count >= UITestCapture.frameCount }, window.debugDescription)

        let item = "Export Marked Packet Dissections…"
        let marked = try XCTUnwrap(
            menuPath(app, menu: "File", path: [item]),
            "File ▸ \(item) must exist: \(app.menuBars.debugDescription)"
        )
        XCTAssertFalse(marked, "With nothing marked the command must be disabled")

        let marks = window.menuButtons
            .matching(NSPredicate(format: "title == %@", "Marks"))
            .firstMatch
        XCTAssertTrue(marks.waitForExistence(timeout: 15), window.debugDescription)
        marks.click()
        app.menuItems["Mark All Displayed"].firstMatch.click()

        XCTAssertTrue(
            waitUntil(15) { menuPath(app, menu: "File", path: [item]) == true },
            "Frames are marked, so the marked-only export must become usable"
        )
    }

    // MARK: Private

    /// Opens `menu` for real and reports whether `item` is enabled, or nil when
    /// the item is not there at all.
    @MainActor
    private func openedMenuItemIsEnabled(_ app: XCUIApplication, menu: String, item: String) -> Bool? {
        menuPath(app, menu: menu, path: [item])
    }

    /// Opens `menu`, walks `path` through its submenus and reports whether the
    /// last entry is enabled. The menu is always dismissed again, so a reading
    /// cannot leave a menu open over the next one.
    @MainActor
    private func menuPath(_ app: XCUIApplication, menu: String, path: [String]) -> Bool? {
        let bar = app.menuBars.menuBarItems[menu]
        guard bar.waitForExistence(timeout: 30) else {
            return nil
        }
        bar.click()
        defer {
            app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
            app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
        }
        var scope = bar
        for (index, title) in path.enumerated() {
            let entry = scope.menuItems[title].firstMatch
            guard entry.waitForExistence(timeout: 10) else {
                return nil
            }
            if index == path.count - 1 {
                return entry.isEnabled
            }
            entry.hover()
            scope = entry
        }
        return nil
    }
}
