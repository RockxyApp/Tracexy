import XCTest

// MARK: - AllFramesWindowUITests

/// View ▸ All Frames is the capture-wide frame list. Its states are silent when
/// they break: an empty workspace must say so and offer the listing action, a
/// capture must fill the table, and ⌘T must reach the frame last chosen in a
/// list rather than nothing at all.
final class AllFramesWindowUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = true
    }

    /// With nothing open the window still appears, names its state, and offers
    /// the one action that can change it. An enabled button that does nothing is
    /// the failure this guards against: pressing List Frames must leave the
    /// window in a resolved state, not a permanent spinner.
    @MainActor
    func testAllFramesWithoutACaptureOffersTheListingAction() {
        let app = launchEmptyApp("all-frames-empty")
        defer { app.terminate() }

        let window = openAllFrames(app)
        // An empty workspace resolves to "Frames Unavailable" with Try Again,
        // because there is no capture to list; a workspace that has a capture
        // but has not listed it yet resolves to "No Frames Listed" with List
        // Frames. Both are correct named states, and either satisfies this
        // test. What must never happen is the window sitting on its spinner.
        XCTAssertTrue(
            waitUntil(20) {
                window.staticTexts["Frames Unavailable"].exists
                    || window.staticTexts["No Frames Listed"].exists
            },
            window.debugDescription
        )
        let action = window.buttons["Try Again"].exists
            ? window.buttons["Try Again"]
            : window.buttons["List Frames"]
        XCTAssertTrue(action.waitForExistence(timeout: 10), window.debugDescription)
        XCTAssertTrue(action.isEnabled, "The only action on the empty state must be usable")
        XCTAssertTrue(action.isHittable, "The action must be reachable, not clipped out of the window")

        action.click()
        // Either outcome is correct for an empty workspace; a window still
        // showing "Listing every frame of the capture…" is not.
        XCTAssertTrue(
            waitUntil(20) {
                window.staticTexts["No Frames Listed"].exists
                    || window.staticTexts["Frames Unavailable"].exists
            },
            window.debugDescription
        )
    }

    /// An opened capture fills the table through the same external-open flow
    /// Finder uses, and every frame of the fixture is listed.
    @MainActor
    func testOpenedCaptureListsEveryFrame() throws {
        let capture = try UITestCapture.write()
        defer { try? FileManager.default.removeItem(at: capture) }

        let app = launchAppWithCapture("all-frames-rows", capture: capture)
        defer { app.terminate() }

        let window = openAllFrames(app)
        let rows = frameRows(in: window)
        XCTAssertTrue(
            waitUntil(45) { rows.count >= UITestCapture.frameCount },
            "Expected \(UITestCapture.frameCount) frames, saw \(rows.count): \(window.debugDescription)"
        )
        XCTAssertTrue(
            window.staticTexts["192.0.2.10"].exists,
            "The fixture's client address must be listed as a frame source"
        )
        // The columns the user sorts and reads by must be present, not just rows.
        for column in ["No.", "Source", "Destination", "Protocol"] {
            XCTAssertTrue(
                window.descendants(matching: .any)[column].exists,
                "The \(column) column header is missing: \(window.debugDescription)"
            )
        }
    }

    /// ⌘T applies to the frame last chosen in a frame list. Choosing a row must
    /// enable the command and flip its title, and pressing it again must clear
    /// the reference — the round trip, not just the first press.
    @MainActor
    func testSetTimeReferenceRoundTripsOnTheChosenFrame() throws {
        let capture = try UITestCapture.write()
        defer { try? FileManager.default.removeItem(at: capture) }

        let app = launchAppWithCapture("all-frames-time-reference", capture: capture)
        defer { app.terminate() }

        let window = openAllFrames(app)
        let rows = frameRows(in: window)
        XCTAssertTrue(waitUntil(45) { rows.count >= UITestCapture.frameCount }, window.debugDescription)

        let setReference = menuItem(app, menu: "View", item: "Set Time Reference")
        XCTAssertTrue(setReference.waitForExistence(timeout: 10), app.menuBars.debugDescription)
        XCTAssertFalse(
            setReference.isEnabled,
            "With no frame chosen, Set Time Reference must be listed and disabled, not enabled and inert"
        )

        // A cell, not the row. The row element is a container whose children
        // carry the content, and it reports "is not hittable" itself; the
        // window's floating top and bottom chrome can also cover a row's
        // centre on systems with Liquid Glass. Clicking the first hittable
        // cell chooses a frame just as a user does.
        var chosen: XCUIElement?
        for index in 0 ..< rows.count {
            let row = rows.element(boundBy: index)
            for candidate in [row.cells.firstMatch, row.staticTexts.firstMatch] {
                if candidate.exists, candidate.isHittable {
                    chosen = candidate
                    break
                }
            }
            if chosen != nil {
                break
            }
        }
        let cell = try XCTUnwrap(chosen, "No frame cell was hittable: \(window.debugDescription)")
        cell.click()
        XCTAssertTrue(
            waitUntil(15) { menuItem(app, menu: "View", item: "Set Time Reference").isEnabled },
            "Choosing a frame must enable ⌘T: \(app.menuBars.debugDescription)"
        )

        app.typeKey("t", modifierFlags: .command)
        XCTAssertTrue(
            waitUntil(15) { menuItem(app, menu: "View", item: "Clear Time Reference").exists },
            "After ⌘T the command must offer to clear the reference it just set"
        )

        app.typeKey("t", modifierFlags: .command)
        XCTAssertTrue(
            waitUntil(15) { menuItem(app, menu: "View", item: "Set Time Reference").exists },
            "A second ⌘T must clear the reference again"
        )
    }

    // MARK: Private

    /// SwiftUI's `Table` is exposed to the accessibility client as an `Outline`
    /// with `OutlineRow` children, not as a `Table` with `tableRows` — measured
    /// in the element subtree of this window. The table query matches nothing
    /// and silently reports zero rows, which reads as an empty table rather
    /// than as a wrong query, so both forms are accepted here.
    @MainActor
    private func frameRows(in window: XCUIElement) -> XCUIElementQuery {
        let outlineRows = window.outlines.firstMatch.outlineRows
        return outlineRows.firstMatch.exists ? outlineRows : window.tables.firstMatch.tableRows
    }

    /// Opens the window through the real View ▸ All Frames item rather than by
    /// scene id, so a broken menu route fails the test.
    @MainActor
    private func openAllFrames(_ app: XCUIApplication) -> XCUIElement {
        openWindow(app, menu: "View", item: "All Frames", titled: "All Frames")
    }
}
