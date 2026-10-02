import XCTest

// MARK: - SettingsLayoutUITests

/// The Settings sidebar keeps every row, icon included, inside the window on
/// every pane: a pane wider than its column would push the whole split view,
/// sidebar first, past the window's edges.
final class SettingsLayoutUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = true
    }

    @MainActor
    func testSidebarRowsStayInsideTheWindowOnEveryPane() {
        let app = XCUIApplication()
        app.launchEnvironment["TRACEXY_TEST_RUN_TOKEN"] = "ui-settings-\(UUID().uuidString)"
        app.launch()
        defer { app.terminate() }

        let settings = app.windows["settings"]
        if !settings.exists {
            app.typeKey(",", modifierFlags: .command)
        }
        XCTAssertTrue(settings.waitForExistence(timeout: 15), "Settings must open")
        settings.click()

        let rows = settings.descendants(matching: .any).matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "settings.tab.")
        )
        XCTAssertTrue(waitFor(timeout: 10) { rows.count >= 6 }, settings.debugDescription)

        visitEveryPane(settings, rows: rows)
    }

    // MARK: Private

    @MainActor
    private func visitEveryPane(_ settings: XCUIElement, rows: XCUIElementQuery) {
        for index in 0 ..< rows.count {
            let row = rows.element(boundBy: index)
            row.click()
            // Let the pane settle before measuring.
            _ = settings.staticTexts.firstMatch.waitForExistence(timeout: 2)
            assertRowsInside(settings, rows: rows, pane: row.identifier)
            if row.identifier == "settings.tab.capture" {
                attachScreenshot(of: settings, named: "settings-capture")
            }
        }
    }

    @MainActor
    private func attachScreenshot(of window: XCUIElement, named name: String) {
        let shot = XCTAttachment(screenshot: window.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }

    /// Every sidebar row, and the leading part of it where the icon is drawn,
    /// lies inside the window with room to spare.
    @MainActor
    private func assertRowsInside(_ window: XCUIElement, rows: XCUIElementQuery, pane: String) {
        let frame = window.frame
        for index in 0 ..< rows.count {
            let row = rows.element(boundBy: index).frame
            XCTAssertGreaterThanOrEqual(
                row.minX, frame.minX + 4,
                "\(pane): sidebar row \(index) starts at \(row.minX), left of the window at \(frame.minX)"
            )
            XCTAssertLessThanOrEqual(
                row.maxX, frame.maxX,
                "\(pane): sidebar row \(index) ends past the window"
            )
        }
    }

    private func waitFor(timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date(timeIntervalSinceNow: timeout)
        while Date() < deadline {
            if condition() {
                return true
            }
            RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
        }
        return condition()
    }
}
