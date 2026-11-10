import XCTest

// MARK: - TrafficRateGraphWindowUITests

/// Statistics ▸ I/O Graph. Charts are the one surface where a silent regression
/// is invisible: an empty graph and a broken graph look alike, and a chart with
/// no accessibility label is unreadable to VoiceOver while looking perfect.
final class TrafficRateGraphWindowUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = true
    }

    /// With nothing captured the window says there is nothing to graph, instead
    /// of drawing empty axes the user would read as "no traffic happened".
    @MainActor
    func testGraphWithoutACaptureNamesItsEmptyState() {
        let app = launchEmptyApp("io-graph-empty")
        defer { app.terminate() }

        let window = openGraph(app)
        XCTAssertTrue(
            window.staticTexts["No Traffic to Graph"].waitForExistence(timeout: 25),
            window.debugDescription
        )
    }

    /// The draft comparison row is the window's only input. Its controls must
    /// carry accessibility labels, and the single remaining series must not be
    /// removable — an enabled Remove on the last row would empty the editor with
    /// no way back to it.
    @MainActor
    func testDraftSeriesRowIsLabelledAndKeepsItsLastSeries() {
        let app = launchEmptyApp("io-graph-draft")
        defer { app.terminate() }

        let window = openGraph(app)
        let name = window.textFields["Graph series 1 name"]
        XCTAssertTrue(name.waitForExistence(timeout: 25), window.debugDescription)
        XCTAssertTrue(
            window.textFields["Graph series 1 Frame Expression"].exists,
            "The expression field must be labelled for VoiceOver: \(window.debugDescription)"
        )
        XCTAssertTrue(
            window.checkBoxes["Enable graph series 1"].exists,
            "The enable toggle must be labelled for VoiceOver: \(window.debugDescription)"
        )

        let remove = window.buttons["Remove graph series 1"]
        XCTAssertTrue(remove.exists, window.debugDescription)
        XCTAssertFalse(remove.isEnabled, "The last draft series must not be removable")
    }

    /// An opened capture gives the graph a timed axis, so it draws rather than
    /// staying on the empty state or the progress view.
    @MainActor
    func testOpenedCaptureDrawsTheRateGraph() throws {
        let capture = try UITestCapture.write()
        defer { try? FileManager.default.removeItem(at: capture) }

        let app = launchAppWithCapture("io-graph-rows", capture: capture)
        defer { app.terminate() }

        let window = openGraph(app)
        // Not the axis label: the chart carries .accessibilityElement(children:
        // .ignore), which collapses it into one element and hides its axis text
        // from the accessibility client, so that assertion could never pass.
        // The window's own interval summary is the observable proof, and it
        // only reads "in N intervals" once the fold produced real columns.
        let summary = window.staticTexts
            .matching(NSPredicate(format: "value CONTAINS %@", "intervals"))
        XCTAssertTrue(
            waitUntil(45) { summary.firstMatch.exists },
            "An opened capture with timed frames must report real intervals: "
                + window.debugDescription
        )
        XCTAssertFalse(
            window.staticTexts["No Traffic to Graph"].exists,
            "An opened capture with timed frames must not report no traffic: \(window.debugDescription)"
        )
        XCTAssertFalse(
            window.staticTexts["Graphing capture traffic…"].exists,
            "The graph must resolve, not stay on the progress view: \(window.debugDescription)"
        )
    }

    // MARK: Private

    /// Opens the window through the real Statistics ▸ I/O Graph item, so a
    /// broken menu route fails the test.
    @MainActor
    private func openGraph(_ app: XCUIApplication) -> XCUIElement {
        openWindow(app, menu: "Statistics", item: "I/O Graph", titled: "I/O Graph")
    }
}
