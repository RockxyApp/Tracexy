import XCTest

// MARK: - FrameExportGatingUITests

/// The File menu's export commands are gated on there being something to
/// export. An export item that is enabled with nothing open, or with no marked
/// frames, is a dead end the user only discovers by choosing it — exactly the
/// class of regression that leaves no visible trace until then.
final class FrameExportGatingUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = true
    }

    /// Nothing open: every export command is listed and disabled. Listed
    /// matters as much as disabled — a vanishing menu item is its own defect.
    @MainActor
    func testExportCommandsAreListedAndDisabledWithNothingOpen() {
        let app = launchEmptyApp("frame-export-gating-empty")
        defer { app.terminate() }

        XCTAssertTrue(
            menuItem(app, menu: "File", item: "Export Frames…").waitForExistence(timeout: 30),
            app.menuBars.debugDescription
        )
        for title in Self.exportCommands + Self.markedOnlyCommands {
            let item = menuItem(app, menu: "File", item: title)
            XCTAssertTrue(item.exists, "File ▸ \(title) must stay listed with nothing open")
            XCTAssertFalse(
                item.isEnabled,
                "File ▸ \(title) must be disabled with nothing open: choosing it would do nothing"
            )
        }
    }

    /// A capture open: the whole-capture exports become usable, and the
    /// marked-only exports stay disabled because nothing is marked yet. The
    /// second half is the one that regresses quietly — the gate on the mark set
    /// is separate from the gate on there being a capture.
    @MainActor
    func testMarkedOnlyExportsStayDisabledUntilAFrameIsMarked() throws {
        let capture = try UITestCapture.write()
        defer { try? FileManager.default.removeItem(at: capture) }

        let app = launchAppWithCapture("frame-export-gating-capture", capture: capture)
        defer { app.terminate() }

        let exportFrames = menuItem(app, menu: "File", item: "Export Frames…")
        XCTAssertTrue(exportFrames.waitForExistence(timeout: 30), app.menuBars.debugDescription)
        XCTAssertTrue(
            waitUntil(45) { menuItem(app, menu: "File", item: "Export Frames…").isEnabled },
            "An opened capture must make File ▸ Export Frames… usable: \(app.menuBars.debugDescription)"
        )

        for title in Self.exportCommands {
            XCTAssertTrue(
                menuItem(app, menu: "File", item: title).isEnabled,
                "File ▸ \(title) must be usable once a capture is open"
            )
        }
        for title in Self.markedOnlyCommands {
            XCTAssertFalse(
                menuItem(app, menu: "File", item: title).isEnabled,
                "File ▸ \(title) must stay disabled while no frame is marked"
            )
        }
    }

    // MARK: Private

    /// Export commands whose only precondition is an exportable capture.
    private static let exportCommands = [
        "Export Frames…",
        "Export PDUs…",
        "Export Packet Dissections…",
        "Export Capture Frame Range Dissections…",
    ]

    /// Export commands that additionally need at least one marked frame.
    private static let markedOnlyCommands = [
        "Export Marked Packet Dissections…",
        "Export First to Last Marked Dissections…",
    ]
}
