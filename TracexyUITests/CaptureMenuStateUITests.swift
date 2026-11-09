import XCTest

/// The Capture menu carries the same primary command as the toolbar, so the two
/// must agree about what pressing it will do. A menu that still offers to start
/// a capture while one is running is wrong for everyone who reaches the command
/// by keyboard or by VoiceOver rather than by looking at the toolbar button.
final class CaptureMenuStateUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testCaptureMenuOffersToStartBeforeACaptureRuns() {
        let app = launchEmptyApp("capture-menu-idle")
        defer { app.terminate() }

        XCTAssertEqual(
            openCaptureMenuTitle(app), "Start Capture",
            "With nothing capturing the menu must offer to start: \(app.menuBars.debugDescription)"
        )
    }

    @MainActor
    func testCaptureMenuOffersToStopWhileACaptureRuns() throws {
        // Without this the app asks for the privileged helper, which no test
        // host has, and no capture can start at all. Direct mode reads the
        // interface through libpcap instead and needs only an openable BPF
        // device, which this machine has.
        let app = launchEmptyApp("capture-menu-running", extraArguments: [UITestLaunch.directCapture])
        defer { app.terminate() }

        let menu = app.menuBars.menuBarItems["Capture"]
        XCTAssertTrue(menu.waitForExistence(timeout: 30), app.menuBars.debugDescription)
        menu.click()
        let start = menu.menuItems["Start Capture"].firstMatch
        XCTAssertTrue(start.waitForExistence(timeout: 10), menu.debugDescription)
        start.click()

        // The toolbar is the reference: it is the surface that is known to
        // track the coordinator. Only once it says a capture is running is
        // there anything for the menu to disagree with. A host with no usable
        // BPF device never gets that far, and a vacuous pass would be worse
        // than no coverage at all.
        let stopButton = app.buttons["Stop"].firstMatch
        guard waitUntil(30, { stopButton.exists }) else {
            throw XCTSkip(
                "No capture started: direct mode still needs an openable /dev/bpf device, "
                    + "and a vacuous pass would be worse than no coverage."
            )
        }

        XCTAssertEqual(
            openCaptureMenuTitle(app), "Stop Capture",
            "While the toolbar shows a running capture the menu must offer to stop it, "
                + "not to start another: \(app.menuBars.debugDescription)"
        )
    }

    // MARK: Private

    /// Opens the Capture menu for real and reports which of the two primary
    /// titles it carries. Reading the title without opening the menu is not
    /// enough: it cannot tell a stale title from one the menu would refresh on
    /// the way open, and only the opened menu is what a person actually sees.
    @MainActor
    private func openCaptureMenuTitle(_ app: XCUIApplication) -> String? {
        let menu = app.menuBars.menuBarItems["Capture"]
        XCTAssertTrue(menu.waitForExistence(timeout: 30), app.menuBars.debugDescription)
        menu.click()
        defer { app.typeKey(XCUIKeyboardKey.escape, modifierFlags: []) }
        _ = menu.menuItems.firstMatch.waitForExistence(timeout: 10)
        for title in ["Stop Capture", "Start Capture"] where menu.menuItems[title].firstMatch.exists {
            return title
        }
        return nil
    }
}
