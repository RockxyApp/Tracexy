import XCTest

// MARK: - InterfaceBPFOptimizerUITests

final class InterfaceBPFOptimizerUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testOptimizerChoiceIsIndependentAndPersistsAfterAppRelaunch() throws {
        let app = XCUIApplication()
        app.launchEnvironment["TRACEXY_TEST_RUN_TOKEN"] = "ui-bpf-\(UUID().uuidString)"
        app.launch()
        var firstIdentifier: String?
        var firstInitiallyEnabled: Bool?
        defer {
            if app.state == .runningForeground,
               let firstIdentifier,
               let firstInitiallyEnabled
            {
                let current = app.descendants(matching: .checkBox)
                    .matching(identifier: firstIdentifier).firstMatch
                if current.exists, (current.value as? Int == 1) != firstInitiallyEnabled {
                    current.click()
                }
            }
            app.terminate()
        }

        openManageInterfaces(in: app)
        let toggles = app.windows["Manage Interfaces"].checkBoxes.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "interfaces.optimizeBPF.")
        )
        XCTAssertTrue(waitFor(timeout: 15) { toggles.count >= 2 }, app.debugDescription)

        let first = toggles.element(boundBy: 0)
        let second = toggles.element(boundBy: 1)
        firstIdentifier = first.identifier
        let wasEnabled = first.value as? Int == 1
        firstInitiallyEnabled = wasEnabled
        let secondInitiallyEnabled = second.value as? Int == 1
        let identifier = try XCTUnwrap(firstIdentifier)

        first.click()
        XCTAssertTrue(waitFor(timeout: 5) { (first.value as? Int == 1) == !wasEnabled })
        XCTAssertEqual(second.value as? Int == 1, secondInitiallyEnabled)

        app.terminate()
        app.launch()
        openManageInterfaces(in: app)
        let persisted = app.windows["Manage Interfaces"].descendants(matching: .checkBox)
            .matching(identifier: identifier).firstMatch
        XCTAssertTrue(persisted.waitForExistence(timeout: 10))
        XCTAssertTrue(waitFor(timeout: 5) { (persisted.value as? Int == 1) == !wasEnabled })

        persisted.click()
        XCTAssertTrue(waitFor(timeout: 5) { (persisted.value as? Int == 1) == wasEnabled })
    }

    // MARK: Private

    @MainActor
    private func openManageInterfaces(in app: XCUIApplication) {
        let captureMenu = app.menuBars.menuBarItems["Capture"]
        XCTAssertTrue(captureMenu.waitForExistence(timeout: 15))
        captureMenu.click()
        app.menuItems["Manage Interfaces…"].click()
        XCTAssertTrue(app.windows["Manage Interfaces"].waitForExistence(timeout: 15))
    }

    @MainActor
    private func waitFor(timeout: TimeInterval, condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() {
                return true
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
        }
        return condition()
    }
}
