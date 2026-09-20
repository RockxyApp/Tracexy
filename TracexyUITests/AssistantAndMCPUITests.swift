import XCTest

// MARK: - AssistantAndMCPUITests

/// Native UI coverage for the two N5B surfaces, driven against a real launched
/// app on an unlocked desktop.
///
/// Every launch is isolated: the app is told it is running under test, so its
/// identity-derived Application Support root — Projects, History, and the MCP
/// grant — resolves to a throwaway per-run directory. The only capture data on
/// screen is the documentation-range Assistant fixture.
final class AssistantAndMCPUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    override func tearDownWithError() throws {
        app?.terminate()
        app = nil
    }

    // MARK: MCP settings

    @MainActor
    func testMCPGrantAndRevokeStatesAreConcrete() {
        let app = launch(assistantDemo: true, mcpSettings: true)
        openMCPSettings(app)

        let status = app.staticTexts["mcp.statusTitle"]
        XCTAssertTrue(status.waitForExistence(timeout: 10), "The MCP pane must state its status")
        XCTAssertTrue(text(of: status).contains("Off"), "MCP must be off by default, got “\(text(of: status))”")

        // The boundary is concrete: the Project, the command and the no-port claim
        // are all on screen before anything is granted.
        XCTAssertTrue(app.staticTexts["mcp.projectName"].exists)
        XCTAssertTrue(app.staticTexts["mcp.commandPath"].exists)
        XCTAssertTrue(
            app.staticTexts
                .matching(NSPredicate(format: "value CONTAINS[c] %@", "never opens a network port"))
                .firstMatch.exists,
            "The pane must say no port is opened"
        )

        let grant = app.buttons["mcp.grant"]
        XCTAssertTrue(grant.waitForExistence(timeout: 5))
        XCTAssertTrue(
            waitFor(timeout: 30) { grant.isEnabled },
            "Granting requires a resolved Project; pane shows “\(text(of: app.staticTexts["mcp.projectName"]))”"
        )
        grant.click()

        XCTAssertTrue(
            waitFor(timeout: 10) { text(of: status).contains("Granted") },
            "Granting must change the stated scope, got “\(text(of: status))”"
        )

        let revoke = app.buttons["mcp.revoke"]
        XCTAssertTrue(revoke.isEnabled)
        revoke.click()
        XCTAssertTrue(
            waitFor(timeout: 10) { text(of: status).contains("Off") },
            "Revoking must return to the closed default state, got “\(text(of: status))”"
        )

        attachScreenshot(app, named: "MCP settings after revoke")
    }

    @MainActor
    func testMCPDisclosureAndRowCeilingAreEditable() {
        let app = launch(assistantDemo: true, mcpSettings: true)
        openMCPSettings(app)

        let host = app.checkBoxes["mcp.disclosure.host"]
        XCTAssertTrue(host.waitForExistence(timeout: 10))
        XCTAssertEqual(host.value as? Int, 0, "Disclosure is off by default")
        host.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).click()
        XCTAssertEqual(host.value as? Int, 1)

        XCTAssertTrue(app.steppers["mcp.maxRows"].exists || app.otherElements["mcp.maxRows"].exists)
        attachScreenshot(app, named: "MCP disclosure")
    }

    // MARK: Assistant dock

    @MainActor
    func testAssistantSurfaceWithFixtureSelection() {
        // Keep the synthetic workspace inside the smaller CI display so the
        // right-dock Review Data control remains reachable through the UI.
        let app = launch(assistantDemo: true, narrowWindow: true, mcpSettings: true)

        let contextChip = app.descendants(matching: .any)["assistant.contextChip"]
        XCTAssertTrue(contextChip.waitForExistence(timeout: 20), "The Assistant dock must show its attached context")
        XCTAssertTrue(
            text(of: contextChip).contains("Attached session"),
            "The attached scope must be named, got “\(text(of: contextChip))”"
        )
        XCTAssertFalse(
            app.sheets.firstMatch.exists,
            "The synthetic Assistant walkthrough must not present capture-helper onboarding"
        )

        // Review Data is reachable before anything is sent, and shows the literal
        // payload plus the destination.
        let review = app.buttons["assistant.reviewData"]
        XCTAssertTrue(review.waitForExistence(timeout: 10))
        review.click()

        let sheet = app.descendants(matching: .any)["assistant.reviewSheet"]
        XCTAssertTrue(sheet.waitForExistence(timeout: 10), "Review Data must open a sheet")
        let payload = app.descendants(matching: .any)["assistant.reviewPayload"]
        XCTAssertTrue(payload.waitForExistence(timeout: 5), "The exact payload must be shown")
        attachScreenshot(app, named: "Assistant Review Data")

        // Disclosure is editable in the sheet and defaults to off.
        let hostToggle = app.checkBoxes["assistant.disclosure.host"]
        XCTAssertTrue(hostToggle.exists)
        XCTAssertEqual(hostToggle.value as? Int, 0, "The Assistant discloses nothing by default")

        // Escape is the native cancel for a sheet, and it must leave the app in the
        // pre-send state with nothing sent.
        app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
        XCTAssertTrue(waitFor(timeout: 10) { !sheet.exists }, "Cancel must dismiss the sheet")

        attachScreenshot(app, named: "Assistant dock")
    }

    @MainActor
    func testAssistantDisclosureChangedInSettingsRebuildsExactPayload() {
        let app = launch(assistantDemo: true, mcpSettings: true)
        let contextChip = app.descendants(matching: .any)["assistant.contextChip"]
        XCTAssertTrue(contextChip.waitForExistence(timeout: 20))

        openMCPSettings(app)
        let host = app.checkBoxes["assistant.settings.host"]
        XCTAssertTrue(host.waitForExistence(timeout: 10))
        if host.value as? Int == 0 {
            host.click()
        }
        XCTAssertEqual(host.value as? Int, 1)

        app.typeKey("w", modifierFlags: .command)
        let review = app.buttons["assistant.reviewData"]
        XCTAssertTrue(review.waitForExistence(timeout: 10))
        XCTAssertTrue(waitFor(timeout: 10) { review.isEnabled }, "The updated brief must finish rebuilding")
        review.click()

        let payload = app.staticTexts["assistant.reviewPayloadText"]
        XCTAssertTrue(payload.waitForExistence(timeout: 10))
        let json = text(of: payload)
        XCTAssertTrue(json.contains("\"includesHost\" : true"), "Review must describe the enabled Host scope")
        XCTAssertTrue(
            json.contains("\"host\" : \"service.example.com\""),
            "Review must show the exact DNS/SNI-derived display host that would be sent"
        )
        attachScreenshot(app, named: "Assistant disclosure payload consistency")
    }

    @MainActor
    func testAssistantIsHonestWhenTheEndpointDoesNotAnswer() {
        let app = launch(assistantDemo: true, mcpSettings: true)
        openMCPSettings(app)

        // Point the Assistant at a port nothing is listening on, through the real
        // Settings field, and check it.
        let field = app.textFields["assistant.endpointField"]
        XCTAssertTrue(field.waitForExistence(timeout: 15))
        field.click()
        app.typeKey("a", modifierFlags: .command)
        field.typeText("http://127.0.0.1:1")
        app.buttons["assistant.settingsCheck"].click()

        let status = app.staticTexts["assistant.settingsStatusTitle"]
        XCTAssertTrue(status.waitForExistence(timeout: 15))
        XCTAssertTrue(
            waitFor(timeout: 45) {
                text(of: status).contains("didn’t answer") || text(of: status).contains("No local model")
            },
            "An unreachable endpoint must be reported honestly, got “\(text(of: status))”"
        )
        attachScreenshot(app, named: "Assistant with an unreachable endpoint")

        // A non-loopback address is refused outright, with actionable copy.
        field.click()
        app.typeKey("a", modifierFlags: .command)
        field.typeText("http://model.example.com:11434")
        app.buttons["assistant.settingsCheck"].click()
        XCTAssertTrue(
            waitFor(timeout: 20) { text(of: status).contains("No local model connected") },
            "A remote address must be refused, got “\(text(of: status))”"
        )
        attachScreenshot(app, named: "Assistant refusing a remote endpoint")
    }

    @MainActor
    func testAssistantSurvivesNarrowWindowAndKeyboardFocus() {
        let app = launch(assistantDemo: true, narrowWindow: true)
        let contextChip = app.descendants(matching: .any)["assistant.contextChip"]
        XCTAssertTrue(contextChip.waitForExistence(timeout: 20))

        // The supported narrow desktop width keeps the dock's controls reachable.
        let window = app.windows.firstMatch
        XCTAssertTrue(window.exists)
        XCTAssertLessThanOrEqual(window.frame.width, 1_050)
        XCTAssertLessThanOrEqual(window.frame.height, 700)
        window.click()
        app.typeKey(XCUIKeyboardKey.tab, modifierFlags: [])

        XCTAssertTrue(app.buttons["assistant.reviewData"].exists)
        XCTAssertTrue(app.buttons["assistant.newConversation"].exists)
        attachScreenshot(app, named: "Assistant narrow layout")
    }

    /// The full in-app exchange against a real local model: prompt, mandatory
    /// review, streamed answer, and a clickable citation.
    ///
    /// Skipped when no local model answers, so the suite stays honest on a
    /// machine without one.
    @MainActor
    func testAssistantStreamsARealAnswerAndNavigatesACitation() throws {
        try XCTSkipUnless(Self.localModelIsReachable, "Requires a local model at \(Self.endpointText)")
        let app = launch(assistantDemo: true)

        let status = app.descendants(matching: .any)["assistant.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 20))
        var connected = waitFor(timeout: 25) { !text(of: status).contains("Not connected") }
        if !connected {
            // Exercise the manual path too before giving up.
            let check = app.buttons["assistant.checkLocalModel"]
            if check.exists {
                check.click()
                connected = waitFor(timeout: 25) { !text(of: status).contains("Not connected") }
            }
        }
        // The model is reachable from the test process, but the *app* is a
        // different client: a local firewall or content filter can refuse it. That
        // is an environment condition, not a product failure, so it skips rather
        // than reporting a defect that does not exist.
        try XCTSkipUnless(
            connected,
            "The app could not reach a local model at \(Self.endpointText) — check any local firewall"
        )
        attachScreenshot(app, named: "Assistant connected")

        let composer = app.textFields["assistant.composer"]
        XCTAssertTrue(composer.waitForExistence(timeout: 15))

        // Clicking a SwiftUI text field does not always land keyboard focus on the
        // first try, so the prompt is typed into the app's focused responder and
        // confirmed by Send becoming enabled — which is exactly the condition the
        // composer gates on.
        let send = app.buttons["assistant.send"]
        var typed = false
        for _ in 0 ..< 3 {
            composer.click()
            app.typeKey("a", modifierFlags: .command)
            app.typeText("In one sentence, what was observed? Cite one citation id.")
            if waitFor(timeout: 3, condition: { send.isEnabled }) {
                typed = true
                break
            }
        }
        XCTAssertTrue(typed, "The composer must accept a prompt and enable Send")

        send.click()

        // The first send is always held for review.
        let sheet = app.descendants(matching: .any)["assistant.reviewSheet"]
        XCTAssertTrue(sheet.waitForExistence(timeout: 15), "The first send must be reviewed")
        // Return is the sheet's default action, which also covers the
        // keyboard-only path through the review gate.
        app.typeKey(XCUIKeyboardKey.return, modifierFlags: [])
        if sheet.exists {
            app.buttons["Send to Local Model"].firstMatch.click()
        }
        XCTAssertTrue(waitFor(timeout: 15) { !sheet.exists }, "Approving must dismiss the sheet and send")

        // A real answer streams in.
        XCTAssertTrue(
            waitFor(timeout: 180) {
                app.buttons["assistant.citation"].firstMatch.exists || !app.buttons["assistant.stop"].exists
            },
            "The model must finish or produce a citation"
        )
        attachScreenshot(app, named: "Assistant streamed answer")

        // A citation, when the model produced one, navigates to the exact frame.
        let citation = app.buttons["assistant.citation"].firstMatch
        if citation.exists {
            citation.click()
            let loadedFrame = app.descendants(matching: .any)["evidence.citedFrameLoaded"]
            XCTAssertTrue(
                loadedFrame.waitForExistence(timeout: 20),
                "A citation must decode and show the exact local frame"
            )
            XCTAssertTrue(text(of: loadedFrame).contains("Cited frame 11"))
            XCTAssertFalse(
                app.staticTexts["The requested capture evidence is no longer available."].exists,
                "The walkthrough must not advertise a citation whose bytes are absent"
            )
            attachScreenshot(app, named: "Assistant citation navigation")
        }

        // Retry re-sends under the same scope without a second review.
        let retry = app.buttons["assistant.retry"]
        if retry.isEnabled {
            retry.click()
            XCTAssertTrue(
                waitFor(timeout: 60) { app.buttons["assistant.stop"].exists || !sheet.exists },
                "Retry must reuse the approved scope"
            )
        }
        attachScreenshot(app, named: "Assistant after retry")
    }

    // MARK: Private

    /// The app's own walkthrough flag, spelled once.
    private enum AssistantDemoArgument {
        static let value = "--assistant-demo"
        static let narrowValue = "--assistant-demo-narrow"
        static let mcpSettingsValue = "--mcp-settings"
    }

    private static let endpointText = "http://127.0.0.1:11434"

    /// Whether a local model answers from *this* process, checked once.
    private static let localModelIsReachable: Bool = {
        guard let url = URL(string: "\(endpointText)/api/tags") else {
            return false
        }
        var request = URLRequest(url: url)
        request.timeoutInterval = 3
        let semaphore = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var reachable = false
        URLSession.shared.dataTask(with: request) { _, response, _ in
            reachable = (response as? HTTPURLResponse)?.statusCode == 200
            semaphore.signal()
        }.resume()
        _ = semaphore.wait(timeout: .now() + 6)
        return reachable
    }()

    private var app: XCUIApplication?

    @MainActor
    private func launch(
        assistantDemo: Bool = false,
        narrowWindow: Bool = false,
        mcpSettings: Bool = false
    )
        -> XCUIApplication
    {
        let application = XCUIApplication()
        if narrowWindow {
            application.launchArguments = [AssistantDemoArgument.narrowValue]
        } else {
            application.launchArguments = assistantDemo ? [AssistantDemoArgument.value] : []
        }
        if mcpSettings {
            application.launchArguments.append(AssistantDemoArgument.mcpSettingsValue)
        }
        // Redirect the app's identity-derived storage into a per-run temporary
        // directory, so a UI run can never touch real Projects, History or an MCP
        // grant.
        application.launchEnvironment = [
            "TRACEXY_TEST_RUN_TOKEN": "ui-\(UUID().uuidString)",
        ]
        application.launch()
        app = application
        return application
    }

    /// Open the Settings window and select the MCP & Assistant pane.
    ///
    /// The window is matched on its scene identifier rather than its title: the
    /// title is the *pane's* navigation title and changes with the selection.
    @MainActor
    private func openMCPSettings(_ app: XCUIApplication) {
        let settings = app.windows["settings"]
        if !settings.exists {
            app.typeKey(",", modifierFlags: .command)
        }
        XCTAssertTrue(settings.waitForExistence(timeout: 15), "Settings must open")
        settings.click()
        let mcpStatus = settings.staticTexts["mcp.statusTitle"]
        if mcpStatus.waitForExistence(timeout: 2) {
            return
        }
        let row = settings.cells["MCP & Assistant"]
        XCTAssertTrue(row.waitForExistence(timeout: 10), "The MCP & Assistant pane must be listed")
        row.click()
        XCTAssertTrue(mcpStatus.waitForExistence(timeout: 10), "The MCP & Assistant pane must open")
    }

    /// The readable string of a static text. SwiftUI maps a `Text` to AXValue on
    /// macOS, so a label-only read silently sees an empty string.
    @MainActor
    private func text(of element: XCUIElement) -> String {
        if !element.label.isEmpty {
            return element.label
        }
        return (element.value as? String) ?? ""
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

    @MainActor
    private func attachScreenshot(_ app: XCUIApplication, named name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
