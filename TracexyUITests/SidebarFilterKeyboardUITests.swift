import XCTest

// MARK: - SidebarFilterKeyboardUITests

/// View ▸ Filter Sidebar (⌥⌘J). The sidebar is re-hosted in its own hosting
/// controller, so the keyboard route reaches the field through a published
/// focused-scene action rather than SwiftUI focus state — a route that can break
/// without anything on screen looking different.
final class SidebarFilterKeyboardUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = true
    }

    /// The View ▸ Filter Sidebar item moves keyboard focus into the field, and
    /// what the user then types lands there. Focus alone is not enough: a field
    /// that is first responder but not receiving keys is the same bug.
    @MainActor
    func testFilterSidebarMenuItemFocusesTheFieldAndAcceptsTyping() {
        let app = launchEmptyApp("sidebar-filter-menu")
        defer { app.terminate() }

        let field = awaitFilterField(app)
        let viewMenu = app.menuBars.menuBarItems["View"]
        XCTAssertTrue(viewMenu.waitForExistence(timeout: 30), app.menuBars.debugDescription)
        viewMenu.click()
        let item = viewMenu.menuItems["Filter Sidebar"].firstMatch
        XCTAssertTrue(item.waitForExistence(timeout: 10), viewMenu.debugDescription)
        XCTAssertTrue(item.isEnabled, "The workspace scene must publish the focus action")
        item.click()

        app.typeText("dns")
        XCTAssertTrue(
            waitUntil(15) { (field.value as? String) == "dns" },
            "View ▸ Filter Sidebar must put keyboard focus in the field so typing lands there, "
                + "but the field holds \(String(describing: field.value)): \(app.debugDescription)"
        )
    }

    /// The same action reached by its ⌥⌘J shortcut. Kept separate from the menu
    /// item so a failure says which of the two routes broke.
    @MainActor
    func testFilterSidebarShortcutFocusesTheField() {
        let app = launchEmptyApp("sidebar-filter-shortcut")
        defer { app.terminate() }

        let field = awaitFilterField(app)
        app.typeKey("j", modifierFlags: [.command, .option])
        app.typeText("tcp")
        XCTAssertTrue(
            waitUntil(15) { (field.value as? String) == "tcp" },
            "⌥⌘J must reach the same focus action as the menu item, "
                + "but the field holds \(String(describing: field.value)): \(app.debugDescription)"
        )
    }

    /// The command is deliberately always listed and disabled where there is no
    /// sidebar, rather than vanishing from the menu. An auxiliary window is the
    /// case that proves it.
    @MainActor
    func testFilterSidebarIsListedAndDisabledInAnAuxiliaryWindow() {
        let app = launchEmptyApp("sidebar-filter-auxiliary")
        defer { app.terminate() }

        // Scoped to the View menu: the bare title also matches the Window
        // menu's entry for the same scene, so an unscoped query is ambiguous.
        openWindow(app, menu: "View", item: "All Frames", titled: "All Frames")

        XCTAssertTrue(
            waitUntil(20) {
                let item = app.menuBars.menuItems["Filter Sidebar"]
                return item.exists && !item.isEnabled
            },
            "Filter Sidebar must stay listed and go disabled in a scene with no sidebar: "
                + app.menuBars.debugDescription
        )
    }

    // MARK: Private

    /// Mirrors `SidebarFilterFocusAction.fieldIdentifier` in the app target,
    /// which the UI test bundle does not import.
    private static let fieldIdentifier = "tracexy.sidebar.filter-field"

    /// Waits for the sidebar filter field, checks the label VoiceOver reads, and
    /// proves focus is not already in it — macOS XCUITest exposes no focus
    /// attribute (`hasFocus` is compiled out for the platform), so focus is
    /// asserted by where typing lands, and that only means something if the
    /// field was demonstrably not taking keystrokes beforehand.
    @MainActor
    private func awaitFilterField(_ app: XCUIApplication) -> XCUIElement {
        let field = app.descendants(matching: .any)[Self.fieldIdentifier]
        XCTAssertTrue(field.waitForExistence(timeout: 30), app.debugDescription)
        XCTAssertEqual(
            field.label, "Search sidebar",
            "The filter field must keep its accessibility label for VoiceOver"
        )
        XCTAssertEqual(field.value as? String, "", "The field must start empty")
        app.typeText("x")
        XCTAssertTrue(
            waitUntil(5) { (field.value as? String) == "" },
            "The field must not take keystrokes before the focus action: "
                + String(describing: field.value)
        )
        return field
    }
}
