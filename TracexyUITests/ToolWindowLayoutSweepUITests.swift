import XCTest

/// Opens every tool window the menus offer and measures its controls for the
/// two layout defects that have actually shipped in this app.
///
/// Both were invisible to the suite before: the window built, it rendered, and
/// every control in it worked. Only the accessibility frames showed them.
///
/// - A control drawn against the window's own edge. Measured in All Frames: the
///   frame-expression field and the Highlight button sat at x=0 with their
///   leading corners clipped flat, because that one safe-area bar did not inset
///   its content the way every other bar does.
/// - A control that has grown taller than one line. Measured in the same
///   window: the "Relative TCP Seq/Ack" toggle wrapped to three lines, 42pt
///   tall, because the footer's row of buttons could not fit the window's own
///   default width.
///
/// The sweep reports every violation it finds rather than stopping at the
/// first, so one run gives the whole list.
final class ToolWindowLayoutSweepUITests: XCTestCase {
    // MARK: Internal

    override func setUp() {
        continueAfterFailure = true
    }

    @MainActor
    func testEveryToolWindowKeepsItsControlsInsideAndOnOneLine() throws {
        try sweep(token: "tool-window-sweep", extraArguments: [])
    }

    /// The same sweep with every window shrunk to the smallest size it
    /// declares. A footer that fits at the default width can still overflow at
    /// the minimum, and the minimum is the width the window promises to stay
    /// usable at — so this is where a row of controls and a long sentence
    /// compete for the same space.
    @MainActor
    func testEveryToolWindowSurvivesItsOwnMinimumSize() throws {
        try sweep(token: "tool-window-sweep-min", extraArguments: [UITestLaunch.minimumSize])
    }

    // MARK: Private

    private struct Route {
        let menu: String
        let item: String
    }

    /// The smallest leading inset a control inside a window may have. The
    /// project's bars use `Theme.Metrics.spacingL`, which measured 12pt; the
    /// defect measured 0.
    private static let minimumLeadingInset: CGFloat = 6

    /// Taller than this and a control has wrapped. A one-line small control
    /// measured 14–24pt; the wrapped toggle measured 42.
    private static let oneLineCeiling: CGFloat = 34

    /// Below this from the window's top edge an element belongs to the titlebar,
    /// whose accessory and window buttons the system lays out, not this app.
    private static let titlebarDepth: CGFloat = 34

    /// Narrower than this and the element is a scroller part rather than a
    /// control of this app's own: the measured page button was 6pt wide, while
    /// the smallest real control in these windows, a window button, is 16.
    private static let narrowestRealControl: CGFloat = 12

    private static let controlTypes: [UInt] = [
        XCUIElement.ElementType.button.rawValue,
        XCUIElement.ElementType.checkBox.rawValue,
        XCUIElement.ElementType.popUpButton.rawValue,
        XCUIElement.ElementType.menuButton.rawValue,
        XCUIElement.ElementType.radioButton.rawValue,
        XCUIElement.ElementType.textField.rawValue,
    ]

    private static let routes = [
        Route(menu: "View", item: "All Frames"),
        Route(menu: "Capture", item: "Decode As…"),
        Route(menu: "Statistics", item: "Findings"),
        Route(menu: "Statistics", item: "Conversations"),
        Route(menu: "Statistics", item: "Endpoints"),
        Route(menu: "Statistics", item: "Protocol Hierarchy"),
        Route(menu: "Statistics", item: "Packet Lengths"),
        Route(menu: "Statistics", item: "I/O Graph"),
        Route(menu: "Statistics", item: "Flow Graph"),
        Route(menu: "Statistics", item: "HTTP"),
        Route(menu: "Statistics", item: "IP Statistics"),
        Route(menu: "Statistics", item: "DNS"),
        Route(menu: "Statistics", item: "RTP Streams"),
        Route(menu: "Statistics", item: "Service Response Time"),
        Route(menu: "Statistics", item: "SIP"),
        Route(menu: "Statistics", item: "UDP Multicast Streams"),
        Route(menu: "Statistics", item: "VoIP Calls"),
        Route(menu: "Statistics", item: "DNS Lookups"),
        Route(menu: "Statistics", item: "Message Counts"),
        Route(menu: "Statistics", item: "Resolved Addresses"),
    ]

    /// Closes exactly this window, through its own close button.
    ///
    /// `⌘W` is sent to the application, not to a window, so it closes whatever
    /// happens to be key. Measured: after a tool window had lost key status the
    /// shortcut closed the main window instead, and from the third route on
    /// every Statistics item then opened nothing at all — which read as a
    /// broken menu rather than as a harness that had shut the app's own window.
    @MainActor
    private func close(_ window: XCUIElement) {
        let button = window.buttons[XCUIIdentifierCloseWindow].firstMatch
        if button.waitForExistence(timeout: 5) {
            button.click()
        } else {
            window.typeKey("w", modifierFlags: .command)
        }
        _ = waitUntil(5) { !window.exists }
    }

    @MainActor
    private func sweep(token: String, extraArguments: [String]) throws {
        let capture = try UITestCapture.write()
        defer { try? FileManager.default.removeItem(at: capture) }

        let app = launchAppWithCapture(token, capture: capture, extraArguments: extraArguments)
        defer { app.terminate() }

        var findings: [String] = []
        var opened = 0

        for route in Self.routes {
            guard let window = openAndIdentify(app, route: route) else {
                findings.append("\(route.item): the menu item opened no window")
                continue
            }
            opened += 1
            findings.append(contentsOf: violations(in: window, named: route.item))
            close(window)
        }

        XCTAssertGreaterThanOrEqual(
            opened,
            Self.routes.count - 1,
            "Most routes must open a window to make this a sweep"
        )
        XCTAssertTrue(
            findings.isEmpty,
            "Layout defects measured in \(opened) tool windows:\n" + findings.joined(separator: "\n")
        )
    }

    /// Clicks the route and returns whichever window it opened. The title is
    /// discovered rather than declared, so a menu item wired to the wrong scene
    /// is caught too.
    @MainActor
    private func openAndIdentify(_ app: XCUIApplication, route: Route) -> XCUIElement? {
        let before = Set(app.windows.allElementsBoundByIndex.map(\.title))
        let bar = app.menuBars.menuBarItems[route.menu]
        guard bar.waitForExistence(timeout: 30) else {
            return nil
        }
        bar.click()
        let entry = bar.menuItems[route.item].firstMatch
        guard entry.waitForExistence(timeout: 10) else {
            app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
            return nil
        }
        entry.click()
        var title: String?
        _ = waitUntil(20) {
            title = app.windows.allElementsBoundByIndex.map(\.title).first { !before.contains($0) }
            return title != nil
        }
        guard let title else {
            return nil
        }
        let window = app.windows[title]
        return window.waitForExistence(timeout: 10) ? window : nil
    }

    /// Every control in this window that is drawn against the window's edge or
    /// has wrapped onto a second line.
    @MainActor
    private func violations(in window: XCUIElement, named name: String) -> [String] {
        let frame = window.frame
        let controls = window.descendants(matching: .any)
            .matching(NSPredicate(format: "elementType IN %@", Self.controlTypes))
        var findings: [String] = []
        for control in controls.allElementsBoundByIndex {
            guard control.exists, !control.identifier.hasPrefix("_XCUI") else {
                continue
            }
            let box = control.frame
            guard box.width > 0, box.height > 0, box.minY > frame.minY + Self.titlebarDepth else {
                continue
            }
            let label = control.title.isEmpty ? control.label : control.title
            // A scroller's parts report as buttons with no label and a few
            // points of width — the DNS list's vertical page button measured
            // 6×110. Nothing there can wrap, and the system lays it out, so it
            // is not this sweep's business.
            guard !label.isEmpty, box.width >= Self.narrowestRealControl else {
                continue
            }
            let inset = box.minX - frame.minX
            if inset < Self.minimumLeadingInset {
                findings.append(
                    "\(name): '\(label)' is \(Int(inset))pt from the window's leading edge, "
                        + "so its leading corner is clipped flat against it"
                )
            }
            if box.height > Self.oneLineCeiling {
                findings.append(
                    "\(name): '\(label)' is \(Int(box.height))pt tall, so its label has wrapped "
                        + "onto a second line inside a row meant for one"
                )
            }
        }
        return findings
    }
}
