import XCTest

// MARK: - UITestCapture

/// A deterministic saved capture built in the test process, never read from a
/// scratch directory another process may wipe mid-run. Two DNS frames and a TCP
/// handshake are enough to give the workspace sessions, the frame list rows, and
/// the traffic graphs a timed axis.
enum UITestCapture {
    // MARK: Internal

    /// Frames in the fixture, in capture order. Asserted on by name so a
    /// generator change cannot quietly weaken a row-count assertion.
    static let frameCount = 5

    /// One microsecond-resolution little-endian pcap written atomically.
    static func write() throws -> URL {
        var capture: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1]
        capture += le16(2) + le16(4) + le32(0) + le32(0) + le32(65_535) + le32(1)
        for (index, frame) in frames().enumerated() {
            // One frame per second, so every frame is timed and the rate graphs
            // have a real axis rather than a single bucket.
            capture += le32(UInt32(1_790_000_000 + index)) + le32(0)
            capture += le32(UInt32(frame.count)) + le32(UInt32(frame.count)) + frame
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-ui-\(UUID().uuidString).pcap")
        try Data(capture).write(to: url, options: .atomic)
        return url
    }

    // MARK: Private

    private static let clientIP: [UInt8] = [192, 0, 2, 10]
    private static let serverIP: [UInt8] = [198, 51, 100, 7]

    private static func frames() -> [[UInt8]] {
        var frames: [[UInt8]] = []
        frames.append(udp(client: true, sourcePort: 50_000, destinationPort: 53, payload: dnsQuery()))
        frames.append(udp(client: false, sourcePort: 53, destinationPort: 50_000, payload: dnsResponse()))
        frames.append(tcp(client: true, flags: 0x02, sequence: 1_000))
        frames.append(tcp(client: false, flags: 0x12, sequence: 5_000))
        frames.append(tcp(client: true, flags: 0x10, sequence: 1_001))
        return frames
    }

    private static func ethernetAndIP(
        client: Bool, protocolNumber: UInt8, payloadLength: Int
    )
        -> [UInt8]
    {
        let sourceIP = client ? clientIP : serverIP
        let destinationIP = client ? serverIP : clientIP
        let total = 20 + payloadLength
        var header: [UInt8] = Array(repeating: 0, count: 12) + [0x08, 0x00]
        header += [0x45, 0, UInt8((total >> 8) & 0xFF), UInt8(total & 0xFF)]
        header += [0, 1, 0x40, 0, 64, protocolNumber, 0, 0] + sourceIP + destinationIP
        return header
    }

    private static func udp(
        client: Bool, sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]
    )
        -> [UInt8]
    {
        var frame = ethernetAndIP(client: client, protocolNumber: 17, payloadLength: 8 + payload.count)
        frame += be16(sourcePort) + be16(destinationPort) + be16(UInt16(8 + payload.count)) + be16(0)
        return frame + payload
    }

    private static func tcp(client: Bool, flags: UInt8, sequence: UInt32) -> [UInt8] {
        var frame = ethernetAndIP(client: client, protocolNumber: 6, payloadLength: 20)
        let sourcePort: UInt16 = client ? 50_001 : 443
        let destinationPort: UInt16 = client ? 443 : 50_001
        frame += be16(sourcePort) + be16(destinationPort) + be32(sequence) + be32(0)
        frame += [0x50, flags] + [0xFF, 0xFF, 0, 0, 0, 0]
        return frame
    }

    /// `example.com` A, standard query with recursion desired.
    private static func dnsQuery() -> [UInt8] {
        be16(0x1234) + be16(0x0100) + be16(1) + be16(0) + be16(0) + be16(0)
            + questionName() + be16(1) + be16(1)
    }

    /// The same question answered with one A record pointing at the server.
    private static func dnsResponse() -> [UInt8] {
        var message = be16(0x1234) + be16(0x8180) + be16(1) + be16(1) + be16(0) + be16(0)
        message += questionName() + be16(1) + be16(1)
        // 0xC00C is the compression pointer back to the question's name.
        message += [0xC0, 0x0C] + be16(1) + be16(1) + be32(60) + be16(4) + serverIP
        return message
    }

    private static func questionName() -> [UInt8] {
        [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0]
    }

    private static func be16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    private static func be32(_ value: UInt32) -> [UInt8] {
        [UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    private static func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
    }

    private static func le32(_ value: UInt32) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)]
    }
}

// MARK: - UITestLaunch

/// Launch arguments the app understands only in a DEBUG build.
enum UITestLaunch {
    /// Places windows on the main display. Without it, a host with a second
    /// display can open them at negative coordinates, where XCUITest reports
    /// every element as not hittable and the run fails on hit testing rather
    /// than on the behaviour under test.
    static let mainScreen = "--ui-test-main-screen"

    /// Sizes every window to the smallest size it declares. A footer that fits
    /// at the default width can still overflow at the minimum, which is the
    /// width the window promises to stay usable at.
    static let minimumSize = "--ui-test-minimum-size"

    /// Captures through libpcap rather than the privileged helper, which no
    /// test host has installed. It still needs an openable BPF device, so a
    /// test that uses it must say what it does when there is none.
    static let directCapture = "--direct-capture"
}

extension XCTestCase {
    /// Launches the app with no capture at all, so empty states are the ones
    /// under test. Each launch gets its own preferences token, as the project's
    /// other UI tests do, so a run never inherits or leaves a defaults domain.
    @MainActor
    func launchEmptyApp(_ token: String, extraArguments: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["TRACEXY_TEST_RUN_TOKEN"] = "ui-\(token)-\(UUID().uuidString)"
        app.launchArguments = [UITestLaunch.mainScreen] + extraArguments
        app.launch()
        // Keyboard routes need the app frontmost; launch() alone does not
        // guarantee it, and this host has a second display where a window can
        // come up without key status.
        app.activate()
        dismissBlockingSheet(app)
        return app
    }

    /// Launches the app with the fixture already opened through the normal
    /// external-open flow, the way Finder opens a capture.
    @MainActor
    func launchAppWithCapture(
        _ token: String, capture: URL, extraArguments: [String] = []
    )
        -> XCUIApplication
    {
        let app = XCUIApplication()
        app.launchArguments = ["--open-capture-ui-test", UITestLaunch.mainScreen] + extraArguments
        app.launchEnvironment = [
            "TRACEXY_TEST_RUN_TOKEN": "ui-\(token)-\(UUID().uuidString)",
            "TRACEXY_UI_TEST_CAPTURE": capture.path,
        ]
        app.launch()
        app.activate()
        dismissBlockingSheet(app)
        return app
    }

    /// A menu item scoped to the menu it belongs to. The bare title is
    /// ambiguous — a window scene's title appears in the Window menu too — so an
    /// unscoped query matches several elements and cannot be clicked.
    /// Without an installed privileged helper — which no test host has — the
    /// workspace comes up behind the helper-install prompt. That sheet is modal
    /// and owns the key window, so any route that needs the workspace to take
    /// keyboard focus cannot work while it is up. Tests that are not about the
    /// prompt dismiss it first and then exercise a plain workspace.
    @MainActor
    func dismissBlockingSheet(_ app: XCUIApplication) {
        let sheet = app.sheets.firstMatch
        guard sheet.waitForExistence(timeout: 10) else {
            return
        }
        // Escape, not a click on Cancel: on a host with a second display the
        // window can open at negative screen coordinates, where every element
        // reports "is not hittable". The prompt binds Cancel to .cancelAction,
        // so the keyboard route is the real one anyway.
        app.typeKey(XCUIKeyboardKey.escape, modifierFlags: [])
        _ = waitUntil(10) { !sheet.exists }
    }

    @MainActor
    func menuItem(_ app: XCUIApplication, menu: String, item: String) -> XCUIElement {
        app.menuBars.menuBarItems[menu].menuItems[item].firstMatch
    }

    /// Opens an auxiliary window through its real menu item, so a broken menu
    /// route fails the test rather than being bypassed by a scene id.
    @MainActor
    func openWindow(
        _ app: XCUIApplication, menu: String, item: String, titled title: String
    )
        -> XCUIElement
    {
        let bar = app.menuBars.menuBarItems[menu]
        XCTAssertTrue(bar.waitForExistence(timeout: 30), app.menuBars.debugDescription)
        bar.click()
        let entry = bar.menuItems[item].firstMatch
        XCTAssertTrue(entry.waitForExistence(timeout: 10), bar.debugDescription)
        entry.click()
        let window = app.windows[title]
        XCTAssertTrue(window.waitForExistence(timeout: 20), app.debugDescription)
        return window
    }

    /// Polls rather than sleeps: no wall-clock dependence beyond the deadline,
    /// and the predicate is re-read once more after it expires so a condition
    /// that became true on the last tick is not reported as a failure.
    func waitUntil(_ timeout: TimeInterval = 10, _ condition: () -> Bool) -> Bool {
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
