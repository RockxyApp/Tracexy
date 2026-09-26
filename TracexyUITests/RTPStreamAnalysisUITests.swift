import XCTest

// MARK: - RTPStreamAnalysisUITests

final class RTPStreamAnalysisUITests: XCTestCase {
    // MARK: Internal

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testReverseDirectionAndGraphSeriesAreOperable() throws {
        let captureURL = try RTPAnalysisUICapture.write()
        defer { try? FileManager.default.removeItem(at: captureURL) }

        let app = XCUIApplication()
        app.launchArguments = ["--rtp-analysis-ui-test"]
        app.launchEnvironment = [
            "TRACEXY_TEST_RUN_TOKEN": "ui-rtp-\(UUID().uuidString)",
            "TRACEXY_RTP_UI_TEST_CAPTURE": captureURL.path,
        ]
        app.launch()
        defer { app.terminate() }

        let streamsWindow = app.windows["RTP Streams"]
        XCTAssertTrue(streamsWindow.waitForExistence(timeout: 30), "The RTP Streams window must open")
        let analysis = app.sheets.firstMatch
        XCTAssertTrue(
            analysis.waitForExistence(timeout: 20),
            "The RTP UI-test launch must open analysis after loading its deterministic capture"
        )
        let forwardSummary = analysis.staticTexts["rtp.analysis.summary.stream.forward"]
        let reverseSummary = analysis.staticTexts["rtp.analysis.summary.stream.reverse"]
        XCTAssertTrue(forwardSummary.waitForExistence(timeout: 5))
        XCTAssertTrue(reverseSummary.exists, "The reverse direction must be summarized beside the forward stream")
        XCTAssertTrue(text(of: forwardSummary).contains("192.0.2.10:40000"))
        XCTAssertTrue(text(of: reverseSummary).contains("198.51.100.7:50000"))

        let directionPicker = analysis.descendants(matching: .any)
            .matching(identifier: "rtp.analysis.direction").firstMatch
        XCTAssertTrue(directionPicker.exists, analysis.debugDescription)
        directionPicker.radioButtons["Reverse"].click()
        XCTAssertTrue(
            waitFor(timeout: 5) { analysis.staticTexts["500"].exists },
            "Selecting Reverse must show reverse-direction packet numbers"
        )
        directionPicker.radioButtons["Forward"].click()
        XCTAssertTrue(
            waitFor(timeout: 5) { analysis.staticTexts["100"].exists },
            "Selecting Forward must restore forward-direction packet numbers"
        )

        let displayPicker = analysis.descendants(matching: .any)
            .matching(identifier: "rtp.analysis.display").firstMatch
        XCTAssertTrue(displayPicker.exists)
        displayPicker.radioButtons["Graph"].click()

        let forwardJitter = analysis.checkBoxes["rtp.analysis.series.forward.jitter"]
        let forwardDelta = analysis.checkBoxes["rtp.analysis.series.forward.delta"]
        let forwardSkew = analysis.checkBoxes["rtp.analysis.series.forward.skew"]
        let reverseJitter = analysis.checkBoxes["rtp.analysis.series.reverse.jitter"]
        XCTAssertTrue(forwardJitter.waitForExistence(timeout: 5))
        XCTAssertEqual(forwardJitter.value as? Int, 1)
        XCTAssertEqual(forwardDelta.value as? Int, 1)
        XCTAssertEqual(forwardSkew.value as? Int, 1)
        XCTAssertEqual(reverseJitter.value as? Int, 1)

        forwardJitter.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).click()
        XCTAssertTrue(
            waitFor(timeout: 5) { forwardJitter.value as? Int == 0 },
            "Hiding forward jitter must leave the other series visible"
        )
        XCTAssertEqual(forwardDelta.value as? Int, 1)
        XCTAssertEqual(forwardSkew.value as? Int, 1)
        XCTAssertEqual(reverseJitter.value as? Int, 1)

        reverseJitter.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).click()
        XCTAssertEqual(reverseJitter.value as? Int, 0)
        XCTAssertEqual(forwardJitter.value as? Int, 0)
        XCTAssertTrue(analysis.buttons["Save as CSV…"].exists)
        analysis.buttons["Done"].click()
        XCTAssertFalse(analysis.exists, "Done must close the analysis sheet")
    }

    // MARK: Private

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
    private func text(of element: XCUIElement) -> String {
        if !element.label.isEmpty {
            return element.label
        }
        return (element.value as? String) ?? ""
    }
}

// MARK: - RTPAnalysisUICapture

private enum RTPAnalysisUICapture {
    // MARK: Internal

    static func write() throws -> URL {
        var frames: [(milliseconds: UInt32, bytes: [UInt8])] = []
        for index in 0 ..< 12 {
            frames.append((UInt32(index * 20), packet(
                source: "192.0.2.10", destination: "198.51.100.7", sourcePort: 40_000, destinationPort: 50_000,
                payloadType: 0, sequence: UInt16(100 + index), timestamp: UInt32(index * 160), ssrc: 0x11111111
            )))
            frames.append((UInt32(index * 20 + 10), packet(
                source: "198.51.100.7", destination: "192.0.2.10", sourcePort: 50_000, destinationPort: 40_000,
                payloadType: 8, sequence: UInt16(500 + index), timestamp: UInt32(index * 160), ssrc: 0x22222222
            )))
        }
        frames.sort { $0.milliseconds < $1.milliseconds }

        var capture: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0]
        appendLittleEndian(0, to: &capture)
        appendLittleEndian(0, to: &capture)
        appendLittleEndian(65_535, to: &capture)
        appendLittleEndian(1, to: &capture)
        for frame in frames {
            appendLittleEndian(1_790_000_000 + frame.milliseconds / 1_000, to: &capture)
            appendLittleEndian((frame.milliseconds % 1_000) * 1_000, to: &capture)
            appendLittleEndian(UInt32(frame.bytes.count), to: &capture)
            appendLittleEndian(UInt32(frame.bytes.count), to: &capture)
            capture.append(contentsOf: frame.bytes)
        }

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-rtp-ui-\(UUID().uuidString).pcap")
        try Data(capture).write(to: url, options: .atomic)
        return url
    }

    // MARK: Private

    private static func packet(
        source: String,
        destination: String,
        sourcePort: UInt16,
        destinationPort: UInt16,
        payloadType: UInt8,
        sequence: UInt16,
        timestamp: UInt32,
        ssrc: UInt32
    )
        -> [UInt8]
    {
        var rtp: [UInt8] = [0x80, payloadType]
        appendBigEndian(sequence, to: &rtp)
        appendBigEndian(timestamp, to: &rtp)
        appendBigEndian(ssrc, to: &rtp)
        rtp.append(contentsOf: repeatElement(0xA5, count: 160))

        var udp: [UInt8] = []
        appendBigEndian(sourcePort, to: &udp)
        appendBigEndian(destinationPort, to: &udp)
        appendBigEndian(UInt16(8 + rtp.count), to: &udp)
        appendBigEndian(UInt16(0), to: &udp)
        udp.append(contentsOf: rtp)

        var ip: [UInt8] = [0x45, 0]
        appendBigEndian(UInt16(20 + udp.count), to: &ip)
        appendBigEndian(UInt16(0), to: &ip)
        appendBigEndian(UInt16(0), to: &ip)
        ip.append(contentsOf: [64, 17])
        appendBigEndian(UInt16(0), to: &ip)
        ip.append(contentsOf: addressBytes(source))
        ip.append(contentsOf: addressBytes(destination))
        ip.append(contentsOf: udp)

        return [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00] + ip
    }

    private static func addressBytes(_ address: String) -> [UInt8] {
        address.split(separator: ".").compactMap { UInt8($0) }
    }

    private static func appendBigEndian(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value >> 8))
        bytes.append(UInt8(value & 0xFF))
    }

    private static func appendBigEndian(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value >> 24))
        bytes.append(UInt8(value >> 16 & 0xFF))
        bytes.append(UInt8(value >> 8 & 0xFF))
        bytes.append(UInt8(value & 0xFF))
    }

    private static func appendLittleEndian(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value & 0xFF))
        bytes.append(UInt8(value >> 8 & 0xFF))
        bytes.append(UInt8(value >> 16 & 0xFF))
        bytes.append(UInt8(value >> 24 & 0xFF))
    }
}
