import XCTest

// MARK: - SMBExportObjectsUITests

/// Exercises the user-facing saved-capture route: open normally, choose SMB,
/// inspect an exact contributing frame, and save the reconstructed bytes.
final class SMBExportObjectsUITests: XCTestCase {
    @MainActor
    func testImportInspectAndSaveSMBObject() throws {
        let fixture = try SMBExportUICapture.write()
        let outputDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-smb-ui-output-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: fixture)
            try? FileManager.default.removeItem(at: outputDirectory)
        }

        let app = XCUIApplication()
        app.launchArguments = ["--smb-export-objects-ui-test"]
        app.launchEnvironment = [
            "TRACEXY_TEST_RUN_TOKEN": "ui-smb-\(UUID().uuidString)",
            "TRACEXY_SMB_UI_TEST_CAPTURE": fixture.path,
            "TRACEXY_SMB_UI_TEST_SAVE_DIRECTORY": outputDirectory.path,
        ]
        app.launch()
        defer { app.terminate() }

        let window = app.windows["Export Objects"]
        XCTAssertTrue(window.waitForExistence(timeout: 30))
        let smbPicker = window.descendants(matching: .any)["exportObjects.kind"]
        XCTAssertTrue(smbPicker.waitForExistence(timeout: 10), app.debugDescription)
        let smbButton = smbPicker.radioButtons["SMB"]
        if smbButton.exists {
            smbButton.click()
        } else {
            smbPicker.click()
            app.radioButtons["SMB"].click()
        }

        let fileName = window.staticTexts["report.txt"]
        XCTAssertTrue(fileName.waitForExistence(timeout: 30), "SMB should list the complete fixture file")
        let row = window.descendants(matching: .outlineRow).firstMatch
        XCTAssertTrue(row.exists, window.debugDescription)
        let evidence = window.descendants(matching: .any)["exportObjects.evidence"]
        XCTAssertTrue(evidence.waitForExistence(timeout: 10), row.debugDescription)
        evidence.click()
        let frameItem = app.menuItems.matching(
            NSPredicate(format: "identifier BEGINSWITH %@", "exportObjects.frame.")
        ).firstMatch
        XCTAssertTrue(frameItem.waitForExistence(timeout: 5), app.debugDescription)
        frameItem.click()

        let citedFrame = app.descendants(matching: .any)["evidence.citedFrameLoaded"]
        XCTAssertTrue(citedFrame.waitForExistence(timeout: 15), "A cited source frame should load in Layers")

        // Re-select the exported row, then complete the native save panel into the
        // isolated per-test temporary directory configured above.
        fileName.click()
        let saveButton = window.buttons["exportObjects.saveSelected"]
        XCTAssertTrue(saveButton.waitForExistence(timeout: 5))
        saveButton.click()
        let savePanel = app.dialogs.firstMatch
        XCTAssertTrue(savePanel.waitForExistence(timeout: 10), app.debugDescription)
        let save = savePanel.buttons["Save"]
        XCTAssertTrue(save.waitForExistence(timeout: 5), savePanel.debugDescription)
        save.click()

        let savedFile = outputDirectory.appendingPathComponent("report.txt")
        let deadline = Date().addingTimeInterval(10)
        while !FileManager.default.fileExists(atPath: savedFile.path), Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        XCTAssertEqual(try Data(contentsOf: savedFile), Data(SMBExportUICapture.fileBytes))
    }
}

// MARK: - SMBExportUICapture

private enum SMBExportUICapture {
    // MARK: Internal

    static let fileBytes = Array("Tracexy SMB UI fixture\n".utf8)

    static func write() throws -> URL {
        let clientIP = [192, 0, 2, 10].map(UInt8.init)
        let serverIP = [198, 51, 100, 7].map(UInt8.init)
        var frames: [[UInt8]] = []
        var clientSequence: UInt32 = 1_001
        var serverSequence: UInt32 = 5_001

        func tcp(_ client: Bool, _ flags: UInt8, _ sequence: UInt32, _ payload: [UInt8] = []) -> [UInt8] {
            let sourceIP = client ? clientIP : serverIP
            let destinationIP = client ? serverIP : clientIP
            let sourcePort: UInt16 = client ? 50_000 : 445
            let destinationPort: UInt16 = client ? 445 : 50_000
            let tcpLength = 20 + payload.count
            var packet: [UInt8] = Array(repeating: 0, count: 12) + [0x08, 0x00]
            packet += [0x45, 0, UInt8((20 + tcpLength) >> 8), UInt8((20 + tcpLength) & 0xFF)]
            packet += [0, 1, 0x40, 0, 64, 6, 0, 0] + sourceIP + destinationIP
            packet += be16(sourcePort) + be16(destinationPort) + be32(sequence) + be32(0)
            packet += [0x50, flags] + [0xFF, 0xFF, 0, 0, 0, 0] + payload
            return packet
        }

        func appendTCP(_ client: Bool, _ flags: UInt8, _ sequence: UInt32, _ payload: [UInt8] = []) {
            frames.append(tcp(client, flags, sequence, payload))
            if !payload.isEmpty {
                if client {
                    clientSequence += UInt32(payload.count)
                } else {
                    serverSequence += UInt32(payload.count)
                }
            }
        }

        func header(_ command: UInt16, _ id: UInt64, _ response: Bool) -> [UInt8] {
            [0xFE, 0x53, 0x4D, 0x42] + le16(64) + le16(1) + le32(0) + le16(command) + le16(1)
                + le32(response ? 1 : 0) + le32(0) + le64(id) + le32(0) + le32(0x200)
                + le64(0x100) + Array(repeating: 0, count: 16)
        }

        func sessionFrame(_ pdu: [UInt8]) -> [UInt8] {
            [0, UInt8((pdu.count >> 16) & 0xFF), UInt8((pdu.count >> 8) & 0xFF), UInt8(pdu.count & 0xFF)] + pdu
        }

        appendTCP(true, 0x02, 1_000)
        appendTCP(false, 0x12, 5_000)
        appendTCP(true, 0x10, clientSequence)

        let name = Array("report.txt".utf16.flatMap(le16))
        var create = header(5, 1, false) + le16(57) + [0, 0]
        create += Array(repeating: 0, count: 7).flatMap { _ in le32(0) }
        create += le32(1) + le32(0) + le32(0)
        create += le16(120) + le16(UInt16(name.count)) + le32(0) + le32(0) + name
        appendTCP(true, 0x18, clientSequence, sessionFrame(create))

        var createReply = header(5, 1, true) + le16(89) + [0, 0] + le32(0)
        createReply += Array(repeating: 0, count: 40) + le64(0) + le32(0) + le32(0)
        createReply += Array(0x20 ... 0x2F).map(UInt8.init) + le32(0) + le32(0)
        appendTCP(false, 0x18, serverSequence, sessionFrame(createReply))

        var write = header(9, 2, false) + le16(49) + [112, 0] + le32(UInt32(fileBytes.count))
        write += le64(0) + Array(0x20 ... 0x2F).map(UInt8.init)
        write += le32(0) + le32(0) + le16(0) + le16(0) + le32(0) + fileBytes
        appendTCP(true, 0x18, clientSequence, sessionFrame(write))
        let writeReply = header(9, 2, true) + le16(17) + le16(0) + le32(UInt32(fileBytes.count))
            + le32(0) + le16(0) + le16(0)
        appendTCP(false, 0x18, serverSequence, sessionFrame(writeReply))

        let fileID = Array(0x20 ... 0x2F).map(UInt8.init)
        let close = header(6, 3, false) + le16(24) + le16(1) + le32(0) + fileID
        appendTCP(true, 0x18, clientSequence, sessionFrame(close))
        var closeReply = header(6, 3, true) + le16(60) + le16(1) + le32(0)
        closeReply += Array(repeating: 0, count: 40) + le64(UInt64(fileBytes.count)) + le32(0)
        appendTCP(false, 0x18, serverSequence, sessionFrame(closeReply))

        var capture: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1]
        capture += le16(2) + le16(4) + le32(0) + le32(0) + le32(65_535) + le32(1)
        for (index, frame) in frames.enumerated() {
            capture += le32(UInt32(1_790_000_000 + index)) + le32(0)
            capture += le32(UInt32(frame.count)) + le32(UInt32(frame.count)) + frame
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-smb-ui-\(UUID().uuidString).pcap")
        try Data(capture).write(to: url, options: .atomic)
        return url
    }

    // MARK: Private

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

    private static func le64(_ value: UInt64) -> [UInt8] {
        (0 ..< 8).map { UInt8((value >> ($0 * 8)) & 0xFF) }
    }
}
