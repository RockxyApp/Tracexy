import AppKit
import Foundation

// MARK: - CaptureImportOperation

nonisolated struct CaptureImportOperation: Sendable {
    static let copy = Self { source, directory, progress in
        let worker = Task.detached(priority: .userInitiated) {
            try Task.checkCancellation()
            return try CaptureImporter.importCapture(
                from: source, intoDirectory: directory, onProgress: progress
            )
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }

    var run: @Sendable (URL, URL, @escaping @Sendable (PcapStreamProgress) -> Void) async throws -> URL

    static func hexDump(
        linkType: UInt32,
        timestampMode: HexDumpCaptureParser.TimestampMode = .untimed,
        offsetRadix: HexDumpCaptureParser.OffsetRadix = .hexadecimal,
        byteGroupMode: HexDumpCaptureParser.ByteGroupMode = .singleBytes,
        directionIndicators: Bool = false,
        regexPattern: String? = nil,
        regexDataEncoding: HexDumpCaptureParser.RegexDataEncoding = .hexadecimal,
        regexPacketMode: HexDumpCaptureParser.RegexPacketMode = .onePerLine,
        syntheticEthernetForIP: Bool = false,
        syntheticUDP: SyntheticUDPPacketBuilder.Options? = nil,
        syntheticTCP: SyntheticTCPPacketBuilder.Options? = nil,
        syntheticSCTP: SyntheticSCTPPacketBuilder.Options? = nil
    )
        -> Self
    {
        Self { source, directory, _ in
            let worker = Task.detached(priority: .userInitiated) {
                try HexDumpCaptureImporter.importCapture(
                    from: source, linkType: linkType, timestampMode: timestampMode,
                    offsetRadix: offsetRadix, byteGroupMode: byteGroupMode,
                    directionIndicators: directionIndicators, regexPattern: regexPattern,
                    regexDataEncoding: regexDataEncoding, regexPacketMode: regexPacketMode,
                    syntheticEthernetForIP: syntheticEthernetForIP, syntheticUDP: syntheticUDP,
                    syntheticTCP: syntheticTCP, syntheticSCTP: syntheticSCTP,
                    intoDirectory: directory
                )
            }
            return try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                worker.cancel()
            }
        }
    }
}

// MARK: - Capture import

@MainActor
extension MainContentCoordinator {
    var isImportingCapture: Bool {
        pendingCaptureImportTask != nil
    }

    var captureImportFraction: Double? {
        guard let progress = captureImportProgress, progress.totalBytes > 0 else {
            return nil
        }
        return min(Double(progress.bytesConsumed) / Double(progress.totalBytes), 1)
    }

    /// File and sidebar share this native picker. Content recognition happens off-main.
    func presentCaptureImportPanel() {
        guard let origin = activeRuntime.projectID, captureImportRefusal == nil else {
            captureError = captureImportRefusal ?? "Load or repair Projects before importing capture data."
            return
        }
        let panel = NSOpenPanel()
        // No extension gate: even an extensionless capture must be selectable.
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.prompt = String(localized: "Import")
        panel
            .message =
            String(
                localized: "Choose PCAP, PCAPNG, a gzip-compressed capture, or a TCP Viewer session. Tracexy checks the file’s contents rather than its name."
            )
        guard panel.runModal() == .OK, let source = panel.url else {
            return
        }
        importCapture(from: source, originProjectID: origin)
    }

    // The modal's option controls and validation share one local scope.
    // Text dumps need an explicit route and link type; ordinary Open continues
    // to recognize only capture containers by their bytes.
    // swiftlint:disable:next function_body_length
    func presentHexDumpImportPanel() {
        guard let origin = activeRuntime.projectID, captureImportRefusal == nil else {
            captureError = captureImportRefusal ?? "Load or repair Projects before importing capture data."
            return
        }
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.prompt = String(localized: "Import")
        panel
            .message =
            String(
                localized: "Choose a hex dump and its byte layout. Timestamp mode requires a UTC ISO 8601 line before each frame."
            )
        let formatLabel = NSTextField(labelWithString: String(localized: "Frame format:"))
        let formats = NSPopUpButton(frame: .zero, pullsDown: false)
        formats.addItems(withTitles: ["Ethernet", "Raw IP", "Linux cooked v1", "Linux cooked v2"])
        formats.selectItem(at: 0)
        formats.setAccessibilityLabel(String(localized: "Frame format"))
        let formatRow = NSStackView(views: [formatLabel, formats])
        formatRow.orientation = .horizontal
        formatRow.spacing = 8
        let radixLabel = NSTextField(labelWithString: String(localized: "Offset format:"))
        let radices = NSPopUpButton(frame: .zero, pullsDown: false)
        radices.addItems(withTitles: ["Hexadecimal", "Decimal", "Octal", "No offsets (one frame)"])
        radices.selectItem(at: 0)
        radices.setAccessibilityLabel(String(localized: "Offset format"))
        let radixRow = NSStackView(views: [radixLabel, radices])
        radixRow.orientation = .horizontal
        radixRow.spacing = 8
        let groupsLabel = NSTextField(labelWithString: String(localized: "Byte groups:"))
        let groups = NSPopUpButton(frame: .zero, pullsDown: false)
        groups.addItems(withTitles: ["Single bytes", "Network order (1–4 bytes)", "Little endian (1–4 bytes)"])
        groups.selectItem(at: 0)
        groups.setAccessibilityLabel(String(localized: "Byte groups"))
        let groupsRow = NSStackView(views: [groupsLabel, groups])
        groupsRow.orientation = .horizontal
        groupsRow.spacing = 8
        let timestamps = NSButton(
            checkboxWithTitle: String(localized: "Read UTC timestamp lines before each frame"),
            target: nil,
            action: nil
        )
        let directions = NSButton(
            checkboxWithTitle: String(localized: "Read I/O direction before each UTC timestamp"),
            target: nil,
            action: nil
        )
        let syntheticLabel = NSTextField(labelWithString: String(localized: "Synthetic headers:"))
        let syntheticModes = NSPopUpButton(frame: .zero, pullsDown: false)
        syntheticModes.addItems(withTitles: [
            "None", "Ethernet for complete IP", "IPv4 + UDP from payload", "IPv6 + UDP from payload",
            "IPv4 + TCP from payload", "IPv6 + TCP from payload",
            "IPv4 + SCTP from chunks", "IPv6 + SCTP from chunks",
            "IPv4 + SCTP DATA from payload", "IPv6 + SCTP DATA from payload",
        ])
        syntheticModes.selectItem(at: 0)
        syntheticModes.setAccessibilityLabel(String(localized: "Synthetic headers"))
        let syntheticRow = NSStackView(views: [syntheticLabel, syntheticModes])
        syntheticRow.orientation = .horizontal
        syntheticRow.spacing = 8
        let addressLabel = NSTextField(labelWithString: String(localized: "IP source → destination:"))
        let sourceAddress = NSTextField(string: "")
        sourceAddress.placeholderString = "192.0.2.1 or 2001:db8::1"
        sourceAddress.setAccessibilityLabel(String(localized: "Synthetic source IP address"))
        let destinationAddress = NSTextField(string: "")
        destinationAddress.placeholderString = "192.0.2.2 or 2001:db8::2"
        destinationAddress.setAccessibilityLabel(String(localized: "Synthetic destination IP address"))
        sourceAddress.widthAnchor.constraint(equalToConstant: 165).isActive = true
        destinationAddress.widthAnchor.constraint(equalToConstant: 165).isActive = true
        let addressRow = NSStackView(views: [addressLabel, sourceAddress, destinationAddress])
        addressRow.orientation = .horizontal
        addressRow.spacing = 8
        let portLabel = NSTextField(labelWithString: String(localized: "Source → destination ports:"))
        let sourcePort = NSTextField(string: "")
        sourcePort.placeholderString = "Source port"
        sourcePort.setAccessibilityLabel(String(localized: "Synthetic source port"))
        let destinationPort = NSTextField(string: "")
        destinationPort.placeholderString = "Destination port"
        destinationPort.setAccessibilityLabel(String(localized: "Synthetic destination port"))
        sourcePort.widthAnchor.constraint(equalToConstant: 145).isActive = true
        destinationPort.widthAnchor.constraint(equalToConstant: 145).isActive = true
        let portRow = NSStackView(views: [portLabel, sourcePort, destinationPort])
        portRow.orientation = .horizontal
        portRow.spacing = 8
        let sctpValueLabel = NSTextField(labelWithString: String(localized: "SCTP tag / DATA PPI (SCTP only):"))
        let sctpValue = NSTextField(string: "")
        sctpValue.placeholderString = "Decimal value from 0 to 4294967295"
        sctpValue.setAccessibilityLabel(String(localized: "SCTP verification tag or DATA PPI"))
        sctpValue.widthAnchor.constraint(equalToConstant: 270).isActive = true
        let sctpValueRow = NSStackView(views: [sctpValueLabel, sctpValue])
        sctpValueRow.orientation = .horizontal
        sctpValueRow.spacing = 8
        let syntheticHelp = NSTextField(labelWithString: String(localized:
            "Generated endpoints are explicit; inbound swaps them. TCP sequences and SCTP DATA TSNs start at zero. No transport handshake is generated."
        ))
        syntheticHelp.lineBreakMode = .byWordWrapping
        syntheticHelp.maximumNumberOfLines = 2
        let regexMode = NSButton(
            checkboxWithTitle: String(localized: "Extract packets with a regular expression"),
            target: nil, action: nil
        )
        let packetModeLabel = NSTextField(labelWithString: String(localized: "Regex match scope:"))
        let packetModes = NSPopUpButton(frame: .zero, pullsDown: false)
        packetModes.addItems(withTitles: ["One packet per line", "Across the file (multiline packets)"])
        packetModes.selectItem(at: 0)
        packetModes.setAccessibilityLabel(String(localized: "Regex match scope"))
        let packetModeRow = NSStackView(views: [packetModeLabel, packetModes])
        packetModeRow.orientation = .horizontal
        packetModeRow.spacing = 8
        let regexField = NSTextField(string: "")
        regexField.placeholderString = "^(?<data>[0-9A-Fa-f]+)$"
        regexField.setAccessibilityLabel(String(localized: "Packet extraction regular expression"))
        let encodingLabel = NSTextField(labelWithString: String(localized: "Regex data encoding:"))
        let encodings = NSPopUpButton(frame: .zero, pullsDown: false)
        encodings.addItems(withTitles: ["Hexadecimal", "Octal", "Binary", "Base64"])
        encodings.selectItem(at: 0)
        encodings.setAccessibilityLabel(String(localized: "Regex data encoding"))
        let encodingRow = NSStackView(views: [encodingLabel, encodings])
        encodingRow.orientation = .horizontal
        encodingRow.spacing = 8
        let regexHelp = NSTextField(labelWithString: String(
            localized: "Regex groups: data, time, dir, seqno. Across-file mode accepts multiline packets and rejects unmatched text. Direction and ID need UTC time."
        ))
        regexHelp.lineBreakMode = .byWordWrapping
        regexHelp.maximumNumberOfLines = 3
        let accessory = NSStackView(views: [
            formatRow, radixRow, groupsRow, timestamps, directions,
            syntheticRow, addressRow, portRow, sctpValueRow, syntheticHelp,
            regexMode, packetModeRow, regexField, encodingRow, regexHelp,
        ])
        accessory.orientation = .vertical
        accessory.alignment = .leading
        accessory.spacing = 6
        accessory.frame = NSRect(x: 0, y: 0, width: 560, height: 425)
        panel.accessoryView = accessory
        panel.isAccessoryViewDisclosed = true
        guard panel.runModal() == .OK, let source = panel.url else {
            return
        }
        guard origin == activeRuntime.projectID else {
            captureError = "Tracexy switched Projects while the import panel was open. Import again in the intended Project."
            return
        }
        let linkTypes = [LinkType.ethernet, LinkType.raw, LinkType.linuxSLL, LinkType.linuxSLL2]
        let selected = formats.indexOfSelectedItem
        guard linkTypes.indices.contains(selected) else {
            return
        }
        let selectedSyntheticMode = syntheticModes.indexOfSelectedItem
        if selectedSyntheticMode == 1, linkTypes[selected] != LinkType.ethernet {
            captureError = "Synthetic Ethernet requires Ethernet frame format."
            return
        }
        let syntheticUDP: SyntheticUDPPacketBuilder.Options?
        let syntheticTCP: SyntheticTCPPacketBuilder.Options?
        let syntheticSCTP: SyntheticSCTPPacketBuilder.Options?
        if (2 ... 9).contains(selectedSyntheticMode) {
            guard linkTypes[selected] == LinkType.ethernet || linkTypes[selected] == LinkType.raw else {
                captureError = "Synthetic UDP, TCP, or SCTP requires Ethernet or Raw IP frame format."
                return
            }
            guard let fromPort = Int(sourcePort.stringValue), let toPort = Int(destinationPort.stringValue),
                  (1 ... 65_535).contains(fromPort), (1 ... 65_535).contains(toPort),
                  !sourceAddress.stringValue.isEmpty, !destinationAddress.stringValue.isEmpty else
            {
                captureError = "Enter source and destination IP addresses and ports from 1 to 65535."
                return
            }
            let ipv6 = [3, 5, 7, 9].contains(selectedSyntheticMode)
            if selectedSyntheticMode <= 3 {
                syntheticUDP = SyntheticUDPPacketBuilder.Options(
                    sourceAddress: sourceAddress.stringValue,
                    destinationAddress: destinationAddress.stringValue,
                    sourcePort: fromPort, destinationPort: toPort, ipv6: ipv6
                )
                syntheticTCP = nil
                syntheticSCTP = nil
            } else if selectedSyntheticMode <= 5 {
                syntheticTCP = SyntheticTCPPacketBuilder.Options(
                    sourceAddress: sourceAddress.stringValue,
                    destinationAddress: destinationAddress.stringValue,
                    sourcePort: fromPort, destinationPort: toPort, ipv6: ipv6
                )
                syntheticUDP = nil
                syntheticSCTP = nil
            } else {
                guard let number = UInt32(sctpValue.stringValue) else {
                    captureError = "Enter a decimal SCTP verification tag or DATA PPI from 0 to 4294967295."
                    return
                }
                let mode: SyntheticSCTPPacketBuilder.Mode = selectedSyntheticMode <= 7
                    ? .chunks(verificationTag: number) : .data(payloadProtocolIdentifier: number)
                syntheticSCTP = SyntheticSCTPPacketBuilder.Options(
                    sourceAddress: sourceAddress.stringValue,
                    destinationAddress: destinationAddress.stringValue,
                    sourcePort: fromPort, destinationPort: toPort,
                    ipv6: ipv6, mode: mode
                )
                syntheticUDP = nil
                syntheticTCP = nil
            }
        } else {
            syntheticUDP = nil
            syntheticTCP = nil
            syntheticSCTP = nil
        }
        let timestampMode: HexDumpCaptureParser.TimestampMode = timestamps.state == .on ? .iso8601UTC : .untimed
        if regexMode.state != .on, directions.state == .on, timestampMode == .untimed {
            captureError = "Direction markers need real UTC timestamps. Select the timestamp option and import again."
            return
        }
        let offsetRadices: [HexDumpCaptureParser.OffsetRadix] = [.hexadecimal, .decimal, .octal, .none]
        let selectedRadix = radices.indexOfSelectedItem
        guard offsetRadices.indices.contains(selectedRadix) else {
            return
        }
        let byteGroupModes: [HexDumpCaptureParser.ByteGroupMode] = [.singleBytes, .networkOrder, .littleEndian]
        let selectedGroup = groups.indexOfSelectedItem
        guard byteGroupModes.indices.contains(selectedGroup) else {
            return
        }
        let regexPattern: String?
        let regexDataEncoding: HexDumpCaptureParser.RegexDataEncoding
        let regexPacketMode: HexDumpCaptureParser.RegexPacketMode
        if regexMode.state == .on {
            let entered = regexField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !entered.isEmpty else {
                captureError = "Enter a regular expression with a named data group before importing."
                return
            }
            regexPattern = entered
            guard let selectedEncoding = HexDumpCaptureParser
                .RegexDataEncoding(rawValue: encodings.indexOfSelectedItem) else
            {
                return
            }
            regexDataEncoding = selectedEncoding
            guard let selectedMode = HexDumpCaptureParser.RegexPacketMode(rawValue: packetModes.indexOfSelectedItem) else {
                return
            }
            regexPacketMode = selectedMode
        } else {
            regexPattern = nil
            regexDataEncoding = .hexadecimal
            regexPacketMode = .onePerLine
        }
        startCaptureImport(
            from: source, origin: origin,
            operation: .hexDump(
                linkType: linkTypes[selected], timestampMode: timestampMode,
                offsetRadix: offsetRadices[selectedRadix], byteGroupMode: byteGroupModes[selectedGroup],
                directionIndicators: directions.state == .on, regexPattern: regexPattern,
                regexDataEncoding: regexDataEncoding, regexPacketMode: regexPacketMode,
                syntheticEthernetForIP: selectedSyntheticMode == 1,
                syntheticUDP: syntheticUDP, syntheticTCP: syntheticTCP,
                syntheticSCTP: syntheticSCTP
            )
        )
    }

    /// Captures arriving from outside the app's own picker — Finder "Open With",
    /// the Dock icon, or a drop onto the main window. They take the same Library
    /// import path as the panel, so recognition, refusal, progress, cancellation
    /// and auto-open cannot drift from ⌘O. One capture per request: the import
    /// pipeline holds one source at a time, so a multi-file drop is refused as a
    /// whole rather than silently importing only its first file.
    ///
    /// A request that lands before Projects have hydrated at launch (the app was
    /// started by opening a file) is held and replayed once hydration finishes.
    func importExternalCaptures(_ urls: [URL]) {
        let files = urls.filter(\.isFileURL)
        guard let source = files.first else {
            return
        }
        guard files.count == 1 else {
            captureError = "Import one capture at a time. \(files.count) files were dropped; none was imported."
            return
        }
        guard hasHydratedProjects else {
            pendingExternalCaptureURL = source
            return
        }
        guard !isImportingCapture else {
            captureError = "Tracexy is still importing “\(captureImportName ?? "a capture")”. "
                + "Wait for it to finish, then open “\(source.lastPathComponent)”."
            return
        }
        // Finder, Dock and drops open in place (or copy, per the Project's Open
        // preference); a multi-gigabyte drop must never silently start a copy.
        openExternalCapture(source)
    }

    /// Replays a capture opened from outside before hydration finished. Called
    /// exactly at the launch-hydration boundary; a request made after that goes
    /// straight through `importExternalCaptures`.
    func replayPendingExternalCapture() {
        guard let source = pendingExternalCaptureURL else {
            return
        }
        pendingExternalCaptureURL = nil
        importExternalCaptures([source])
    }

    func importCapture(from source: URL, originProjectID: UUID? = nil) {
        if let originProjectID, originProjectID != activeRuntime.projectID {
            captureError = "Tracexy switched Projects while the import panel was open. Import again in the intended Project."
            return
        }
        if let refusal = captureImportRefusal {
            captureError = refusal
            return
        }
        guard let origin = activeRuntime.projectID else {
            return
        }
        startCaptureImport(from: source, origin: origin, operation: captureImportOperation)
    }

    private func startCaptureImport(from source: URL, origin: UUID, operation: CaptureImportOperation) {
        if let refusal = captureImportRefusal {
            captureError = refusal
            return
        }
        guard activeRuntime.projectID == origin, let directory = capturesDirectory() else {
            return
        }
        cancelSavedCaptureOpen(clearPublishedEvidence: false)
        captureImportRequestID &+= 1
        let requestID = captureImportRequestID
        let relay = CoordinatorProgressRelay(coordinator: self, requestID: requestID) { coordinator, progress, id in
            coordinator.publishCaptureImportProgress(progress, requestID: id)
        }
        let scoped = source.startAccessingSecurityScopedResource()
        captureImportName = source.lastPathComponent
        captureImportProgress = nil
        isCancellingCaptureImport = false
        captureError = nil
        // Reveal progress without clearing search or any existing evidence.
        activeWorkspace.sidebarSelection = .sessions
        pendingCaptureImportTask = Task { @MainActor [weak self] in
            defer {
                if scoped {
                    source.stopAccessingSecurityScopedResource()
                }
            }
            var destination: URL?
            var failure: String?
            do {
                destination = try await operation.run(source, directory, relay.submit)
            } catch is CancellationError {
                // Cancellation is a normal outcome; the worker cleans its staging file.
            } catch {
                failure = "Couldn’t import “\(source.lastPathComponent)”: \(error.localizedDescription)"
            }
            guard let self, self.captureImportRequestID == requestID else {
                return
            }
            let cancelled = self.isCancellingCaptureImport || Task.isCancelled
            let holdMessage = self.captureSourceHoldMessage
            self.pendingCaptureImportTask = nil
            self.captureImportProgress = nil
            self.captureImportName = nil
            self.isCancellingCaptureImport = false
            guard self.activeRuntime.projectID == origin else {
                return
            }
            self.refreshSavedCaptures()
            if self.captureError == holdMessage {
                self.captureError = nil
            }
            if let failure, !cancelled {
                self.captureError = failure
            }
            // Publication may win a late cancellation; keep the complete Library
            // copy, but never auto-open it after cancellation or a Project change.
            guard !cancelled, !self.projectTransitionStatus.isPending,
                  let destination,
                  let capture = self.savedCaptures.first(where: { $0.url.isSameFileSystemPath(as: destination) }) else
            {
                return
            }
            self.noteRecentCapture(source)
            self.openSavedCapture(capture)
        }
    }

    func cancelCaptureImport() {
        guard let task = pendingCaptureImportTask else {
            return
        }
        isCancellingCaptureImport = true
        task.cancel()
        // The source hold remains until the worker's cleanup completes.
    }

    func waitForCaptureImport() async {
        await pendingCaptureImportTask?.value
    }

    private func publishCaptureImportProgress(_ progress: PcapStreamProgress, requestID: Int) {
        guard requestID == captureImportRequestID, isImportingCapture,
              !isCancellingCaptureImport else
        {
            return
        }
        if let current = captureImportProgress, progress.bytesConsumed < current.bytesConsumed {
            return
        }
        captureImportProgress = progress
    }

    private var captureImportRefusal: String? {
        if let held = captureSourceHoldMessage {
            return held
        }
        if isImportingCapture {
            return "Finish the current import before starting another."
        }
        guard hasHydratedProjects, activeRuntime.projectID != nil else {
            return "Load or repair Projects before importing capture data."
        }
        guard !isProjectBoundaryBusy else {
            return "Tracexy is finishing the current capture change. Import again in a moment."
        }
        guard capturesDirectory() != nil else {
            return "This Project’s capture Library isn’t available. Repair the Project, then import again."
        }
        return nil
    }
}
