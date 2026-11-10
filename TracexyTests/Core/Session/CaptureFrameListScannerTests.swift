import Foundation
import Testing
@testable import Tracexy

/// View ▸ All Frames: every frame of a stable capture, in order, with its session,
/// bounded, identity-checked and agreeing with tshark on the columns it shares.
struct CaptureFrameListScannerTests {
    // MARK: Internal

    @Test
    func captureDirectionFlowsIntoAllFramesRows() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("all-frames-direction-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("directed.pcapng")
        let time = Date(timeIntervalSince1970: 42)
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: [
            CapturedFrame(bytes: [1], timestamp: time, originalLength: 1, direction: .inbound),
            CapturedFrame(bytes: [2], timestamp: time, originalLength: 1, direction: .outbound),
            CapturedFrame(bytes: [3], timestamp: nil, originalLength: 1),
        ], to: url)
        let rows = try CaptureFrameListScanner(
            contentsOf: url, expectedIdentity: Self.identity(url), sourceToken: UUID()
        ).scan().rows
        #expect(rows.map(\.captureDirection) == [.inbound, .outbound, .unknown])
        #expect(rows.compactMap(\.filterFacts).map(\.captureDirection) == [.inbound, .outbound, .unknown])
        var parser = FrameExpressionParser()
        let inbound = try parser.parse("frame.capture_direction == inbound")
        let notOutbound = try parser.parse("not frame.capture_direction == outbound")
        #expect(FrameExpressionSelection.evaluate(inbound, rows: rows)?.matchingOrdinals == [1])
        #expect(FrameExpressionSelection.evaluate(inbound, rows: rows)?.unknownCount == 1)
        #expect(FrameExpressionSelection.evaluate(notOutbound, rows: rows)?.matchingOrdinals == [1])
        #expect(FrameExpressionSelection.evaluate(notOutbound, rows: rows)?.unknownCount == 1)
    }

    @Test
    func recordsExactPreviousCapturedFrameTimeIncludingUntimedPredecessors() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("all-frames-time-predecessor-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("times.pcapng")
        let first = Date(timeIntervalSince1970: 10)
        let outOfOrder = Date(timeIntervalSince1970: 5)
        try PcapngWriter.write(defaultLinkType: LinkType.ethernet, frames: [
            CapturedFrame(bytes: [1], timestamp: first, originalLength: 1),
            CapturedFrame(bytes: [2], timestamp: nil, originalLength: 1),
            CapturedFrame(bytes: [3], timestamp: outOfOrder, originalLength: 1),
        ], to: url)
        let list = try CaptureFrameListScanner(
            contentsOf: url, expectedIdentity: Self.identity(url), sourceToken: UUID()
        ).scan()
        #expect(list.rows.map(\.previousCapturedFrame) == [.none, .timestamp(first), .unknown])
        #expect(list.captureStartTimestamp == first, "the first packet may differ from the earliest timestamp")
    }

    @Test
    func listsEveryFrameWithItsSession() throws {
        try withCapture { url, frames in
            let identity = try Self.identity(url)
            let list = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID())
                .scan()
            #expect(list.rows.count == frames.count)
            #expect(list.scannedFrameCount == frames.count)
            #expect(list.rows.map(\.ordinal) == Array(1 ... UInt64(frames.count)))
            #expect(list.completeness == .complete)
            #expect(list.rows.allSatisfy { $0.filterFacts != nil })

            var parser = FrameExpressionParser()
            let tcpOpening = try parser.parse("tcp.syn and tcp.port == 443")
            let dnsAnswers = try parser.parse("dns.response")
            let dnsPort = try parser.parse("udp.port == 53")
            let dnsAddress = try parser.parse("ip.addr == 203.0.113.53")
            let largeFrames = try parser.parse("frame.len > 100")
            let capturedFrames = try parser.parse("frame.cap_len >= 0")
            let firstCapturedLength = try #require(list.rows.first?.provenance.capturedLength)
            let sameCapturedLength = try parser.parse("frame.cap_len == \(firstCapturedLength)")
            let truncatedFrames = try parser.parse("frame.truncated")
            let rawTCPWindow = try parser.parse("tcp.window_size_value == 65535")
            let successfulDNSAnswers = try parser.parse("dns.response and dns.rcode == 0")
            #expect(FrameExpressionSelection.evaluate(tcpOpening, rows: list.rows)?.matchingOrdinals == Set([5]))
            #expect(FrameExpressionSelection.evaluate(dnsAnswers, rows: list.rows)?.matchingOrdinals == Set([4, 12]))
            #expect(FrameExpressionSelection.evaluate(dnsPort, rows: list.rows)?.matchingOrdinals == Set([
                3,
                4,
                11,
                12
            ]))
            #expect(FrameExpressionSelection.evaluate(dnsAddress, rows: list.rows)?.matchingOrdinals == Set([3, 4]))
            #expect(FrameExpressionSelection.evaluate(largeFrames, rows: list.rows)?.matchingOrdinals
                == Set(list.rows.filter { $0.length > 100 }.map(\.ordinal)))
            #expect(FrameExpressionSelection.evaluate(capturedFrames, rows: list.rows)?.matchingOrdinals
                == Set(list.rows.map(\.ordinal)))
            #expect(FrameExpressionSelection.evaluate(sameCapturedLength, rows: list.rows)?.matchingOrdinals
                == Set(list.rows.filter { $0.provenance.capturedLength == firstCapturedLength }.map(\.ordinal)))
            #expect(FrameExpressionSelection.evaluate(truncatedFrames, rows: list.rows)?.matchingOrdinals
                == Set(list.rows.filter { $0.provenance.capturedLength < $0.provenance.originalLength }.map(\.ordinal)))
            #expect(list.rows[4].filterFacts?.tcpWindowSizeValue == 65_535)
            #expect(FrameExpressionSelection.evaluate(rawTCPWindow, rows: list.rows)?.matchingOrdinals
                .contains(5) == true)
            #expect(FrameExpressionSelection.evaluate(successfulDNSAnswers, rows: list.rows)?.matchingOrdinals == Set([
                4,
                12
            ]))

            let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
            let sessionIDs = Set(loaded.sessions.map(\.id))
            #expect(list.rows.compactMap(\.sessionID).allSatisfy(sessionIDs.contains))

            if WiresharkOracle.isAvailable {
                let rows = try WiresharkOracle.tsharkFields(
                    url,
                    fields: ["frame.number", "ip.src", "ipv6.src", "frame.len"]
                )
                for (row, oracle) in zip(list.rows, rows) {
                    let source = oracle[1].isEmpty ? oracle[2] : oracle[1]
                    if !source.isEmpty {
                        #expect(row.source == source, "frame \(row.ordinal)")
                    }
                    #expect(String(row.length) == oracle[3], "frame \(row.ordinal)")
                }
            }
        }
    }

    @Test
    func boundedAndRefusesAChangedFile() throws {
        try withCapture { url, frames in
            let identity = try Self.identity(url)
            let bounded = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 3)
            ).scan()
            #expect(bounded.rows.count == 3)
            #expect(bounded.omittedFrameCount == frames.count - 3)

            var streamed: [UInt64] = []
            let callbackResult = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 1)
            ).scan(onRow: { streamed.append($0.ordinal) })
            #expect(callbackResult.rows.count == 1)
            #expect(streamed == Array(1 ... UInt64(frames.count)))

            let handle = try FileHandle(forWritingTo: url)
            try handle.seekToEnd()
            try handle.write(contentsOf: Data([0, 0, 0, 0]))
            try handle.close()
            #expect(throws: FollowStreamError.self) {
                _ = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID())
            }
        }
    }

    @Test
    func decodedCallbackAndTCPHealthScanCoverTheWholeCorrectedSource() throws {
        try withCapture { url, frames in
            let identity = try Self.identity(url)
            let baseline = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID()
            ).scan()
            let correction = try CaptureTimeCorrection(shiftBy: 1_000)
            var packets: [(DecodedPacket, SessionFrameProvenance)] = []
            let list = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 1, timeCorrection: correction)
            ).scan(onDecodedPacket: { packets.append(($0, $1)) })
            #expect(list.rows.count == 1)
            #expect(packets.count == frames.count)
            #expect(packets.map(\.1.ordinal.rawValue) == Array(1 ... UInt64(frames.count)))
            for (index, pair) in packets.enumerated() {
                #expect(pair.1.timestamp == baseline.rows[index].provenance.timestamp?.addingTimeInterval(1_000))
                #expect(pair.0.timestamp == pair.1.timestamp)
            }

            let tcp = packets.compactMap { pair -> (UUID, SessionFrameProvenance)? in
                let (packet, provenance) = pair
                guard packet.tcpFacts != nil, let tuple = packet.fiveTuple else {
                    return nil
                }
                return (SessionBuilder.sessionID(for: tuple), provenance)
            }
            let grouped = Dictionary(grouping: tcp, by: \.0)
            let selected = try #require(grouped.max { $0.value.count < $1.value.count })
            #expect(selected.value.count > 1)
            let result = try MainContentCoordinator.readTCPHealthSource(
                url: url, identity: identity, token: UUID(), sessionID: selected.key, correction: correction
            )
            #expect(result.segmentCount == selected.value.count)
            #expect(throws: TCPHealthSourceScanError.segmentLimit(1)) {
                try MainContentCoordinator.readTCPHealthSource(
                    url: url, identity: identity, token: UUID(), sessionID: selected.key,
                    correction: correction, maximumSegments: 1
                )
            }

            let handle = try FileHandle(forWritingTo: url)
            try handle.seekToEnd()
            try handle.write(contentsOf: Data([0, 0]))
            try handle.close()
            #expect(throws: TCPHealthSourceScanError.incompleteSource) {
                try MainContentCoordinator.readTCPHealthSource(
                    url: url, identity: Self.identity(url), token: UUID(), sessionID: selected.key, correction: nil
                )
            }
        }
    }

    @Test
    func retainsLaterWindowWithOriginalOrdinalsAndDecodeFacts() throws {
        try withCapture { url, frames in
            let identity = try Self.identity(url)
            let firstWindow = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 2)
            ).scan()
            let laterWindow = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 2, retainedFrameStartOrdinal: 4)
            ).scan()
            #expect(firstWindow.rows.map(\.ordinal) == [1, 2])
            #expect(laterWindow.rows.map(\.ordinal) == [4, 5])
            #expect(laterWindow.firstRetainedOrdinal == 4)
            #expect(laterWindow.captureStartTimestamp == frames.first?.timestamp)
            #expect(laterWindow.precedingRetainedFrameTimestamp == frames[2].timestamp)
            #expect(laterWindow.scannedFrameCount == frames.count)
            #expect(laterWindow.completeness == .complete)
            #expect(laterWindow.rows.allSatisfy { $0.filterFacts != nil })
            #expect(laterWindow.rows[1].filterFacts?.tcpWindowSizeValue == 65_535)
        }
    }

    @Test
    func completeCaptureFilterCountsAndFindsAdjacentMatchingPages() throws {
        try withCapture { url, _ in
            var parser = FrameExpressionParser()
            let expression = try parser.parse("dns.response")
            var counter = FrameExpressionCaptureCounter(expression: expression, pageStart: 5, pageSize: 3)
            let identity = try Self.identity(url)
            _ = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 3, retainedFrameStartOrdinal: 5)
            ).scan(onRow: { counter.record($0) })
            #expect(counter.coverage.matchingCount == 2)
            #expect(counter.coverage.previousMatchOrdinal == 4)
            #expect(counter.coverage.nextMatchOrdinal == 12)
        }
    }

    @Test
    func canRetainFrameBeyondFormerTwoHundredThousandRowLimit() throws {
        try withCapture { url, frames in
            let frame = try #require(frames.first)
            let shortFrame = CapturedFrame(
                bytes: [0], timestamp: frame.timestamp, originalLength: 1, linkType: LinkType.ethernet
            )
            let finalFrame = CapturedFrame(
                bytes: [0, 0], timestamp: frame.timestamp, originalLength: 2, linkType: LinkType.ethernet
            )
            let largeURL = url.deletingLastPathComponent().appendingPathComponent("large.pcap")
            var largeFrames = [CapturedFrame](repeating: shortFrame, count: 200_000)
            largeFrames.append(finalFrame)
            try PcapWriter.write(
                linkType: LinkType.ethernet,
                frames: largeFrames,
                to: largeURL
            )
            let identity = try Self.identity(largeURL)
            var parser = FrameExpressionParser()
            let expression = try parser.parse("frame.len == 1")
            var counter = FrameExpressionCaptureCounter(expression: expression, pageStart: 200_001, pageSize: 1)
            let finalExpression = try parser.parse("frame.len == 2")
            var finalCounter = FrameExpressionCaptureCounter(
                expression: finalExpression, pageStart: 1, pageSize: 200_000
            )
            let list = try CaptureFrameListScanner(
                contentsOf: largeURL, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 1, retainedFrameStartOrdinal: 200_001)
            ).scan(onRow: {
                counter.record($0)
                finalCounter.record($0)
            })
            #expect(list.scannedFrameCount == 200_001)
            #expect(list.rows.map(\.ordinal) == [200_001])
            #expect(list.captureStartTimestamp == frame.timestamp)
            #expect(list.precedingRetainedFrameTimestamp == frame.timestamp)
            #expect(list.completeness == .complete)
            #expect(counter.coverage.matchingCount == 200_000)
            #expect(counter.coverage.unknownCount == 0)
            #expect(counter.coverage.previousMatchOrdinal == 200_000)
            #expect(counter.coverage.nextMatchOrdinal == nil)
            #expect(finalCounter.coverage.matchingCount == 1)
            #expect(finalCounter.coverage.nextMatchOrdinal == 200_001)
        }
    }

    @Test
    func streamedRowsStillRequirePostScanSourceIdentity() throws {
        try withCapture { url, _ in
            let identity = try Self.identity(url)
            let scanner = try CaptureFrameListScanner(
                contentsOf: url, expectedIdentity: identity, sourceToken: UUID(),
                configuration: .init(maxRetainedFrames: 1)
            )
            #expect(throws: FollowStreamError.self) {
                _ = try scanner.scan(onRow: { row in
                    guard row.ordinal == 1 else {
                        return
                    }
                    let writer = try FileHandle(forWritingTo: url)
                    try writer.seekToEnd()
                    try writer.write(contentsOf: Data([0x01]))
                    try writer.close()
                })
            }
        }
    }

    @Test
    func capturedLengthFilterFindsAnActualSnapshotTruncatedRecord() throws {
        try withCapture { url, frames in
            let first = try #require(frames.first)
            let captured = Array(first.bytes.dropLast(10))
            let truncated = CapturedFrame(
                bytes: captured, timestamp: first.timestamp, originalLength: first.originalLength,
                linkType: LinkType.ethernet
            )
            let truncatedURL = url.deletingLastPathComponent().appendingPathComponent("snaplen.pcap")
            try PcapWriter.write(linkType: LinkType.ethernet, frames: [truncated], to: truncatedURL)
            let identity = try Self.identity(truncatedURL)
            let list = try CaptureFrameListScanner(
                contentsOf: truncatedURL, expectedIdentity: identity, sourceToken: UUID()
            ).scan()
            let row = try #require(list.rows.first)
            #expect(row.provenance.capturedLength == captured.count)
            #expect(row.provenance.originalLength == first.originalLength)
            var parser = FrameExpressionParser()
            let captureLength = try parser.parse("frame.cap_len == \(captured.count)")
            let originalLength = try parser.parse("frame.len == \(first.originalLength)")
            let truncatedExpression = try parser.parse("frame.truncated")
            #expect(captureLength.evaluate(row.filterFacts) == .yes)
            #expect(originalLength.evaluate(row.filterFacts) == .yes)
            #expect(truncatedExpression.evaluate(row.filterFacts) == .yes)
        }
    }

    @Test @MainActor
    func temporaryHighlightPublishesMatchesAndUnknownsForTheRetainedRows() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("all-frames-highlight-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixtureURL = directory.appendingPathComponent("highlight.pcap")
        let frames = ReplayCorpus.conversationCapturedFrames() + [CapturedFrame(
            bytes: Array(repeating: 0, count: 12) + [0x08, 0x00],
            timestamp: Date(timeIntervalSince1970: 100),
            originalLength: 60, linkType: LinkType.ethernet
        )]
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: fixtureURL)
        let list = try CaptureFrameListScanner(
            contentsOf: fixtureURL, expectedIdentity: Self.identity(fixtureURL), sourceToken: UUID()
        ).scan()

        let state = CaptureFrameListState()
        state.list = list
        state.frameExpressionDraft = "frame.len >= 1"
        state.applyFrameExpression()
        try await Self.waitUntil { !state.isEvaluatingFrameExpression }
        let appliedFilter = state.acceptedFrameExpressionText

        state.frameExpressionDraft = "tcp.rst"
        state.highlightFramesFromDraft()
        try await Self.waitUntil { !state.isEvaluatingFrameHighlight }

        var parser = FrameExpressionParser()
        let expression = try parser.parse("tcp.rst")
        let expected = try #require(FrameExpressionSelection.evaluate(expression, rows: list.rows))
        #expect(state.acceptedFrameExpressionText == appliedFilter)
        #expect(state.highlightedFrameOrdinals == expected.matchingOrdinals)
        #expect(state.highlightedFrameUnknownCount == expected.unknownCount)
        #expect(state.highlightedFrameUnknownCount == 1)
    }

    @Test @MainActor
    func captureTimeReferenceRowSurvivesPagingAndDisplayFilters() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("all-frames-time-reference-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixtureURL = directory.appendingPathComponent("references.pcap")
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: ReplayCorpus.conversationCapturedFrames(),
            to: fixtureURL
        )
        let identity = try Self.identity(fixtureURL)
        let firstPage = try CaptureFrameListScanner(
            contentsOf: fixtureURL, expectedIdentity: identity, sourceToken: UUID(),
            configuration: .init(maxRetainedFrames: 2, retainedFrameStartOrdinal: 1)
        ).scan()
        let secondPage = try CaptureFrameListScanner(
            contentsOf: fixtureURL, expectedIdentity: identity, sourceToken: UUID(),
            configuration: .init(maxRetainedFrames: 2, retainedFrameStartOrdinal: 3)
        ).scan()
        let state = CaptureFrameListState()
        state.list = firstPage
        state.limitToSessionsInView = false
        try state.retainCaptureTimeReferenceRow(#require(firstPage.rows.first))
        state.cancel(clearList: true, clearAnnotations: false)
        state.list = secondPage
        state.search = "no matching row"

        #expect(state.visibleRows(sessionsInView: []).map(\.id) == [1])
        state.search = ""
        #expect(state.visibleRows(sessionsInView: []).map(\.id) == [1, 3, 4])

        var pinnedWithOldColumn = try #require(firstPage.rows.first)
        pinnedWithOldColumn.columnValues = ["old column value"]
        state.retainCaptureTimeReferenceRow(pinnedWithOldColumn)
        state.clearCaptureTimeReferenceColumnValues()
        #expect(state.captureTimeReferenceRows[1]?.columnValues.isEmpty == true)

        let retainedOrdinals = Set(secondPage.rows.map(\.ordinal))
        let mergedRows = try [#require(firstPage.rows.first)] + secondPage.rows
        let predecessors = AllFramesWindow.previousDisplayedFrames(mergedRows, retainedOrdinals: retainedOrdinals)
        #expect(predecessors[3] == .unknown, "page one must not become page two's displayed predecessor")
        #expect(try predecessors[4] == .timestamp(#require(secondPage.rows[0].provenance.timestamp)))

        state.cancel(clearList: true, clearAnnotations: true)
        #expect(state.captureTimeReferenceRows.isEmpty)
    }

    @Test @MainActor
    func pinnedFrameRowsStayInASeparateBoundedShelfAcrossPagesAndFilters() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("all-frames-pinned-rows-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixtureURL = directory.appendingPathComponent("pinned.pcap")
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: ReplayCorpus.conversationCapturedFrames(),
            to: fixtureURL
        )
        let identity = try Self.identity(fixtureURL)
        let firstPage = try CaptureFrameListScanner(
            contentsOf: fixtureURL, expectedIdentity: identity, sourceToken: UUID(),
            configuration: .init(maxRetainedFrames: 2, retainedFrameStartOrdinal: 1)
        ).scan()
        let secondPage = try CaptureFrameListScanner(
            contentsOf: fixtureURL, expectedIdentity: identity, sourceToken: UUID(),
            configuration: .init(maxRetainedFrames: 2, retainedFrameStartOrdinal: 3)
        ).scan()

        let state = CaptureFrameListState()
        state.list = firstPage
        state.limitToSessionsInView = false
        let firstRow = try #require(firstPage.rows.first)
        #expect(state.togglePinnedFrameRow(firstRow))
        #expect(state.pinnedFrameRows.keys.sorted() == [firstRow.id])

        state.cancel(clearList: true, clearAnnotations: false)
        state.list = secondPage
        state.search = "no matching row"
        #expect(state.visibleRows(sessionsInView: []).isEmpty)
        #expect(state.pinnedFrameRows[firstRow.id] == firstRow)

        var staleColumns = firstRow
        staleColumns.columnValues = ["old column value"]
        #expect(state.togglePinnedFrameRow(firstRow))
        #expect(state.togglePinnedFrameRow(staleColumns))
        state.clearPinnedFrameColumnValues()
        #expect(state.pinnedFrameRows[firstRow.id]?.columnValues.isEmpty == true)

        let pins = (1 ... CaptureFrameListState.maximumPinnedFrameRows + 1).map { ordinal in
            CaptureFrameRow(
                provenance: SessionFrameProvenance(
                    ordinal: FrameOrdinal(UInt64(ordinal)), timestamp: nil,
                    capturedLength: 0, originalLength: 0, linkType: LinkType.ethernet
                ),
                source: "192.0.2.1", destination: "192.0.2.2", protocolName: "TCP", info: "test",
                sessionID: nil, interfaceID: 0, hasComment: false
            )
        }
        let boundedState = CaptureFrameListState()
        for row in pins.prefix(CaptureFrameListState.maximumPinnedFrameRows) {
            #expect(boundedState.togglePinnedFrameRow(row))
        }
        #expect(try !boundedState.togglePinnedFrameRow(#require(pins.last)))
        #expect(boundedState.pinnedFrameRows.count == CaptureFrameListState.maximumPinnedFrameRows)
        boundedState.unpinAllFrameRows()
        #expect(boundedState.pinnedFrameRows.isEmpty)
        boundedState.cancel(clearList: false, clearAnnotations: true)
        #expect(boundedState.pinnedFrameRows.isEmpty)
    }

    @Test @MainActor
    func commandTRemovesThePinnedRowWhenClearingCaptureReferenceFromSessionFrames() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("all-frames-reference-command-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixtureURL = directory.appendingPathComponent("references.pcap")
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: ReplayCorpus.conversationCapturedFrames(),
            to: fixtureURL
        )
        let firstPage = try CaptureFrameListScanner(
            contentsOf: fixtureURL, expectedIdentity: Self.identity(fixtureURL), sourceToken: UUID(),
            configuration: .init(maxRetainedFrames: 2, retainedFrameStartOrdinal: 1)
        ).scan()
        let row = try #require(firstPage.rows.first)
        let sessionID = try #require(row.sessionID)
        let timestamp = try #require(row.provenance.timestamp)
        let coordinator = MainContentCoordinator()
        let globalReference = FrameTimeReference(sessionID: nil, ordinal: row.ordinal, timestamp: timestamp)
        #expect(coordinator.sessionTimeDisplay.toggleTimeReference(globalReference))
        coordinator.sessionTimeDisplay.selectedFrame = FrameTimeReference(
            sessionID: sessionID, ordinal: row.ordinal, timestamp: timestamp
        )
        coordinator.allFrames.retainCaptureTimeReferenceRow(row)

        coordinator.toggleSelectedFrameTimeReference()

        #expect(coordinator.sessionTimeDisplay.captureReferences().isEmpty)
        #expect(coordinator.allFrames.captureTimeReferenceRows.isEmpty)
    }

    // MARK: Private

    @MainActor
    private static func waitUntil(timeout: Duration = .seconds(2), condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + timeout
        while !condition(), ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(2))
        }
        #expect(condition(), "Timed out while waiting for frame expression evaluation")
    }

    private static func identity(_ url: URL) throws -> PcapFileIdentity {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        return PcapFileIdentity.snapshot(of: handle)
    }

    private func withCapture(_ body: (URL, [CapturedFrame]) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("all-frames-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("conv.pcap")
        let frames = ReplayCorpus.conversationCapturedFrames()
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        try body(url, frames)
    }
}
