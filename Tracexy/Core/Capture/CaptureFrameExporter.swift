import Foundation
import zlib

// MARK: - FrameExportScope

/// Which frames of the source an export keeps. Every scope is evaluated frame by
/// frame during one streaming pass; nothing is materialized.
nonisolated enum FrameExportScope: Sendable, Equatable {
    /// Every frame, as opened.
    case wholeCapture
    /// Frames whose decoded canonical tuple folds into one of these sessions.
    case sessions(Set<UUID>)
    /// Frames whose capture time lies in the closed range. Untimed frames are
    /// excluded and counted.
    case timeRange(start: Date, end: Date)
    /// Exactly these frames, by 1-based capture-order number (the marked frames).
    case frames(Set<UInt64>)
    /// Frames matching one accepted packet-level expression, evaluated from a
    /// fresh streaming decode of the complete source.
    case frameExpression(FrameExpression)

    // MARK: Internal

    func addingFrameOrdinalOffset(_ offset: UInt64) throws -> FrameExportScope {
        guard case let .frames(ordinals) = self else {
            return self
        }
        return try .frames(Set(ordinals.map { try offsetFrameOrdinal($0, by: offset) }))
    }
}

// MARK: - FrameExportFormat

nonisolated enum FrameExportFormat: String, Sendable, CaseIterable, Identifiable {
    case pcapng
    case pcap

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .pcapng: "PCAPNG"
        case .pcap: "PCAP (libpcap)"
        }
    }

    var fileExtension: String {
        rawValue
    }
}

// MARK: - FrameExportOptions

nonisolated struct FrameExportOptions: Sendable, Equatable {
    /// Most comments written, and the most UTF-8 bytes kept of each.
    static let maximumCaptureComments = 500
    static let maximumCommentBytes = 16_000

    static let duplicateWindow = 5
    static let maximumNameRecords = 10_000
    static let truncationRange = 14 ... 262_144

    /// Address → name pairs written into a PCAPNG Name Resolution Block, so
    /// Wireshark shows the same names (resolved from the capture's DNS answers or
    /// given by the investigator). Left out when addresses are replaced.
    var nameRecords: [FrameExportNameRecord] = []

    var format: FrameExportFormat = .pcapng
    /// Copy section hardware/OS/application/comments and interface names,
    /// descriptions, filters and per-frame options from a pcapng source.
    var preservesMetadata = true
    /// Wrap the output in a gzip stream (`.gz`).
    var compressesWithGzip = false
    /// Capture comments added to the PCAPNG section header (the investigator's
    /// notes). Classic PCAP has nowhere to carry them and ignores them.
    var captureComments: [String] = []
    /// A comment for the first exported frame of each of these sessions (the
    /// investigator's notes), so Wireshark shows it on that packet. PCAPNG only;
    /// a frame without a capture time has no options to carry it.
    var sessionFrameComments: [UUID: String] = [:]
    /// Comments for individual frames, by 1-based capture-order number (Wireshark's
    /// Packet Comment…). PCAPNG only; written beside any session note on that frame.
    var frameComments: [UInt64: String] = [:]
    /// Replace the addresses in every packet header (see ``AddressAnonymizer``).
    /// Copied metadata and comments are left out, since they can name hosts too;
    /// frames whose headers cannot be parsed are left out and counted.
    var anonymizesAddresses = false
    /// Strip Headers: write each frame's inner packet instead of the whole frame.
    /// Frames without that inner layer are left out and counted.
    var stripsHeaders: FrameHeaderStrip?
    /// editcap -d: leave out a frame whose bytes equal one of the previous
    /// ``duplicateWindow`` frames exactly.
    var removesDuplicates = false
    /// Original capture ordinals deliberately omitted from output. The stream is
    /// still fully decoded so this cannot change sequential analysis context.
    var excludedFrameOrdinals: Set<UInt64> = []
    /// editcap -s: keep at most this many captured bytes of each frame (the
    /// original length is kept). `nil` keeps every byte.
    var truncatesTo: Int?
    /// Seconds added to every written frame's time (editcap `-t`, Wireshark's Time
    /// Shift); frames are chosen by their original times.
    var shiftsTimeBy: TimeInterval = 0
    /// Existing in-memory saved-capture correction to retain on export, before
    /// any optional new explicit correction or fixed export offset.
    var baseTimeCorrection: CaptureTimeCorrection?
    /// Resolved against original capture ordinals before exporting. PCAPNG only;
    /// cannot be combined with the legacy fixed `shiftsTimeBy` option.
    var timeCorrection: CaptureTimeCorrectionRequest?

    mutating func addFrameOrdinalOffset(_ offset: UInt64) throws {
        timeCorrection = try timeCorrection?.addingFrameOrdinalOffset(offset)
        excludedFrameOrdinals = try Set(excludedFrameOrdinals.map { try offsetFrameOrdinal($0, by: offset) })
        frameComments = try Dictionary(uniqueKeysWithValues: frameComments.map { ordinal, comment in
            try (offsetFrameOrdinal(ordinal, by: offset), comment)
        })
    }
}

private func offsetFrameOrdinal(_ ordinal: UInt64, by offset: UInt64) throws -> UInt64 {
    let (result, overflow) = ordinal.addingReportingOverflow(offset)
    guard !overflow else {
        throw FrameExportError.frameOrdinalOverflow
    }
    return result
}

// MARK: - FrameExportNameRecord

nonisolated struct FrameExportNameRecord: Sendable, Equatable {
    let address: String
    let name: String
}

// MARK: - FrameExportSummary

nonisolated struct FrameExportSummary: Sendable, Equatable {
    let scannedFrameCount: Int
    let writtenFrameCount: Int
    let writtenByteCount: UInt64
    /// Frames the scope matched but the format could not represent (untimed
    /// frames for classic pcap). Non-zero is reported, never silent.
    let unrepresentableFrameCount: Int
    /// Per-frame option lists not retained in full (big-endian source sections,
    /// oversized lists, transformed packet bytes, or a classic pcap target).
    let omittedFrameOptionCount: Int
    /// Interface options that could not be re-emitted safely or completely.
    let omittedInterfaceOptionCount: Int
    /// Section options or bounded section text that could not be copied completely.
    var omittedSectionOptionCount = 0
    /// Source section/interface metadata exceeded the bounded container inventory.
    var sourceMetadataInventoryTruncated = false
    let completeness: CaptureLoadCompleteness
    /// Frames an address-replacing export left out because their headers could not
    /// be parsed safely.
    var unanonymizedFrameCount = 0
    /// Frames a Strip Headers export left out because they carry no inner packet
    /// of the requested kind.
    var unstrippedFrameCount = 0
    /// Frames left out as exact duplicates of a recent frame.
    var removedDuplicateCount = 0
    /// Frames whose captured bytes were cut to the byte limit.
    var truncatedFrameCount = 0
    /// Frames excluded because they were marked ignored in All Frames.
    var excludedIgnoredFrameCount = 0
    /// Address names written into the Name Resolution Block.
    var writtenNameCount = 0
    /// Distinct addresses replaced (MAC, IPv4 and IPv6 together).
    var replacedAddressCount = 0
    /// Matching-scope frames whose typed decode could not establish yes or no.
    var unknownExpressionFrameCount = 0
}

// MARK: - FrameExportError

nonisolated enum FrameExportError: LocalizedError, Equatable {
    case mixedLinkTypesRequirePcapng
    case untimedFramesRequirePcapng
    case directionRequiresPcapng
    case packetIDRequiresPcapng
    case timeCorrectionRequiresPcapng
    case timeCorrectionRequiresUncompressedOutput
    case conflictingTimeCorrections
    case timeCorrectionNeedsDistinctDestination
    case identityMismatch
    case frameOrdinalOverflow
    case nothingMatched
    case ignoredFramesExcludedAll(count: Int)
    case expressionExportNoFrames(unknownCount: Int)
    case compression(String)

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case .mixedLinkTypesRequirePcapng:
            "The selected frames use more than one link type, which classic PCAP can’t represent. Choose PCAPNG."
        case .untimedFramesRequirePcapng:
            "Some selected frames carry no capture time, which classic PCAP can’t represent. Choose PCAPNG."
        case .directionRequiresPcapng:
            "Some selected frames carry interface direction, which classic PCAP can’t represent. Choose PCAPNG."
        case .packetIDRequiresPcapng:
            "Some selected frames carry packet IDs, which classic PCAP can’t represent. Choose PCAPNG."
        case .timeCorrectionRequiresPcapng:
            "Time-corrected capture copies require PCAPNG."
        case .timeCorrectionRequiresUncompressedOutput:
            "A corrected capture copy must be an uncompressed PCAPNG so Tracexy can reopen and analyze it."
        case .conflictingTimeCorrections:
            "Choose one time correction instead of combining anchored correction with a separate time shift."
        case .timeCorrectionNeedsDistinctDestination:
            "Save the corrected capture to a different file so the original capture is preserved."
        case .identityMismatch:
            "The capture file changed on disk while exporting. Reload the capture and export again."
        case .frameOrdinalOverflow:
            "The capture frame number is too large to export safely."
        case .nothingMatched:
            "No frames matched the selected scope, so no file was written."
        case let .ignoredFramesExcludedAll(count):
            "No frames were written. \(count) frame(s) matching the selected scope were excluded as ignored. Review the scope or turn off Exclude ignored frames."
        case let .expressionExportNoFrames(unknownCount):
            "No frames were exported. \(unknownCount) frame\(unknownCount == 1 ? "" : "s") had an unknown expression result. No file was written."
        case let .compression(detail):
            "The gzip stream could not be written: \(detail)"
        }
    }
}

// MARK: - CaptureFrameExporter

/// Streams the frames of one stable capture that match a scope into a new
/// PCAPNG or classic PCAP file, optionally gzip-compressed. The source is read
/// through ``CaptureStreamReader``; anchored time correction and session selection
/// use a preliminary streaming pass. The output is written to a temporary
/// sibling and renamed into place only after the final identity check, so a
/// cancelled or failed export leaves no partial file behind.
///
/// Metadata preservation re-emits typed section/interface facts from the source's
/// ``CaptureFileProperties``. It copies a complete packet-option list verbatim only
/// for unchanged frames in a complete little-endian export. For subsets, other byte
/// orders, or transformed frames, it carries independent comments and hashes that
/// remain valid, reconstructs typed packet IDs and flags, and counts options that
/// cannot safely be preserved.
nonisolated enum CaptureFrameExporter {
    // MARK: Internal

    /// Largest per-frame option list copied verbatim.
    static let maxCopiedOptionBytes = 65_536

    static func export(
        from source: URL,
        expectedIdentity: PcapFileIdentity? = nil,
        scope: FrameExportScope,
        options: FrameExportOptions,
        to destination: URL,
        onProgress: (PcapStreamProgress) -> Void = { _ in },
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> FrameExportSummary
    {
        try CaptureFrameTimeCorrection.validateOptions(options)
        let reader = try validatedReader(
            from: source, expectedIdentity: expectedIdentity, isCancelled: isCancelled
        )
        var timeCorrection = try CaptureFrameTimeCorrection(
            options: options, source: source, destination: destination,
            identity: reader.identity, isCancelled: isCancelled
        )
        // A session's frames include every fragment of a datagram that completes
        // into it, and those come before the frame that names the session. One
        // read first settles the frame set; the write then keeps exactly those.
        var scope = scope
        if case let .sessions(ids) = scope {
            scope = try .frames(sessionOrdinals(ids, in: source, isCancelled: isCancelled))
        }
        let exportsEverySourceFrame = if case .wholeCapture = scope {
            options.excludedFrameOrdinals.isEmpty && !options.removesDuplicates && options.stripsHeaders == nil
                && !options.anonymizesAddresses
        } else {
            false
        }
        let optionSource = try validatedOptionSource(from: source, identity: reader.identity)
        defer { try? optionSource.close() }

        let temporary = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).partial")
        FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600])
        var sink = try OutputSink(url: temporary, gzip: options.compressesWithGzip)
        var failed = true
        defer {
            if failed {
                try? sink.abort()
                try? FileManager.default.removeItem(at: temporary)
            }
        }

        var state = writerState(options: options, timeCorrection: timeCorrection)
        var anonymizer = options.anonymizesAddresses ? AddressAnonymizer() : nil
        var unanonymized = 0, unstripped = 0, duplicates = 0, truncated = 0
        var recent: [[UInt8]] = []
        var scanned = 0, commentedSessions: Set<UUID> = []
        // Session notes go on each session's first written frame; which session a
        // frame belongs to comes from the same in-order decode every reader uses,
        // so a datagram rebuilt from fragments counts on the frame completing it.
        let needsSessionNotes = !options.anonymizesAddresses && !options.sessionFrameComments.isEmpty
        var scopeEvaluator = FrameExportScopeEvaluator(scope: scope, needsSessionNotes: needsSessionNotes)
        var completion: CaptureStreamCompletion?
        walk: while true {
            switch try reader.next() {
            case let .frame(event):
                scanned += 1
                try timeCorrection.validate(event, ordinal: UInt64(scanned))
                let scopeEvent = try timeCorrection.eventForScope(event, ordinal: UInt64(scanned))
                let packet = scopeEvaluator.decode(scopeEvent, ordinal: scanned)
                let frameSessionID = packet?.fiveTuple.map(SessionBuilder.sessionID(for:))
                let excluded = options.excludedFrameOrdinals.contains(UInt64(scanned))
                let decision = scopeEvaluator.decision(
                    scopeEvent, ordinal: scanned, packet: packet, excluded: excluded
                )
                if scanned % 256 == 0 {
                    onProgress(event.progress)
                }
                if decision == .excludedMatch {
                    state.excludedIgnoredFrameCount += 1
                    continue walk
                }
                if decision == .include {
                    if options.removesDuplicates {
                        if recent.contains(event.bytes) {
                            duplicates += 1
                            continue walk
                        }
                        recent.append(event.bytes)
                        if recent.count > FrameExportOptions.duplicateWindow {
                            recent.removeFirst()
                        }
                    }
                    var written = event
                    if let target = options.stripsHeaders {
                        guard let inner = FrameHeaderStripper.strip(event, to: target) else {
                            unstripped += 1
                            continue walk
                        }
                        written = inner
                    }
                    if anonymizer != nil {
                        guard let bytes = anonymizer?.anonymize(written.bytes, linkType: written.reference.linkType) else {
                            unanonymized += 1
                            continue walk
                        }
                        written = CaptureFrameEvent(
                            reference: written.reference,
                            bytes: bytes,
                            progress: event.progress
                        )
                    }
                    if let limit = options.truncatesTo.map({ min(
                        max($0, FrameExportOptions.truncationRange.lowerBound),
                        FrameExportOptions.truncationRange.upperBound
                    ) }), written.bytes.count > limit {
                        written = Self.truncated(written, to: limit)
                        truncated += 1
                    }
                    written = try timeCorrection.apply(to: written, ordinal: UInt64(scanned))
                    var comment: String?
                    // An untimed frame is a Simple Packet Block, which has no options;
                    // the note waits for the session's first timed frame.
                    if !options.anonymizesAddresses, !options.sessionFrameComments.isEmpty,
                       event.reference.timestamp != nil,
                       let id = frameSessionID,
                       !commentedSessions.contains(id), let text = options.sessionFrameComments[id]
                    {
                        comment = text
                        commentedSessions.insert(id)
                    }
                    if !options.anonymizesAddresses, event.reference.timestamp != nil,
                       let text = options.frameComments[UInt64(scanned)], !text.isEmpty
                    {
                        comment = comment.map { $0 + "\n" + text } ?? text
                    }
                    try state.write(
                        written, properties: reader.fileProperties, sourceFormat: reader.format,
                        optionSource: optionSource, comment: comment,
                        sourceFrameBytesUnchanged: written.bytes == event.bytes,
                        exportsEverySourceFrame: exportsEverySourceFrame,
                        into: &sink
                    )
                }
            case let .end(end):
                completion = end
                break walk
            }
        }
        guard let completion else {
            throw FrameExportError.nothingMatched
        }
        try timeCorrection.finish()
        let written = try Self.finishExport(
            source: source,
            optionSource: optionSource,
            identity: reader.identity,
            destination: destination,
            temporary: temporary,
            sink: &sink,
            state: state,
            scope: scope,
            unknownExpressionFrameCount: scopeEvaluator.unknownExpressionFrameCount,
            isCancelled: isCancelled
        )
        failed = false
        onProgress(completion.progress)
        Self.finishMetadataAccounting(state: &state, properties: reader.fileProperties, options: options, scope: scope)
        return summary(
            scanned: scanned,
            state: state,
            writtenBytes: written,
            completeness: Self.completeness(for: completion.reason),
            unanonymized: unanonymized,
            unstripped: unstripped,
            duplicates: duplicates,
            truncated: truncated,
            anonymizer: anonymizer,
            unknownExpressionFrameCount: scopeEvaluator.unknownExpressionFrameCount
        )
    }

    /// `event` at a time `shift` seconds later (earlier when negative); an untimed
    /// frame stays untimed.
    static func shifted(_ event: CaptureFrameEvent, by shift: TimeInterval) -> CaptureFrameEvent {
        CaptureFrameTimeCorrection.retimed(event, to: event.reference.timestamp?.addingTimeInterval(shift))
    }

    /// `event` with its captured bytes cut to `limit`; the original length stays.
    static func truncated(_ event: CaptureFrameEvent, to limit: Int) -> CaptureFrameEvent {
        let reference = event.reference
        return CaptureFrameEvent(
            reference: CaptureFrameReference(
                payloadOffset: reference.payloadOffset, capturedLength: limit,
                originalLength: max(reference.originalLength, reference.capturedLength), timestamp: reference.timestamp,
                direction: reference.direction,
                packetFlags: reference.packetFlags,
                packetID: reference.packetID,
                linkType: reference.linkType, sectionIndex: reference.sectionIndex, interfaceID: reference.interfaceID,
                hasComment: reference.hasComment, hasPacketOptions: reference.hasPacketOptions,
                frameCommentReference: reference.frameCommentReference,
                packetOptionsReference: reference.packetOptionsReference,
                copyableOptionsRange: reference.copyableOptionsRange
            ),
            bytes: Array(event.bytes.prefix(limit)),
            progress: event.progress
        )
    }

    // MARK: Private

    /// Output interface bookkeeping keyed by the source (section, interface).
    private struct OutputInterface {
        let id: UInt32
        let snapLength: UInt32
    }

    private struct WriterState {
        // MARK: Lifecycle

        init(
            format: FrameExportFormat,
            preservesMetadata: Bool,
            captureComments: [String] = [],
            nameRecords: [FrameExportNameRecord] = []
        ) {
            self.format = format
            self.preservesMetadata = preservesMetadata
            self.captureComments = captureComments
            self.nameRecords = nameRecords
        }

        // MARK: Internal

        let format: FrameExportFormat
        let preservesMetadata: Bool
        let captureComments: [String]
        let nameRecords: [FrameExportNameRecord]
        var writtenFrames = 0
        var writtenNames = 0
        var excludedIgnoredFrameCount = 0
        var unrepresentableFrames = 0
        var omittedFrameOptions = 0
        var omittedInterfaceOptions = 0
        var omittedSectionOptions = 0
        var sourceMetadataInventoryTruncated = false
        var writtenSourceSections: Set<Int> = []
        var countedSectionMetadata: Set<Int> = []

        mutating func write(
            _ event: CaptureFrameEvent,
            properties: CaptureFileProperties,
            sourceFormat: CaptureStreamFormat,
            optionSource: FileHandle,
            comment: String? = nil,
            sourceFrameBytesUnchanged: Bool,
            exportsEverySourceFrame: Bool,
            into sink: inout OutputSink
        )
            throws
        {
            switch format {
            case .pcap:
                try writeClassic(event, into: &sink)
            case .pcapng:
                try writePcapng(
                    event,
                    properties: properties,
                    sourceFormat: sourceFormat,
                    optionSource: optionSource,
                    comment: comment,
                    sourceFrameBytesUnchanged: sourceFrameBytesUnchanged,
                    exportsEverySourceFrame: exportsEverySourceFrame,
                    into: &sink
                )
            }
        }

        // MARK: Private

        private var wroteHeader = false
        private var activeSourceSection: Int?
        private var captureNotesWritten = false
        private var sequenceOptionsRemainValid = true
        private var hasTransformedFramesInSection = false
        private var omittedFCSInterfaces: Set<CaptureInterface.ID> = []
        private var classicLinkType: UInt32?
        private var interfaces: [CaptureInterface.ID: OutputInterface] = [:]

        /// `comment` cut to ``FrameExportOptions/maximumCommentBytes`` at a
        /// character boundary.
        private static func boundedComment(_ comment: String) -> String {
            var kept = ""
            for character in comment {
                guard kept.utf8.count + String(character).utf8.count <= FrameExportOptions.maximumCommentBytes else {
                    break
                }
                kept.append(character)
            }
            return kept
        }

        private mutating func writeClassic(_ event: CaptureFrameEvent, into sink: inout OutputSink) throws {
            guard event.reference.direction == .unknown else {
                throw FrameExportError.directionRequiresPcapng
            }
            guard event.reference.packetID == nil else {
                throw FrameExportError.packetIDRequiresPcapng
            }
            guard let timestamp = event.reference.timestamp else {
                unrepresentableFrames += 1
                throw FrameExportError.untimedFramesRequirePcapng
            }
            if preservesMetadata, event.reference.hasPacketOptions {
                omittedFrameOptions += 1
            }
            if let classicLinkType, classicLinkType != event.reference.linkType {
                throw FrameExportError.mixedLinkTypesRequirePcapng
            }
            if !wroteHeader {
                classicLinkType = event.reference.linkType
                var header = Data()
                append32(0xA1B2C3D4, to: &header)
                append16(2, to: &header)
                append16(4, to: &header)
                append32(0, to: &header)
                append32(0, to: &header)
                append32(PcapWriter.snapLength, to: &header)
                append32(event.reference.linkType, to: &header)
                try sink.write(header)
                wroteHeader = true
            }
            let (seconds, micros) = try CaptureTimestampEncoding.classic(timestamp)
            var record = Data(capacity: 16 + event.bytes.count)
            append32(seconds, to: &record)
            append32(micros, to: &record)
            append32(UInt32(event.reference.capturedLength), to: &record)
            append32(UInt32(max(event.reference.originalLength, event.reference.capturedLength)), to: &record)
            record.append(contentsOf: event.bytes)
            try sink.write(record)
            writtenFrames += 1
        }

        private mutating func writePcapng(
            _ event: CaptureFrameEvent,
            properties: CaptureFileProperties,
            sourceFormat: CaptureStreamFormat,
            optionSource: FileHandle,
            comment: String?,
            sourceFrameBytesUnchanged: Bool,
            exportsEverySourceFrame: Bool,
            into sink: inout OutputSink
        )
            throws
        {
            if activeSourceSection != event.reference.sectionIndex {
                try beginSection(
                    properties: properties, sourceSectionIndex: event.reference.sectionIndex, into: &sink
                )
            }
            if !sourceFrameBytesUnchanged, !hasTransformedFramesInSection, !interfaces.isEmpty {
                try beginSection(
                    properties: properties, sourceSectionIndex: event.reference.sectionIndex,
                    includesCaptureNotes: false, containsTransformedFrames: true, into: &sink
                )
                sequenceOptionsRemainValid = false
            } else if !sourceFrameBytesUnchanged {
                hasTransformedFramesInSection = true
            }
            let key = CaptureInterface.ID(
                sectionIndex: event.reference.sectionIndex,
                interfaceID: event.reference.interfaceID
            )
            var output: OutputInterface
            if let existing = interfaces[key] {
                output = existing
            } else {
                let source = properties.sections.first { $0.id == key.sectionIndex }?
                    .interfaces.first { $0.id == key }
                let id = UInt32(interfaces.count)
                try sink.write(interfaceDescription(
                    id: id, linkType: event.reference.linkType, source: source,
                    preservesSourceFCS: !hasTransformedFramesInSection, sourceInterfaceID: key
                ))
                output = OutputInterface(
                    id: id,
                    snapLength: source?.snapLength ?? PcapWriter.snapLength
                )
                interfaces[key] = output
            }

            let capturedLength = event.reference.capturedLength
            let originalLength = event.reference.originalLength
            let simplePacketLength = output.snapLength == 0
                ? originalLength : min(originalLength, Int(output.snapLength))
            let requiresSimplePacketSection = event.reference.timestamp == nil
                && (output.id != 0 || simplePacketLength != capturedLength)
            let requiresLargerTimedInterface = event.reference.timestamp != nil
                && output.snapLength != 0 && Int(output.snapLength) < capturedLength
            if requiresSimplePacketSection || requiresLargerTimedInterface {
                guard capturedLength > 0 || originalLength == 0 else {
                    unrepresentableFrames += 1
                    throw SessionExportError.untimedFrameNotRepresentable
                }
                try beginSection(
                    properties: properties, sourceSectionIndex: event.reference.sectionIndex,
                    includesCaptureNotes: false, containsTransformedFrames: hasTransformedFramesInSection,
                    into: &sink
                )
                sequenceOptionsRemainValid = false
                let source = properties.sections.first { $0.id == key.sectionIndex }?
                    .interfaces.first { $0.id == key }
                let snapLength = UInt32(capturedLength)
                try sink.write(interfaceDescription(
                    id: 0, linkType: event.reference.linkType, source: source,
                    snapLengthOverride: snapLength,
                    preservesSourceFCS: !hasTransformedFramesInSection, sourceInterfaceID: key
                ))
                output = OutputInterface(id: 0, snapLength: snapLength)
                interfaces[key] = output
            }

            var body = Data(capacity: 20 + event.bytes.count)
            append32(output.id, to: &body)
            if let timestamp = event.reference.timestamp {
                let micros = try CaptureTimestampEncoding.microseconds(timestamp)
                append32(UInt32(micros >> 32), to: &body)
                append32(UInt32(micros & UInt64(UInt32.max)), to: &body)
                append32(UInt32(event.reference.capturedLength), to: &body)
                append32(UInt32(max(event.reference.originalLength, event.reference.capturedLength)), to: &body)
                body.append(contentsOf: event.bytes)
                while body.count % 4 != 0 {
                    body.append(0)
                }
                // The investigator's note leads the option list; any copied source
                // options (with their own end marker, if present) follow it.
                let noted = comment.map(Self.boundedComment).flatMap { $0.isEmpty ? nil : $0 }
                if let noted {
                    appendOption(code: 1, value: Array(noted.utf8), to: &body)
                }
                var copiedOptions = false
                if preservesMetadata, exportsEverySourceFrame, sequenceOptionsRemainValid,
                   sourceFrameBytesUnchanged, sourceFormat == .pcapng
                {
                    if let range = event.reference.copyableOptionsRange {
                        if range.count <= CaptureFrameExporter.maxCopiedOptionBytes {
                            let copied = try readOptions(range, from: optionSource)
                            body.append(copied)
                            copiedOptions = true
                        }
                    }
                }
                var allSourceOptionsPreserved = copiedOptions
                var copiedIndependentOptions = Data()
                if !copiedOptions, preservesMetadata, sourceFormat == .pcapng,
                   let reference = event.reference.packetOptionsReference
                {
                    let reconstructedFlags = event.reference.packetFlags.map { _ in
                        event.reference.direction.rawValue
                    }
                    let copiedComments = try CapturePacketOptionCopier.copyIndependentOptions(
                        reference, maxBytes: CaptureFrameExporter.maxCopiedOptionBytes,
                        preserveHash: sourceFrameBytesUnchanged, reconstructedFlags: reconstructedFlags,
                        from: optionSource
                    )
                    copiedIndependentOptions = copiedComments.bytes
                    body.append(copiedIndependentOptions)
                    allSourceOptionsPreserved = copiedComments.preservedAllOptions
                }
                if preservesMetadata, sourceFormat == .pcapng, event.reference.hasPacketOptions, !copiedOptions {
                    if !allSourceOptionsPreserved {
                        omittedFrameOptions += 1
                    }
                }
                if !copiedOptions {
                    let writesFlags = event.reference.packetFlags != nil || event.reference.direction != .unknown
                    if writesFlags {
                        var flags = Data()
                        append32(event.reference.direction.rawValue, to: &flags)
                        appendOption(code: 2, value: Array(flags), to: &body)
                    }
                    if let packetID = event.reference.packetID {
                        var value = Data()
                        append64(packetID, to: &value)
                        appendOption(code: 5, value: Array(value), to: &body)
                    }
                    if noted != nil || !copiedIndependentOptions.isEmpty || writesFlags
                        || event.reference.packetID != nil
                    {
                        append16(0, to: &body)
                        append16(0, to: &body)
                    }
                }
                try sink.write(block(type: 0x00000006, body: body))
            } else {
                guard event.reference.direction == .unknown else {
                    throw SessionExportError.untimedDirectionNotRepresentable
                }
                guard event.reference.packetID == nil else {
                    throw SessionExportError.untimedPacketIDNotRepresentable
                }
                // A fresh section's interface-zero snap length is the captured
                // length, so SPB represents truncated packets without inventing time.
                var simple = Data()
                append32(UInt32(event.reference.originalLength), to: &simple)
                simple.append(contentsOf: event.bytes)
                if event.reference.hasPacketOptions {
                    omittedFrameOptions += 1
                }
                try sink.write(block(type: 0x00000003, body: simple))
            }
            writtenFrames += 1
        }

        private func readOptions(_ range: Range<UInt64>, from handle: FileHandle) throws -> Data {
            try handle.seek(toOffset: range.lowerBound)
            let data = try handle.read(upToCount: range.count) ?? Data()
            guard data.count == range.count else {
                throw FrameExportError.identityMismatch
            }
            return data
        }

        private mutating func beginSection(
            properties: CaptureFileProperties,
            sourceSectionIndex: Int,
            includesCaptureNotes: Bool = true,
            containsTransformedFrames: Bool = false,
            into sink: inout OutputSink
        )
            throws
        {
            activeSourceSection = sourceSectionIndex
            if properties.sections.contains(where: { $0.id == sourceSectionIndex }) {
                writtenSourceSections.insert(sourceSectionIndex)
            }
            interfaces.removeAll(keepingCapacity: true)
            hasTransformedFramesInSection = containsTransformedFrames
            try sink.write(sectionHeader(properties: properties, includesCaptureNotes: includesCaptureNotes))
            captureNotesWritten = captureNotesWritten || includesCaptureNotes
            if let names = nameResolutionBlock() {
                try sink.write(names)
            }
            wroteHeader = true
        }

        private mutating func sectionHeader(properties: CaptureFileProperties, includesCaptureNotes: Bool) -> Data {
            var body = Data()
            append32(0x1A2B3C4D, to: &body)
            append16(1, to: &body)
            append16(0, to: &body)
            append64(UInt64.max, to: &body)
            var options = Data()
            if preservesMetadata, let section = properties.sections.first(where: { $0.id == activeSourceSection }) {
                let shouldCountOmissions = countedSectionMetadata.insert(section.id).inserted
                if shouldCountOmissions {
                    omittedSectionOptions += section.comments.omittedCount
                }
                for comment in section.comments.values {
                    if !appendTextOption(code: 1, comment, to: &options), shouldCountOmissions {
                        omittedSectionOptions += 1
                    }
                }
                if let hardware = section.hardware,
                   !appendTextOption(code: 2, hardware, to: &options), shouldCountOmissions
                {
                    omittedSectionOptions += 1
                }
                if let os = section.operatingSystem,
                   !appendTextOption(code: 3, os, to: &options), shouldCountOmissions
                {
                    omittedSectionOptions += 1
                }
                if let application = section.application,
                   !appendTextOption(code: 4, application, to: &options), shouldCountOmissions
                {
                    omittedSectionOptions += 1
                }
            }
            if includesCaptureNotes, !captureNotesWritten {
                for comment in captureComments.prefix(FrameExportOptions.maximumCaptureComments) {
                    let kept = Self.boundedComment(comment)
                    if !kept.isEmpty {
                        appendOption(code: 1, value: Array(kept.utf8), to: &options)
                    }
                }
            }
            if !options.isEmpty {
                append16(0, to: &options)
                append16(0, to: &options)
                body.append(options)
            }
            return block(type: 0x0A0D0D0A, body: body)
        }

        private mutating func interfaceDescription(
            id _: UInt32,
            linkType: UInt32,
            source: CaptureInterface?,
            snapLengthOverride: UInt32? = nil,
            preservesSourceFCS: Bool,
            sourceInterfaceID: CaptureInterface.ID
        )
            throws -> Data
        {
            guard linkType <= UInt32(UInt16.max) else {
                throw SessionExportError.unsupportedLinkType
            }
            var body = Data()
            append16(UInt16(linkType), to: &body)
            append16(0, to: &body)
            append32(snapLengthOverride ?? source?.snapLength ?? PcapWriter.snapLength, to: &body)
            var options = Data()
            if preservesMetadata, let source {
                for comment in source.comments.values {
                    if !appendTextOption(code: 1, comment, to: &options) {
                        omittedInterfaceOptions += 1
                    }
                }
                if let name = source.name,
                   !appendTextOption(code: 2, name, to: &options)
                {
                    omittedInterfaceOptions += 1
                }
                if let description = source.interfaceDescription,
                   !appendTextOption(code: 3, description, to: &options)
                {
                    omittedInterfaceOptions += 1
                }
                if let speed = source.speedBitsPerSecond {
                    append16(8, to: &options)
                    append16(8, to: &options)
                    append64(speed, to: &options)
                }
                if let filter = source.filter {
                    if filter.isTruncated || filter.isLossy {
                        omittedInterfaceOptions += 1
                    } else {
                        let value = [source.filterKind ?? 0] + Array(filter.text.utf8)
                        appendOption(code: 11, value: value, to: &options)
                    }
                }
                if let os = source.operatingSystem,
                   !appendTextOption(code: 12, os, to: &options)
                {
                    omittedInterfaceOptions += 1
                }
                if let fcs = source.fcsLength {
                    if preservesSourceFCS {
                        appendOption(code: 13, value: [fcs], to: &options)
                    } else if omittedFCSInterfaces.insert(sourceInterfaceID).inserted {
                        omittedInterfaceOptions += 1
                    }
                }
                if let hardware = source.hardware, !appendTextOption(code: 15, hardware, to: &options) {
                    omittedInterfaceOptions += 1
                }
            }
            // Timestamps are always re-encoded at microsecond resolution, the
            // default when `if_tsresol` is absent, so no resolution option is written.
            if !options.isEmpty {
                append16(0, to: &options)
                append16(0, to: &options)
                body.append(options)
            }
            return block(type: 0x00000001, body: body)
        }

        @discardableResult
        private func appendTextOption(code: UInt16, _ text: CaptureBoundedText, to data: inout Data) -> Bool {
            guard !text.isTruncated, !text.isLossy else {
                return false
            }
            appendOption(code: code, value: Array(text.text.utf8), to: &data)
            return true
        }

        private func appendOption(code: UInt16, value: [UInt8], to data: inout Data) {
            append16(code, to: &data)
            append16(UInt16(clamping: value.count), to: &data)
            data.append(contentsOf: value)
            while data.count % 4 != 0 {
                data.append(0)
            }
        }

        /// A Name Resolution Block (type 4): one IPv4 (1) or IPv6 (2) record per
        /// address and name, then the end record. `nil` when there is nothing to name.
        private mutating func nameResolutionBlock() -> Data? {
            var body = Data()
            var count = 0
            for record in nameRecords.prefix(FrameExportOptions.maximumNameRecords) {
                let name = Array(record.name.utf8.prefix(255))
                guard !name.isEmpty, !name.contains(0) else {
                    continue
                }
                var v4 = in_addr()
                var v6 = in6_addr()
                let type: UInt16
                var value: [UInt8]
                if record.address.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
                    type = 1
                    value = withUnsafeBytes(of: &v4) { Array($0) }
                } else if record.address.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
                    type = 2
                    value = withUnsafeBytes(of: &v6) { Array($0) }
                } else {
                    continue
                }
                value += name + [0]
                append16(type, to: &body)
                append16(UInt16(value.count), to: &body)
                body.append(contentsOf: value)
                while body.count % 4 != 0 {
                    body.append(0)
                }
                count += 1
            }
            guard count > 0 else {
                return nil
            }
            append32(0, to: &body) // nrb_record_end
            writtenNames = count
            return block(type: 4, body: body)
        }

        private func block(type: UInt32, body: Data) -> Data {
            var padded = body
            while padded.count % 4 != 0 {
                padded.append(0)
            }
            let total = UInt32(12 + padded.count)
            var out = Data(capacity: Int(total))
            append32(type, to: &out)
            append32(total, to: &out)
            out.append(padded)
            append32(total, to: &out)
            return out
        }
    }

    /// A file sink that optionally deflates into a gzip member on the way out.
    private struct OutputSink {
        // MARK: Lifecycle

        init(url: URL, gzip: Bool) throws {
            handle = try FileHandle(forWritingTo: url)
            deflater = gzip ? try GzipDeflater() : nil
        }

        // MARK: Internal

        mutating func write(_ data: Data) throws {
            guard let deflater else {
                try handle.write(contentsOf: data)
                written += UInt64(data.count)
                return
            }
            try deflater.compress(data, finish: false) { chunk in
                try handle.write(contentsOf: chunk)
                written += UInt64(chunk.count)
            }
        }

        mutating func finish() throws -> UInt64 {
            if let deflater {
                try deflater.compress(Data(), finish: true) { chunk in
                    try handle.write(contentsOf: chunk)
                    written += UInt64(chunk.count)
                }
                deflater.end()
            }
            try handle.synchronize()
            try handle.close()
            return written
        }

        func abort() throws {
            deflater?.end()
            try handle.close()
        }

        // MARK: Private

        private let handle: FileHandle
        private let deflater: GzipDeflater?
        private var written: UInt64 = 0
    }

    /// One zlib deflate stream producing a gzip member. Pointers are set only
    /// inside the `withUnsafe…` scopes that own them, exactly as the inflate side does.
    private final class GzipDeflater {
        // MARK: Lifecycle

        init() throws {
            let status = deflateInit2_(
                &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY,
                ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)
            )
            guard status == Z_OK else {
                throw FrameExportError.compression("deflateInit2 returned \(status)")
            }
            active = true
        }

        deinit {
            end()
        }

        // MARK: Internal

        func compress(_ input: Data, finish: Bool, emit: (Data) throws -> Void) throws {
            var bytes = [UInt8](input)
            if bytes.isEmpty {
                bytes = [0]
            }
            let inputCount = input.count
            var offset = 0
            var done = false
            while !done {
                var produced = 0
                var status: Int32 = Z_OK
                try bytes.withUnsafeMutableBufferPointer { source in
                    try buffer.withUnsafeMutableBufferPointer { destination in
                        guard let sourceBase = source.baseAddress, let destinationBase = destination.baseAddress else {
                            throw FrameExportError.compression("buffer")
                        }
                        stream.next_in = sourceBase + offset
                        stream.avail_in = UInt32(inputCount - offset)
                        stream.next_out = destinationBase
                        stream.avail_out = UInt32(destination.count)
                        status = zlib.deflate(&stream, finish ? Z_FINISH : Z_NO_FLUSH)
                        produced = destination.count - Int(stream.avail_out)
                        offset = inputCount - Int(stream.avail_in)
                        stream.next_in = nil
                        stream.next_out = nil
                    }
                }
                guard status == Z_OK || status == Z_STREAM_END || status == Z_BUF_ERROR else {
                    throw FrameExportError.compression("deflate returned \(status)")
                }
                if produced > 0 {
                    try emit(Data(buffer[0 ..< produced]))
                }
                done = finish ? status == Z_STREAM_END : (offset >= inputCount && produced < buffer.count)
            }
        }

        func end() {
            if active {
                deflateEnd(&stream)
                active = false
            }
        }

        // MARK: Private

        private var stream = z_stream()
        private var active = false
        private var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
    }

    private static func summary(
        scanned: Int,
        state: WriterState,
        writtenBytes: UInt64,
        completeness: CaptureLoadCompleteness,
        unanonymized: Int,
        unstripped: Int,
        duplicates: Int,
        truncated: Int,
        anonymizer: AddressAnonymizer?,
        unknownExpressionFrameCount: Int
    )
        -> FrameExportSummary
    {
        FrameExportSummary(
            scannedFrameCount: scanned,
            writtenFrameCount: state.writtenFrames,
            writtenByteCount: writtenBytes,
            unrepresentableFrameCount: state.unrepresentableFrames,
            omittedFrameOptionCount: state.omittedFrameOptions,
            omittedInterfaceOptionCount: state.omittedInterfaceOptions,
            omittedSectionOptionCount: state.omittedSectionOptions,
            sourceMetadataInventoryTruncated: state.sourceMetadataInventoryTruncated,
            completeness: completeness,
            unanonymizedFrameCount: unanonymized,
            unstrippedFrameCount: unstripped,
            removedDuplicateCount: duplicates,
            truncatedFrameCount: truncated,
            excludedIgnoredFrameCount: state.excludedIgnoredFrameCount,
            writtenNameCount: state.writtenNames,
            replacedAddressCount: anonymizer.map {
                $0.replacedMACCount + $0.replacedIPv4Count + $0.replacedIPv6Count
            } ?? 0,
            unknownExpressionFrameCount: unknownExpressionFrameCount
        )
    }

    private static func finishMetadataAccounting(
        state: inout WriterState,
        properties: CaptureFileProperties,
        options: FrameExportOptions,
        scope: FrameExportScope
    ) {
        guard options.format == .pcapng, state.preservesMetadata else {
            return
        }
        if case .wholeCapture = scope {
            state.omittedSectionOptions += CaptureMetadataExportAccounting.omittedSectionMetadata(
                properties, excluding: state.writtenSourceSections
            )
        }
        state.sourceMetadataInventoryTruncated = CaptureMetadataExportAccounting.hasInventoryOverflow(properties)
    }

    private static func writerState(
        options: FrameExportOptions, timeCorrection: CaptureFrameTimeCorrection
    )
        -> WriterState
    {
        WriterState(
            format: options.format,
            preservesMetadata: options.preservesMetadata && !options.anonymizesAddresses,
            captureComments: timeCorrection.captureComments(
                from: options.captureComments,
                anonymizingAddresses: options.anonymizesAddresses
            ),
            nameRecords: options.anonymizesAddresses ? [] : options.nameRecords
        )
    }

    private static func validatedReader(
        from source: URL,
        expectedIdentity: PcapFileIdentity?,
        isCancelled: @escaping @Sendable () -> Bool
    )
        throws -> CaptureStreamReader
    {
        let reader = try CaptureStreamReader(contentsOf: source, configuration: .init(isCancelled: isCancelled))
        guard expectedIdentity.map({ reader.identity.matches($0) }) ?? true else {
            throw FrameExportError.identityMismatch
        }
        return reader
    }

    private static func validatedOptionSource(from source: URL, identity: PcapFileIdentity) throws -> FileHandle {
        let handle = try FileHandle(forReadingFrom: source)
        guard PcapFileIdentity.snapshot(of: handle).matches(identity) else {
            try? handle.close()
            throw FrameExportError.identityMismatch
        }
        return handle
    }

    private static func finishExport(
        source: URL,
        optionSource: FileHandle,
        identity: PcapFileIdentity,
        destination: URL,
        temporary: URL,
        sink: inout OutputSink,
        state: WriterState,
        scope: FrameExportScope,
        unknownExpressionFrameCount: Int,
        isCancelled: @Sendable () -> Bool
    )
        throws -> UInt64
    {
        if isCancelled() {
            throw CancellationError()
        }
        guard PcapFileIdentity.snapshot(of: optionSource).matches(identity) else {
            throw FrameExportError.identityMismatch
        }
        // Recheck identity even when the chosen scope writes no frames; report a
        // changing source instead of misattributing a stale empty result.
        let recheck = try FileHandle(forReadingFrom: source)
        let stillSame = PcapFileIdentity.snapshot(of: recheck).matches(identity)
        try recheck.close()
        guard stillSame else {
            throw FrameExportError.identityMismatch
        }
        guard state.writtenFrames > 0 else {
            if state.excludedIgnoredFrameCount > 0 {
                throw FrameExportError.ignoredFramesExcludedAll(count: state.excludedIgnoredFrameCount)
            }
            if case .frameExpression = scope, unknownExpressionFrameCount > 0 {
                throw FrameExportError.expressionExportNoFrames(unknownCount: unknownExpressionFrameCount)
            }
            throw FrameExportError.nothingMatched
        }
        if isCancelled() {
            throw CancellationError()
        }
        let written = try sink.finish()
        if isCancelled() {
            throw CancellationError()
        }
        if FileManager.default.fileExists(atPath: destination.path) {
            _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
        } else {
            try FileManager.default.moveItem(at: temporary, to: destination)
        }
        return written
    }

    private static func completeness(for reason: CaptureStreamTermination) -> CaptureLoadCompleteness {
        switch reason {
        case .cleanEndOfFile: .complete
        case .partialHeader,
             .partialBody: .incompleteTruncatedTail(reason)
        }
    }

    /// The frames of `ids`'s sessions, by capture-order number, with every fragment
    /// of a datagram that completed into one of them.
    private static func sessionOrdinals(
        _ ids: Set<UUID>,
        in source: URL,
        isCancelled: @escaping @Sendable () -> Bool
    )
        throws -> Set<UInt64>
    {
        let reader = try CaptureStreamReader(contentsOf: source, configuration: .init(isCancelled: isCancelled))
        var sequential = SequentialFrameDecoder()
        var ordinals = Set<UInt64>()
        var ordinal: UInt64 = 0
        while case let .frame(event) = try reader.next() {
            ordinal += 1
            let frame = CapturedFrame(
                bytes: event.bytes,
                timestamp: event.reference.timestamp,
                originalLength: event.reference.originalLength,
                capturedLength: event.reference.capturedLength,
                linkType: event.reference.linkType
            )
            let packet = sequential.decode(frame, linkType: event.reference.linkType, ordinal: ordinal)
            guard let tuple = packet.fiveTuple, ids.contains(SessionBuilder.sessionID(for: tuple)) else {
                continue
            }
            let sources = sequential.lastReassembledFrom.map(\.ordinal.rawValue)
            ordinals.formUnion(sources.isEmpty ? [ordinal] : sources)
        }
        return ordinals
    }
}

// MARK: - FrameExportScopeEvaluator

private struct FrameExportScopeEvaluator {
    // MARK: Lifecycle

    init(scope: FrameExportScope, needsSessionNotes: Bool) {
        self.scope = scope
        let usesFrameExpression = if case .frameExpression = scope {
            true
        } else {
            false
        }
        let needsDecode = needsSessionNotes || usesFrameExpression
        decoder = needsDecode ? SequentialFrameDecoder() : nil
    }

    // MARK: Internal

    let scope: FrameExportScope
    var unknownExpressionFrameCount = 0

    mutating func decode(_ event: CaptureFrameEvent, ordinal: Int) -> DecodedPacket? {
        guard decoder != nil else {
            return nil
        }
        let frame = CapturedFrame(
            bytes: event.bytes,
            timestamp: event.reference.timestamp,
            originalLength: event.reference.originalLength,
            capturedLength: event.reference.capturedLength,
            linkType: event.reference.linkType
        )
        return decoder?.decode(frame, linkType: event.reference.linkType, ordinal: UInt64(ordinal))
    }

    mutating func decision(
        _ event: CaptureFrameEvent,
        ordinal: Int,
        packet: DecodedPacket?,
        excluded: Bool
    )
        -> FrameExportScopeDecision
    {
        switch evaluate(event, ordinal: ordinal, packet: packet) {
        case .match:
            return excluded ? .excludedMatch : .include
        case .noMatch:
            return .skip
        case .unknown:
            unknownExpressionFrameCount += 1
            return .skip
        }
    }

    // MARK: Private

    private var decoder: SequentialFrameDecoder?

    private func evaluate(
        _ event: CaptureFrameEvent,
        ordinal: Int,
        packet: DecodedPacket?
    )
        -> FrameExportScopeEvaluation
    {
        switch scope {
        case .wholeCapture:
            return .match
        case let .frames(ordinals):
            return ordinals.contains(UInt64(ordinal)) ? .match : .noMatch
        case let .timeRange(start, end):
            guard let timestamp = event.reference.timestamp else {
                return .noMatch
            }
            return timestamp >= start && timestamp <= end ? .match : .noMatch
        case let .frameExpression(expression):
            switch expression.evaluate(packet.map {
                FrameFilterFacts(
                    packet: $0,
                    capturedLength: event.reference.capturedLength,
                    originalLength: event.reference.originalLength,
                    captureDirection: event.reference.direction
                )
            }) {
            case .yes:
                return .match
            case .no:
                return .noMatch
            case .unknown:
                return .unknown
            }
        case .sessions:
            // Session scopes are resolved to frame numbers before writing.
            preconditionFailure("A session scope is resolved to frames before writing.")
        }
    }
}

// MARK: - FrameExportScopeEvaluation

private enum FrameExportScopeEvaluation: Equatable {
    case match
    case noMatch
    case unknown
}

// MARK: - FrameExportScopeDecision

private enum FrameExportScopeDecision: Equatable {
    case include
    case skip
    case excludedMatch
}

private func append16(_ value: UInt16, to data: inout Data) {
    var little = value.littleEndian
    withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
}

private func append32(_ value: UInt32, to data: inout Data) {
    var little = value.littleEndian
    withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
}

private func append64(_ value: UInt64, to data: inout Data) {
    var little = value.littleEndian
    withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
}
