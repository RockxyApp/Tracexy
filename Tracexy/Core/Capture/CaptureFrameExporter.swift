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
    var format: FrameExportFormat = .pcapng
    /// Copy section hardware/OS/application/comments and interface names,
    /// descriptions, filters and per-frame options from a pcapng source.
    var preservesMetadata = true
    /// Wrap the output in a gzip stream (`.gz`).
    var compressesWithGzip = false
}

// MARK: - FrameExportSummary

nonisolated struct FrameExportSummary: Sendable, Equatable {
    let scannedFrameCount: Int
    let writtenFrameCount: Int
    let writtenByteCount: UInt64
    /// Frames the scope matched but the format could not represent (untimed
    /// frames for classic pcap). Non-zero is reported, never silent.
    let unrepresentableFrameCount: Int
    /// Per-frame option lists that could not be copied (big-endian source
    /// sections, oversized option lists, or a classic pcap target).
    let omittedFrameOptionCount: Int
    /// Interface options that could not be re-emitted (truncated strings).
    let omittedInterfaceOptionCount: Int
    let completeness: CaptureLoadCompleteness
}

// MARK: - FrameExportError

nonisolated enum FrameExportError: LocalizedError, Equatable {
    case mixedLinkTypesRequirePcapng
    case untimedFramesRequirePcapng
    case identityMismatch
    case nothingMatched
    case compression(String)

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case .mixedLinkTypesRequirePcapng:
            "The selected frames use more than one link type, which classic PCAP can’t represent. Choose PCAPNG."
        case .untimedFramesRequirePcapng:
            "Some selected frames carry no capture time, which classic PCAP can’t represent. Choose PCAPNG."
        case .identityMismatch:
            "The capture file changed on disk while exporting. Reload the capture and export again."
        case .nothingMatched:
            "No frames matched the selected scope, so no file was written."
        case let .compression(detail):
            "The gzip stream could not be written: \(detail)"
        }
    }
}

// MARK: - CaptureFrameExporter

/// Streams the frames of one stable capture that match a scope into a new
/// PCAPNG or classic PCAP file, optionally gzip-compressed. The source is read
/// once through ``CaptureStreamReader``; the output is written to a temporary
/// sibling and renamed into place only after the final identity check, so a
/// cancelled or failed export leaves no partial file behind.
///
/// Metadata preservation re-emits typed section/interface facts from the source's
/// ``CaptureFileProperties`` and copies each frame's option list verbatim when
/// the source section is little-endian (the only case where the bytes are valid
/// unchanged). Anything that cannot be carried is counted in the summary.
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
        let reader = try CaptureStreamReader(contentsOf: source, configuration: .init(isCancelled: isCancelled))
        if let expectedIdentity, !reader.identity.matches(expectedIdentity) {
            throw FrameExportError.identityMismatch
        }
        let optionSource = try FileHandle(forReadingFrom: source)
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

        var state = WriterState(format: options.format, preservesMetadata: options.preservesMetadata)
        var scanned = 0
        var completion: CaptureStreamCompletion?
        walk: while true {
            switch try reader.next() {
            case let .frame(event):
                scanned += 1
                if try matches(event, scope: scope) {
                    try state.write(
                        event, properties: reader.fileProperties, sourceFormat: reader.format,
                        optionSource: optionSource, into: &sink
                    )
                }
                if scanned % 256 == 0 {
                    onProgress(event.progress)
                }
            case let .end(end):
                completion = end
                break walk
            }
        }
        guard let completion else {
            throw FrameExportError.nothingMatched
        }
        guard state.writtenFrames > 0 else {
            throw FrameExportError.nothingMatched
        }
        // Identity is rechecked after the walk exactly as Follow Stream does.
        let recheck = try FileHandle(forReadingFrom: source)
        let stillSame = PcapFileIdentity.snapshot(of: recheck).matches(reader.identity)
        try recheck.close()
        guard stillSame else {
            throw FrameExportError.identityMismatch
        }
        let written = try sink.finish()
        if FileManager.default.fileExists(atPath: destination.path) {
            _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
        } else {
            try FileManager.default.moveItem(at: temporary, to: destination)
        }
        failed = false
        onProgress(completion.progress)
        let completeness: CaptureLoadCompleteness = switch completion.reason {
        case .cleanEndOfFile: .complete
        case .partialHeader,
             .partialBody: .incompleteTruncatedTail(completion.reason)
        }
        return FrameExportSummary(
            scannedFrameCount: scanned,
            writtenFrameCount: state.writtenFrames,
            writtenByteCount: written,
            unrepresentableFrameCount: state.unrepresentableFrames,
            omittedFrameOptionCount: state.omittedFrameOptions,
            omittedInterfaceOptionCount: state.omittedInterfaceOptions,
            completeness: completeness
        )
    }

    // MARK: Private

    /// Output interface bookkeeping keyed by the source (section, interface).
    private struct OutputInterface {
        let id: UInt32
        let linkType: UInt32
    }

    private struct WriterState {
        // MARK: Lifecycle

        init(format: FrameExportFormat, preservesMetadata: Bool) {
            self.format = format
            self.preservesMetadata = preservesMetadata
        }

        // MARK: Internal

        let format: FrameExportFormat
        let preservesMetadata: Bool
        var writtenFrames = 0
        var unrepresentableFrames = 0
        var omittedFrameOptions = 0
        var omittedInterfaceOptions = 0

        mutating func write(
            _ event: CaptureFrameEvent,
            properties: CaptureFileProperties,
            sourceFormat: CaptureStreamFormat,
            optionSource: FileHandle,
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
                    into: &sink
                )
            }
        }

        // MARK: Private

        private var wroteHeader = false
        private var classicLinkType: UInt32?
        private var interfaces: [CaptureInterface.ID: OutputInterface] = [:]

        private mutating func writeClassic(_ event: CaptureFrameEvent, into sink: inout OutputSink) throws {
            guard let timestamp = event.reference.timestamp else {
                unrepresentableFrames += 1
                throw FrameExportError.untimedFramesRequirePcapng
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
            into sink: inout OutputSink
        )
            throws
        {
            if !wroteHeader {
                try sink.write(sectionHeader(properties: properties))
                wroteHeader = true
            }
            let key = CaptureInterface.ID(
                sectionIndex: event.reference.sectionIndex,
                interfaceID: event.reference.interfaceID
            )
            let output: OutputInterface
            if let existing = interfaces[key] {
                output = existing
            } else {
                let source = properties.sections.first { $0.id == key.sectionIndex }?
                    .interfaces.first { $0.id == key }
                let id = UInt32(interfaces.count)
                try sink.write(interfaceDescription(id: id, linkType: event.reference.linkType, source: source))
                output = OutputInterface(id: id, linkType: event.reference.linkType)
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
                if preservesMetadata, sourceFormat == .pcapng {
                    if let range = event.reference.copyableOptionsRange,
                       range.count <= CaptureFrameExporter.maxCopiedOptionBytes,
                       let copied = try? readOptions(range, from: optionSource)
                    {
                        body.append(copied)
                    } else if event.reference.hasComment || (event.reference.copyableOptionsRange == nil
                        && sourceFormat == .pcapng && event.reference.hasComment)
                    {
                        omittedFrameOptions += 1
                    }
                } else if event.reference.hasComment {
                    omittedFrameOptions += 1
                }
                try sink.write(block(type: 0x00000006, body: body))
            } else {
                // Untimed source frames stay untimed: a Simple Packet Block on an
                // interface whose snap length is 0 (whole frame) — the same rule
                // `PcapngWriter` applies. Truncated untimed frames are rejected
                // rather than given an invented time.
                guard event.reference.capturedLength == event.reference.originalLength else {
                    unrepresentableFrames += 1
                    throw SessionExportError.untimedFrameNotRepresentable
                }
                var simple = Data()
                append32(UInt32(event.reference.originalLength), to: &simple)
                simple.append(contentsOf: event.bytes)
                if event.reference.hasComment {
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

        private func sectionHeader(properties: CaptureFileProperties) -> Data {
            var body = Data()
            append32(0x1A2B3C4D, to: &body)
            append16(1, to: &body)
            append16(0, to: &body)
            append64(UInt64.max, to: &body)
            var options = Data()
            if preservesMetadata, let section = properties.sections.first {
                for comment in section.comments.values {
                    appendTextOption(code: 1, comment, to: &options)
                }
                if let hardware = section.hardware {
                    appendTextOption(code: 2, hardware, to: &options)
                }
                if let os = section.operatingSystem {
                    appendTextOption(code: 3, os, to: &options)
                }
                if let application = section.application {
                    appendTextOption(code: 4, application, to: &options)
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
            source: CaptureInterface?
        )
            throws -> Data
        {
            guard linkType <= UInt32(UInt16.max) else {
                throw SessionExportError.unsupportedLinkType
            }
            var body = Data()
            append16(UInt16(linkType), to: &body)
            append16(0, to: &body)
            append32(source?.snapLength ?? PcapWriter.snapLength, to: &body)
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
                    appendOption(code: 13, value: [fcs], to: &options)
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

    private static func matches(_ event: CaptureFrameEvent, scope: FrameExportScope) throws -> Bool {
        switch scope {
        case .wholeCapture:
            return true
        case let .timeRange(start, end):
            guard let timestamp = event.reference.timestamp else {
                return false
            }
            return timestamp >= start && timestamp <= end
        case let .sessions(ids):
            let frame = CapturedFrame(
                bytes: event.bytes,
                timestamp: event.reference.timestamp,
                originalLength: event.reference.originalLength,
                capturedLength: event.reference.capturedLength,
                linkType: event.reference.linkType
            )
            let packet = SessionBuilder.decodePacket(frame, linkType: event.reference.linkType)
            guard let tuple = packet.fiveTuple else {
                return false
            }
            return ids.contains(SessionBuilder.sessionID(for: tuple))
        }
    }
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
