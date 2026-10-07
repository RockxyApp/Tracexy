import Foundation

// MARK: - CaptureSplitOptions

nonisolated struct CaptureSplitOptions: Sendable, Equatable {
    enum Boundary: Sendable, Equatable {
        /// Start a new file after this many frames.
        case frames(Int)
        /// Start a new file once a frame is this many seconds after the first frame
        /// of the current file.
        case seconds(TimeInterval)
    }

    var boundary: Boundary
    /// Added to every frame's capture time, as `editcap -t` does. Zero keeps times.
    var timeShift: TimeInterval = 0
}

// MARK: - CaptureSplitSummary

nonisolated struct CaptureSplitSummary: Sendable, Equatable {
    /// The written files in order; together they are one file set.
    let files: [URL]
    let frameCount: Int
    /// The source ended mid-record; every complete frame before the cut was written.
    let sourceTruncated: Bool
    /// Frame comments in the source that the split files do not carry.
    let omittedFrameCommentCount: Int
}

// MARK: - CaptureSplitError

nonisolated enum CaptureSplitError: LocalizedError, Equatable {
    case invalidBoundary
    case untimedFrame
    case unsupportedLinkType
    case nothingToSplit
    case tooManyFiles(limit: Int)
    case fileExists(String)
    case sourceChanged

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case .invalidBoundary:
            "Choose a positive number of frames or seconds per file."
        case .untimedFrame:
            "This capture has frames without a capture time, which a split file can’t record."
        case .unsupportedLinkType:
            "This capture uses a link type PCAPNG can’t record."
        case .nothingToSplit:
            "The capture holds no frames, so no file was written."
        case let .tooManyFiles(limit):
            "That would write more than \(limit.formatted()) files. Choose a larger size per file."
        case let .fileExists(name):
            "“\(name)” already exists in that folder. Choose another name."
        case .sourceChanged:
            "The capture changed on disk while splitting. Split again."
        }
    }
}

// MARK: - CaptureSplitter

/// Splits one capture into a file set, the job `editcap -c` / `-i` does: every file
/// is a PCAPNG named `<prefix>_<NNNNN>_<YYYYMMDDHHMMSS>.pcapng` — the ring-buffer
/// naming ``CaptureFileSet`` already navigates — stamped with its first frame's
/// (shifted) local time. Frames stream through once; each file carries only the
/// interfaces its own frames use. Every file is written under a hidden temporary
/// name and all are published together only after the source is verified
/// unchanged, so a failure or cancellation leaves no partial set behind. Existing
/// files are never replaced.
nonisolated enum CaptureSplitter {
    // MARK: Internal

    static let maximumFiles = CaptureFileSet.maxMembers

    static func split(
        source: URL,
        into directory: URL,
        prefix: String,
        options: CaptureSplitOptions,
        timeZone: TimeZone = .current,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> CaptureSplitSummary
    {
        switch options.boundary {
        case let .frames(count) where count > 0: break
        case let .seconds(seconds) where seconds > 0 && seconds.isFinite: break
        default: throw CaptureSplitError.invalidBoundary
        }
        let reader = try CaptureStreamReader(contentsOf: source, configuration: .init(isCancelled: isCancelled))
        let sourceName = source.lastPathComponent
        var partials: [(partial: URL, final: URL)] = []
        var published = false
        defer {
            if !published {
                for entry in partials {
                    try? FileManager.default.removeItem(at: entry.partial)
                }
            }
        }

        var handle: FileHandle?
        var interfaces: [InterfaceKey: UInt32] = [:]
        var fileStart: Date?
        var framesInFile = 0
        var total = 0
        var truncated = false
        var omittedComments = 0

        /// `time` is the frame's own capture time; the file is named for it shifted.
        func startFile(at time: Date) throws {
            try handle?.close()
            guard partials.count < maximumFiles else {
                throw CaptureSplitError.tooManyFiles(limit: maximumFiles)
            }
            let name = fileName(
                prefix: prefix, sequence: partials.count + 1, time: time.addingTimeInterval(options.timeShift),
                timeZone: timeZone
            )
            let final = directory.appendingPathComponent(name)
            guard !FileManager.default.fileExists(atPath: final.path) else {
                throw CaptureSplitError.fileExists(name)
            }
            let partial = directory.appendingPathComponent(".\(name).\(UUID().uuidString).partial")
            FileManager.default.createFile(atPath: partial.path, contents: nil, attributes: [.posixPermissions: 0o600])
            partials.append((partial, final))
            let next = try FileHandle(forWritingTo: partial)
            handle = next
            let shiftNote = options.timeShift == 0 ? "" : " with times shifted by \(options.timeShift.formatted()) s"
            try next.write(contentsOf: PcapngBlockWriter.sectionHeader(
                comment: "Split by Tracexy from \(sourceName), part \(partials.count)\(shiftNote)."
            ))
            interfaces = [:]
            fileStart = time
            framesInFile = 0
        }

        loop: while true {
            if isCancelled() {
                throw CancellationError()
            }
            let event: CaptureFrameEvent
            switch try reader.next() {
            case let .frame(next):
                event = next
            case let .end(completion):
                truncated = completion.reason != .cleanEndOfFile
                break loop
            }
            guard let time = event.reference.timestamp else {
                throw CaptureSplitError.untimedFrame
            }
            let needsFile: Bool = switch options.boundary {
            case let .frames(count): handle == nil || framesInFile >= count
            case let .seconds(seconds): handle == nil || time.timeIntervalSince(fileStart ?? time) >= seconds
            }
            if needsFile {
                try startFile(at: time)
            }
            guard let handle else {
                break loop
            }
            let key = InterfaceKey(section: event.reference.sectionIndex, interface: event.reference.interfaceID)
            let interfaceID: UInt32
            if let existing = interfaces[key] {
                interfaceID = existing
            } else {
                guard event.reference.linkType <= UInt32(UInt16.max) else {
                    throw CaptureSplitError.unsupportedLinkType
                }
                interfaceID = UInt32(interfaces.count)
                interfaces[key] = interfaceID
                let section = reader.fileProperties.sections.first { $0.id == key.section }
                let sourceInterface = section?.interfaces.first { $0.id.interfaceID == key.interface }
                var interfaceName: String?
                if let name = sourceInterface?.name, !name.isTruncated, !name.isLossy {
                    interfaceName = name.text
                }
                try handle.write(contentsOf: PcapngBlockWriter.interfaceDescription(
                    linkType: event.reference.linkType, name: interfaceName, fileName: sourceName
                ))
            }
            try handle.write(contentsOf: PcapngBlockWriter.enhancedPacket(
                event, interfaceID: interfaceID, time: time, shift: options.timeShift
            ))
            if event.reference.hasComment {
                omittedComments += 1
            }
            framesInFile += 1
            total += 1
        }
        guard total > 0 else {
            throw CaptureSplitError.nothingToSplit
        }
        try handle?.synchronize()
        try handle?.close()
        let check = try FileHandle(forReadingFrom: source)
        let same = PcapFileIdentity.snapshot(of: check).matches(reader.identity)
        try check.close()
        guard same else {
            throw CaptureSplitError.sourceChanged
        }
        for entry in partials {
            guard !FileManager.default.fileExists(atPath: entry.final.path) else {
                throw CaptureSplitError.fileExists(entry.final.lastPathComponent)
            }
        }
        var moved: [URL] = []
        do {
            for entry in partials {
                try FileManager.default.moveItem(at: entry.partial, to: entry.final)
                moved.append(entry.final)
            }
        } catch {
            for url in moved {
                try? FileManager.default.removeItem(at: url)
            }
            throw error
        }
        published = true
        return CaptureSplitSummary(
            files: partials.map(\.final),
            frameCount: total,
            sourceTruncated: truncated,
            omittedFrameCommentCount: omittedComments
        )
    }

    /// `<prefix>_<NNNNN>_<YYYYMMDDHHMMSS>.pcapng` in `timeZone`.
    static func fileName(prefix: String, sequence: Int, time: Date, timeZone: TimeZone) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let parts = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: time)
        let stamp = String(
            format: "%04d%02d%02d%02d%02d%02d",
            parts.year ?? 0, parts.month ?? 0, parts.day ?? 0, parts.hour ?? 0, parts.minute ?? 0, parts.second ?? 0
        )
        return "\(prefix)_\(String(format: "%05d", sequence % 100_000))_\(stamp).pcapng"
    }

    // MARK: Private

    private struct InterfaceKey: Hashable {
        let section: Int
        let interface: Int
    }
}
