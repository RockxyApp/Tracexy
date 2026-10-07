import Foundation

// MARK: - CaptureMergeSummary

nonisolated struct CaptureMergeSummary: Sendable, Equatable {
    /// Frames written from each source, in the order the sources were given.
    let framesPerSource: [Int]
    let writtenFrameCount: Int
    let writtenByteCount: UInt64
    /// Sources whose tail was cut mid-record; every complete frame before the cut
    /// was merged.
    let truncatedSources: [String]
    /// Frame comments in the sources that the merged file does not carry.
    let omittedFrameCommentCount: Int
}

// MARK: - CaptureMergeError

nonisolated enum CaptureMergeError: LocalizedError, Equatable {
    case needsTwoSources
    case destinationIsASource
    case untimedFrame(source: String)
    case sourceChanged(source: String)
    case unsupportedLinkType(source: String)
    case nothingToMerge

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case .needsTwoSources:
            "Choose at least two capture files to merge."
        case .destinationIsASource:
            "The merged file can’t replace one of the captures being merged. Choose another name."
        case let .untimedFrame(source):
            "“\(source)” has frames without a capture time, so they can’t be placed in time order."
        case let .sourceChanged(source):
            "“\(source)” changed on disk while merging. Merge again."
        case let .unsupportedLinkType(source):
            "“\(source)” uses a link type PCAPNG can’t record."
        case .nothingToMerge:
            "The chosen captures hold no frames, so no file was written."
        }
    }
}

// MARK: - CaptureMerger

/// Merges several capture files into one PCAPNG in capture-time order, the job
/// `mergecap` does: a client-side and a server-side capture of the same problem
/// become one timeline.
///
/// Every source is streamed once through ``CaptureStreamReader`` and merged with
/// one frame per source held at a time. Each source interface becomes its own
/// output interface described by the source file's name, so every merged frame
/// still says which file it came from. Frames with equal times keep the order the
/// sources were given. A frame without a capture time cannot be placed and stops
/// the merge; nothing is guessed. The output is written to a temporary sibling and
/// moved into place only after every source is verified unchanged.
nonisolated enum CaptureMerger {
    // MARK: Internal

    static func merge(
        sources: [URL],
        to destination: URL,
        onProgress: (Int) -> Void = { _ in },
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> CaptureMergeSummary
    {
        guard sources.count >= 2 else {
            throw CaptureMergeError.needsTwoSources
        }
        let destinationPath = destination.standardizedFileURL.resolvingSymlinksInPath().path
        guard !sources.contains(where: { $0.standardizedFileURL.resolvingSymlinksInPath().path == destinationPath }) else {
            throw CaptureMergeError.destinationIsASource
        }
        let names = sources.map(\.lastPathComponent)
        var readers: [CaptureStreamReader] = []
        for source in sources {
            try readers.append(CaptureStreamReader(contentsOf: source, configuration: .init(isCancelled: isCancelled)))
        }

        let temporary = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).partial")
        FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let handle = try FileHandle(forWritingTo: temporary)
        var published = false
        defer {
            try? handle.close()
            if !published {
                try? FileManager.default.removeItem(at: temporary)
            }
        }

        var written: UInt64 = 0
        func emit(_ data: Data) throws {
            try handle.write(contentsOf: data)
            written += UInt64(data.count)
        }
        try emit(sectionHeader(names: names))

        var interfaces: [InterfaceKey: UInt32] = [:]
        var heads: [CaptureFrameEvent?] = []
        var truncated: [String] = []
        var framesPerSource = Array(repeating: 0, count: sources.count)
        var omittedComments = 0
        for (index, reader) in readers.enumerated() {
            try heads.append(pull(reader, name: names[index], truncated: &truncated))
        }

        var total = 0
        while true {
            var chosen: Int?
            for (index, head) in heads.enumerated() {
                guard let head else {
                    continue
                }
                guard let time = head.reference.timestamp else {
                    throw CaptureMergeError.untimedFrame(source: names[index])
                }
                if let current = chosen, let currentTime = heads[current]?.reference.timestamp, currentTime <= time {
                    continue
                }
                chosen = index
            }
            guard let index = chosen, let event = heads[index], let time = event.reference.timestamp else {
                break
            }
            if isCancelled() {
                throw CancellationError()
            }
            let key = InterfaceKey(
                source: index, section: event.reference.sectionIndex, interface: event.reference.interfaceID
            )
            let interfaceID: UInt32
            if let existing = interfaces[key] {
                interfaceID = existing
            } else {
                guard event.reference.linkType <= UInt32(UInt16.max) else {
                    throw CaptureMergeError.unsupportedLinkType(source: names[index])
                }
                interfaceID = UInt32(interfaces.count)
                interfaces[key] = interfaceID
                let section = readers[index].fileProperties.sections.first { $0.id == key.section }
                let sourceInterface = section?.interfaces.first { $0.id.interfaceID == key.interface }
                var interfaceName: String?
                if let name = sourceInterface?.name, !name.isTruncated, !name.isLossy {
                    interfaceName = name.text
                }
                try emit(PcapngBlockWriter.interfaceDescription(
                    linkType: event.reference.linkType,
                    name: interfaceName,
                    fileName: names[index]
                ))
            }
            try emit(PcapngBlockWriter.enhancedPacket(event, interfaceID: interfaceID, time: time))
            if event.reference.hasComment {
                omittedComments += 1
            }
            framesPerSource[index] += 1
            total += 1
            if total % 1_024 == 0 {
                onProgress(total)
            }
            heads[index] = try pull(readers[index], name: names[index], truncated: &truncated)
        }
        guard total > 0 else {
            throw CaptureMergeError.nothingToMerge
        }
        for (index, source) in sources.enumerated() {
            let check = try FileHandle(forReadingFrom: source)
            let same = PcapFileIdentity.snapshot(of: check).matches(readers[index].identity)
            try check.close()
            guard same else {
                throw CaptureMergeError.sourceChanged(source: names[index])
            }
        }
        try handle.synchronize()
        try handle.close()
        if FileManager.default.fileExists(atPath: destination.path) {
            _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
        } else {
            try FileManager.default.moveItem(at: temporary, to: destination)
        }
        published = true
        onProgress(total)
        return CaptureMergeSummary(
            framesPerSource: framesPerSource,
            writtenFrameCount: total,
            writtenByteCount: written,
            truncatedSources: truncated,
            omittedFrameCommentCount: omittedComments
        )
    }

    // MARK: Private

    private struct InterfaceKey: Hashable {
        let source: Int
        let section: Int
        let interface: Int
    }

    private static func pull(
        _ reader: CaptureStreamReader,
        name: String,
        truncated: inout [String]
    )
        throws -> CaptureFrameEvent?
    {
        switch try reader.next() {
        case let .frame(event):
            return event
        case let .end(completion):
            if completion.reason != .cleanEndOfFile, !truncated.contains(name) {
                truncated.append(name)
            }
            return nil
        }
    }

    private static func sectionHeader(names: [String]) -> Data {
        // An option length is 16 bits; a long list of files is named by count instead.
        let list = ListFormatter.localizedString(byJoining: names)
        var comment = "Merged by Tracexy in capture-time order from \(list)."
        if comment.utf8.count > 4_096 {
            comment = "Merged by Tracexy in capture-time order from \(names.count.formatted()) files."
        }
        return PcapngBlockWriter.sectionHeader(comment: comment)
    }
}
