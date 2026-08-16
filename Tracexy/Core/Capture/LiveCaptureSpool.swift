import Foundation

/// Disk-backed, append-only pcapng spool for the current live capture.
///
/// The UI keeps only a bounded frame window in memory, while this actor preserves
/// every accepted frame for complete save/session export. All file IO is actor-
/// isolated and therefore stays off `@MainActor`. The spool is local, temporary,
/// and replaced only at an explicit capture boundary.
actor LiveCaptureSpool {
    // MARK: Lifecycle

    init(directoryName: String) {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        directory = base
            .appendingPathComponent(directoryName, isDirectory: true)
            .appendingPathComponent("LiveCaptureSpool", isDirectory: true)
    }

    deinit {
        try? handle?.close()
    }

    // MARK: Internal

    enum Failure: Error, LocalizedError {
        case unavailable(String)
        case empty

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case let .unavailable(message): message
            case .empty: "The live capture spool has no frames."
            }
        }
    }

    func reset(epoch: Int) throws {
        try handle?.close()
        handle = nil
        if let url {
            try? FileManager.default.removeItem(at: url)
        }
        self.epoch = epoch
        url = nil
        interfaceIDs.removeAll(keepingCapacity: false)
        frameCount = 0
        failure = nil
        do {
            try prepareFile()
        } catch {
            failure = error.localizedDescription
            throw error
        }
    }

    func append(_ frames: [CapturedFrame], defaultLinkType: UInt32, epoch: Int) throws {
        guard epoch == self.epoch, !frames.isEmpty else {
            return
        }
        guard failure == nil, let handle else {
            throw Failure.unavailable(failure ?? "The local capture spool is unavailable.")
        }
        do {
            for frame in frames {
                let linkType = frame.linkType ?? defaultLinkType
                let interfaceID: UInt32
                if let existing = interfaceIDs[linkType] {
                    interfaceID = existing
                } else {
                    guard linkType <= UInt32(UInt16.max) else {
                        throw Failure.unavailable("Capture link type \(linkType) cannot be written to pcapng.")
                    }
                    interfaceID = UInt32(interfaceIDs.count)
                    try handle.write(contentsOf: Self.interfaceDescriptionBlock(linkType: linkType))
                    interfaceIDs[linkType] = interfaceID
                }
                try handle.write(contentsOf: Self.enhancedPacketBlock(frame: frame, interfaceID: interfaceID))
                frameCount += 1
            }
        } catch {
            let message = error.localizedDescription
            failure = message
            throw Failure.unavailable(message)
        }
    }

    func capture() throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        guard frameCount > 0, let url else {
            throw Failure.empty
        }
        try handle?.synchronize()
        return try CaptureFileReader.read(contentsOf: url)
    }

    func copy(to destination: URL) throws {
        guard frameCount > 0, let url else {
            throw Failure.empty
        }
        try handle?.synchronize()
        try FileManager.default.copyItem(at: url, to: destination)
    }

    /// Non-nil means the file is a valid recoverable prefix, not a complete
    /// capture. Callers keep this warning visible after an explicit save/export.
    func incompletenessReason() -> String? {
        failure
    }

    // MARK: Private

    private let directory: URL
    private var epoch = -1
    private var url: URL?
    private var handle: FileHandle?
    private var interfaceIDs: [UInt32: UInt32] = [:]
    private var frameCount = 0
    private var failure: String?

    private static func sectionHeaderBlock() -> Data {
        block(type: 0x0A0D0D0A) { body in
            append32(0x1A2B3C4D, to: &body)
            append16(1, to: &body)
            append16(0, to: &body)
            append64(UInt64.max, to: &body)
        }
    }

    private static func interfaceDescriptionBlock(linkType: UInt32) -> Data {
        block(type: 0x00000001) { body in
            append16(UInt16(linkType), to: &body)
            append16(0, to: &body)
            append32(PcapWriter.snapLength, to: &body)
        }
    }

    private static func enhancedPacketBlock(frame: CapturedFrame, interfaceID: UInt32) -> Data {
        block(type: 0x00000006) { body in
            let microseconds = timestampMicroseconds(frame.timestamp)
            append32(interfaceID, to: &body)
            append32(UInt32(microseconds >> 32), to: &body)
            append32(UInt32(microseconds & UInt64(UInt32.max)), to: &body)
            append32(UInt32(frame.bytes.count), to: &body)
            append32(UInt32(max(frame.originalLength, frame.bytes.count)), to: &body)
            body.append(contentsOf: frame.bytes)
        }
    }

    private static func block(type: UInt32, body build: (inout Data) -> Void) -> Data {
        var body = Data()
        build(&body)
        while body.count % 4 != 0 {
            body.append(0)
        }
        var data = Data()
        let totalLength = UInt32(12 + body.count)
        append32(type, to: &data)
        append32(totalLength, to: &data)
        data.append(body)
        append32(totalLength, to: &data)
        return data
    }

    private static func timestampMicroseconds(_ date: Date) -> UInt64 {
        let interval = max(0, date.timeIntervalSince1970)
        return UInt64(min((interval * 1_000_000).rounded(), Double(UInt64.max)))
    }

    private static func append16(_ value: UInt16, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private static func append32(_ value: UInt32, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private static func append64(_ value: UInt64, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private func prepareFile() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let nextURL = directory.appendingPathComponent("capture-\(UUID().uuidString).pcapng")
        guard FileManager.default.createFile(atPath: nextURL.path, contents: nil) else {
            throw Failure.unavailable("Couldn’t create the local capture spool.")
        }
        let nextHandle = try FileHandle(forWritingTo: nextURL)
        try nextHandle.write(contentsOf: Self.sectionHeaderBlock())
        url = nextURL
        handle = nextHandle
    }
}
