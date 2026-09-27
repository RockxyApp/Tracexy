import Foundation

// MARK: - SMBObjectReader

/// Reconstructs only complete files whose clear SMB2-family READ/WRITE traffic is
/// fully present in one bounded TCP stream. The decoder is deliberately separate
/// from per-frame SMB header recognition: it consumes validated session-framed
/// records and never searches payload bytes for a new header after an error.
nonisolated enum SMBObjectReader {
    // MARK: Internal

    static let maximumFileBytes = 16 << 20
    static let maximumAggregateBytes = 32 << 20
    static let maximumOpenFiles = 32
    static let maximumPendingRequests = 512
    static let maximumFilenameBytes = 2_048
    static let maximumCitationsPerObject = 512

    static func objects(
        of result: FollowStreamResult,
        sessionID: UUID,
        maxObjects: Int = 2_000,
        maxAggregateBytes: Int = maximumAggregateBytes,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        -> [CaptureObject]
    {
        guard maxObjects > 0, maxAggregateBytes > 0,
              result.completeness == .complete,
              result.limitations.subtracting(.outOfOrder).isEmpty,
              let clientDirection = clientDirection(for: result.tuple) else
        {
            return []
        }
        let clientSnapshot = clientDirection == .aToB ? result.aToB : result.bToA
        let serverSnapshot = clientDirection == .aToB ? result.bToA : result.aToB
        guard let clientRun = oneRun(clientSnapshot), let serverRun = oneRun(serverSnapshot),
              let clientPDUs = pdus(in: clientRun, snapshot: clientSnapshot),
              let serverPDUs = pdus(in: serverRun, snapshot: serverSnapshot) else
        {
            return []
        }

        let events = (clientPDUs.map { Event(pdu: $0, direction: .client) }
            + serverPDUs.map { Event(pdu: $0, direction: .server) })
            .sorted {
                if $0.pdu.firstOrdinal != $1.pdu.firstOrdinal {
                    return $0.pdu.firstOrdinal < $1.pdu.firstOrdinal
                }
                if $0.direction != $1.direction {
                    return $0.direction == .client
                }
                return $0.pdu.streamOffset < $1.pdu.streamOffset
            }

        var outstanding: [RequestKey: Request] = [:]
        var files: [FileKey: FileState] = [:]
        var totalAllocated = 0
        for event in events {
            if isCancelled() {
                return []
            }
            guard let header = Header(event.pdu.bytes) else {
                return []
            }
            // Compounds require related-operation FileId/TreeId substitution and
            // compound response semantics. This slice rejects the whole flow.
            guard header.nextCommand == 0 else {
                return []
            }
            if header.isResponse {
                guard event.direction == .server else {
                    return []
                }
                if header.status == statusPending || header.isAsync {
                    let pendingKeys = outstanding.keys.filter {
                        $0.messageID == header.messageID && $0.sessionID == header.sessionID
                            && $0.command == header.command
                    }
                    for pendingKey in pendingKeys {
                        guard let request = outstanding.removeValue(forKey: pendingKey) else {
                            continue
                        }
                        invalidate(request.fileKey, in: &files)
                    }
                    continue
                }
                let key = RequestKey(
                    messageID: header.messageID, sessionID: header.sessionID,
                    treeID: header.treeID, command: header.command
                )
                guard let request = outstanding.removeValue(forKey: key) else {
                    continue
                }
                guard header.status == statusSuccess || header.status == statusEndOfFile else {
                    invalidate(request.fileKey, in: &files)
                    continue
                }
                guard apply(
                    response: event.pdu, header: header, to: request,
                    files: &files, totalAllocated: &totalAllocated,
                    aggregateLimit: min(maxAggregateBytes, maximumAggregateBytes)
                ) else {
                    invalidate(request.fileKey, in: &files)
                    continue
                }
            } else {
                guard event.direction == .client else {
                    // Server-initiated lease/oplock notifications do not open a
                    // client file and have no export request to pair.
                    continue
                }
                guard outstanding.count < maximumPendingRequests,
                      let request = Request(
                          pdu: event.pdu, header: header,
                          isClientDirection: event.direction == .client
                      ) else
                {
                    return []
                }
                let key = RequestKey(
                    messageID: header.messageID, sessionID: header.sessionID,
                    treeID: header.treeID, command: header.command
                )
                guard outstanding[key] == nil else {
                    invalidate(request.fileKey, in: &files)
                    continue
                }
                if request.kind == .create {
                    guard files.count < maximumOpenFiles else {
                        return []
                    }
                }
                outstanding[key] = request
            }
        }

        var output: [CaptureObject] = []
        var totalOutput = 0
        for state in files.values {
            guard output.count < maxObjects, state.isUsable,
                  let name = state.fileName, let eof = state.finalEOF,
                  eof >= 0, eof <= state.bytes.count,
                  state.coverage.count >= eof,
                  state.coverage[..<eof].allSatisfy({ $0 }),
                  state.citationsComplete, state.citations.count <= maximumCitationsPerObject,
                  totalOutput <= maxAggregateBytes - eof else
            {
                continue
            }
            let citations = state.citations.sorted { $0.ordinal < $1.ordinal }
            guard !citations.isEmpty else {
                continue
            }
            totalOutput += eof
            output.append(CaptureObject(
                id: "\(sessionID.uuidString)-smb-\(state.key.description)",
                sessionID: sessionID,
                frameOrdinal: citations.first?.ordinal.rawValue,
                host: result.tuple.b.port == 445 || result.tuple.b.port == 139
                    ? result.tuple.b.ip : result.tuple.a.ip,
                contentType: "SMB file",
                fileName: name,
                body: Array(state.bytes.prefix(eof)),
                contributingFrames: citations
            ))
        }
        return output.sorted { ($0.frameOrdinal ?? .max, $0.id) < ($1.frameOrdinal ?? .max, $1.id) }
    }

    // MARK: Private

    private enum Direction: Equatable {
        case client
        case server
    }

    private enum RequestKind: Equatable {
        case create
        case read
        case write
        case close
        case ignored
    }

    private struct Event {
        let pdu: PDU
        let direction: Direction
    }

    private struct PDU {
        let bytes: [UInt8]
        let firstOrdinal: UInt64
        let streamOffset: Int
        let citations: [SessionFrameProvenance]
    }

    private struct Header {
        // MARK: Lifecycle

        init?(_ bytes: [UInt8]) {
            guard bytes.count >= 64,
                  Array(bytes[0 ..< 4]) == [0xFE, 0x53, 0x4D, 0x42],
                  u16(bytes, 4) == 64,
                  let command = u16(bytes, 12), let flags = u32(bytes, 16),
                  let next = u32(bytes, 20), let message = u64(bytes, 24),
                  let session = u64(bytes, 40), let status = u32(bytes, 8) else
            {
                return nil
            }
            self.command = command
            messageID = message
            sessionID = session
            isResponse = flags & 1 != 0
            isAsync = flags & 2 != 0
            nextCommand = next
            self.status = status
            treeID = isAsync ? 0 : (u32(bytes, 36) ?? 0)
        }

        // MARK: Internal

        let command: UInt16
        let messageID: UInt64
        let sessionID: UInt64
        let treeID: UInt32
        let status: UInt32
        let isResponse: Bool
        let isAsync: Bool
        let nextCommand: UInt32
    }

    private struct RequestKey: Hashable {
        let messageID: UInt64
        let sessionID: UInt64
        let treeID: UInt32
        let command: UInt16
    }

    private struct FileKey: Hashable, CustomStringConvertible {
        let sessionID: UInt64
        let treeID: UInt32
        let fileID: [UInt8]

        var description: String {
            "\(sessionID)-\(treeID)-\(fileID.map { String(format: "%02x", $0) }.joined())"
        }

        static func make(session: UInt64, tree: UInt32, file: [UInt8]) -> Self? {
            guard file.count == 16, file != Array(repeating: 0xFF, count: 16) else {
                return nil
            }
            return Self(sessionID: session, treeID: tree, fileID: file)
        }
    }

    private struct Request {
        // MARK: Lifecycle

        init?(pdu: PDU, header: Header, isClientDirection: Bool) {
            guard isClientDirection else {
                return nil
            }
            let body = pdu.bytes
            key = RequestKey(
                messageID: header.messageID, sessionID: header.sessionID,
                treeID: header.treeID, command: header.command
            )
            citations = pdu.citations
            switch header.command {
            case 5: // CREATE
                guard body.count >= 112, u16(body, 64) == 57,
                      let nameOffset = u16(body, 108), let nameLength = u16(body, 110),
                      let contextOffset = u32(body, 112), let contextLength = u32(body, 116),
                      nameLength > 0, nameOffset >= 120, nameOffset % 8 == 0,
                      nameLength <= maximumFilenameBytes, nameLength % 2 == 0,
                      contextLength == 0,
                      nameLength == 0 || range(offset: Int(nameOffset), length: Int(nameLength), in: body) != nil,
                      contextLength == 0, contextOffset == 0 else
                {
                    return nil
                }
                kind = .create
                guard let options = u32(body, 104), options & 0x00002000 == 0,
                      options & 0x00000001 == 0,
                      let range = range(offset: Int(nameOffset), length: Int(nameLength), in: body),
                      let decoded = String(data: Data(body[range]), encoding: .utf16LittleEndian),
                      let safeName = safeRelativeName(decoded),
                      !decoded.split(whereSeparator: { $0 == "/" || $0 == "\\" })
                      .contains(where: { $0.caseInsensitiveCompare("pipe") == .orderedSame }) else
                {
                    return nil
                }
                name = safeName
            case 8: // READ
                guard body.count >= 112, u16(body, 64) == 49,
                      let length = u32(body, 68), let offset = u64(body, 72),
                      let file = slice(body, 80, 16), let fileOffset = checkedInt(offset),
                      let channel = u32(body, 100), channel == 0,
                      let remaining = u32(body, 104), remaining == 0,
                      let channelOffset = u16(body, 108), channelOffset == 0,
                      let channelLength = u16(body, 110), channelLength == 0,
                      Int(length) <= maximumFileBytes,
                      let key = FileKey.make(session: header.sessionID, tree: header.treeID, file: file) else
                {
                    return nil
                }
                kind = .read
                fileKey = key
                self.offset = fileOffset
                self.length = Int(length)
            case 9: // WRITE
                guard body.count >= 112, u16(body, 64) == 49,
                      let dataOffset = u16(body, 66), dataOffset >= 112,
                      let length = u32(body, 68),
                      let offset = u64(body, 72), let file = slice(body, 80, 16),
                      let fileOffset = checkedInt(offset), Int(length) <= maximumFileBytes,
                      let channel = u32(body, 96), channel == 0,
                      let remaining = u32(body, 100), remaining == 0,
                      let channelOffset = u16(body, 104), channelOffset == 0,
                      let channelLength = u16(body, 106), channelLength == 0,
                      let flags = u32(body, 108), flags & ~UInt32(0x3) == 0,
                      let dataRange = range(offset: Int(dataOffset), length: Int(length), in: body),
                      let key = FileKey.make(session: header.sessionID, tree: header.treeID, file: file) else
                {
                    return nil
                }
                kind = .write
                fileKey = key
                self.offset = fileOffset
                self.length = Int(length)
                data = Array(body[dataRange])
            case 6: // CLOSE
                guard body.count >= 88, u16(body, 64) == 24,
                      let flags = u16(body, 66), let file = slice(body, 72, 16),
                      let key = FileKey.make(session: header.sessionID, tree: header.treeID, file: file) else
                {
                    return nil
                }
                kind = .close
                fileKey = key
                closePostQuery = flags & 1 != 0
            default:
                kind = .ignored
            }
        }

        // MARK: Internal

        var kind: RequestKind = .ignored
        let key: RequestKey
        var fileKey: FileKey?
        var name: String?
        var offset = 0
        var length = 0
        var data: [UInt8] = []
        var closePostQuery = false
        let citations: [SessionFrameProvenance]
    }

    private struct FileState {
        let key: FileKey
        var fileName: String?
        var bytes: [UInt8] = []
        var coverage: [Bool] = []
        var citations = Set<SessionFrameProvenance>()
        var citationsComplete = true
        var isUsable = true
        var closed = false
        var closeEOF: Int?
        var readEOF: Int?

        var finalEOF: Int? {
            closeEOF ?? readEOF
        }

        mutating func addCitations(_ new: [SessionFrameProvenance]) {
            for citation in new {
                citations.insert(citation)
                if citations.count > maximumCitationsPerObject {
                    citationsComplete = false
                    return
                }
            }
        }
    }

    private static let statusSuccess: UInt32 = 0
    private static let statusPending: UInt32 = 0x00000103
    private static let statusEndOfFile: UInt32 = 0xC0000011

    private static func apply(
        response pdu: PDU,
        header: Header,
        to request: Request,
        files: inout [FileKey: FileState],
        totalAllocated: inout Int,
        aggregateLimit: Int
    )
        -> Bool
    {
        switch request.kind {
        case .ignored:
            return true
        case .create:
            guard header.status == statusSuccess,
                  pdu.bytes.count >= 152, u16(pdu.bytes, 64) == 89,
                  let fileID = slice(pdu.bytes, 128, 16),
                  let attributes = u32(pdu.bytes, 120), attributes & 0x10 == 0,
                  let contextOffset = u32(pdu.bytes, 144), contextOffset == 0,
                  let contextLength = u32(pdu.bytes, 148), contextLength == 0,
                  let name = request.name,
                  let key = FileKey.make(session: header.sessionID, tree: header.treeID, file: fileID) else
            {
                return false
            }
            if files[key] != nil {
                files[key]?.isUsable = false
                return false
            }
            var state = FileState(key: key, fileName: name)
            state.addCitations(request.citations + pdu.citations)
            files[key] = state
            return true
        case .read:
            guard let key = request.fileKey, var state = files[key], state.isUsable, !state.closed else {
                return false
            }
            if header.status == statusEndOfFile {
                guard pdu.bytes.count == 72, u16(pdu.bytes, 64) == 9,
                      pdu.bytes[66] == 0, pdu.bytes[67] == 0,
                      u32(pdu.bytes, 68) == 0 else
                {
                    return false
                }
                state.readEOF = request.offset
                state.addCitations(request.citations + pdu.citations)
                files[key] = state
                return true
            }
            guard header.status == statusSuccess, pdu.bytes.count >= 80,
                  u16(pdu.bytes, 64) == 17, pdu.bytes[66] >= 80,
                  let length = u32(pdu.bytes, 68), let rdmaFlags = u32(pdu.bytes, 76),
                  rdmaFlags == 0, Int(length) <= request.length,
                  let dataRemaining = u32(pdu.bytes, 72), dataRemaining == 0,
                  let span = range(offset: Int(pdu.bytes[66]), length: Int(length), in: pdu.bytes),
                  put(
                      Array(pdu.bytes[span]),
                      at: request.offset,
                      in: &state,
                      totalAllocated: &totalAllocated,
                      aggregateLimit: aggregateLimit
                  ) else
            {
                return false
            }
            state.readEOF = nil
            state.addCitations(request.citations + pdu.citations)
            files[key] = state
            return true
        case .write:
            guard header.status == statusSuccess, let key = request.fileKey,
                  var state = files[key], state.isUsable, !state.closed,
                  pdu.bytes.count >= 80, u16(pdu.bytes, 64) == 17,
                  let remaining = u32(pdu.bytes, 72), remaining == 0,
                  let channelOffset = u16(pdu.bytes, 76), channelOffset == 0,
                  let channelLength = u16(pdu.bytes, 78), channelLength == 0,
                  let count = u32(pdu.bytes, 68), Int(count) <= request.data.count,
                  put(
                      Array(request.data.prefix(Int(count))),
                      at: request.offset,
                      in: &state,
                      totalAllocated: &totalAllocated,
                      aggregateLimit: aggregateLimit
                  ) else
            {
                return false
            }
            state.readEOF = nil
            state.addCitations(request.citations + pdu.citations)
            files[key] = state
            return true
        case .close:
            guard let key = request.fileKey, var state = files[key], state.isUsable,
                  pdu.bytes.count >= 120, u16(pdu.bytes, 64) == 60,
                  let responseFlags = u16(pdu.bytes, 66), let eof = u64(pdu.bytes, 112),
                  let size = checkedInt(eof) else
            {
                return false
            }
            state.closed = true
            if request.closePostQuery, responseFlags & 1 != 0 {
                state.closeEOF = size
            }
            state.addCitations(request.citations + pdu.citations)
            files[key] = state
            return true
        }
    }

    private static func put(
        _ incoming: [UInt8],
        at offset: Int,
        in state: inout FileState,
        totalAllocated: inout Int,
        aggregateLimit: Int
    )
        -> Bool
    {
        guard offset >= 0, incoming.count <= maximumFileBytes,
              offset <= maximumFileBytes - incoming.count else
        {
            return false
        }
        let end = offset + incoming.count
        guard end <= state.bytes.count || end <= maximumFileBytes else {
            return false
        }
        if end > state.bytes.count {
            let growth = end - state.bytes.count
            guard growth <= aggregateLimit / 2,
                  totalAllocated <= aggregateLimit - growth * 2 else
            {
                return false
            }
            state.bytes.append(contentsOf: repeatElement(0, count: growth))
            state.coverage.append(contentsOf: repeatElement(false, count: growth))
            totalAllocated += growth * 2
        }
        for (index, byte) in incoming.enumerated() {
            let destination = offset + index
            if state.coverage[destination], state.bytes[destination] != byte {
                return false
            }
            state.bytes[destination] = byte
            state.coverage[destination] = true
        }
        return true
    }

    private static func invalidate(_ key: FileKey?, in files: inout [FileKey: FileState]) {
        guard let key else {
            return
        }
        files[key]?.isUsable = false
    }

    private static func clientDirection(for tuple: FiveTuple) -> ConnectionDirection? {
        let aIsService = tuple.a.port == 445 || tuple.a.port == 139
        let bIsService = tuple.b.port == 445 || tuple.b.port == 139
        guard aIsService != bIsService else {
            return nil
        }
        return aIsService ? .bToA : .aToB
    }

    private static func oneRun(_ snapshot: FollowStreamDirectionSnapshot) -> FollowStreamRun? {
        guard snapshot.runs.count == 1 else {
            return nil
        }
        return snapshot.runs[0]
    }

    private static func pdus(in run: FollowStreamRun, snapshot: FollowStreamDirectionSnapshot) -> [PDU]? {
        var result: [PDU] = []
        var offset = 0
        while offset < run.bytes.count {
            guard offset <= run.bytes.count - 4,
                  run.bytes[offset] == 0,
                  let length = u24(run.bytes, offset + 1), length >= 64,
                  length <= run.bytes.count - offset - 4 else
            {
                return nil
            }
            let start = offset + 4
            let end = start + length
            guard let header = slice(run.bytes, start, 4),
                  header == [0xFE, 0x53, 0x4D, 0x42] else
            {
                return nil
            }
            let pduRange = start ..< end
            guard let citations = citations(
                for: pduRange, run: run, snapshot: snapshot
            ), let first = citations.first else {
                return nil
            }
            let bytes = Array(run.bytes[pduRange])
            guard let parsed = Header(bytes), parsed.nextCommand == 0 else {
                return nil
            }
            result.append(PDU(
                bytes: bytes, firstOrdinal: citations.map(\.ordinal.rawValue).min() ?? first.ordinal.rawValue,
                streamOffset: start, citations: citations
            ))
            offset = end
        }
        return result
    }

    private static func citations(
        for range: Range<Int>, run: FollowStreamRun, snapshot: FollowStreamDirectionSnapshot
    )
        -> [SessionFrameProvenance]?
    {
        guard let anchor = snapshot.anchorSequence else {
            return nil
        }
        let runOffset = Int64(Int32(bitPattern: run.sequenceAnchor &- anchor))
        let start = runOffset + Int64(range.lowerBound)
        let end = runOffset + Int64(range.upperBound)
        if let dropped = snapshot.segmentMarksDroppedFrom, dropped < end {
            return nil
        }
        guard let first = snapshot.firstFrame(ofByte: range.lowerBound, in: run), first.locator != nil else {
            return nil
        }
        var seen = Set<UInt64>()
        var found = [first]
        seen.insert(first.ordinal.rawValue)
        for mark in snapshot.segmentMarks where mark.offset > start && mark.offset < end {
            guard mark.provenance.locator != nil else {
                return nil
            }
            if seen.insert(mark.provenance.ordinal.rawValue).inserted {
                found.append(mark.provenance)
            }
            if found.count > maximumCitationsPerObject {
                return nil
            }
        }
        return found.sorted { $0.ordinal < $1.ordinal }
    }

    private static func safeRelativeName(_ raw: String) -> String? {
        guard !raw.isEmpty, raw.utf8.count <= maximumFilenameBytes,
              !raw.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else
        {
            return nil
        }
        let components = raw.split(whereSeparator: { $0 == "/" || $0 == "\\" })
        guard let last = components.last,
              !components.contains(where: { $0 == "." || $0 == ".." }) else
        {
            return nil
        }
        return String(last)
    }

    private static func checkedInt(_ value: UInt64) -> Int? {
        value <= UInt64(Int.max) ? Int(value) : nil
    }

    private static func range(offset: Int, length: Int, in bytes: [UInt8]) -> Range<Int>? {
        guard offset >= 0, length >= 0, offset <= bytes.count, length <= bytes.count - offset else {
            return nil
        }
        return offset ..< offset + length
    }

    private static func slice(_ bytes: [UInt8], _ offset: Int, _ length: Int) -> [UInt8]? {
        guard let range = range(offset: offset, length: length, in: bytes) else {
            return nil
        }
        return Array(bytes[range])
    }

    private static func u16(_ bytes: [UInt8], _ offset: Int) -> UInt16? {
        guard let range = range(offset: offset, length: 2, in: bytes) else {
            return nil
        }
        return UInt16(bytes[range.lowerBound]) | UInt16(bytes[range.lowerBound + 1]) << 8
    }

    private static func u24(_ bytes: [UInt8], _ offset: Int) -> Int? {
        guard let range = range(offset: offset, length: 3, in: bytes) else {
            return nil
        }
        return Int(bytes[range.lowerBound]) << 16 | Int(bytes[range.lowerBound + 1]) << 8
            | Int(bytes[range.lowerBound + 2])
    }

    private static func u32(_ bytes: [UInt8], _ offset: Int) -> UInt32? {
        guard let range = range(offset: offset, length: 4, in: bytes) else {
            return nil
        }
        return UInt32(bytes[range.lowerBound]) | UInt32(bytes[range.lowerBound + 1]) << 8
            | UInt32(bytes[range.lowerBound + 2]) << 16 | UInt32(bytes[range.lowerBound + 3]) << 24
    }

    private static func u64(_ bytes: [UInt8], _ offset: Int) -> UInt64? {
        guard let range = range(offset: offset, length: 8, in: bytes) else {
            return nil
        }
        return bytes[range].reversed().reduce(0) { $0 << 8 | UInt64($1) }
    }
}
