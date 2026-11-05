import Foundation

// MARK: - CaptureFrameCommentReadResult

nonisolated struct CaptureFrameCommentReadResult: Sendable, Equatable {
    let comments: [CaptureBoundedText]
    let omittedCount: Int
}

// MARK: - CaptureFrameCommentReadOutcome

nonisolated enum CaptureFrameCommentReadOutcome: Sendable, Equatable {
    case comments(CaptureFrameCommentReadResult)
    case unavailable
    case superseded
}

// MARK: - CaptureFrameCommentReader

/// Reads only the selected pcapng packet's option list after validating the
/// source identity. Comment text is not retained in capture rows or History.
nonisolated enum CaptureFrameCommentReader {
    static let maximumOptionBytes = 1_048_576

    static func read(
        _ reference: CaptureFrameCommentReference,
        from url: URL,
        expectedIdentity: PcapFileIdentity,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> CaptureFrameCommentReadResult
    {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        let identity = PcapFileIdentity.snapshot(of: handle)
        guard identity.matches(expectedIdentity) else {
            throw FollowStreamError.identityMismatch
        }
        let range = reference.optionsRange
        guard range.lowerBound <= range.upperBound,
              range.upperBound <= identity.size,
              range.upperBound - range.lowerBound <= UInt64(maximumOptionBytes) else
        {
            throw PacketError.malformed("pcapng: selected packet options exceed the read limit")
        }

        var cursor = range.lowerBound
        var comments = CaptureBoundedTextList.empty
        while cursor <= range.upperBound, range.upperBound - cursor >= 4 {
            try Task.checkCancellation()
            guard !isCancelled() else {
                throw CancellationError()
            }
            try handle.seek(toOffset: cursor)
            guard let header = try handle.read(upToCount: 4), header.count == 4 else {
                throw PacketError.malformed("pcapng: truncated selected packet option header")
            }
            let bytes = [UInt8](header)
            let code = reference.littleEndian
                ? UInt16(bytes[0]) | (UInt16(bytes[1]) << 8)
                : (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
            let length = reference.littleEndian
                ? UInt16(bytes[2]) | (UInt16(bytes[3]) << 8)
                : (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
            cursor += 4
            if code == 0 {
                guard length == 0 else {
                    throw PacketError.malformed("pcapng: invalid selected packet end-of-options")
                }
                break
            }
            let paddedLength = (UInt64(length) + 3) & ~UInt64(3)
            let (valueEnd, overflow) = cursor.addingReportingOverflow(paddedLength)
            guard !overflow, valueEnd <= range.upperBound else {
                throw PacketError.malformed("pcapng: selected packet option overruns its block")
            }
            if code == 1 {
                let retainedLength = min(Int(length), CaptureBoundedText.maxBytes)
                let value = try handle.read(upToCount: retainedLength) ?? Data()
                guard value.count == retainedLength else {
                    throw PacketError.malformed("pcapng: truncated selected packet comment")
                }
                comments.append(CaptureBoundedText(bytes: [UInt8](value), declaredLength: Int(length)))
            }
            cursor = valueEnd
        }

        let finalIdentity = PcapFileIdentity.snapshot(of: handle)
        guard finalIdentity.matches(expectedIdentity) else {
            throw FollowStreamError.identityMismatch
        }
        return CaptureFrameCommentReadResult(comments: comments.values, omittedCount: comments.omittedCount)
    }
}
