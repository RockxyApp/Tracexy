import Foundation

// MARK: - FollowHTTP2StreamRow

/// One HTTP/2 stream as the Stream facet lists it. Plain values; the view lays
/// them out and owns no wording.
nonisolated struct FollowHTTP2StreamRow: Identifiable, Equatable, Sendable {
    let id: UInt32
    /// Method and path, e.g. `GET /index.html`, or what the stream carried instead.
    let request: String
    let authority: String?
    /// `200`, or what is known when there is no final response.
    let status: String
    let isError: Bool
    /// From the frame carrying the request head to the frame carrying the response head.
    let elapsed: String?
    /// Response DATA size, when there was any.
    let size: String?
    let requestHeaders: [HPACKHeader]
    let responseHeaders: [HPACKHeader]
    let requestFrame: SessionFrameProvenance?
    let responseFrame: SessionFrameProvenance?
}

// MARK: - FollowHTTP2FrameRow

/// One HTTP/2 frame in the order the capture carried it.
nonisolated struct FollowHTTP2FrameRow: Identifiable, Equatable, Sendable {
    let id: Int
    let fromClient: Bool
    let type: String
    let streamID: UInt32
    let length: Int
    let detail: String
    let frame: SessionFrameProvenance?
}

// MARK: - FollowHTTP2Presentation

/// The HTTP/2 streams and frames of a followed TCP stream, read by
/// ``HTTP2ConnectionReader`` from the leading run of each direction. `nil` for a
/// stream that does not open with the HTTP/2 connection preface.
nonisolated struct FollowHTTP2Presentation: Equatable, Sendable {
    // MARK: Lifecycle

    init?(result: FollowStreamResult) {
        let aRun = result.aToB.runs.first
        let bRun = result.bToA.runs.first
        guard let conversation = HTTP2ConnectionReader.read(aToB: aRun?.bytes ?? [], bToA: bRun?.bytes ?? []) else {
            return nil
        }
        let client = conversation.clientIsAToB ? result.aToB : result.bToA
        let server = conversation.clientIsAToB ? result.bToA : result.aToB
        let clientRun = conversation.clientIsAToB ? aRun : bRun
        let serverRun = conversation.clientIsAToB ? bRun : aRun
        func capturedFrame(fromClient: Bool, offset: Int) -> SessionFrameProvenance? {
            fromClient
                ? clientRun.flatMap { client.firstFrame(ofByte: offset, in: $0) }
                : serverRun.flatMap { server.firstFrame(ofByte: offset, in: $0) }
        }

        streams = conversation.streams.map { stream in
            // A pushed stream's request head arrives in the server's PUSH_PROMISE.
            let requestFrame = stream.requestOffset.flatMap {
                capturedFrame(fromClient: stream.promisedBy == nil, offset: $0)
            }
            let responseFrame = stream.responseOffset.flatMap { capturedFrame(fromClient: false, offset: $0) }
            return FollowHTTP2StreamRow(
                id: stream.id,
                request: Self.requestLabel(stream),
                authority: stream.authority,
                status: Self.statusLabel(stream),
                isError: stream.status.map { $0 >= 400 } ?? (stream.resetCode.map { $0 != 0 } ?? false),
                elapsed: Self.elapsed(from: requestFrame, to: responseFrame),
                size: stream.responseDataBytes > 0 ? ByteUnits.string(Int64(stream.responseDataBytes)) : nil,
                requestHeaders: stream.requestHeaders,
                responseHeaders: stream.responseHeaders,
                requestFrame: requestFrame,
                responseFrame: responseFrame
            )
        }

        let located = conversation.frames.map { frame in
            (frame, capturedFrame(fromClient: frame.fromClient, offset: frame.offset))
        }
        // Capture order where both frames are known; otherwise client before server.
        let ordered = located.enumerated().sorted { lhs, rhs in
            switch (lhs.element.1?.ordinal.rawValue, rhs.element.1?.ordinal.rawValue) {
            case let (left?, right?) where left != right: left < right
            default: lhs.offset < rhs.offset
            }
        }
        frameCount = ordered.count
        frames = ordered.prefix(Self.maximumListedFrames).enumerated().map { position, entry in
            let (frame, captured) = entry.element
            return FollowHTTP2FrameRow(
                id: position,
                fromClient: frame.fromClient,
                type: frame.typeName,
                streamID: frame.streamID,
                length: frame.length,
                detail: frame.detail,
                frame: captured
            )
        }
        clientIsAToB = conversation.clientIsAToB

        var notes: [String] = []
        if conversation.upgrade != nil {
            notes
                .append(
                    "The connection began as HTTP/1.1 and switched to HTTP/2 with Upgrade: h2c. Stream 1 is that first request."
                )
        }
        for (side, stop) in [("client", conversation.clientStop), ("server", conversation.serverStop)] {
            switch stop {
            case .frameLimit:
                notes.append("Only the first \(HTTP2ConnectionReader.maximumFrames) \(side) frames were read.")
            case .streamLimit:
                notes.append("Only the first \(HTTP2ConnectionReader.maximumStreams) streams are listed.")
            case .cutShort:
                notes.append("The retained \(side) bytes end inside a frame.")
            case .malformed:
                notes.append("A \(side) frame broke HTTP/2 framing, so reading that side stopped there.")
            case .headerCompression:
                notes
                    .append("A \(side) header block could not be decompressed, so later \(side) headers are not shown.")
            case nil:
                break
            }
        }
        if frameCount > Self.maximumListedFrames {
            notes.append("The first \(Self.maximumListedFrames) of \(frameCount.formatted()) frames are listed.")
        }
        if result.aToB.runs.count > 1 || result.bToA.runs.count > 1 {
            notes.append("Frames after a gap in the stream were not read.")
        }
        self.notes = notes
    }

    // MARK: Internal

    static let maximumListedFrames = 1_000

    let streams: [FollowHTTP2StreamRow]
    /// In capture order, at most ``maximumListedFrames``.
    let frames: [FollowHTTP2FrameRow]
    let frameCount: Int
    let clientIsAToB: Bool
    /// Why the lists may be shorter than the connection.
    let notes: [String]

    // MARK: Private

    private static func requestLabel(_ stream: HTTP2Stream) -> String {
        if let method = stream.method {
            let target = stream.path ?? stream.authority ?? ""
            return target.isEmpty ? method : "\(method) \(target)"
        }
        return "Stream \(stream.id)"
    }

    private static func statusLabel(_ stream: HTTP2Stream) -> String {
        if let status = stream.status {
            return stream.responseEnded || stream.resetCode != nil ? "\(status)" : "\(status), no end seen"
        }
        if let code = stream.resetCode {
            let who = stream.resetByClient ? "client" : "server"
            return "Reset by \(who), \(HTTP2ConnectionReader.errorName(code))"
        }
        return "No response"
    }

    private static func elapsed(from start: SessionFrameProvenance?, to end: SessionFrameProvenance?) -> String? {
        guard let begin = start?.timestamp, let finish = end?.timestamp else {
            return nil
        }
        let interval = finish.timeIntervalSince(begin)
        guard interval.isFinite, interval >= 0 else {
            return nil
        }
        return SessionResponseTimes.durationLabel(interval)
    }
}
