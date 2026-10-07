import Foundation

// MARK: - FollowWebSocketMessageRow

/// One WebSocket message as the Stream facet lists it.
nonisolated struct FollowWebSocketMessageRow: Identifiable, Equatable, Sendable {
    let id: Int
    let fromClient: Bool
    /// Text, Binary, Close, Ping or Pong.
    let kind: String
    /// The text, a hex preview, or the close code and reason. At most one line.
    let content: String
    /// Size after inflating, or what is known.
    let size: String
    let isCompressed: Bool
    let frameCount: Int
    let frame: SessionFrameProvenance?
}

// MARK: - FollowWebSocketFrameRow

nonisolated struct FollowWebSocketFrameRow: Identifiable, Equatable, Sendable {
    let id: Int
    let fromClient: Bool
    let opcode: String
    let fin: Bool
    let compressed: Bool
    let masked: Bool
    let length: Int
    let frame: SessionFrameProvenance?
}

// MARK: - FollowWebSocketPresentation

/// The WebSocket messages and frames after an HTTP/1.1 upgrade on a followed TCP
/// stream, read by ``WebSocketReader``. `nil` for a stream that is not one.
nonisolated struct FollowWebSocketPresentation: Equatable, Sendable {
    // MARK: Lifecycle

    init?(result: FollowStreamResult) {
        let aRun = result.aToB.runs.first
        let bRun = result.bToA.runs.first
        guard let conversation = WebSocketReader.read(aToB: aRun?.bytes ?? [], bToA: bRun?.bytes ?? []) else {
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
        func captureOrder<T>(_ items: [(T, SessionFrameProvenance?)]) -> [(T, SessionFrameProvenance?)] {
            items.enumerated().sorted { lhs, rhs in
                switch (lhs.element.1?.ordinal.rawValue, rhs.element.1?.ordinal.rawValue) {
                case let (left?, right?) where left != right: left < right
                default: lhs.offset < rhs.offset
                }
            }.map(\.element)
        }

        let orderedMessages = captureOrder(conversation.messages.map {
            ($0, capturedFrame(fromClient: $0.fromClient, offset: $0.offset))
        })
        messageCount = orderedMessages.count
        messages = orderedMessages.prefix(Self.maximumListedRows).enumerated().map { position, entry in
            let (message, captured) = entry
            return FollowWebSocketMessageRow(
                id: position,
                fromClient: message.fromClient,
                kind: message.opcode.name,
                content: Self.content(message),
                size: Self.size(message),
                isCompressed: message.compressed,
                frameCount: message.frameCount,
                frame: captured
            )
        }
        let orderedFrames = captureOrder(conversation.frames.map {
            ($0, capturedFrame(fromClient: $0.fromClient, offset: $0.offset))
        })
        frameCount = orderedFrames.count
        frames = orderedFrames.prefix(Self.maximumListedRows).enumerated().map { position, entry in
            let (frame, captured) = entry
            return FollowWebSocketFrameRow(
                id: position, fromClient: frame.fromClient, opcode: frame.opcodeName, fin: frame.fin,
                compressed: frame.compressed, masked: frame.masked, length: frame.payloadLength, frame: captured
            )
        }
        isCompressed = conversation.deflate

        var notes: [String] = []
        for (side, stop) in [("client", conversation.clientStop), ("server", conversation.serverStop)] {
            switch stop {
            case .frameLimit:
                notes.append("Only the first \(WebSocketReader.maximumFrames) \(side) frames were read.")
            case .messageLimit:
                notes.append("Only the first \(WebSocketReader.maximumMessages) messages were read.")
            case .cutShort:
                notes.append("The retained \(side) bytes end inside a frame or a fragmented message.")
            case .malformed:
                notes.append("A \(side) frame broke WebSocket framing, so reading that side stopped there.")
            case nil:
                break
            }
        }
        if conversation.clientInflateFailed || conversation.serverInflateFailed {
            notes
                .append(
                    "A compressed message could not be decompressed; later compressed messages from that side are shown without their content."
                )
        }
        if messageCount > Self.maximumListedRows || frameCount > Self.maximumListedRows {
            notes.append("The first \(Self.maximumListedRows) messages and frames are listed.")
        }
        if result.aToB.runs.count > 1 || result.bToA.runs.count > 1 {
            notes.append("Frames after a gap in the stream were not read.")
        }
        self.notes = notes
    }

    // MARK: Internal

    static let maximumListedRows = 1_000
    static let previewCharacters = 200

    let messages: [FollowWebSocketMessageRow]
    let messageCount: Int
    let frames: [FollowWebSocketFrameRow]
    let frameCount: Int
    /// Whether permessage-deflate was accepted.
    let isCompressed: Bool
    let notes: [String]

    // MARK: Private

    private static func content(_ message: WebSocketMessage) -> String {
        switch message.opcode {
        case .close:
            guard let code = message.closeCode else {
                return "No status code"
            }
            let reason = message.closeReason.map { $0.isEmpty ? "" : " \($0)" } ?? ""
            let name = closeName(code)
            return "\(code)" + (name.isEmpty ? "" : " \(name)") + reason
        case .text:
            guard let payload = message.payload else {
                return "Not decompressed"
            }
            guard let text = message.text else {
                return "Not valid UTF-8: " + hexPreview(payload)
            }
            let line = text.replacingOccurrences(of: "\r\n", with: " ").replacingOccurrences(of: "\n", with: " ")
            return line.count > previewCharacters ? String(line.prefix(previewCharacters)) + "…" : line
        case .binary,
             .ping,
             .pong,
             .continuation:
            guard let payload = message.payload else {
                return "Not decompressed"
            }
            return payload.isEmpty ? "Empty" : hexPreview(payload)
        }
    }

    private static func size(_ message: WebSocketMessage) -> String {
        guard let size = message.size else {
            return "\(message.wireSize.formatted()) bytes on the wire"
        }
        return size == 1 ? "1 byte" : "\(size.formatted()) bytes"
    }

    private static func hexPreview(_ bytes: [UInt8]) -> String {
        let shown = bytes.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
        return bytes.count > 16 ? shown + " …" : shown
    }

    /// RFC 6455 §7.4.1 names for the registered close codes.
    private static func closeName(_ code: UInt16) -> String {
        switch code {
        case 1_000: "normal closure"
        case 1_001: "going away"
        case 1_002: "protocol error"
        case 1_003: "unsupported data"
        case 1_007: "invalid payload"
        case 1_008: "policy violation"
        case 1_009: "message too big"
        case 1_010: "extension required"
        case 1_011: "internal error"
        default: ""
        }
    }
}
