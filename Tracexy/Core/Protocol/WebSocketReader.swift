import Foundation

// MARK: - WebSocketOpcode

nonisolated enum WebSocketOpcode: UInt8, Hashable, Sendable {
    case continuation = 0x0
    case text = 0x1
    case binary = 0x2
    case close = 0x8
    case ping = 0x9
    case pong = 0xA

    // MARK: Internal

    var name: String {
        switch self {
        case .continuation: "Continuation"
        case .text: "Text"
        case .binary: "Binary"
        case .close: "Close"
        case .ping: "Ping"
        case .pong: "Pong"
        }
    }

    var isControl: Bool {
        rawValue >= 0x8
    }
}

// MARK: - WebSocketFrame

/// One WebSocket frame (RFC 6455 §5.2) read from a followed TCP stream.
nonisolated struct WebSocketFrame: Hashable, Sendable {
    let fromClient: Bool
    /// Offset of the frame's first byte within its direction's leading run.
    let offset: Int
    let fin: Bool
    /// RSV1: the frame starts a compressed message when permessage-deflate is in use.
    let compressed: Bool
    /// The raw opcode; ``WebSocketOpcode`` when it is a defined one.
    let opcode: UInt8
    let masked: Bool
    let payloadLength: Int

    var opcodeName: String {
        WebSocketOpcode(rawValue: opcode)?.name ?? "Reserved (0x\(String(opcode, radix: 16)))"
    }
}

// MARK: - WebSocketMessage

/// One WebSocket message: a data message reassembled from its fragments, or a
/// control frame. Payloads are unmasked and, for permessage-deflate, inflated.
nonisolated struct WebSocketMessage: Hashable, Sendable, Identifiable {
    let id: Int
    let fromClient: Bool
    let opcode: WebSocketOpcode
    /// Offset of the message's first frame within its direction's leading run.
    let offset: Int
    let frameCount: Int
    /// Size as carried on the wire (payload bytes of every frame).
    let wireSize: Int
    let compressed: Bool
    /// The message after unmasking and inflating; at most ``WebSocketReader/maximumMessageBytes``,
    /// `nil` when it could not be decompressed.
    let payload: [UInt8]?
    /// The payload size after inflating, when it was read to the end.
    let size: Int?
    let closeCode: UInt16?
    let closeReason: String?

    /// A text message's text, when it is valid UTF-8.
    var text: String? {
        guard opcode == .text, let payload else {
            return nil
        }
        return String(bytes: payload, encoding: .utf8)
    }
}

// MARK: - WebSocketConversation

nonisolated struct WebSocketConversation: Hashable, Sendable {
    enum Stop: Hashable, Sendable {
        case frameLimit
        case messageLimit
        /// The retained bytes end inside a frame.
        case cutShort
        /// A frame broke RFC 6455 framing (a fragmented or oversized control frame,
        /// a continuation with no message open, a reserved opcode, a 64-bit length
        /// with its top bit set), so nothing after it can be placed.
        case malformed
    }

    let clientIsAToB: Bool
    /// Where the WebSocket bytes begin in each direction's leading run.
    let clientStart: Int
    let serverStart: Int
    /// Whether the server accepted permessage-deflate.
    let deflate: Bool
    let frames: [WebSocketFrame]
    /// Client messages first, then server messages, each in byte order.
    let messages: [WebSocketMessage]
    let clientStop: Stop?
    let serverStop: Stop?
    /// A compressed message that failed to inflate; later compressed messages from
    /// that side depend on it and are not inflated.
    let clientInflateFailed: Bool
    let serverInflateFailed: Bool
}

// MARK: - WebSocketReader

/// Reads WebSocket frames and messages that follow an HTTP/1.1 `101 Switching
/// Protocols` upgrade to `websocket` on a followed TCP stream.
///
/// Bounded and fail-closed: at most ``maximumFrames`` frames per direction and
/// ``maximumMessages`` messages; a message is kept up to ``maximumMessageBytes``
/// (its full size is still counted). A direction stops at the first frame it
/// cannot place.
nonisolated enum WebSocketReader {
    // MARK: Internal

    static let maximumFrames = 50_000
    static let maximumMessages = 10_000
    static let maximumMessageBytes = 256 * 1_024

    /// `nil` unless the stream opens with an HTTP/1.1 request answered by a 101
    /// that upgrades it to WebSocket.
    static func read(aToB: [UInt8], bToA: [UInt8]) -> WebSocketConversation? {
        guard let conversation = HTTPExchangeReader.read(aToB: aToB, bToA: bToA),
              let upgrade = conversation.exchanges.last, upgrade.status == 101,
              let requestLength = upgrade.request.length,
              let response = upgrade.response, let responseLength = response.length else
        {
            return nil
        }
        let client = conversation.clientIsAToB ? aToB : bToA
        let server = conversation.clientIsAToB ? bToA : aToB
        let requestHead = headFields(client, from: upgrade.request.offset, to: upgrade.request.bodyOffset)
        let responseHead = headFields(server, from: response.offset, to: response.bodyOffset)
        guard (requestHead["upgrade"] ?? responseHead["upgrade"])?.lowercased().contains("websocket") == true else {
            return nil
        }
        let extensions = (responseHead["sec-websocket-extensions"] ?? "").lowercased()
        let deflate = extensions.contains("permessage-deflate")
        let clientStart = upgrade.request.offset + requestLength
        let serverStart = response.offset + responseLength
        let clientReading = readDirection(
            client, from: clientStart, fromClient: true,
            inflater: deflate ? Inflater(resetsEachMessage: extensions.contains("client_no_context_takeover")) : nil
        )
        let serverReading = readDirection(
            server, from: serverStart, fromClient: false,
            inflater: deflate ? Inflater(resetsEachMessage: extensions.contains("server_no_context_takeover")) : nil
        )
        // By where each message starts: a control frame between two fragments of a data
        // message is read first but comes after that message's start.
        var messages = clientReading.messages.sorted { $0.offset < $1.offset }
            + serverReading.messages.sorted { $0.offset < $1.offset }
        let overLimit = messages.count > maximumMessages
        messages = Array(messages.prefix(maximumMessages)).enumerated().map { index, message in
            message.renumbered(index)
        }
        return WebSocketConversation(
            clientIsAToB: conversation.clientIsAToB,
            clientStart: clientStart,
            serverStart: serverStart,
            deflate: deflate,
            frames: clientReading.frames + serverReading.frames,
            messages: messages,
            clientStop: clientReading.stop ?? (overLimit ? .messageLimit : nil),
            serverStop: serverReading.stop,
            clientInflateFailed: clientReading.inflateFailed,
            serverInflateFailed: serverReading.inflateFailed
        )
    }

    // MARK: Private

    private struct DirectionReading {
        var frames: [WebSocketFrame] = []
        var messages: [WebSocketMessage] = []
        var stop: WebSocketConversation.Stop?
        var inflateFailed = false
    }

    /// A data message being gathered across its fragments.
    private struct OpenMessage {
        let opcode: WebSocketOpcode
        let offset: Int
        let compressed: Bool
        var frameCount = 0
        var wireSize = 0
        var payload: [UInt8] = []
        var truncated = false
    }

    /// permessage-deflate (RFC 7692): raw DEFLATE whose context carries from one
    /// message to the next unless the peer asked for no context takeover.
    private final class Inflater {
        // MARK: Lifecycle

        init(resetsEachMessage: Bool) {
            self.resetsEachMessage = resetsEachMessage
        }

        // MARK: Internal

        var failed = false

        /// The inflated message, at most `limit` bytes, or `nil` once inflating has failed.
        func inflate(_ compressed: [UInt8], limit: Int) -> (bytes: [UInt8], complete: Bool)? {
            guard !failed else {
                return nil
            }
            do {
                if stream == nil || resetsEachMessage {
                    stream = try ZlibInflateStream(mode: .rawDeflate)
                }
                guard let stream else {
                    return nil
                }
                // §7.2.2: the sender removed this empty stored block's tail.
                let input = compressed + [0x00, 0x00, 0xFF, 0xFF]
                var output: [UInt8] = []
                var offset = 0
                var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
                while true {
                    let step = try stream.step(
                        input: input,
                        offset: offset,
                        available: input.count - offset,
                        into: &buffer
                    )
                    offset += step.consumed
                    output += buffer.prefix(step.produced)
                    if output.count > limit {
                        // The rest of this message is not needed, but the context
                        // must still see every byte for the next message.
                        output = Array(output.prefix(limit))
                        while offset < input.count {
                            let more = try stream.step(
                                input: input, offset: offset, available: input.count - offset, into: &buffer
                            )
                            offset += more.consumed
                            guard more.madeProgress else {
                                break
                            }
                        }
                        return (output, false)
                    }
                    if offset >= input.count, step.produced < buffer.count {
                        return (output, true)
                    }
                    guard step.madeProgress else {
                        failed = true
                        return nil
                    }
                }
            } catch {
                failed = true
                return nil
            }
        }

        // MARK: Private

        private let resetsEachMessage: Bool
        private var stream: ZlibInflateStream?
    }

    private struct FrameHeader {
        let fin: Bool
        let rsv1: Bool
        let opcode: UInt8
        let maskingKey: [UInt8]?
        let payloadLength: Int
        let payloadStart: Int
    }

    private static func readDirection(
        _ bytes: [UInt8],
        from start: Int,
        fromClient: Bool,
        inflater: Inflater?
    )
        -> DirectionReading
    {
        var reading = DirectionReading()
        var open: OpenMessage?
        var index = start
        while index < bytes.count {
            guard reading.frames.count < maximumFrames else {
                reading.stop = .frameLimit
                break
            }
            guard let header = frameHeader(bytes, at: index) else {
                reading.stop = .cutShort
                break
            }
            guard let opcode = WebSocketOpcode(rawValue: header.opcode),
                  header.payloadLength <= bytes.count - header.payloadStart else
            {
                reading.stop = WebSocketOpcode(rawValue: header.opcode) == nil ? .malformed : .cutShort
                break
            }
            // Control frames are never fragmented and carry at most 125 bytes (§5.5).
            if opcode.isControl, !header.fin || header.payloadLength > 125 {
                reading.stop = .malformed
                break
            }
            var payload = Array(bytes[header.payloadStart ..< header.payloadStart + min(
                header.payloadLength,
                maximumMessageBytes
            )])
            if let key = header.maskingKey {
                for position in payload.indices {
                    payload[position] ^= key[position % 4]
                }
            }
            let frame = WebSocketFrame(
                fromClient: fromClient, offset: index, fin: header.fin, compressed: header.rsv1,
                opcode: header.opcode, masked: header.maskingKey != nil, payloadLength: header.payloadLength
            )
            reading.frames.append(frame)
            index = header.payloadStart + header.payloadLength

            if opcode.isControl {
                var closeCode: UInt16?
                var closeReason: String?
                if opcode == .close, payload.count >= 2 {
                    closeCode = UInt16(payload[0]) << 8 | UInt16(payload[1])
                    closeReason = payload.count > 2 ? String(bytes: payload.dropFirst(2), encoding: .utf8) : nil
                }
                reading.messages.append(WebSocketMessage(
                    id: 0, fromClient: fromClient, opcode: opcode, offset: frame.offset, frameCount: 1,
                    wireSize: header.payloadLength, compressed: false, payload: payload, size: payload.count,
                    closeCode: closeCode, closeReason: closeReason
                ))
                continue
            }
            if opcode == .continuation {
                guard open != nil else {
                    reading.stop = .malformed
                    break
                }
            } else {
                guard open == nil else {
                    // A new data message while another is still open.
                    reading.stop = .malformed
                    break
                }
                open = OpenMessage(opcode: opcode, offset: frame.offset, compressed: header.rsv1 && inflater != nil)
            }
            guard var message = open else {
                break
            }
            message.frameCount += 1
            message.wireSize += header.payloadLength
            let room = maximumMessageBytes - message.payload.count
            message.payload += payload.prefix(room)
            message.truncated = message.truncated || header.payloadLength > room
            if header.fin {
                reading.messages.append(finish(message, fromClient: fromClient, inflater: inflater))
                open = nil
            } else {
                open = message
            }
        }
        if open != nil, reading.stop == nil {
            reading.stop = .cutShort
        }
        reading.inflateFailed = inflater?.failed ?? false
        return reading
    }

    private static func finish(_ message: OpenMessage, fromClient: Bool, inflater: Inflater?) -> WebSocketMessage {
        var payload: [UInt8]? = message.payload
        var size: Int? = message.truncated ? nil : message.payload.count
        if message.compressed, let inflater {
            // A truncated compressed message cannot be inflated reliably, and the
            // context after it is lost too.
            if message.truncated {
                inflater.failed = true
                payload = nil
                size = nil
            } else if let inflated = inflater.inflate(message.payload, limit: maximumMessageBytes) {
                payload = inflated.bytes
                size = inflated.complete ? inflated.bytes.count : nil
            } else {
                payload = nil
                size = nil
            }
        }
        return WebSocketMessage(
            id: 0, fromClient: fromClient, opcode: message.opcode, offset: message.offset,
            frameCount: message.frameCount, wireSize: message.wireSize, compressed: message.compressed,
            payload: payload, size: size, closeCode: nil, closeReason: nil
        )
    }

    private static func frameHeader(_ bytes: [UInt8], at index: Int) -> FrameHeader? {
        guard bytes.count - index >= 2 else {
            return nil
        }
        let first = bytes[index]
        let second = bytes[index + 1]
        var cursor = index + 2
        var length = Int(second & 0x7F)
        if length == 126 {
            guard bytes.count - cursor >= 2 else {
                return nil
            }
            length = Int(bytes[cursor]) << 8 | Int(bytes[cursor + 1])
            cursor += 2
        } else if length == 127 {
            guard bytes.count - cursor >= 8 else {
                return nil
            }
            var value: UInt64 = 0
            for offset in 0 ..< 8 {
                value = value << 8 | UInt64(bytes[cursor + offset])
            }
            cursor += 8
            // The top bit must be zero; anything past Int is past the retained bytes anyway.
            length = value > UInt64(Int.max / 2) ? Int.max / 2 : Int(value)
        }
        var key: [UInt8]?
        if second & 0x80 != 0 {
            guard bytes.count - cursor >= 4 else {
                return nil
            }
            key = Array(bytes[cursor ..< cursor + 4])
            cursor += 4
        }
        return FrameHeader(
            fin: first & 0x80 != 0, rsv1: first & 0x40 != 0, opcode: first & 0x0F,
            maskingKey: key, payloadLength: length, payloadStart: cursor
        )
    }

    /// Lowercased field names to their first value, from one HTTP/1 head.
    private static func headFields(_ bytes: [UInt8], from start: Int, to end: Int) -> [String: String] {
        guard start < end, end <= bytes.count,
              let text = String(bytes: bytes[start ..< end], encoding: .isoLatin1) else
        {
            return [:]
        }
        var fields: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline).dropFirst() {
            guard let colon = line.firstIndex(of: ":") else {
                continue
            }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if fields[name] == nil {
                fields[name] = value
            }
        }
        return fields
    }
}

private extension WebSocketMessage {
    func renumbered(_ id: Int) -> WebSocketMessage {
        WebSocketMessage(
            id: id, fromClient: fromClient, opcode: opcode, offset: offset, frameCount: frameCount,
            wireSize: wireSize, compressed: compressed, payload: payload, size: size,
            closeCode: closeCode, closeReason: closeReason
        )
    }
}
