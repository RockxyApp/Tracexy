import Foundation

// MARK: - HTTP2Frame

/// One HTTP/2 frame (RFC 9113 §4.1) read from a followed TCP stream.
nonisolated struct HTTP2Frame: Hashable, Sendable {
    /// Sent by the client (the side that opened with the connection preface).
    let fromClient: Bool
    /// Offset of the 9-byte frame header within its direction's leading run.
    let offset: Int
    /// Payload length.
    let length: Int
    let type: UInt8
    let flags: UInt8
    let streamID: UInt32
    /// What the frame said beyond its header, in plain words: flags that matter,
    /// an error code, settings, a window increment. Empty when there is nothing.
    let detail: String

    var typeName: String {
        HTTP2ConnectionReader.typeName(type)
    }
}

// MARK: - HTTP2Stream

/// One HTTP/2 stream: the request and response heads, how much DATA each side
/// sent, and how the stream ended.
nonisolated struct HTTP2Stream: Hashable, Sendable, Identifiable {
    let id: UInt32
    var requestHeaders: [HPACKHeader] = []
    var responseHeaders: [HPACKHeader] = []
    /// Interim 1xx statuses the server sent before its final response.
    var informationalStatuses: [Int] = []
    /// Offset of the first request HEADERS frame header (client direction), or of
    /// the PUSH_PROMISE that announced a pushed stream (server direction).
    var requestOffset: Int?
    /// Offset of the frame header carrying the final response head (server direction).
    var responseOffset: Int?
    var requestDataBytes = 0
    var responseDataBytes = 0
    var requestEnded = false
    var responseEnded = false
    /// The RST_STREAM error code, and which side sent it.
    var resetCode: UInt32?
    var resetByClient = false
    /// The stream whose PUSH_PROMISE announced this one.
    var promisedBy: UInt32?

    var method: String? {
        Self.value(":method", in: requestHeaders)
    }

    var path: String? {
        Self.value(":path", in: requestHeaders)
    }

    var authority: String? {
        Self.value(":authority", in: requestHeaders) ?? Self.value("host", in: requestHeaders)
    }

    var status: Int? {
        Self.value(":status", in: responseHeaders).flatMap { Int($0) }
    }

    var contentType: String? {
        Self.value("content-type", in: responseHeaders)
    }

    static func value(_ name: String, in headers: [HPACKHeader]) -> String? {
        headers.first { $0.name == name }?.value
    }
}

// MARK: - HTTP2Conversation

/// The HTTP/2 frames and streams on one TCP connection, as far as the leading
/// retained bytes of each direction allow.
nonisolated struct HTTP2Conversation: Hashable, Sendable {
    /// Why one direction stopped before the end of its retained bytes.
    enum Stop: Hashable, Sendable {
        /// The frame bound was reached.
        case frameLimit
        /// The stream bound was reached.
        case streamLimit
        /// The retained bytes end inside a frame.
        case cutShort
        /// A frame broke the framing rules, so nothing after it can be placed.
        case malformed
        /// A header block could not be decompressed; later header blocks in this
        /// direction depend on it and are not read.
        case headerCompression
    }

    let clientIsAToB: Bool
    /// Client frames first, then server frames, each in byte order.
    let frames: [HTTP2Frame]
    /// Ordered by stream identifier.
    let streams: [HTTP2Stream]
    let clientSettings: [HTTP2Setting]
    let serverSettings: [HTTP2Setting]
    let clientStop: Stop?
    let serverStop: Stop?
    /// Set when the connection began as HTTP/1.1 and switched to HTTP/2 with
    /// `Upgrade: h2c`; stream 1 then carries that HTTP/1.1 request.
    var upgrade: HTTP2Upgrade?
}

// MARK: - HTTP2Upgrade

/// Where an `Upgrade: h2c` switch (RFC 7540 §3.2) sits in each direction.
nonisolated struct HTTP2Upgrade: Hashable, Sendable {
    /// Offset of the HTTP/1.1 request in the client direction.
    let requestOffset: Int
    /// Offset of the `101 Switching Protocols` response in the server direction.
    let responseOffset: Int
    /// Where the client connection preface starts.
    let clientStart: Int
    /// Where the server's first HTTP/2 frame starts.
    let serverStart: Int
}

// MARK: - HTTP2Setting

nonisolated struct HTTP2Setting: Hashable, Sendable {
    let identifier: UInt16
    let value: UInt32

    var name: String {
        switch identifier {
        case 1: "HEADER_TABLE_SIZE"
        case 2: "ENABLE_PUSH"
        case 3: "MAX_CONCURRENT_STREAMS"
        case 4: "INITIAL_WINDOW_SIZE"
        case 5: "MAX_FRAME_SIZE"
        case 6: "MAX_HEADER_LIST_SIZE"
        case 8: "ENABLE_CONNECT_PROTOCOL"
        case 9: "NO_RFC7540_PRIORITIES"
        default: "0x\(String(identifier, radix: 16))"
        }
    }
}

// MARK: - HTTP2ConnectionReader

/// Reads HTTP/2 from the leading run of each direction of a followed TCP stream:
/// a connection that opens with the client preface, as the stream reading
/// presents it. Each direction is read on its own — its header compression state
/// depends only on its own header blocks — and the two are joined by stream.
///
/// Bounded and fail-closed: at most ``maximumFrames`` frames per direction and
/// ``maximumStreams`` streams; a direction stops at the first frame it cannot
/// place, and nothing after that point is guessed.
nonisolated enum HTTP2ConnectionReader {
    // MARK: Internal

    static let maximumFrames = 50_000
    static let maximumStreams = 1_000
    /// Joined HEADERS + CONTINUATION payload bound.
    static let maximumHeaderBlockBytes = 256 * 1_024
    static let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// `nil` unless one direction opens with the HTTP/2 client connection preface,
    /// or the connection switched to HTTP/2 with an `Upgrade: h2c` exchange.
    static func read(aToB: [UInt8], bToA: [UInt8]) -> HTTP2Conversation? {
        if aToB.starts(with: preface) {
            return read(client: aToB, server: bToA, clientIsAToB: true)
        }
        if bToA.starts(with: preface) {
            return read(client: bToA, server: aToB, clientIsAToB: false)
        }
        return upgraded(aToB: aToB, bToA: bToA)
    }

    static func typeName(_ type: UInt8) -> String {
        switch type {
        case 0: "DATA"
        case 1: "HEADERS"
        case 2: "PRIORITY"
        case 3: "RST_STREAM"
        case 4: "SETTINGS"
        case 5: "PUSH_PROMISE"
        case 6: "PING"
        case 7: "GOAWAY"
        case 8: "WINDOW_UPDATE"
        case 9: "CONTINUATION"
        default: "Unknown (0x\(String(type, radix: 16)))"
        }
    }

    static func errorName(_ code: UInt32) -> String {
        switch code {
        case 0x0: "NO_ERROR"
        case 0x1: "PROTOCOL_ERROR"
        case 0x2: "INTERNAL_ERROR"
        case 0x3: "FLOW_CONTROL_ERROR"
        case 0x4: "SETTINGS_TIMEOUT"
        case 0x5: "STREAM_CLOSED"
        case 0x6: "FRAME_SIZE_ERROR"
        case 0x7: "REFUSED_STREAM"
        case 0x8: "CANCEL"
        case 0x9: "COMPRESSION_ERROR"
        case 0xA: "CONNECT_ERROR"
        case 0xB: "ENHANCE_YOUR_CALM"
        case 0xC: "INADEQUATE_SECURITY"
        case 0xD: "HTTP_1_1_REQUIRED"
        default: "0x\(String(code, radix: 16))"
        }
    }

    /// Reads both directions: the client's frames from just past its preface at
    /// `clientStart`, the server's from `serverStart`. `firstStream` is a stream the
    /// connection already opened before its first frame (the upgraded request).
    static func read(
        client: [UInt8],
        server: [UInt8],
        clientIsAToB: Bool,
        clientStart: Int = 0,
        serverStart: Int = 0,
        firstStream: HTTP2Stream? = nil
    )
        -> HTTP2Conversation
    {
        let clientReading = readDirection(client, from: clientStart + preface.count, fromClient: true)
        let serverReading = readDirection(server, from: serverStart, fromClient: false)
        var joined = clientReading.streams
        if let firstStream, joined[firstStream.id] == nil {
            joined[firstStream.id] = firstStream
        }
        for (id, served) in serverReading.streams {
            var stream = joined[id] ?? HTTP2Stream(id: id)
            stream.responseHeaders = served.responseHeaders
            stream.informationalStatuses = served.informationalStatuses
            stream.responseOffset = served.responseOffset
            stream.responseDataBytes = served.responseDataBytes
            stream.responseEnded = served.responseEnded
            if served.resetCode != nil, stream.resetCode == nil {
                stream.resetCode = served.resetCode
                stream.resetByClient = false
            }
            if served.promisedBy != nil {
                stream.promisedBy = served.promisedBy
                stream.requestHeaders = served.requestHeaders
                stream.requestOffset = served.requestOffset
                stream.requestEnded = true
            }
            joined[id] = stream
        }
        let streams = joined.values.sorted { $0.id < $1.id }
        return HTTP2Conversation(
            clientIsAToB: clientIsAToB,
            frames: clientReading.frames + serverReading.frames,
            streams: Array(streams.prefix(maximumStreams)),
            clientSettings: clientReading.settings,
            serverSettings: serverReading.settings,
            clientStop: clientReading.stop ?? (streams.count > maximumStreams ? .streamLimit : nil),
            serverStop: serverReading.stop
        )
    }

    // MARK: Private

    private enum FrameType {
        static let data: UInt8 = 0
        static let headers: UInt8 = 1
        static let rstStream: UInt8 = 3
        static let settings: UInt8 = 4
        static let pushPromise: UInt8 = 5
        static let ping: UInt8 = 6
        static let goAway: UInt8 = 7
        static let windowUpdate: UInt8 = 8
        static let continuation: UInt8 = 9
    }

    private enum Flag {
        static let endStream: UInt8 = 0x1
        static let ack: UInt8 = 0x1
        static let endHeaders: UInt8 = 0x4
        static let padded: UInt8 = 0x8
        static let priority: UInt8 = 0x20
    }

    /// One direction's reading, before the two are joined.
    private struct DirectionReading {
        var frames: [HTTP2Frame] = []
        var streams: [UInt32: HTTP2Stream] = [:]
        var settings: [HTTP2Setting] = []
        var stop: HTTP2Conversation.Stop?
    }

    /// A header block being gathered across HEADERS/PUSH_PROMISE + CONTINUATION.
    private struct PendingBlock {
        let streamID: UInt32
        /// For PUSH_PROMISE: the stream it announces.
        let promisedStreamID: UInt32?
        let offset: Int
        let endStream: Bool
        var bytes: [UInt8]
    }

    // swiftlint:disable:next function_body_length
    private static func readDirection(_ bytes: [UInt8], from start: Int, fromClient: Bool) -> DirectionReading {
        var reading = DirectionReading()
        var decoder = HPACKDecoder()
        var pending: PendingBlock?
        var index = start
        while index < bytes.count {
            guard reading.frames.count < maximumFrames else {
                reading.stop = .frameLimit
                return reading
            }
            guard bytes.count - index >= 9 else {
                reading.stop = .cutShort
                return reading
            }
            let length = Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
            let type = bytes[index + 3]
            let flags = bytes[index + 4]
            let streamID = readUInt32(bytes, index + 5) & 0x7FFFFFFF
            let payloadStart = index + 9
            guard length <= bytes.count - payloadStart else {
                reading.stop = .cutShort
                return reading
            }
            let payload = Array(bytes[payloadStart ..< payloadStart + length])
            let frameOffset = index
            index = payloadStart + length

            // A header block in progress admits only its own CONTINUATION frames.
            if var block = pending {
                guard type == FrameType.continuation, streamID == block.streamID else {
                    reading.stop = .malformed
                    return reading
                }
                block.bytes += payload
                guard block.bytes.count <= maximumHeaderBlockBytes else {
                    reading.stop = .malformed
                    return reading
                }
                reading.frames.append(frame(fromClient, frameOffset, length, type, flags, streamID, ""))
                if flags & Flag.endHeaders != 0 {
                    pending = nil
                    guard finish(block, decoder: &decoder, into: &reading, fromClient: fromClient) else {
                        return reading
                    }
                } else {
                    pending = block
                }
                continue
            }

            var detail = ""
            switch type {
            case FrameType.data:
                guard streamID != 0, let data = unpadded(payload, flags: flags, fixed: 0) else {
                    reading.stop = .malformed
                    return reading
                }
                var stream = reading.streams[streamID] ?? HTTP2Stream(id: streamID)
                let ends = flags & Flag.endStream != 0
                if fromClient {
                    stream.requestDataBytes += data.count
                    stream.requestEnded = stream.requestEnded || ends
                } else {
                    stream.responseDataBytes += data.count
                    stream.responseEnded = stream.responseEnded || ends
                }
                reading.streams[streamID] = stream
                detail = ends ? "END_STREAM" : ""
            case FrameType.headers,
                 FrameType.pushPromise:
                let isPush = type == FrameType.pushPromise
                guard streamID != 0,
                      let body = unpadded(
                          payload,
                          flags: flags,
                          fixed: isPush ? 4 : (flags & Flag.priority != 0 ? 5 : 0)
                      ) else
                {
                    reading.stop = .malformed
                    return reading
                }
                var promised: UInt32?
                var block = body
                if isPush {
                    guard !fromClient, body.count >= 4 else {
                        reading.stop = .malformed
                        return reading
                    }
                    promised = readUInt32(body, 0) & 0x7FFFFFFF
                    block = Array(body.dropFirst(4))
                    detail = "Promised stream \(promised ?? 0)"
                } else if flags & Flag.priority != 0 {
                    block = Array(body.dropFirst(5))
                }
                let ends = !isPush && flags & Flag.endStream != 0
                if ends {
                    detail = "END_STREAM"
                }
                let gathered = PendingBlock(
                    streamID: streamID,
                    promisedStreamID: promised,
                    offset: frameOffset,
                    endStream: ends,
                    bytes: block
                )
                reading.frames.append(frame(fromClient, frameOffset, length, type, flags, streamID, detail))
                if flags & Flag.endHeaders != 0 {
                    guard finish(gathered, decoder: &decoder, into: &reading, fromClient: fromClient) else {
                        return reading
                    }
                } else {
                    pending = gathered
                }
                continue
            case FrameType.rstStream:
                guard streamID != 0, payload.count == 4 else {
                    reading.stop = .malformed
                    return reading
                }
                let code = readUInt32(payload, 0)
                var stream = reading.streams[streamID] ?? HTTP2Stream(id: streamID)
                stream.resetCode = code
                stream.resetByClient = fromClient
                reading.streams[streamID] = stream
                detail = errorName(code)
            case FrameType.settings:
                guard streamID == 0, payload.count % 6 == 0 else {
                    reading.stop = .malformed
                    return reading
                }
                if flags & Flag.ack != 0 {
                    detail = "ACK"
                } else {
                    let settings = stride(from: 0, to: payload.count, by: 6).map { offset in
                        HTTP2Setting(
                            identifier: UInt16(payload[offset]) << 8 | UInt16(payload[offset + 1]),
                            value: readUInt32(payload, offset + 2)
                        )
                    }
                    if reading.settings.isEmpty {
                        reading.settings = settings
                    }
                    detail = settings.map { "\($0.name) \($0.value)" }.joined(separator: ", ")
                }
            case FrameType.ping:
                detail = flags & Flag.ack != 0 ? "ACK" : ""
            case FrameType.goAway:
                guard streamID == 0, payload.count >= 8 else {
                    reading.stop = .malformed
                    return reading
                }
                let last = readUInt32(payload, 0) & 0x7FFFFFFF
                detail = "Last stream \(last), \(errorName(readUInt32(payload, 4)))"
            case FrameType.windowUpdate:
                guard payload.count == 4 else {
                    reading.stop = .malformed
                    return reading
                }
                detail = "Increment \(readUInt32(payload, 0) & 0x7FFFFFFF)"
            case FrameType.continuation:
                // A CONTINUATION with no header block open.
                reading.stop = .malformed
                return reading
            default:
                break
            }
            reading.frames.append(frame(fromClient, frameOffset, length, type, flags, streamID, detail))
            if reading.streams.count > maximumStreams {
                reading.stop = .streamLimit
                return reading
            }
        }
        if pending != nil {
            reading.stop = .cutShort
        }
        return reading
    }

    /// Decode a complete header block and file it on its stream. `false` when
    /// decompression failed and the direction has to stop.
    private static func finish(
        _ block: PendingBlock,
        decoder: inout HPACKDecoder,
        into reading: inout DirectionReading,
        fromClient: Bool
    )
        -> Bool
    {
        let headers: [HPACKHeader]
        do {
            headers = try decoder.decode(block.bytes)
        } catch {
            reading.stop = .headerCompression
            return false
        }
        if let promised = block.promisedStreamID {
            var stream = reading.streams[promised] ?? HTTP2Stream(id: promised)
            stream.requestHeaders = headers
            stream.requestOffset = block.offset
            stream.promisedBy = block.streamID
            reading.streams[promised] = stream
            return true
        }
        var stream = reading.streams[block.streamID] ?? HTTP2Stream(id: block.streamID)
        if fromClient {
            // The first block is the request head; a later one carries trailers.
            if stream.requestHeaders.isEmpty {
                stream.requestHeaders = headers
                stream.requestOffset = block.offset
            }
            stream.requestEnded = stream.requestEnded || block.endStream
        } else {
            let status = HTTP2Stream.value(":status", in: headers).flatMap { Int($0) }
            if let status, (100 ..< 200).contains(status) {
                stream.informationalStatuses.append(status)
            } else if stream.responseHeaders.isEmpty, status != nil {
                stream.responseHeaders = headers
                stream.responseOffset = block.offset
            }
            stream.responseEnded = stream.responseEnded || block.endStream
        }
        reading.streams[block.streamID] = stream
        return true
    }

    /// The payload without its padding (and the Pad Length octet) and without
    /// `fixed` leading bytes the caller reads itself; `nil` when padding overruns.
    private static func unpadded(_ payload: [UInt8], flags: UInt8, fixed: Int) -> [UInt8]? {
        guard flags & Flag.padded != 0 else {
            guard payload.count >= fixed else {
                return nil
            }
            return payload
        }
        guard let padLength = payload.first.map(Int.init), padLength + 1 + fixed <= payload.count else {
            return nil
        }
        return Array(payload[1 ..< payload.count - padLength])
    }

    private static func frame(
        _ fromClient: Bool,
        _ offset: Int,
        _ length: Int,
        _ type: UInt8,
        _ flags: UInt8,
        _ streamID: UInt32,
        _ detail: String
    )
        -> HTTP2Frame
    {
        HTTP2Frame(
            fromClient: fromClient,
            offset: offset,
            length: length,
            type: type,
            flags: flags,
            streamID: streamID,
            detail: detail
        )
    }

    private static func readUInt32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16 | UInt32(bytes[offset + 2]) << 8 |
            UInt32(bytes[offset + 3])
    }
}
