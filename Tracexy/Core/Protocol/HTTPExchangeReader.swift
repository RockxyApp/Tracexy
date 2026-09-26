import Foundation

// MARK: - HTTPBodyFraming

/// How a message said its body ends (RFC 9112 §6.3).
nonisolated enum HTTPBodyFraming: Hashable, Sendable {
    /// No body: a request without Content-Length, a HEAD response, 1xx, 204 or 304.
    case none
    case contentLength(Int)
    case chunked
    /// A response with neither Content-Length nor chunked coding: the body runs to
    /// the end of the connection.
    case untilClose
}

// MARK: - HTTPMessageSummary

/// One HTTP/1 message read from a followed TCP stream: where it starts in the
/// direction's leading run, how long it is, and the head facts worth showing.
nonisolated struct HTTPMessageSummary: Hashable, Sendable {
    /// Offset of the first byte of the start line within the leading run.
    let offset: Int
    /// Head plus body, or `nil` when the retained bytes ended inside the message.
    let length: Int?
    let framing: HTTPBodyFraming
    /// Body bytes carried (chunk data only, for chunked coding); `nil` when the
    /// message was cut short.
    let bodyLength: Int?
    let contentType: String?
    /// Offset of the first body byte (just past the blank line ending the head).
    var bodyOffset = 0
    /// The Content-Encoding the sender declared (`gzip`, `br`…), if any.
    var contentEncoding: String?

    var isComplete: Bool {
        length != nil
    }
}

// MARK: - HTTPExchange

/// A request and the final response that answered it, paired in order as HTTP/1.1
/// requires. Interim 1xx responses are recorded but do not answer the request.
nonisolated struct HTTPExchange: Hashable, Sendable, Identifiable {
    /// 0-based position of the request on the connection.
    let id: Int
    let method: String
    let target: String
    let host: String?
    let request: HTTPMessageSummary
    let interimStatuses: [Int]
    let status: Int?
    let reason: String?
    let response: HTTPMessageSummary?
}

// MARK: - HTTPConversation

/// The HTTP/1 exchanges on one TCP connection, as far as the leading retained bytes
/// of both directions allow.
nonisolated struct HTTPConversation: Hashable, Sendable {
    /// Why reading stopped before the end of the retained bytes, if it did.
    enum Stop: Hashable, Sendable {
        /// The exchange bound was reached.
        case exchangeLimit
        /// A request's bytes ended before the message did.
        case requestCutShort
        /// A response's bytes ended before the message did, or it ran to close.
        case responseCutShort
        /// Bytes after a message were not an HTTP/1 message (an upgrade such as
        /// WebSocket, or a protocol this reader does not know).
        case notHTTP
        /// A message declared its length in a way that cannot be trusted
        /// (conflicting or malformed Content-Length), so its end is unknown.
        case malformed
    }

    /// Whether the client (the side that sent the first request) is `a → b`.
    let clientIsAToB: Bool
    let exchanges: [HTTPExchange]
    let stop: Stop?
}

// MARK: - HTTPExchangeReader

/// Reads HTTP/1.0 and HTTP/1.1 messages from the leading run of each direction of a
/// followed TCP stream and pairs each request with the response that answered it.
///
/// Bounded and fail-closed: at most ``maximumExchanges`` requests, a head of at most
/// ``maximumHeadBytes``, and ``maximumChunks`` chunks per body. Reading stops at the
/// first message it cannot parse or that the retained bytes cut short; nothing past
/// that point is guessed. A stream that does not open with an HTTP/1 request line
/// in either direction is not HTTP and yields `nil`.
nonisolated enum HTTPExchangeReader {
    // MARK: Internal

    static let maximumExchanges = 256
    static let maximumHeadBytes = 32 * 1_024
    static let maximumChunks = 65_536

    /// - Parameter skippingResponses: responses at the start of the server side
    ///   to pass over before pairing, for a capture that began after a request was
    ///   sent but before its response arrived.
    static func read(aToB: [UInt8], bToA: [UInt8], skippingResponses: Int = 0) -> HTTPConversation? {
        if case .request = parseHead(aToB, at: skipBlankLines(aToB, from: 0)) {
            return read(client: aToB, server: bToA, clientIsAToB: true, skippingResponses: skippingResponses)
        }
        if case .request = parseHead(bToA, at: skipBlankLines(bToA, from: 0)) {
            return read(client: bToA, server: aToB, clientIsAToB: false, skippingResponses: skippingResponses)
        }
        return nil
    }

    /// The body of a complete `message` read from `bytes` (the same leading run it
    /// was parsed from), with chunked coding removed. Content coding such as gzip is
    /// left exactly as sent. `nil` when the message was cut short or has no body.
    static func body(of message: HTTPMessageSummary, in bytes: [UInt8]) -> [UInt8]? {
        guard message.isComplete, let length = message.bodyLength, length > 0,
              message.bodyOffset <= bytes.count else
        {
            return nil
        }
        switch message.framing {
        case .contentLength:
            guard message.bodyOffset + length <= bytes.count else {
                return nil
            }
            return Array(bytes[message.bodyOffset ..< message.bodyOffset + length])
        case .chunked:
            var output: [UInt8] = []
            output.reserveCapacity(length)
            var offset = message.bodyOffset
            for _ in 0 ..< maximumChunks {
                guard let (line, next) = readLine(bytes, from: offset),
                      let size = Int(
                          line.split(separator: ";", maxSplits: 1).first.map(String.init)?
                              .trimmingCharacters(in: .whitespaces) ?? "",
                          radix: 16
                      ),
                      size >= 0, next + size <= bytes.count else
                {
                    return nil
                }
                if size == 0 {
                    return output
                }
                output += bytes[next ..< next + size]
                guard let (_, after) = readLine(bytes, from: next + size) else {
                    return nil
                }
                offset = after
            }
            return nil
        case .none,
             .untilClose:
            return nil
        }
    }

    // MARK: Private

    private enum StartLine {
        case request(method: String, target: String)
        case response(status: Int, reason: String)
    }

    private enum HeadParse {
        case request(Head, method: String, target: String)
        case response(Head, status: Int, reason: String)
        case incomplete
        case invalid
    }

    private struct Head {
        /// Offset just past the blank line that ends the head.
        let end: Int
        /// Header names lower-cased; the first occurrence wins.
        let fields: [String: String]
        let isChunked: Bool
        let contentLength: Int?
        /// A Content-Length the reader could not trust (malformed or conflicting).
        let hasInvalidLength: Bool
    }

    private enum BodyParse {
        case complete(end: Int, bodyLength: Int)
        case incomplete
        case invalid
    }

    private static let methods: Set<String> = [
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    ]

    private static func read(
        client: [UInt8],
        server: [UInt8],
        clientIsAToB: Bool,
        skippingResponses: Int
    )
        -> HTTPConversation
    {
        var exchanges: [HTTPExchange] = []
        var requestOffset = 0
        var responseOffset = 0
        var responsesReadable = true
        var stop: HTTPConversation.Stop?

        // Each skipped response is one final response and any interim 1xx before it.
        var skipped = 0
        while skipped < max(0, skippingResponses), responsesReadable {
            responseOffset = skipBlankLines(server, from: responseOffset)
            guard case let .response(head, code, _) = parseHead(server, at: responseOffset),
                  !head.hasInvalidLength,
                  case let .complete(end, _) = body(
                      server, from: head.end, framing: responseFraming(head, status: code, method: "GET")
                  ) else
            {
                responsesReadable = false
                break
            }
            responseOffset = end
            if !(100 ..< 200).contains(code) || code == 101 {
                skipped += 1
            }
        }

        while true {
            // RFC 9112 §2.2: empty lines before a request-line are ignored.
            requestOffset = skipBlankLines(client, from: requestOffset)
            guard requestOffset < client.count else {
                break
            }
            guard exchanges.count < maximumExchanges else {
                stop = .exchangeLimit
                break
            }
            guard case let .request(head, method, target) = parseHead(client, at: requestOffset) else {
                stop = if case .incomplete = parseHead(client, at: requestOffset) {
                    .requestCutShort
                } else {
                    .notHTTP
                }
                break
            }
            let requestBody = requestFraming(head)
            let parsedBody = head.hasInvalidLength ? .invalid : body(client, from: head.end, framing: requestBody)
            var requestMalformed = false
            if case .invalid = parsedBody {
                requestMalformed = true
            }
            let request = switch parsedBody {
            case let .complete(end, bodyLength):
                HTTPMessageSummary(
                    offset: requestOffset, length: end - requestOffset, framing: requestBody,
                    bodyLength: bodyLength, contentType: head.fields["content-type"],
                    bodyOffset: head.end, contentEncoding: head.fields["content-encoding"]
                )
            case .incomplete,
                 .invalid:
                HTTPMessageSummary(
                    offset: requestOffset, length: nil, framing: requestBody,
                    bodyLength: nil, contentType: head.fields["content-type"],
                    bodyOffset: head.end, contentEncoding: head.fields["content-encoding"]
                )
            }

            var interim: [Int] = []
            var status: Int?
            var reason: String?
            var response: HTTPMessageSummary?
            while responsesReadable {
                responseOffset = skipBlankLines(server, from: responseOffset)
                guard responseOffset < server.count else {
                    break
                }
                guard case let .response(responseHead, code, phrase) = parseHead(server, at: responseOffset) else {
                    responsesReadable = false
                    if case .incomplete = parseHead(server, at: responseOffset) {
                        stop = stop ?? .responseCutShort
                    } else {
                        stop = stop ?? .notHTTP
                    }
                    break
                }
                let framing = responseFraming(responseHead, status: code, method: method)
                let parsed = responseHead.hasInvalidLength
                    ? .invalid
                    : body(server, from: responseHead.end, framing: framing)
                if (100 ..< 200).contains(code), code != 101 {
                    guard case let .complete(end, _) = parsed else {
                        responsesReadable = false
                        break
                    }
                    interim.append(code)
                    responseOffset = end
                    continue
                }
                status = code
                reason = phrase
                switch parsed {
                case let .complete(end, bodyLength):
                    response = HTTPMessageSummary(
                        offset: responseOffset, length: end - responseOffset, framing: framing,
                        bodyLength: bodyLength, contentType: responseHead.fields["content-type"],
                        bodyOffset: responseHead.end, contentEncoding: responseHead.fields["content-encoding"]
                    )
                    responseOffset = end
                case .incomplete,
                     .invalid:
                    response = HTTPMessageSummary(
                        offset: responseOffset, length: nil, framing: framing,
                        bodyLength: nil, contentType: responseHead.fields["content-type"],
                        bodyOffset: responseHead.end, contentEncoding: responseHead.fields["content-encoding"]
                    )
                    responsesReadable = false
                    var malformed = false
                    if case .invalid = parsed {
                        malformed = true
                    }
                    stop = stop ?? (malformed ? .malformed : .responseCutShort)
                }
                if code == 101 {
                    // Switching Protocols: what follows is no longer HTTP/1.
                    responsesReadable = false
                }
                break
            }

            exchanges.append(HTTPExchange(
                id: exchanges.count, method: method, target: target, host: head.fields["host"],
                request: request, interimStatuses: interim, status: status, reason: reason, response: response
            ))
            guard let length = request.length else {
                stop = requestMalformed ? .malformed : .requestCutShort
                break
            }
            requestOffset += length
            if status == 101 || method == "CONNECT" && status.map({ (200 ..< 300).contains($0) }) == true {
                if requestOffset < client.count {
                    stop = .notHTTP
                }
                break
            }
        }
        return HTTPConversation(clientIsAToB: clientIsAToB, exchanges: exchanges, stop: stop)
    }

    /// The offset of the first byte at or after `offset` that is not part of an
    /// empty line (CRLF or bare LF).
    private static func skipBlankLines(_ bytes: [UInt8], from offset: Int) -> Int {
        var index = offset
        while index < bytes.count {
            if bytes[index] == 0x0A {
                index += 1
            } else if bytes[index] == 0x0D, index + 1 < bytes.count, bytes[index + 1] == 0x0A {
                index += 2
            } else {
                break
            }
        }
        return index
    }

    private static func requestFraming(_ head: Head) -> HTTPBodyFraming {
        if head.isChunked {
            return .chunked
        }
        return head.contentLength.map(HTTPBodyFraming.contentLength) ?? .none
    }

    private static func responseFraming(_ head: Head, status: Int, method: String) -> HTTPBodyFraming {
        if method == "HEAD" || (100 ..< 200).contains(status) || status == 204 || status == 304 {
            return .none
        }
        if method == "CONNECT", (200 ..< 300).contains(status) {
            return .none
        }
        if head.isChunked {
            return .chunked
        }
        return head.contentLength.map(HTTPBodyFraming.contentLength) ?? .untilClose
    }

    // MARK: Head

    private static func parseHead(_ bytes: [UInt8], at start: Int) -> HeadParse {
        guard start < bytes.count else {
            return .incomplete
        }
        let limit = min(bytes.count, start + maximumHeadBytes)
        var lines: [String] = []
        var lineStart = start
        var index = start
        var end: Int?
        while index < limit {
            if bytes[index] == 0x0A {
                var lineEnd = index
                if lineEnd > lineStart, bytes[lineEnd - 1] == 0x0D {
                    lineEnd -= 1
                }
                if lineEnd == lineStart {
                    end = index + 1
                    break
                }
                guard let line = String(bytes: bytes[lineStart ..< lineEnd], encoding: .isoLatin1) else {
                    return .invalid
                }
                lines.append(line)
                if lines.count == 1, startLine(line) == nil {
                    return .invalid
                }
                lineStart = index + 1
            }
            index += 1
        }
        guard let end else {
            // A first line already seen but no blank line yet: cut short. A first line
            // never seen within the bound is not a head this reader will accept.
            if lines.isEmpty {
                let pending = bytes[start ..< limit]
                return limit - start < maximumHeadBytes && prefixCouldStartMessage(pending) ? .incomplete : .invalid
            }
            return limit - start < maximumHeadBytes ? .incomplete : .invalid
        }
        guard let first = lines.first, let kind = startLine(first) else {
            return .invalid
        }
        var fields: [String: String] = [:]
        var lengths: Set<String> = []
        var isChunked = false
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else {
                return .invalid
            }
            let name = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if fields[name] == nil {
                fields[name] = value
            }
            if name == "content-length" {
                lengths.insert(value)
            }
            if name == "transfer-encoding",
               value.lowercased().split(separator: ",").last?.trimmingCharacters(in: .whitespaces) == "chunked"
            {
                isChunked = true
            }
        }
        var contentLength: Int?
        var invalidLength = false
        if !isChunked, !lengths.isEmpty {
            if lengths.count == 1, let value = lengths.first, !value.isEmpty,
               value.allSatisfy(\.isASCII), value.allSatisfy(\.isNumber), let parsed = Int(value)
            {
                contentLength = parsed
            } else {
                invalidLength = true
            }
        }
        let head = Head(
            end: end, fields: fields, isChunked: isChunked,
            contentLength: contentLength, hasInvalidLength: invalidLength
        )
        switch kind {
        case let .request(method, target): return .request(head, method: method, target: target)
        case let .response(status, reason): return .response(head, status: status, reason: reason)
        }
    }

    private static func startLine(_ line: String) -> StartLine? {
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else {
            return nil
        }
        if parts[0].hasPrefix("HTTP/1."), parts[0].count == 8 {
            guard parts[1].count == 3, let status = Int(parts[1]), (100 ... 999).contains(status) else {
                return nil
            }
            return .response(status: status, reason: parts.count == 3 ? String(parts[2]) : "")
        }
        guard parts.count == 3, methods.contains(String(parts[0])), !parts[1].isEmpty,
              parts[2].hasPrefix("HTTP/1."), parts[2].count == 8 else
        {
            return nil
        }
        return .request(method: String(parts[0]), target: String(parts[1]))
    }

    /// Whether bytes without a complete first line could still become one: a
    /// method or `HTTP/` prefix, so a cut-short head is told apart from binary data.
    private static func prefixCouldStartMessage(_ bytes: ArraySlice<UInt8>) -> Bool {
        let text = String(bytes: bytes.prefix(8), encoding: .isoLatin1) ?? ""
        return (methods.map { $0 + " " } + ["HTTP/1."]).contains { $0.hasPrefix(text) || text.hasPrefix($0) }
    }

    // MARK: Body

    private static func body(_ bytes: [UInt8], from start: Int, framing: HTTPBodyFraming) -> BodyParse {
        switch framing {
        case .none:
            return .complete(end: start, bodyLength: 0)
        case let .contentLength(length):
            let (end, overflow) = start.addingReportingOverflow(length)
            return !overflow && end <= bytes.count ? .complete(end: end, bodyLength: length) : .incomplete
        case .untilClose:
            // The body's end is the connection's end, which the retained bytes cannot
            // prove; it is reported as cut short rather than claimed complete.
            return .incomplete
        case .chunked:
            return chunked(bytes, from: start)
        }
    }

    private static func chunked(_ bytes: [UInt8], from start: Int) -> BodyParse {
        var offset = start
        var total = 0
        for _ in 0 ..< maximumChunks {
            guard let (line, next) = readLine(bytes, from: offset) else {
                return .incomplete
            }
            let sizeText = line.split(separator: ";", maxSplits: 1).first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            guard !sizeText.isEmpty, sizeText.count <= 16, let size = Int(sizeText, radix: 16), size >= 0 else {
                return .invalid
            }
            offset = next
            if size == 0 {
                // Trailer fields, then the blank line that ends the message.
                while true {
                    guard let (trailer, after) = readLine(bytes, from: offset) else {
                        return .incomplete
                    }
                    offset = after
                    if trailer.isEmpty {
                        return .complete(end: offset, bodyLength: total)
                    }
                }
            }
            let (dataEnd, overflow) = offset.addingReportingOverflow(size)
            guard !overflow, dataEnd <= bytes.count else {
                return .incomplete
            }
            guard let (terminator, after) = readLine(bytes, from: dataEnd) else {
                return .incomplete
            }
            guard terminator.isEmpty else {
                return .invalid
            }
            total += size
            offset = after
        }
        return .invalid
    }

    /// One CRLF- or LF-terminated line starting at `offset`, at most 4 KiB, and the
    /// offset just past its terminator.
    private static func readLine(_ bytes: [UInt8], from offset: Int) -> (String, Int)? {
        var index = offset
        let limit = min(bytes.count, offset + 4_096)
        while index < limit {
            if bytes[index] == 0x0A {
                var end = index
                if end > offset, bytes[end - 1] == 0x0D {
                    end -= 1
                }
                return (String(bytes: bytes[offset ..< end], encoding: .isoLatin1) ?? "", index + 1)
            }
            index += 1
        }
        return nil
    }
}
