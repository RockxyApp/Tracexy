import Foundation

// MARK: - FollowHTTPExchangeRow

/// One HTTP request and its response as the Stream facet lists them. Plain values;
/// the view lays them out and owns no wording.
nonisolated struct FollowHTTPExchangeRow: Identifiable, Equatable, Sendable {
    let id: Int
    /// Method and request target, e.g. `GET /index.html`.
    let request: String
    /// The Host header, shown as help.
    let host: String?
    /// `200 OK`, or what is known when there is no final response.
    let status: String
    let isError: Bool
    /// From the frame that completed the request to the frame that carried the
    /// first response byte; `nil` when either frame is untimed or unknown.
    let elapsed: String?
    /// Response body size, when the response was read to its end and had a body.
    let size: String?
    let requestFrame: SessionFrameProvenance?
    let responseFrame: SessionFrameProvenance?
    /// The response, when its body was read to the end and can be saved.
    var savableResponse: HTTPMessageSummary?
    /// The file name a saved body is offered under.
    var bodyFileName: String?
}

// MARK: - FollowHTTPPresentation

/// The HTTP/1 exchanges of a followed TCP stream, read by ``HTTPExchangeReader`` from
/// the leading run of each direction and timed from the frames that delivered each
/// message's bytes. `nil` for a stream that is not plain HTTP/1.
nonisolated struct FollowHTTPPresentation: Equatable, Sendable {
    // MARK: Lifecycle

    init?(result: FollowStreamResult) {
        let aRun = result.aToB.runs.first
        let bRun = result.bToA.runs.first
        // A capture that began between a request and its response holds that
        // response with no request: pairing from byte zero would shift every
        // exchange by one. The first paired response must arrive after its request,
        // so leading responses that do not are passed over, a few at most.
        var skipped = 0
        var paired: HTTPConversation?
        while skipped <= Self.maximumSkippedResponses {
            guard let candidate = HTTPExchangeReader.read(
                aToB: aRun?.bytes ?? [], bToA: bRun?.bytes ?? [], skippingResponses: skipped
            ) else {
                return nil
            }
            if Self.firstResponseFollowsItsRequest(candidate, result: result) {
                paired = candidate
                break
            }
            skipped += 1
        }
        guard let conversation = paired, !conversation.exchanges.isEmpty else {
            return nil
        }
        let client = conversation.clientIsAToB ? result.aToB : result.bToA
        let server = conversation.clientIsAToB ? result.bToA : result.aToB
        let clientRun = conversation.clientIsAToB ? aRun : bRun
        let serverRun = conversation.clientIsAToB ? bRun : aRun

        rows = conversation.exchanges.map { exchange in
            let requestFirst = clientRun.flatMap { client.firstFrame(ofByte: exchange.request.offset, in: $0) }
            let requestLast = exchange.request.length.flatMap { length in
                clientRun.flatMap { client.firstFrame(ofByte: exchange.request.offset + length - 1, in: $0) }
            }
            let responseFirst = exchange.response.flatMap { response in
                serverRun.flatMap { server.firstFrame(ofByte: response.offset, in: $0) }
            }
            let savable = exchange.response.flatMap { response -> HTTPMessageSummary? in
                guard response.isComplete, (response.bodyLength ?? 0) > 0 else {
                    return nil
                }
                switch response.framing {
                case .contentLength,
                     .chunked: return response
                case .none,
                     .untilClose: return nil
                }
            }
            return FollowHTTPExchangeRow(
                id: exchange.id,
                request: "\(exchange.method) \(exchange.target)",
                host: exchange.host,
                status: Self.statusLabel(exchange),
                isError: exchange.status.map { $0 >= 400 } ?? false,
                elapsed: Self.elapsed(from: requestLast, to: responseFirst),
                size: exchange.response?.bodyLength.flatMap { $0 > 0 ? ByteUnits.string(Int64($0)) : nil },
                requestFrame: requestFirst,
                responseFrame: responseFirst,
                savableResponse: savable,
                bodyFileName: savable.map {
                    HTTPBodyFileName.suggested(
                        target: exchange.target, contentType: $0.contentType, contentEncoding: $0.contentEncoding
                    )
                }
            )
        }
        serverIsAToB = !conversation.clientIsAToB
        var notes: [String] = []
        switch conversation.stop {
        case .exchangeLimit:
            notes.append("Only the first \(HTTPExchangeReader.maximumExchanges) requests are listed.")
        case .requestCutShort:
            notes.append("The retained bytes end inside a request.")
        case .responseCutShort:
            notes.append("The retained bytes end inside a response, or it ran until the connection closed.")
        case .notHTTP:
            notes.append("The connection stopped carrying HTTP/1 messages here, for example after an upgrade.")
        case .malformed:
            notes.append("A message here declared its length in a way that can’t be trusted, so reading stopped.")
        case nil:
            break
        }
        if skipped > 0 {
            notes.append(skipped == 1
                ? "The capture began after one request was sent; its response is not listed."
                : "The capture began after \(skipped) requests were sent; their responses are not listed.")
        }
        if result.aToB.runs.count > 1 || result.bToA.runs.count > 1 {
            notes.append("Messages after a gap in the stream were not read.")
        }
        self.notes = notes
    }

    // MARK: Internal

    let rows: [FollowHTTPExchangeRow]
    /// Why the list may be shorter than the conversation. At most two lines.
    let notes: [String]
    /// Which direction carried the responses, for reading a body back out.
    let serverIsAToB: Bool

    /// The de-chunked body of `row`'s response, read from `result`'s leading run.
    func responseBody(of row: FollowHTTPExchangeRow, in result: FollowStreamResult) -> [UInt8]? {
        guard let message = row.savableResponse,
              let run = (serverIsAToB ? result.aToB : result.bToA).runs.first else
        {
            return nil
        }
        return HTTPExchangeReader.body(of: message, in: run.bytes)
    }

    // MARK: Private

    /// Leading responses passed over at most, before pairing is abandoned.
    private static let maximumSkippedResponses = 8

    /// Whether the first exchange's response starts in a frame captured after the
    /// frame that started its request (capture order, so untimed frames count).
    /// With no response, or no frame known for either, there is nothing to contradict.
    private static func firstResponseFollowsItsRequest(
        _ conversation: HTTPConversation,
        result: FollowStreamResult
    )
        -> Bool
    {
        guard let exchange = conversation.exchanges.first, let response = exchange.response else {
            return true
        }
        let client = conversation.clientIsAToB ? result.aToB : result.bToA
        let server = conversation.clientIsAToB ? result.bToA : result.aToB
        guard let clientRun = client.runs.first, let serverRun = server.runs.first,
              let request = client.firstFrame(ofByte: exchange.request.offset, in: clientRun),
              let reply = server.firstFrame(ofByte: response.offset, in: serverRun) else
        {
            return true
        }
        return reply.ordinal.rawValue > request.ordinal.rawValue
    }

    private static func statusLabel(_ exchange: HTTPExchange) -> String {
        guard let status = exchange.status else {
            return "No response"
        }
        let reason = exchange.reason?.trimmingCharacters(in: .whitespaces) ?? ""
        let line = reason.isEmpty ? "\(status)" : "\(status) \(reason)"
        return exchange.response?.isComplete == false ? "\(line), cut short" : line
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

// MARK: - HTTPBodyFileName

/// A safe file name for a saved HTTP body: the last path component of the request
/// target when it names a file, else `response`, with an extension from the
/// Content-Type when the name has none, and a coding suffix (`.gz`, `.br`) when the
/// body is still content-coded — it is saved exactly as sent.
nonisolated enum HTTPBodyFileName {
    // MARK: Internal

    static func suggested(target: String, contentType: String?, contentEncoding: String?) -> String {
        let path = target.split(separator: "?", maxSplits: 1).first.map(String.init) ?? target
        let last = path.split(separator: "/").last.map(String.init) ?? ""
        var name = String(
            (last.removingPercentEncoding ?? last)
                .map { "/:\\".contains($0) || $0.isNewline || $0 == "\0" ? "_" : $0 }
                .prefix(100)
        )
        if name.isEmpty || name.hasPrefix(".") {
            name = "response"
        }
        if !name.contains("."), let ext = contentType.flatMap(extensionFor(contentType:)) {
            name += ".\(ext)"
        }
        switch contentEncoding?.lowercased().trimmingCharacters(in: .whitespaces) {
        case "gzip",
             "x-gzip": name += ".gz"
        case "br": name += ".br"
        case "deflate": name += ".deflate"
        case "zstd": name += ".zst"
        default: break
        }
        return name
    }

    // MARK: Private

    private static func extensionFor(contentType: String) -> String? {
        let type = contentType.split(separator: ";").first.map {
            $0.trimmingCharacters(in: .whitespaces).lowercased()
        } ?? ""
        let known: [String: String] = [
            "text/html": "html", "text/plain": "txt", "text/css": "css", "text/javascript": "js",
            "application/javascript": "js", "application/json": "json", "application/xml": "xml",
            "text/xml": "xml", "image/png": "png", "image/jpeg": "jpg", "image/gif": "gif",
            "image/svg+xml": "svg", "image/webp": "webp", "image/x-icon": "ico",
            "image/vnd.microsoft.icon": "ico", "application/pdf": "pdf", "application/wasm": "wasm",
            "application/zip": "zip", "font/woff2": "woff2", "font/woff": "woff",
        ]
        return known[type]
    }
}
