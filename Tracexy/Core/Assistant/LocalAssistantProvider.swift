import Foundation

// The one shipped ``AssistantProviding`` conformance: a credential-free HTTP
// adapter that only ever talks to a loopback endpoint the user chose.
//
// It sends no API key, no bearer token, no cookie and no custom identity header;
// it uses an ephemeral session with cookie, cache and credential storage removed,
// so there is nothing to leak and nothing to persist. Every redirect target is
// re-validated as loopback before it is followed, and a target that is not is
// refused outright rather than followed and then judged.

// MARK: - AssistantStreamFragment

/// One decoded piece of a streamed answer.
nonisolated struct AssistantStreamFragment: Sendable, Equatable {
    /// The text this line contributed, possibly empty.
    let text: String
    /// Whether this line ended the stream.
    let isDone: Bool
    /// The endpoint's own finish reason, when it supplied one.
    let finishReason: String?
}

// MARK: - AssistantStreamDecoder

/// Pure, line-at-a-time decoding for the two streamed shapes this adapter reads.
/// Kept separate from the transport so fragmentation, malformed lines and
/// terminators are testable without a server.
nonisolated enum AssistantStreamDecoder {
    /// Decode one NDJSON line from an Ollama `/api/chat` stream. Every non-blank
    /// line must be a JSON object; anything else is a controlled error, never a
    /// silently skipped fragment.
    static func ollama(line: String) throws -> AssistantStreamFragment? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        guard let object = try? JSONSerialization.jsonObject(with: Data(trimmed.utf8)),
              let dictionary = object as? [String: Any] else
        {
            throw AssistantError.malformedStream
        }
        // An endpoint that reports its own error mid-stream is a controlled
        // failure, not a fragment to append.
        if dictionary["error"] != nil {
            throw AssistantError.malformedStream
        }
        let message = dictionary["message"] as? [String: Any]
        let text = (message?["content"] as? String) ?? ""
        let isDone = (dictionary["done"] as? Bool) ?? false
        return AssistantStreamFragment(
            text: text,
            isDone: isDone,
            finishReason: dictionary["done_reason"] as? String
        )
    }

    /// Decode one Server-Sent-Events line from an OpenAI-compatible stream.
    /// Comments, blank lines and non-`data:` fields are ignorable by the SSE
    /// specification and return `nil`.
    static func openAICompatible(line: String) throws -> AssistantStreamFragment? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix(":") else {
            return nil
        }
        guard trimmed.hasPrefix("data:") else {
            // `event:`, `id:` and `retry:` are valid SSE fields this reader ignores.
            guard trimmed.contains(":") else {
                throw AssistantError.malformedStream
            }
            return nil
        }
        let payload = trimmed.dropFirst("data:".count).trimmingCharacters(in: .whitespaces)
        guard payload != "[DONE]" else {
            return AssistantStreamFragment(text: "", isDone: true, finishReason: nil)
        }
        guard let object = try? JSONSerialization.jsonObject(with: Data(payload.utf8)),
              let dictionary = object as? [String: Any] else
        {
            throw AssistantError.malformedStream
        }
        if dictionary["error"] != nil {
            throw AssistantError.malformedStream
        }
        let choices = dictionary["choices"] as? [[String: Any]]
        let first = choices?.first
        let delta = first?["delta"] as? [String: Any]
        let text = (delta?["content"] as? String) ?? ""
        let reason = first?["finish_reason"] as? String
        return AssistantStreamFragment(text: text, isDone: reason != nil, finishReason: reason)
    }
}

// MARK: - LoopbackRedirectGuard

/// Refuses any redirect that leaves this Mac, and records that it did so.
///
/// `URLSession` is told not to follow the redirect by completing with `nil`,
/// which surfaces the 3xx itself; the recorded flag is what turns that into the
/// precise ``AssistantError/redirectRejected`` rather than a generic status.
private final class LoopbackRedirectGuard: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    // MARK: Internal

    var didRejectRedirect: Bool {
        lock.withLock { rejected }
    }

    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let url = request.url, let canonical = AssistantLocalEndpoint.canonicalLoopbackURL(url) else {
            lock.withLock { rejected = true }
            completionHandler(nil)
            return
        }
        // Follow the numeric loopback address, never the name a redirect used.
        var next = request
        next.url = canonical
        completionHandler(next)
    }

    // MARK: Private

    private let lock = NSLock()
    private var rejected = false
}

// MARK: - LocalAssistantProvider

/// The shipped local adapter.
nonisolated struct LocalAssistantProvider: AssistantProviding {
    // MARK: Lifecycle

    init(endpoint: AssistantLocalEndpoint, session: URLSession? = nil) {
        self.endpoint = endpoint
        self.session = session ?? Self.makeSession()
    }

    // MARK: Internal

    let endpoint: AssistantLocalEndpoint

    /// Discover which local API answers, preferring the Ollama-native path. An
    /// endpoint that only answers the OpenAI-compatible path is labelled as such
    /// — the app never claims to know which server it is.
    func discover() async throws -> AssistantDiscovery {
        if let discovery = try await discoverOllama() {
            return discovery
        }
        if let discovery = try await discoverOpenAICompatible() {
            return discovery
        }
        throw AssistantError.notALocalModelEndpoint
    }

    func stream(
        _ request: AssistantChatRequest,
        kind: AssistantProviderKind
    )
        -> AsyncThrowingStream<AssistantStreamEvent, Error>
    {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    try await self.run(request, kind: kind, into: continuation)
                    continuation.finish()
                } catch is CancellationError {
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    // MARK: Private

    private let session: URLSession

    /// Cookies, caches and credentials are removed rather than merely unused, so
    /// a local exchange leaves nothing behind and can carry nothing forward.
    private static func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = AssistantLimits.firstByteTimeout
        configuration.timeoutIntervalForResource = AssistantLimits.totalTimeout
        configuration.waitsForConnectivity = false
        return URLSession(configuration: configuration)
    }

    /// The user turn: the question, then the reviewed brief verbatim under a
    /// labelled fence so the model can tell instruction from evidence.
    private static func userContent(_ request: AssistantChatRequest) -> String {
        """
        \(request.userPrompt)

        EVIDENCE BRIEF (JSON, the complete set of facts available):
        \(request.briefJSON)
        """
    }

    // MARK: Discovery

    private func discoverOllama() async throws -> AssistantDiscovery? {
        guard let data = try await get(path: "api/tags") else {
            return nil
        }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let raw = object["models"] as? [[String: Any]] else
        {
            return nil
        }
        let names = raw.compactMap { $0["name"] as? String }.filter { !$0.isEmpty }
        return discovery(kind: .ollama, names: names)
    }

    private func discoverOpenAICompatible() async throws -> AssistantDiscovery? {
        guard let data = try await get(path: "v1/models") else {
            return nil
        }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let raw = object["data"] as? [[String: Any]] else
        {
            return nil
        }
        let names = raw.compactMap { $0["id"] as? String }.filter { !$0.isEmpty }
        return discovery(kind: .localOpenAICompatible, names: names)
    }

    private func discovery(kind: AssistantProviderKind, names: [String]) -> AssistantDiscovery {
        let unique = NSOrderedSet(array: names).compactMap { $0 as? String }
        let bounded = unique.prefix(AssistantLimits.maxModels)
        return AssistantDiscovery(
            kind: kind,
            models: bounded.map { AssistantModel(id: $0, name: $0) },
            omittedModelCount: max(0, unique.count - bounded.count)
        )
    }

    /// One bounded GET. Returns `nil` when the endpoint answered with a non-success
    /// status — a probe that misses is not an error, it is the next probe's cue.
    private func get(path: String) async throws -> Data? {
        var request = URLRequest(url: endpoint.url(path: path))
        request.httpMethod = "GET"
        request.timeoutInterval = AssistantLimits.discoveryTimeout
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let guardDelegate = LoopbackRedirectGuard()
        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: request, delegate: guardDelegate)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError where error.code == .cancelled {
            // A cancelled task is not an unreachable endpoint. Reporting it as one
            // would tell the user their model is down because a view went away.
            throw CancellationError()
        } catch {
            if guardDelegate.didRejectRedirect {
                throw AssistantError.redirectRejected
            }
            throw AssistantError.unreachable
        }
        if guardDelegate.didRejectRedirect {
            throw AssistantError.redirectRejected
        }
        guard let http = response as? HTTPURLResponse, (200 ... 299).contains(http.statusCode) else {
            return nil
        }

        // Read incrementally so a hostile local endpoint cannot make URLSession
        // materialize an unbounded model list before Tracexy checks its limit.
        var data = Data()
        data.reserveCapacity(min(16_384, AssistantLimits.maxDiscoveryBytes))
        do {
            for try await byte in bytes {
                try Task.checkCancellation()
                guard data.count < AssistantLimits.maxDiscoveryBytes else {
                    return nil
                }
                data.append(byte)
            }
        } catch let error as URLError where error.code == .timedOut {
            throw AssistantError.timedOut
        }
        return data
    }

    // MARK: Streaming

    private func run(
        _ request: AssistantChatRequest,
        kind: AssistantProviderKind,
        into continuation: AsyncThrowingStream<AssistantStreamEvent, Error>.Continuation
    )
        async throws
    {
        let urlRequest = try chatRequest(request, kind: kind)
        let guardDelegate = LoopbackRedirectGuard()

        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: urlRequest, delegate: guardDelegate)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError where error.code == .cancelled {
            throw CancellationError()
        } catch let error as URLError where error.code == .timedOut {
            throw AssistantError.timedOut
        } catch {
            if guardDelegate.didRejectRedirect {
                throw AssistantError.redirectRejected
            }
            throw AssistantError.unreachable
        }
        if guardDelegate.didRejectRedirect {
            throw AssistantError.redirectRejected
        }
        guard let http = response as? HTTPURLResponse else {
            throw AssistantError.unreachable
        }
        guard (200 ... 299).contains(http.statusCode) else {
            throw AssistantError.httpStatus(http.statusCode)
        }

        let deadline = Date().addingTimeInterval(AssistantLimits.totalTimeout)
        var responseBytes = 0
        var outputCharacters = 0
        var didYieldText = false
        var lineData = Data()
        lineData.reserveCapacity(min(4_096, AssistantLimits.maxLineBytes))

        /// Decode and publish one already-bounded line. Returns `true` when the
        /// provider emitted an explicit terminal event and the caller must stop.
        func consumeLine(_ data: Data) throws -> Bool {
            var content = data
            if content.last == 0x0D {
                content.removeLast()
            }
            guard let line = String(data: content, encoding: .utf8) else {
                throw AssistantError.malformedStream
            }
            guard let fragment = try decode(line: line, kind: kind) else {
                return false
            }
            if !fragment.text.isEmpty {
                let remaining = AssistantLimits.maxOutputCharacters - outputCharacters
                guard remaining > 0 else {
                    continuation.yield(.truncated(.outputLimit))
                    return true
                }
                let text = fragment.text.count <= remaining
                    ? fragment.text
                    : String(fragment.text.prefix(remaining))
                outputCharacters += text.count
                didYieldText = true
                continuation.yield(.token(text))
                if text.count < fragment.text.count {
                    continuation.yield(.truncated(.outputLimit))
                    return true
                }
            }
            if fragment.isDone {
                continuation.yield(.completed(reason: fragment.finishReason))
                return true
            }
            return false
        }

        do {
            for try await byte in bytes {
                try Task.checkCancellation()
                responseBytes += 1
                guard responseBytes <= AssistantLimits.maxResponseBytes else {
                    continuation.yield(.truncated(.responseSizeLimit))
                    return
                }
                guard Date() < deadline else {
                    continuation.yield(.truncated(.timeLimit))
                    return
                }

                if byte == 0x0A {
                    if try consumeLine(lineData) {
                        return
                    }
                    lineData.removeAll(keepingCapacity: true)
                } else {
                    // Refuse on the first byte past the cap; at no point is an
                    // oversized no-newline fragment held in memory.
                    guard lineData.count < AssistantLimits.maxLineBytes else {
                        throw AssistantError.streamLineTooLong
                    }
                    lineData.append(byte)
                }
            }
        } catch let error as URLError where error.code == .timedOut {
            throw AssistantError.timedOut
        }
        if !lineData.isEmpty, try consumeLine(lineData) {
            return
        }
        // EOF is not completion. Preserve any real partial text but label it
        // incomplete; an empty unterminated body is simply malformed.
        guard didYieldText else {
            throw AssistantError.malformedStream
        }
        continuation.yield(.truncated(.unexpectedEnd))
    }

    private func decode(line: String, kind: AssistantProviderKind) throws -> AssistantStreamFragment? {
        switch kind {
        case .ollama: try AssistantStreamDecoder.ollama(line: line)
        case .localOpenAICompatible: try AssistantStreamDecoder.openAICompatible(line: line)
        }
    }

    private func chatRequest(_ request: AssistantChatRequest, kind: AssistantProviderKind) throws -> URLRequest {
        let messages: [[String: Any]] = [
            ["role": "system", "content": request.systemPrompt],
            ["role": "user", "content": Self.userContent(request)],
        ]
        let body: [String: Any] = switch kind {
        case .ollama:
            [
                "model": request.model,
                "stream": true,
                "messages": messages,
                "options": ["num_predict": AssistantLimits.maxOutputTokens, "temperature": 0.2],
            ]
        case .localOpenAICompatible:
            [
                "model": request.model,
                "stream": true,
                "messages": messages,
                "max_tokens": AssistantLimits.maxOutputTokens,
                "temperature": 0.2,
            ]
        }

        guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) else {
            throw AssistantError.requestTooLarge
        }
        guard data.count <= AssistantLimits.maxRequestBytes else {
            throw AssistantError.requestTooLarge
        }

        let path = kind == .ollama ? "api/chat" : "v1/chat/completions"
        var urlRequest = URLRequest(url: endpoint.url(path: path))
        urlRequest.httpMethod = "POST"
        urlRequest.httpBody = data
        urlRequest.timeoutInterval = AssistantLimits.firstByteTimeout
        // Exactly two headers. No authorization, no api key, no identity.
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        return urlRequest
    }
}
