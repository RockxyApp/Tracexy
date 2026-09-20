import Foundation
import Testing
@testable import Tracexy

// MARK: - LocalAssistantProviderTests

/// Exercises the shipped adapter against a real loopback socket: real status
/// codes, real redirects, real chunk boundaries and real cancellation.
@Suite("Local assistant adapter: discovery, streaming bounds, redirects and cancellation")
struct LocalAssistantProviderTests {
    // MARK: Internal

    @Test("Ollama-native discovery is preferred and reported as Ollama")
    func discoversOllama() async throws {
        let server = LoopbackHTTPServer { path in
            guard path == "/api/tags" else {
                return .init(status: 404, chunks: ["{}"])
            }
            return .json(#"{"models":[{"name":"llama3.2:3b"},{"name":"qwen2.5:7b"}]}"#)
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        let discovery = try await provider.discover()
        #expect(discovery.kind == .ollama)
        #expect(discovery.models.map(\.id) == ["llama3.2:3b", "qwen2.5:7b"])
        #expect(discovery.omittedModelCount == 0)
    }

    @Test("An endpoint that only speaks the OpenAI-compatible API is labelled as such, not claimed")
    func discoversOpenAICompatible() async throws {
        let server = LoopbackHTTPServer { path in
            switch path {
            case "/v1/models": .json(#"{"data":[{"id":"local-model"}]}"#)
            default: .init(status: 404, chunks: ["{}"])
            }
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        let discovery = try await provider.discover()
        #expect(discovery.kind == .localOpenAICompatible)
        #expect(discovery.kind.label == "Local OpenAI-compatible")
        #expect(discovery.models.map(\.id) == ["local-model"])
    }

    @Test("An endpoint that is not a model API is a typed refusal")
    func rejectsNonModelEndpoint() async throws {
        let server = LoopbackHTTPServer { _ in .init(status: 404, chunks: ["not found"]) }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        await #expect(throws: AssistantError.notALocalModelEndpoint) {
            _ = try await provider.discover()
        }
    }

    @Test("The advertised model list is bounded and the overflow is counted")
    func discoveryIsBounded() async throws {
        let names = (0 ..< (AssistantLimits.maxModels + 25)).map { "{\"name\":\"model-\($0)\"}" }
        let body = "{\"models\":[\(names.joined(separator: ","))]}"
        let server = LoopbackHTTPServer { path in
            path == "/api/tags" ? .json(body) : .init(status: 404, chunks: ["{}"])
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        let discovery = try await provider.discover()
        #expect(discovery.models.count == AssistantLimits.maxModels)
        #expect(discovery.omittedModelCount == 25)
    }

    @Test("An oversized discovery body is refused while it is being read")
    func oversizedDiscoveryIsRefusedIncrementally() async throws {
        let giant = String(repeating: "x", count: AssistantLimits.maxDiscoveryBytes + 512)
        let server = LoopbackHTTPServer { path in
            path == "/api/tags" ? .json(giant) : .init(status: 404, chunks: ["{}"])
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        await #expect(throws: AssistantError.notALocalModelEndpoint) {
            _ = try await provider.discover()
        }
    }

    @Test("A redirect off this Mac is refused and nothing is sent there")
    func rejectsNonLoopbackRedirect() async throws {
        let server = LoopbackHTTPServer { _ in
            .init(
                status: 302,
                headers: ["Location": "http://model.example.com/api/tags"],
                chunks: []
            )
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        await #expect(throws: AssistantError.redirectRejected) {
            _ = try await provider.discover()
        }
    }

    @Test("A streamed answer arrives incrementally, in order, and completes")
    func streamsIncrementally() async throws {
        let server = LoopbackHTTPServer { path in
            guard path == "/api/chat" else {
                return .init(status: 404, chunks: ["{}"])
            }
            return .init(chunks: [
                #"{"message":{"content":"A "},"done":false}"# + "\n",
                #"{"message":{"content":"reset "},"done":false}"# + "\n",
                #"{"message":{"content":"was observed."},"done":false}"# + "\n",
                #"{"done":true,"done_reason":"stop"}"# + "\n",
            ])
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        var tokens: [String] = []
        var completed = false
        for try await event in provider.stream(Self.request, kind: .ollama) {
            switch event {
            case let .token(text): tokens.append(text)
            case .completed: completed = true
            case .truncated: Issue.record("Unexpected truncation")
            }
        }
        #expect(tokens == ["A ", "reset ", "was observed."])
        #expect(completed)
    }

    @Test("A fragment split across chunk boundaries still decodes exactly once")
    func handlesSplitLines() async throws {
        let line = #"{"message":{"content":"partial fragment"},"done":false}"# + "\n"
        let midpoint = line.index(line.startIndex, offsetBy: 20)
        let server = LoopbackHTTPServer { path in
            guard path == "/api/chat" else {
                return .init(status: 404, chunks: ["{}"])
            }
            return .init(chunks: [
                String(line[line.startIndex ..< midpoint]),
                String(line[midpoint...]),
                #"{"done":true}"# + "\n",
            ])
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        var text = ""
        for try await event in provider.stream(Self.request, kind: .ollama) {
            if case let .token(fragment) = event {
                text += fragment
            }
        }
        #expect(text == "partial fragment")
    }

    @Test("A malformed line ends the stream as a controlled error")
    func malformedStreamIsControlled() async throws {
        let server = LoopbackHTTPServer { path in
            guard path == "/api/chat" else {
                return .init(status: 404, chunks: ["{}"])
            }
            return .init(chunks: [
                #"{"message":{"content":"ok"},"done":false}"# + "\n",
                "<html>not json</html>\n",
            ])
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        var text = ""
        var thrown: (any Error)?
        do {
            for try await event in provider.stream(Self.request, kind: .ollama) {
                if case let .token(fragment) = event {
                    text += fragment
                }
            }
        } catch {
            thrown = error
        }
        #expect(text == "ok")
        #expect(thrown as? AssistantError == .malformedStream)
    }

    @Test("An oversized stream line is refused rather than buffered")
    func oversizedLineIsRefused() async throws {
        let giant = String(repeating: "x", count: AssistantLimits.maxLineBytes + 512)
        let server = LoopbackHTTPServer { path in
            guard path == "/api/chat" else {
                return .init(status: 404, chunks: ["{}"])
            }
            return .init(chunks: [giant + "\n"])
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        var thrown: (any Error)?
        do {
            for try await _ in provider.stream(Self.request, kind: .ollama) {}
        } catch {
            thrown = error
        }
        #expect(thrown as? AssistantError == .streamLineTooLong)
    }

    @Test("EOF without a done marker keeps text but reports an incomplete answer")
    func unexpectedEOFIsIncomplete() async throws {
        let server = LoopbackHTTPServer { path in
            guard path == "/api/chat" else {
                return .init(status: 404, chunks: ["{}"])
            }
            return .init(chunks: [#"{"message":{"content":"partial"},"done":false}"# + "\n"])
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        var events: [AssistantStreamEvent] = []
        for try await event in provider.stream(Self.request, kind: .ollama) {
            events.append(event)
        }
        #expect(events == [.token("partial"), .truncated(.unexpectedEnd)])
    }

    @Test("Output past the answer-length limit is truncated and explicitly reported")
    func outputLimitIsReported() async throws {
        let long = String(repeating: "y", count: AssistantLimits.maxOutputCharacters + 100)
        let body = "{\"message\":{\"content\":\"\(long)\"},\"done\":false}\n"
        let server = LoopbackHTTPServer { path in
            guard path == "/api/chat" else {
                return .init(status: 404, chunks: ["{}"])
            }
            return .init(chunks: [body, #"{"done":true}"# + "\n"])
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        var text = ""
        var truncation: AssistantTruncationReason?
        for try await event in provider.stream(Self.request, kind: .ollama) {
            switch event {
            case let .token(fragment): text += fragment
            case let .truncated(reason): truncation = reason
            case .completed: break
            }
        }
        #expect(text.count == AssistantLimits.maxOutputCharacters)
        #expect(truncation == .outputLimit)
    }

    @Test("A non-success status is a typed error carrying only the code")
    func httpStatusIsTyped() async throws {
        let server = LoopbackHTTPServer { _ in .init(status: 500, chunks: ["boom"]) }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        var thrown: (any Error)?
        do {
            for try await _ in provider.stream(Self.request, kind: .ollama) {}
        } catch {
            thrown = error
        }
        #expect(thrown as? AssistantError == .httpStatus(500))
    }

    @Test("An unreachable endpoint is a typed error, not a hang")
    func unreachableEndpointIsTyped() async throws {
        // Bind and immediately release a port so nothing is listening on it.
        let server = LoopbackHTTPServer { _ in .init() }
        let endpoint = try server.start()
        server.stop()
        let provider = LocalAssistantProvider(endpoint: endpoint)

        await #expect(throws: AssistantError.unreachable) {
            _ = try await provider.discover()
        }
    }

    @Test("Cancelling the consuming task stops the stream promptly")
    func cancellationStopsTheStream() async throws {
        let server = LoopbackHTTPServer { path in
            guard path == "/api/chat" else {
                return .init(status: 404, chunks: ["{}"])
            }
            // A long, slow stream that would never finish inside the test.
            return .init(
                chunks: (0 ..< 500).map { #"{"message":{"content":"tick\#($0) "},"done":false}"# + "\n" },
                chunkDelay: .milliseconds(20)
            )
        }
        defer { server.stop() }
        let provider = try LocalAssistantProvider(endpoint: server.start())

        let collected = Collector()
        let task = Task {
            for try await event in provider.stream(Self.request, kind: .ollama) {
                if case .token = event {
                    await collected.increment()
                }
            }
        }
        // Wait for real fragments rather than a fixed delay, so a loaded machine
        // cancels a *running* stream instead of one that never started.
        for _ in 0 ..< 200 where await collected.isEmpty {
            try await Task.sleep(for: .milliseconds(25))
        }
        task.cancel()
        _ = try? await task.value

        let seen = await collected.count
        #expect(seen > 0)
        #expect(seen < 500)
    }

    // MARK: Private

    /// A tiny actor so the streamed count crosses isolation safely.
    private actor Collector {
        private(set) var count = 0

        /// Spelled as a property rather than compared against zero at the call
        /// site, so the formatter's `count == 0` → `isEmpty` rewrite has a real
        /// member to land on.
        var isEmpty: Bool {
            count == 0
        }

        func increment() {
            count += 1
        }
    }

    private static var request: AssistantChatRequest {
        AssistantChatRequest(
            model: "llama3.2:3b",
            systemPrompt: AssistantSessionModel.systemPrompt,
            userPrompt: "Summarize this session.",
            briefJSON: "{\"schemaVersion\":1}"
        )
    }
}
