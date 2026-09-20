import Foundation
import Testing
@testable import Tracexy

// MARK: - LocalModelAvailability

/// A synchronous reachability probe for a real local Ollama daemon.
///
/// It exists so this suite is *skipped* rather than failed on a machine without
/// the model installed — the coverage is real when the model is present and
/// honestly absent when it is not.
enum LocalModelAvailability {
    // MARK: Internal

    static let modelID = "llama3.2:3b"

    static var isReachable: Bool {
        state.reachable
    }

    static var installedModels: [String] {
        state.models
    }

    // MARK: Private

    private static let state: (reachable: Bool, models: [String]) = {
        guard let endpoint = try? AssistantLocalEndpoint.standard() else {
            return (false, [])
        }
        var request = URLRequest(url: endpoint.url(path: "api/tags"))
        request.timeoutInterval = 2
        let semaphore = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var models: [String] = []
        URLSession.shared.dataTask(with: request) { data, response, _ in
            defer { semaphore.signal() }
            guard let data,
                  let http = response as? HTTPURLResponse,
                  http.statusCode == 200,
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let raw = object["models"] as? [[String: Any]] else
            {
                return
            }
            models = raw.compactMap { $0["name"] as? String }
        }.resume()
        _ = semaphore.wait(timeout: .now() + 5)
        return (models.contains(modelID), models)
    }()
}

// MARK: - LocalModelLiveE2ETests

/// End-to-end coverage against a **real** local model.
///
/// Every byte sent here is the same bounded, documentation-range brief the app
/// would send, and the destination is `127.0.0.1` by construction — the adapter
/// cannot be pointed anywhere else, and the non-loopback refusals are asserted
/// alongside the live exchange.
@Suite(
    "Local model E2E: real Ollama llama3.2:3b streaming and cancellation",
    .enabled(if: LocalModelAvailability.isReachable, "Requires a local Ollama with llama3.2:3b"),
    .serialized
)
struct LocalModelLiveE2ETests {
    // MARK: Internal

    @Test("Discovery finds the real daemon and reports it as Ollama")
    func discoversRealDaemon() async throws {
        let provider = try LocalAssistantProvider(endpoint: AssistantLocalEndpoint.standard())
        let discovery = try await provider.discover()
        #expect(discovery.kind == .ollama)
        #expect(discovery.models.contains { $0.id == LocalModelAvailability.modelID })
    }

    @Test("A bounded fixture brief streams a real answer to completion", .timeLimit(.minutes(2)))
    func streamsRealAnswer() async throws {
        let provider = try LocalAssistantProvider(endpoint: AssistantLocalEndpoint.standard())
        let request = try Self.request(prompt: """
        In one short sentence, what does this evidence show? \
        Cite one citation id from the brief.
        """)

        var text = ""
        var completed = false
        for try await event in provider.stream(request, kind: .ollama) {
            switch event {
            case let .token(fragment):
                text += fragment
            case .completed:
                completed = true
            case let .truncated(reason):
                // A bound is a legitimate outcome, and it is explicitly labelled.
                Issue.record("Truncated at \(reason.rawValue) — the answer is incomplete, not wrong")
                completed = true
            }
        }
        #expect(completed)
        #expect(!text.isEmpty)
        #expect(text.count <= AssistantLimits.maxOutputCharacters)
    }

    @Test("Cancelling a real stream stops it promptly", .timeLimit(.minutes(2)))
    func cancellationIsPrompt() async throws {
        let provider = try LocalAssistantProvider(endpoint: AssistantLocalEndpoint.standard())
        let request = try Self.request(prompt: """
        Write a long, detailed, multi-paragraph explanation of every observation in the brief.
        """)

        let collected = Collector()
        let started = Date()
        let task = Task {
            for try await event in provider.stream(request, kind: .ollama) {
                if case let .token(fragment) = event {
                    await collected.append(fragment)
                }
            }
        }
        // Wait for real tokens, then cancel.
        for _ in 0 ..< 600 where await collected.text.isEmpty {
            try await Task.sleep(for: .milliseconds(50))
        }
        #expect(await !(collected.text.isEmpty), "The model produced no tokens to cancel")
        task.cancel()
        _ = try? await task.value
        let elapsed = Date().timeIntervalSince(started)

        let afterCancel = await collected.text
        try await Task.sleep(for: .milliseconds(400))
        // Nothing is adopted after cancellation.
        #expect(await collected.text == afterCancel)
        #expect(elapsed < 60)
    }

    @Test("What is sent is exactly the reviewed brief, and nothing else leaves the app")
    func payloadIsExactlyTheBrief() throws {
        let build = try Self.build()
        let json = try build.brief.canonicalJSON()

        // The brief carries no raw evidence — re-asserted structurally on the exact
        // bytes that go to the model, not merely on the builder. The scan walks
        // decoded *keys*: a text search would false-positive on the redaction
        // statement, which names the excluded families as values on purpose.
        let object = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let leaked = Self.keys(in: object).intersection(AssistantEvidenceBriefTests.forbiddenKeys)
        #expect(leaked.isEmpty, "Brief leaked keys \(leaked.sorted())")
        #expect(!json.contains("service.example.com"), "Host disclosure is off by default")
        #expect(!json.contains("192.0.2.10"), "Endpoint disclosure is off by default")
        #expect(json.contains("\"neverIncluded\""))

        // And the destination cannot be anywhere but this Mac.
        #expect(throws: (any Error).self) {
            try AssistantLocalEndpoint.validate("http://ollama.example.com:11434")
        }
    }

    // MARK: Private

    private actor Collector {
        private(set) var text = ""

        func append(_ fragment: String) {
            text += fragment
        }
    }

    /// Every key name anywhere in the decoded brief.
    private static func keys(in value: Any) -> Set<String> {
        if let dictionary = value as? [String: Any] {
            var found = Set(dictionary.keys)
            for nested in dictionary.values {
                found.formUnion(keys(in: nested))
            }
            return found
        }
        if let array = value as? [Any] {
            return array.reduce(into: Set<String>()) { $0.formUnion(keys(in: $1)) }
        }
        return []
    }

    private static func build() throws -> AssistantBriefBuild {
        try AssistantBriefBuilder.build(
            snapshot: AssistantDemoFixture.snapshot(),
            sessionID: AssistantDemoFixture.sessionID,
            projectID: AssistantDemoFixture.projectID,
            disclosure: .minimum
        )
    }

    private static func request(prompt: String) throws -> AssistantChatRequest {
        try AssistantChatRequest(
            model: LocalModelAvailability.modelID,
            systemPrompt: AssistantSessionModel.systemPrompt,
            userPrompt: prompt,
            briefJSON: build().brief.canonicalJSON()
        )
    }
}
