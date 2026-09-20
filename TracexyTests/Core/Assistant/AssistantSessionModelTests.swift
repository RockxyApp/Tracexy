import Foundation
import Testing
@testable import Tracexy

// MARK: - StubAssistantProvider

/// A scripted provider so the lifecycle can be exercised without a socket.
private final class StubAssistantProvider: AssistantProviding, @unchecked Sendable {
    // MARK: Lifecycle

    init(
        endpoint: AssistantLocalEndpoint,
        discovery: AssistantDiscovery,
        script: @escaping @Sendable (AsyncThrowingStream<AssistantStreamEvent, Error>.Continuation) async -> Void
    ) {
        self.endpoint = endpoint
        self.discovery = discovery
        self.script = script
    }

    // MARK: Internal

    let endpoint: AssistantLocalEndpoint
    private(set) var sentRequests: [AssistantChatRequest] = []

    func discover() async throws -> AssistantDiscovery {
        discovery
    }

    func stream(
        _ request: AssistantChatRequest,
        kind _: AssistantProviderKind
    )
        -> AsyncThrowingStream<AssistantStreamEvent, Error>
    {
        lock.withLock { sentRequests.append(request) }
        return AsyncThrowingStream { continuation in
            let task = Task {
                await script(continuation)
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    // MARK: Private

    private let discovery: AssistantDiscovery
    private let script: @Sendable (AsyncThrowingStream<AssistantStreamEvent, Error>.Continuation) async -> Void
    private let lock = NSLock()
}

// MARK: - AssistantSessionModelTests

@Suite("Assistant lifecycle: the review gate, guarded adoption and bounded conversations")
@MainActor
struct AssistantSessionModelTests {
    // MARK: Internal

    @Test("The first send is held for review and nothing is sent until it is approved")
    func firstSendRequiresReview() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }

        harness.model.composerText = "What happened?"
        await harness.model.send(coordinator: harness.coordinator)
        #expect(harness.model.isReviewPresented)
        #expect(harness.model.pendingPrompt == "What happened?")
        #expect(harness.model.messages.isEmpty)
        #expect(harness.provider.sentRequests.isEmpty)

        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        await harness.settle()
        #expect(!harness.model.isReviewPresented)
        #expect(harness.model.messages.count == 2)
        #expect(harness.provider.sentRequests.count == 1)
        // The reviewed bytes are exactly the bytes that were sent.
        #expect(harness.provider.sentRequests[0].briefJSON == harness.model.briefJSON)
    }

    @Test("Cancelling the review sends nothing and clears the pending prompt")
    func cancellingReviewSendsNothing() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }

        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        harness.model.cancelReview()
        #expect(!harness.model.isReviewPresented)
        #expect(harness.model.pendingPrompt == nil)
        #expect(harness.provider.sentRequests.isEmpty)
    }

    @Test("A second send under the same scope skips the sheet")
    func approvalCoversTheSameScope() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }
        try await harness.approveAndSend("First.")

        harness.model.composerText = "Second."
        await harness.model.send(coordinator: harness.coordinator)
        await harness.settle()
        #expect(!harness.model.isReviewPresented)
        #expect(harness.provider.sentRequests.count == 2)
    }

    @Test("Changing the model, the endpoint or the disclosure requires review again")
    func scopeChangesRetireTheApproval() async throws {
        for change in Change.allCases {
            let harness = try await Harness()
            defer { harness.tearDown() }
            try await harness.approveAndSend("First.")

            switch change {
            case .model:
                harness.model.selectModel("other-model")
            case .endpoint:
                harness.model.endpointText = "http://127.0.0.1:9999"
                await harness.model.applyEndpoint("http://127.0.0.1:9999")
            case .disclosure:
                harness.model.setDisclosure(.init(includesHost: true))
            }

            harness.model.composerText = "Second."
            await harness.model.send(coordinator: harness.coordinator)
            #expect(harness.model.isReviewPresented, "\(change) should require review again")
            #expect(harness.provider.sentRequests.count == 1)
        }
    }

    @Test("Changing the selected session requires review again and rebuilds the brief")
    func selectionChangeRetiresTheApproval() async throws {
        let harness = try await Harness(extraSession: true)
        defer { harness.tearDown() }
        try await harness.approveAndSend("First.")

        let other = try #require(harness.coordinator.sessions.last)
        harness.coordinator.select(other)
        await harness.model.refreshBrief(coordinator: harness.coordinator)

        harness.model.composerText = "Second."
        await harness.model.send(coordinator: harness.coordinator)
        #expect(harness.model.isReviewPresented)
        #expect(harness.provider.sentRequests.count == 1)
    }

    @Test("Stopping keeps the partial text and marks it incomplete")
    func stopMarksPartialIncomplete() async throws {
        let harness = try await Harness(script: { continuation in
            continuation.yield(.token("A reset was "))
            // Never completes on its own.
            try? await Task.sleep(for: .seconds(30))
        })
        defer { harness.tearDown() }

        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        try await harness.waitUntil { harness.model.messages.last?.text.isEmpty == false }

        harness.model.stop()
        let answer = try #require(harness.model.messages.last)
        #expect(answer.text == "A reset was ")
        guard case let .incomplete(reason) = answer.state else {
            Issue.record("Expected an incomplete answer, got \(answer.state)")
            return
        }
        #expect(reason.contains("Stopped"))
        #expect(!harness.model.isStreaming)
    }

    @Test("A bound reached mid-stream marks the answer incomplete with its reason")
    func truncationMarksIncomplete() async throws {
        let harness = try await Harness(script: { continuation in
            continuation.yield(.token("Partial"))
            continuation.yield(.truncated(.outputLimit))
        })
        defer { harness.tearDown() }
        try await harness.approveAndSend("Explain.")

        let answer = try #require(harness.model.messages.last)
        #expect(answer.text == "Partial")
        guard case let .incomplete(reason) = answer.state else {
            Issue.record("Expected an incomplete answer, got \(answer.state)")
            return
        }
        #expect(reason.contains("answer-length"))
    }

    @Test("A provider failure becomes actionable copy, never a silent empty answer")
    func failureIsSurfaced() async throws {
        let harness = try await Harness(script: { continuation in
            continuation.finish(throwing: AssistantError.httpStatus(500))
        })
        defer { harness.tearDown() }
        try await harness.approveAndSend("Explain.")

        let answer = try #require(harness.model.messages.last)
        guard case let .failed(message) = answer.state else {
            Issue.record("Expected a failed answer, got \(answer.state)")
            return
        }
        #expect(message == AssistantError.httpStatus(500).message)
    }

    @Test("A Project boundary retires the run and marks the partial answer incomplete")
    func projectBoundaryInvalidatesTheRun() async throws {
        let harness = try await Harness(script: { continuation in
            continuation.yield(.token("Streaming"))
            try? await Task.sleep(for: .seconds(30))
        })
        defer { harness.tearDown() }

        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        try await harness.waitUntil { harness.model.messages.last?.text.isEmpty == false }

        harness.model.invalidateForBoundary()
        #expect(!harness.model.isStreaming)
        #expect(harness.model.brief == nil)

        // The transcript is kept — a Project boundary is not a conversation
        // boundary — and the partial answer is labelled.
        try harness.coordinator.select(#require(harness.coordinator.sessions.first))
        await harness.model.refreshBrief(coordinator: harness.coordinator)
        let answer = try #require(harness.model.messages.last)
        #expect(answer.text == "Streaming")
        guard case .incomplete = answer.state else {
            Issue.record("Expected an incomplete answer, got \(answer.state)")
            return
        }
    }

    @Test("A late token is not adopted after the selection moved on")
    func lateTokenIsNotAdopted() async throws {
        let gate = Gate()
        let harness = try await Harness(extraSession: true, script: { continuation in
            continuation.yield(.token("first"))
            await gate.wait()
            continuation.yield(.token(" late"))
            continuation.yield(.completed(reason: "stop"))
        })
        defer { harness.tearDown() }

        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        try await harness.waitUntil { harness.model.messages.last?.text == "first" }

        // Move the selection, then let the provider emit its late fragment.
        let other = try #require(harness.coordinator.sessions.last)
        harness.coordinator.select(other)
        await gate.open()
        try await harness.waitUntil {
            if case .incomplete = harness.model.messages.last?.state {
                return true
            }
            return false
        }

        let answer = try #require(harness.model.messages.last)
        #expect(answer.text == "first")
    }

    @Test("Changing model, endpoint or disclosure immediately retires a running answer")
    func configurationChangeImmediatelyRetiresRun() async throws {
        for change in Change.allCases {
            let harness = try await Harness(script: { continuation in
                continuation.yield(.token("partial"))
                try? await Task.sleep(for: .seconds(30))
            })
            defer { harness.tearDown() }

            harness.model.composerText = "Explain."
            await harness.model.send(coordinator: harness.coordinator)
            await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
            try await harness.waitUntil { harness.model.messages.last?.text == "partial" }

            switch change {
            case .model:
                harness.model.selectModel("other-model")
            case .endpoint:
                await harness.model.applyEndpoint("http://127.0.0.1:9999")
            case .disclosure:
                harness.model.setDisclosure(.init(includesHost: true))
            }

            #expect(!harness.model.isStreaming)
            guard case .incomplete = harness.model.messages.last?.state else {
                Issue.record("Expected \(change) to retire the active run")
                continue
            }
        }
    }

    @Test("A valid endpoint is normalized before a run is pinned")
    func endpointIsNormalized() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }

        await harness.model.applyEndpoint("  http://127.0.0.1:11434/  ")
        #expect(harness.model.endpointText == "http://127.0.0.1:11434")
    }

    @Test("Conversations are owned per Project workspace and bounded")
    func conversationsAreScopedAndBounded() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }
        try await harness.approveAndSend("First.")
        #expect(harness.model.messages.count == 2)

        harness.model.newConversation()
        #expect(harness.model.messages.isEmpty)

        // The bound drops the oldest turns and counts the drop.
        for index in 0 ..< (AssistantConversationLimits.maxMessages) {
            harness.model.composerText = "Prompt \(index)"
            await harness.model.send(coordinator: harness.coordinator)
            await harness.settle()
        }
        #expect(harness.model.messages.count == AssistantConversationLimits.maxMessages)
        #expect(harness.model.droppedMessageCount > 0)
    }

    @Test("Citations resolve to real provenance and only known ids are clickable")
    func citationsResolve() async throws {
        let harness = try await Harness(script: { continuation in
            continuation.yield(.token("A reset was observed at frame-10, not frame-99999."))
            continuation.yield(.completed(reason: "stop"))
        })
        defer { harness.tearDown() }
        try await harness.approveAndSend("Explain.")

        let answer = try #require(harness.model.messages.last)
        let ids = answer.citationIDs(knownIDs: harness.model.knownCitationIDs)
        #expect(ids == ["frame-10"])
        #expect(harness.model.provenance(forCitation: "frame-10") != nil)
        #expect(harness.model.provenance(forCitation: "frame-99999") == nil)
    }

    @Test("An over-long prompt is refused before anything is built or sent")
    func promptIsBounded() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }
        harness.model.composerText = String(repeating: "x", count: AssistantLimits.maxPromptCharacters + 1)
        await harness.model.send(coordinator: harness.coordinator)
        #expect(!harness.model.isReviewPresented)
        #expect(harness.provider.sentRequests.isEmpty)
    }

    @Test("A budget-limited finish is incomplete, never complete", arguments: ["length", "max_tokens", "LENGTH"])
    func lengthFinishIsIncomplete(_ reason: String) async throws {
        let harness = try await Harness(script: { continuation in
            continuation.yield(.token("Cut off"))
            continuation.yield(.completed(reason: reason))
        })
        defer { harness.tearDown() }
        try await harness.approveAndSend("Explain.")

        let answer = try #require(harness.model.messages.last)
        #expect(answer.text == "Cut off")
        guard case let .incomplete(copy) = answer.state else {
            Issue.record("Expected an incomplete answer for \(reason), got \(answer.state)")
            return
        }
        #expect(copy.contains("answer-length"))
        #expect(!harness.model.isStreaming)
    }

    @Test("An unrecognized finish reason fails conservatively and is never displayed")
    func unrecognizedFinishFailsClosed() async throws {
        let hostile = "content_filter <b>visit evil.example.com</b>"
        let harness = try await Harness(script: { continuation in
            continuation.yield(.token("Partial"))
            continuation.yield(.completed(reason: hostile))
        })
        defer { harness.tearDown() }
        try await harness.approveAndSend("Explain.")

        let answer = try #require(harness.model.messages.last)
        guard case let .failed(message) = answer.state else {
            Issue.record("Expected a failed answer, got \(answer.state)")
            return
        }
        #expect(!message.contains("evil.example.com"))
        #expect(!message.contains("content_filter"))
        #expect(!harness.model.isStreaming)
    }

    @Test("A disclosure change discards the brief, and approving a stale sheet sends nothing")
    func disclosureChangeFailsClosed() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }

        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        #expect(harness.model.isReviewPresented)

        // The sheet is up, showing a brief built under the old disclosure.
        harness.model.setDisclosure(.init(includesHost: true))
        #expect(harness.model.brief == nil)
        #expect(!harness.model.isBriefCurrent(coordinator: harness.coordinator))

        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        await harness.settle()
        #expect(harness.provider.sentRequests.isEmpty)
        #expect(!harness.model.isReviewPresented)
        #expect(harness.model.pendingPrompt == nil)
        guard case .failed = harness.model.messages.last?.state else {
            Issue.record("Expected a failed row, got \(String(describing: harness.model.messages.last?.state))")
            return
        }

        // A fresh send rebuilds the brief under the new disclosure and reviews it.
        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        #expect(harness.model.isReviewPresented)
        let brief = try #require(harness.model.brief)
        #expect(brief.brief.redaction == AssistantRedaction(disclosure: .init(includesHost: true)))
        #expect(harness.model.isBriefCurrent(coordinator: harness.coordinator))
        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        await harness.settle()
        #expect(harness.provider.sentRequests.count == 1)
        #expect(harness.provider.sentRequests[0].briefJSON == harness.model.briefJSON)
        #expect(harness.provider.sentRequests[0].briefJSON.contains("\"includesHost\" : true"))
    }

    @Test("applyDisclosure rebuilds the brief immediately under the new disclosure")
    func applyDisclosureRebuilds() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }
        await harness.model.applyDisclosure(.init(includesProcess: true), coordinator: harness.coordinator)
        let brief = try #require(harness.model.brief)
        #expect(brief.brief.redaction.includesProcess)
        #expect(harness.model.isBriefCurrent(coordinator: harness.coordinator))
    }

    @Test("Every adopted snapshot advances the evidence revision the brief and context carry")
    func publicationAdvancesEvidenceRevision() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }
        let before = harness.coordinator.assistantContext
        #expect(harness.model.brief?.evidenceRevision == before.evidenceRevision)
        #expect(harness.model.isBriefCurrent(coordinator: harness.coordinator))

        harness.coordinator.adoptInvestigation(harness.coordinator.investigationSnapshot)
        let after = harness.coordinator.assistantContext
        #expect(after.evidenceRevision != before.evidenceRevision)
        #expect(after != before)
        // Capture generation is untouched by a republication.
        #expect(after.generation == before.generation)
        #expect(!harness.model.isBriefCurrent(coordinator: harness.coordinator))

        await harness.model.refreshBrief(coordinator: harness.coordinator)
        #expect(harness.model.brief?.evidenceRevision == after.evidenceRevision)
        #expect(harness.model.isBriefCurrent(coordinator: harness.coordinator))
    }

    @Test("Approving a sheet after a republication sends nothing")
    func stalePublicationFailsClosedAtApproval() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }

        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        #expect(harness.model.isReviewPresented)
        harness.coordinator.adoptInvestigation(harness.coordinator.investigationSnapshot)

        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        await harness.settle()
        #expect(harness.provider.sentRequests.isEmpty)
        #expect(!harness.model.isReviewPresented)
        guard case .failed = harness.model.messages.last?.state else {
            Issue.record("Expected a failed row, got \(String(describing: harness.model.messages.last?.state))")
            return
        }
    }

    @Test("A new evidence publication requires reviewing its new exact payload")
    func publicationRetiresPriorApproval() async throws {
        let harness = try await Harness()
        defer { harness.tearDown() }
        try await harness.approveAndSend("First.")

        harness.coordinator.adoptInvestigation(harness.coordinator.investigationSnapshot)
        await harness.model.refreshBrief(coordinator: harness.coordinator)
        harness.model.composerText = "Second."
        await harness.model.send(coordinator: harness.coordinator)

        #expect(harness.model.isReviewPresented)
        #expect(harness.provider.sentRequests.count == 1)
    }

    @Test("A late token is not adopted after the evidence was republished")
    func latePublicationRetiresRun() async throws {
        let gate = Gate()
        let harness = try await Harness(script: { continuation in
            continuation.yield(.token("first"))
            await gate.wait()
            continuation.yield(.token(" late"))
            continuation.yield(.completed(reason: "stop"))
        })
        defer { harness.tearDown() }

        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        try await harness.waitUntil { harness.model.messages.last?.text == "first" }

        harness.coordinator.adoptInvestigation(harness.coordinator.investigationSnapshot)
        await gate.open()
        try await harness.waitUntil {
            if case .incomplete = harness.model.messages.last?.state {
                return true
            }
            return false
        }
        let answer = try #require(harness.model.messages.last)
        #expect(answer.text == "first")
        #expect(!harness.model.isStreaming)
    }

    @Test("Re-checking an unchanged endpoint keeps the approval and the running answer")
    func recheckingUnchangedEndpointIsNotAScopeChange() async throws {
        let gate = Gate()
        let harness = try await Harness(script: { continuation in
            continuation.yield(.token("first"))
            await gate.wait()
            continuation.yield(.token(" second"))
            continuation.yield(.completed(reason: "stop"))
        })
        defer { harness.tearDown() }

        harness.model.composerText = "Explain."
        await harness.model.send(coordinator: harness.coordinator)
        await harness.model.approveReviewAndSend(coordinator: harness.coordinator)
        try await harness.waitUntil { harness.model.messages.last?.text == "first" }

        // The Check button, and the typed-but-unchanged forms of the same address.
        await harness.model.checkLocalModel()
        await harness.model.applyEndpoint("  http://127.0.0.1:11434/  ")
        await harness.model.applyEndpoint("http://localhost:11434")
        #expect(harness.model.isStreaming)
        #expect(harness.model.messages.last?.state == .streaming)

        await gate.open()
        await harness.settle()
        let answer = try #require(harness.model.messages.last)
        #expect(answer.text == "first second")
        #expect(answer.state == .complete)

        // The approval survives too: the next send under the same scope skips the sheet.
        harness.model.composerText = "Again."
        await harness.model.send(coordinator: harness.coordinator)
        await harness.settle()
        #expect(!harness.model.isReviewPresented)
        #expect(harness.provider.sentRequests.count == 2)

        // A genuinely different endpoint still retires the approval.
        await harness.model.applyEndpoint("http://127.0.0.1:9999")
        harness.model.composerText = "Once more."
        await harness.model.send(coordinator: harness.coordinator)
        #expect(harness.model.isReviewPresented)
        #expect(harness.provider.sentRequests.count == 2)
    }

    @Test("A test-run token is one bounded, deterministic, path-safe component", arguments: [
        "../../Library/Application Support",
        "a/b",
        "..",
        "token with spaces",
        "tab\there",
        "nul\u{0}byte",
        "ünïcode",
        String(repeating: "x", count: TracexyIdentity.maxTestRunTokenLength + 1),
    ])
    func runTokenIsSanitized(_ raw: String) {
        let token = TracexyIdentity.sanitizedTestRunToken(raw)
        #expect(token == TracexyIdentity.sanitizedTestRunToken(raw))
        #expect(token != raw)
        #expect(token.hasPrefix("h-"))
        #expect(token.count <= TracexyIdentity.maxTestRunTokenLength)
        #expect(!token.contains("/"))
        #expect(!token.contains(".."))
        #expect(token.utf8.allSatisfy { $0 < 0x80 && $0 > 0x20 })
        // Distinct hostile inputs still land in distinct locations.
        #expect(token != TracexyIdentity.sanitizedTestRunToken(raw + "x"))
    }

    @Test("An ordinary test-run token is used verbatim", arguments: [
        "ui-run-42",
        UUID().uuidString,
        "abc_DEF-123",
    ])
    func ordinaryTestRunTokenIsVerbatim(_ raw: String) {
        #expect(TracexyIdentity.sanitizedTestRunToken(raw) == raw)
    }

    @Test("Automated launches keep application settings out of the standard defaults domain")
    func automatedApplicationDefaultsAreIsolated() {
        let key = "tracexy.tests.defaults-isolation.\(UUID().uuidString)"
        defer {
            TracexyIdentity.applicationDefaults.removeObject(forKey: key)
            UserDefaults.standard.removeObject(forKey: key)
        }

        TracexyIdentity.applicationDefaults.set("isolated", forKey: key)
        #expect(TracexyIdentity.applicationDefaults.string(forKey: key) == "isolated")
        #expect(UserDefaults.standard.object(forKey: key) == nil)
    }

    // MARK: Private

    private enum Change: CaseIterable {
        case model
        case endpoint
        case disclosure
    }

    /// A one-shot gate so a scripted provider can pause mid-stream.
    private actor Gate {
        // MARK: Internal

        func open() {
            isOpen = true
            for continuation in waiters {
                continuation.resume()
            }
            waiters.removeAll()
        }

        func wait() async {
            guard !isOpen else {
                return
            }
            await withCheckedContinuation { continuation in
                waiters.append(continuation)
            }
        }

        // MARK: Private

        private var isOpen = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
    }

    @MainActor
    private final class Harness {
        // MARK: Lifecycle

        init(
            extraSession: Bool = false,
            script: @escaping @Sendable (AsyncThrowingStream<AssistantStreamEvent, Error>.Continuation)
            async -> Void = { continuation in
                continuation.yield(.token("An answer."))
                continuation.yield(.completed(reason: "stop"))
            }
        )
        async throws {
            isolation = ProjectIsolationEnvironment(name: "assistant-\(UUID().uuidString)")
            coordinator = isolation.makeCoordinator()
            await coordinator.hydrateProjectsOnLaunch()

            let endpoint = try AssistantLocalEndpoint.standard()
            let stub = StubAssistantProvider(
                endpoint: endpoint,
                discovery: AssistantDiscovery(
                    kind: .ollama,
                    models: [
                        AssistantModel(id: "llama3.2:3b", name: "llama3.2:3b"),
                        AssistantModel(id: "other-model", name: "other-model"),
                    ],
                    omittedModelCount: 0
                ),
                script: script
            )
            provider = stub
            defaults = UserDefaults(suiteName: "com.amunx.tracexy.tests.assistant.\(UUID().uuidString)")
            model = AssistantSessionModel(
                defaults: defaults ?? .standard,
                providerFactory: { _ in stub }
            )

            var snapshot = AssistantDemoFixture.snapshot()
            var sessions = snapshot.sessions
            if extraSession {
                var second = AssistantDemoFixture.session(host: "other.example.com")
                second = SessionSummary(
                    id: UUID(),
                    startTime: second.startTime,
                    duration: second.duration,
                    processName: second.processName,
                    host: second.host,
                    sourceEndpoint: second.sourceEndpoint,
                    destinationEndpoint: second.destinationEndpoint,
                    protocolStack: second.protocolStack,
                    status: second.status,
                    bytesUp: second.bytesUp,
                    bytesDown: second.bytesDown
                )
                sessions.append(second)
                snapshot = snapshot.replacingSessions(with: sessions)
            }
            coordinator.sessions = sessions
            coordinator.adoptInvestigation(snapshot)
            try coordinator.select(#require(sessions.first))

            await model.checkLocalModel()
            await model.refreshBrief(coordinator: coordinator)
        }

        // MARK: Internal

        let coordinator: MainContentCoordinator
        let model: AssistantSessionModel
        let provider: StubAssistantProvider

        func approveAndSend(_ prompt: String) async throws {
            model.composerText = prompt
            await model.send(coordinator: coordinator)
            if model.isReviewPresented {
                await model.approveReviewAndSend(coordinator: coordinator)
            }
            await settle()
        }

        /// Let the streaming task run to completion.
        func settle() async {
            for _ in 0 ..< 200 where model.isStreaming {
                try? await Task.sleep(for: .milliseconds(5))
            }
        }

        func waitUntil(_ condition: () -> Bool) async throws {
            for _ in 0 ..< 400 {
                if condition() {
                    return
                }
                try await Task.sleep(for: .milliseconds(5))
            }
            Issue.record("Condition never became true")
        }

        func tearDown() {
            model.invalidateForBoundary()
            if let name = defaults?.description, name.isEmpty {
                // No-op: the suite name is removed below.
            }
            isolation.tearDown()
        }

        // MARK: Private

        private let isolation: ProjectIsolationEnvironment
        private let defaults: UserDefaults?
    }
}
