import Foundation
import Observation

// The AI Assistant's observable state machine.
//
// It owns the whole lifecycle: endpoint validation, local-model discovery, the
// mandatory Review Data gate, one bounded streamed exchange at a time, and the
// guards that stop a late token from being adopted into a workspace it no longer
// describes. Bounded conversations live here, in memory, per Project workspace.
//
// It holds no credential, no provider account and no persisted transcript.

// MARK: - AssistantStatus

/// What the app can honestly say about the configured endpoint right now.
nonisolated enum AssistantStatus: Sendable, Equatable {
    /// No endpoint has been validated yet, or the saved one is invalid.
    case notConfigured(String)
    /// Discovery is in flight.
    case checking
    /// A local endpoint answered and advertised at least one model.
    case ready(AssistantProviderKind)
    /// The endpoint is valid but did not answer usefully.
    case unavailable(String)

    // MARK: Internal

    var isReady: Bool {
        if case .ready = self {
            return true
        }
        return false
    }
}

// MARK: - AssistantReviewFingerprint

/// Exactly what a Review Data approval covers. Any change to one of these fields
/// invalidates the approval and the sheet is required again — that is the whole
/// contract, stated as a value so it cannot drift from the check.
nonisolated struct AssistantReviewFingerprint: Equatable, Sendable {
    let projectID: UUID
    let sessionID: UUID
    let evidenceRevision: Int
    let disclosure: AutomationDisclosure
    let endpoint: String
    let model: String
}

// MARK: - AssistantRun

/// The identity one streamed run is pinned to, captured at send time and
/// re-checked before every adoption.
nonisolated struct AssistantRun: Sendable, Equatable {
    let requestID: Int
    let context: AssistantContext
    let endpoint: String
    let model: String
    let disclosure: AutomationDisclosure
    let kind: AssistantProviderKind
    let messageID: UUID
}

// MARK: - AssistantSessionModel

@MainActor
@Observable
final class AssistantSessionModel {
    // MARK: Lifecycle

    /// - Parameters:
    ///   - defaults: where the endpoint, model and disclosure preferences live.
    ///   - providerFactory: how a provider is made for a validated endpoint,
    ///     injectable so tests never open a socket.
    init(
        defaults: UserDefaults = .standard,
        providerFactory: @escaping @Sendable (AssistantLocalEndpoint) -> any AssistantProviding = {
            LocalAssistantProvider(endpoint: $0)
        }
    ) {
        self.defaults = defaults
        self.providerFactory = providerFactory
        endpointText = defaults.string(forKey: SettingsKeys.assistantEndpoint)
            ?? AssistantLocalEndpoint.defaultText
        selectedModelID = defaults.string(forKey: SettingsKeys.assistantModel) ?? ""
        disclosure = AutomationDisclosure(
            includesProcess: defaults.bool(forKey: SettingsKeys.assistantDisclosureProcess),
            includesHost: defaults.bool(forKey: SettingsKeys.assistantDisclosureHost),
            includesEndpoints: defaults.bool(forKey: SettingsKeys.assistantDisclosureEndpoints)
        )
        status = .notConfigured("Check the local model to get started.")
    }

    // MARK: Internal

    /// The system prompt. It is fixed, visible in Review Data, and written to make
    /// the model's job describing bounded evidence rather than speculating past it.
    nonisolated static let systemPrompt = """
    You are a network-evidence assistant inside Tracexy, a passive macOS capture tool. \
    You receive one JSON evidence brief describing exactly one captured session. That brief is the \
    complete set of facts you have.

    Rules:
    - Never state anything the brief does not support. Absence of evidence is not evidence of absence.
    - Respect the coverage counters: omitted or truncated evidence means your answer is bounded, and you \
    must say so.
    - The brief carries no packet bytes, payload bodies, URLs, file paths or credentials. The optional \
    session.host is a display value that may be DNS- or SNI-derived; do not reconstruct any other \
    redacted or unavailable data.
    - Cite evidence by its citation id exactly as written, for example frame-1024. Cite only ids present \
    in the brief.
    - Be concise and concrete. Prefer "observed" over "caused".
    """

    /// The suggested openers. They are questions the bounded brief can actually
    /// answer, so a first-time user is not taught to ask for something the
    /// evidence cannot support.
    static let suggestedPrompts = [
        "Summarize what was observed in this session.",
        "What do the findings actually prove, and what stays unknown?",
        "Which coverage limits should I keep in mind here?",
    ]

    private(set) var status: AssistantStatus
    private(set) var discovery: AssistantDiscovery?
    private(set) var brief: AssistantBriefBuild?
    private(set) var briefError: String?
    private(set) var isStreaming = false
    /// The prompt held back until the user approves the Review Data sheet.
    private(set) var pendingPrompt: String?
    var isReviewPresented = false
    var composerText = ""

    var endpointText: String
    var selectedModelID: String
    private(set) var disclosure: AutomationDisclosure

    /// The transcript for the current Project workspace.
    var messages: [AssistantMessage] {
        guard let key = currentKey else {
            return []
        }
        return conversations[key]?.messages ?? []
    }

    var droppedMessageCount: Int {
        guard let key = currentKey else {
            return 0
        }
        return conversations[key]?.droppedMessageCount ?? 0
    }

    var availableModels: [AssistantModel] {
        discovery?.models ?? []
    }

    /// Whether the composer can send right now.
    var canSend: Bool {
        status.isReady
            && !isStreaming
            && brief != nil
            && !selectedModelID.isEmpty
            && !composerText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var canRetry: Bool {
        guard let key = currentKey, let conversation = conversations[key] else {
            return false
        }
        return !isStreaming && conversation.lastUserPrompt != nil && status.isReady && brief != nil
    }

    /// The citation ids the current brief actually minted.
    var knownCitationIDs: Set<String> {
        Set(brief?.brief.citations.map(\.id) ?? [])
    }

    /// The literal JSON the Review Data sheet shows and the model receives.
    var briefJSON: String {
        (try? brief?.brief.canonicalJSON()) ?? ""
    }

    /// Whether the held brief describes exactly the current disclosure and the
    /// coordinator's current evidence publication. `false` means the brief must
    /// be rebuilt — ``refreshBrief(coordinator:)`` — before it can be reviewed
    /// or sent; ``send(coordinator:)`` does that itself, and approval refuses it.
    func isBriefCurrent(coordinator: MainContentCoordinator) -> Bool {
        briefIsCurrent(for: coordinator.assistantContext)
    }

    // MARK: Endpoint and discovery

    /// Validate and persist the typed endpoint, then discover it.
    ///
    /// Only a *changed* normalized endpoint retires the reviewed approval and an
    /// in-flight run. Re-checking the same address — the Check button, or the
    /// first-show probe — is a liveness question, not a scope change, so it
    /// leaves both alone even while status passes through `.checking`.
    func applyEndpoint(_ text: String) async {
        do {
            let endpoint = try AssistantLocalEndpoint.validate(text)
            if endpoint.displayText != endpointText {
                retireActiveRunForConfigurationChange()
                // A changed endpoint retires any previous approval.
                approvedFingerprint = nil
            }
            endpointText = endpoint.displayText
            defaults.set(endpoint.displayText, forKey: SettingsKeys.assistantEndpoint)
            await refreshDiscovery(endpoint: endpoint)
        } catch let error as AssistantEndpointError {
            retireActiveRunForConfigurationChange()
            endpointText = text
            discovery = nil
            status = .notConfigured(error.message)
        } catch {
            retireActiveRunForConfigurationChange()
            endpointText = text
            discovery = nil
            status = .notConfigured(AssistantEndpointError.notAURL.message)
        }
    }

    /// Re-run discovery against the saved endpoint.
    func checkLocalModel() async {
        hasAttemptedDiscovery = true
        await applyEndpoint(endpointText)
    }

    /// Discover once per run when the dock is first shown.
    ///
    /// This is a loopback `GET` for the endpoint's model list and nothing else —
    /// no capture data, no brief and no prompt is involved — so the surface can
    /// state whether a local model is present instead of asking the user to find
    /// out.
    ///
    /// The work runs in a task this model owns rather than the view's structured
    /// task: the dock is rebuilt on selection, Project and layout changes, and a
    /// probe cancelled by a rebuild must not be reported as an unreachable model.
    func discoverIfNeeded() {
        guard !hasAttemptedDiscovery, discoveryTask == nil else {
            return
        }
        discoveryTask = Task { [weak self] in
            await self?.checkLocalModel()
            self?.discoveryTask = nil
        }
    }

    func selectModel(_ id: String) {
        guard selectedModelID != id else {
            return
        }
        retireActiveRunForConfigurationChange()
        selectedModelID = id
        defaults.set(id, forKey: SettingsKeys.assistantModel)
        // A changed model retires any previous approval.
        approvedFingerprint = nil
    }

    /// Change the disclosure. The current brief was built under the previous
    /// disclosure, so it is discarded here — a brief whose redaction does not
    /// match the disclosure is never left in place to be reviewed or sent.
    /// Prefer ``applyDisclosure(_:coordinator:)`` to rebuild immediately.
    func setDisclosure(_ value: AutomationDisclosure) {
        guard disclosure != value else {
            return
        }
        retireActiveRunForConfigurationChange()
        disclosure = value
        defaults.set(value.includesProcess, forKey: SettingsKeys.assistantDisclosureProcess)
        defaults.set(value.includesHost, forKey: SettingsKeys.assistantDisclosureHost)
        defaults.set(value.includesEndpoints, forKey: SettingsKeys.assistantDisclosureEndpoints)
        approvedFingerprint = nil
        // Any build still in flight under the old disclosure is superseded too.
        briefRequestID &+= 1
        brief = nil
        briefError = nil
    }

    /// Change the disclosure and rebuild the brief for the current selection in
    /// one step, so the surface never shows a gap between the two.
    func applyDisclosure(_ value: AutomationDisclosure, coordinator: MainContentCoordinator) async {
        setDisclosure(value)
        await refreshBrief(coordinator: coordinator)
    }

    // MARK: Selection

    /// Rebuild the brief for the coordinator's current selection.
    ///
    /// A selection change also cancels an in-flight run: an answer about the
    /// previous session must never land under the new one.
    func refreshBrief(coordinator: MainContentCoordinator) async {
        let context = coordinator.assistantContext
        if let lastContext, lastContext != context {
            retireActiveRunForConfigurationChange()
            cancelRun()
        }
        // Adopted even when nothing is selected, so the transcript shown always
        // belongs to the *current* Project workspace. Leaving it stale would show
        // one Project's conversation while another is active.
        lastContext = context
        guard context.sessionID != nil else {
            brief = nil
            briefError = nil
            return
        }
        briefRequestID &+= 1
        let requestID = briefRequestID
        let requestedDisclosure = disclosure
        do {
            let build = try await coordinator.makeAssistantBrief(disclosure: requestedDisclosure)
            guard requestID == briefRequestID,
                  coordinator.assistantContext == context,
                  disclosure == requestedDisclosure else
            {
                return
            }
            brief = build
            briefError = nil
        } catch {
            guard requestID == briefRequestID,
                  coordinator.assistantContext == context,
                  disclosure == requestedDisclosure else
            {
                return
            }
            brief = nil
            briefError = "The selected session's evidence is no longer available."
        }
    }

    // MARK: Sending

    /// Begin a send. If the exact scope has not been reviewed, this presents the
    /// Review Data sheet instead of sending; nothing leaves the app until
    /// ``approveReviewAndSend(coordinator:)`` runs.
    func send(coordinator: MainContentCoordinator) async {
        let prompt = composerText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !prompt.isEmpty, !isStreaming else {
            return
        }
        guard prompt.count <= AssistantLimits.maxPromptCharacters else {
            appendFailure("That prompt is longer than Tracexy will send. Shorten it and try again.")
            return
        }
        pendingPrompt = prompt
        guard let fingerprint = currentFingerprint(coordinator: coordinator) else {
            pendingPrompt = nil
            return
        }
        // The sheet must show, and the send must carry, a brief built under the
        // current disclosure and evidence publication. A missing or superseded
        // brief is rebuilt here rather than reviewed as if it were current.
        if !briefIsCurrent(for: coordinator.assistantContext) {
            await refreshBrief(coordinator: coordinator)
        }
        guard briefIsCurrent(for: coordinator.assistantContext) else {
            pendingPrompt = nil
            appendFailure(Self.staleBriefReason)
            return
        }
        guard approvedFingerprint == fingerprint else {
            isReviewPresented = true
            return
        }
        await performSend(prompt, coordinator: coordinator)
    }

    /// The user approved the sheet. This is the only path that records an
    /// approval, and it approves exactly one fingerprint.
    func approveReviewAndSend(coordinator: MainContentCoordinator) async {
        guard let fingerprint = currentFingerprint(coordinator: coordinator) else {
            isReviewPresented = false
            pendingPrompt = nil
            return
        }
        // Fail closed: the approval covers the bytes the sheet showed. If the
        // disclosure or the evidence moved underneath the sheet, those bytes are
        // not the current brief, so nothing is approved and nothing is sent.
        guard briefIsCurrent(for: coordinator.assistantContext) else {
            approvedFingerprint = nil
            isReviewPresented = false
            pendingPrompt = nil
            appendFailure(Self.staleBriefReason)
            return
        }
        approvedFingerprint = fingerprint
        isReviewPresented = false
        guard let prompt = pendingPrompt else {
            return
        }
        await performSend(prompt, coordinator: coordinator)
    }

    func cancelReview() {
        isReviewPresented = false
        pendingPrompt = nil
    }

    /// Re-send the last user prompt under the current scope. It goes through the
    /// same review gate, so a retry after a Project or model change is reviewed
    /// again rather than inheriting the old approval.
    func retry(coordinator: MainContentCoordinator) async {
        guard let key = currentKey, let prompt = conversations[key]?.lastUserPrompt else {
            return
        }
        composerText = prompt
        await send(coordinator: coordinator)
    }

    /// Stop the current run. Text already streamed is retained and explicitly
    /// marked incomplete — never presented as a conclusion.
    func stop() {
        guard let run = activeRun else {
            return
        }
        cancelRun()
        update(run) { message in
            message.state = .incomplete(reason: "Stopped before the model finished.")
        }
        isStreaming = false
    }

    func newConversation() {
        cancelRun()
        isStreaming = false
        guard let key = currentKey else {
            return
        }
        conversations[key] = AssistantConversation()
    }

    func clearConversation() {
        newConversation()
    }

    /// Retire everything scoped to a Project or workspace boundary: the in-flight
    /// run, the reviewed approval and the derived brief.
    ///
    /// Conversations are deliberately *kept*. A Project boundary is not a
    /// conversation boundary — the outgoing Project's transcript is its own state,
    /// exactly like its investigation drafts — and it is discarded only when that
    /// Project itself goes away.
    func invalidateForBoundary() {
        if let run = activeRun {
            abandon(run, reason: Self.boundaryReason)
        }
        cancelRun()
        isStreaming = false
        approvedFingerprint = nil
        brief = nil
        lastContext = nil
    }

    /// Discard every conversation belonging to a deleted Project.
    func discardConversations(forProject projectID: UUID) {
        conversations = conversations.filter { $0.key.projectID != projectID }
    }

    // MARK: Citations

    /// The provenance behind one citation id, or `nil` when the current brief does
    /// not carry it.
    func provenance(forCitation id: String) -> SessionFrameProvenance? {
        brief?.provenanceByCitationID[id]
    }

    func navigate(toCitation id: String, coordinator: MainContentCoordinator) {
        guard let build = brief,
              let provenance = build.provenanceByCitationID[id],
              let sessionID = UUID(uuidString: build.brief.sessionID) else
        {
            return
        }
        coordinator.navigateToAssistantCitation(sessionID: sessionID, provenance: provenance)
    }

    // MARK: Private

    /// The one sentence used whenever a run is retired because its scope changed.
    private static let boundaryReason =
        "Stopped: the Project, workspace, selection, evidence, model or endpoint changed before the answer finished."

    /// The one sentence used whenever a send is refused because the brief no
    /// longer matches the disclosure or the published evidence.
    private static let staleBriefReason =
        "The reviewed evidence is out of date. Send again to review the current brief."

    /// Copy for a finish reason this app does not recognize. The reason string
    /// itself is never shown.
    private static let unrecognizedFinishReason =
        "The local model ended the answer for a reason Tracexy doesn’t recognize. Try again."

    private let defaults: UserDefaults
    private let providerFactory: @Sendable (AssistantLocalEndpoint) -> any AssistantProviding

    private var conversations: [AssistantConversationKey: AssistantConversation] = [:]
    private var approvedFingerprint: AssistantReviewFingerprint?
    private var lastContext: AssistantContext?
    private var hasAttemptedDiscovery = false
    private var discoveryTask: Task<Void, Never>?
    private var briefRequestID = 0
    private var requestID = 0
    private var activeRun: AssistantRun?
    private var streamTask: Task<Void, Never>?

    private var currentKey: AssistantConversationKey? {
        lastContext?.conversationKey
    }

    /// The terminal state for a provider's own done marker. A budget-limited
    /// finish is the same bounded outcome as the app's answer-length limit; an
    /// unrecognized reason is a conservative failure rather than a conclusion.
    private static func finalState(for reason: String?, text: String) -> AssistantMessageState {
        switch AssistantFinishOutcome.classify(reason) {
        case .complete:
            text.isEmpty ? .failed(message: "The local model returned no text.") : .complete
        case .outputLimit:
            .incomplete(reason: copy(for: .outputLimit))
        case .unrecognized:
            .failed(message: unrecognizedFinishReason)
        }
    }

    private static func copy(for reason: AssistantTruncationReason) -> String {
        switch reason {
        case .outputLimit: "Stopped at Tracexy’s answer-length limit."
        case .responseSizeLimit: "Stopped at Tracexy’s response-size limit."
        case .timeLimit: "Stopped at Tracexy’s time limit."
        case .unexpectedEnd: "Stopped because the local model connection ended before completion."
        }
    }

    private func refreshDiscovery(endpoint: AssistantLocalEndpoint) async {
        let previous = status
        status = .checking
        let provider = providerFactory(endpoint)
        do {
            let found = try await provider.discover()
            guard !found.models.isEmpty else {
                discovery = nil
                status = .unavailable(AssistantError.noModelsAvailable.message)
                return
            }
            discovery = found
            status = .ready(found.kind)
            // Keep the saved model when the endpoint still has it; otherwise adopt
            // the first advertised one rather than leaving a stale name selected.
            if !found.models.contains(where: { $0.id == selectedModelID }) {
                selectModel(found.models[0].id)
            }
        } catch is CancellationError {
            // Superseded, not unreachable: leave the previous state and allow a
            // later attempt rather than claiming the endpoint failed.
            hasAttemptedDiscovery = false
            status = previous
        } catch let error as AssistantError {
            discovery = nil
            status = .unavailable(error.message)
        } catch {
            discovery = nil
            status = .unavailable(AssistantError.unreachable.message)
        }
    }

    /// The single staleness rule: the brief exists, was built under the current
    /// disclosure, and was derived from the evidence publication `context` names.
    private func briefIsCurrent(for context: AssistantContext) -> Bool {
        guard let brief else {
            return false
        }
        return brief.brief.redaction == AssistantRedaction(disclosure: disclosure)
            && brief.evidenceRevision == context.evidenceRevision
            && brief.brief.sessionID == context.sessionID?.uuidString
    }

    private func currentFingerprint(coordinator: MainContentCoordinator) -> AssistantReviewFingerprint? {
        let context = coordinator.assistantContext
        guard let sessionID = context.sessionID, !selectedModelID.isEmpty else {
            return nil
        }
        return AssistantReviewFingerprint(
            projectID: context.projectID,
            sessionID: sessionID,
            evidenceRevision: context.evidenceRevision,
            disclosure: disclosure,
            endpoint: endpointText,
            model: selectedModelID
        )
    }

    private func performSend(_ prompt: String, coordinator: MainContentCoordinator) async {
        pendingPrompt = nil
        let context = coordinator.assistantContext
        guard let build = brief,
              case let .ready(kind) = status,
              let endpoint = try? AssistantLocalEndpoint.validate(endpointText),
              let briefJSON = try? build.brief.canonicalJSON() else
        {
            appendFailure(AssistantError.unreachable.message)
            return
        }
        // The brief must still describe the session that is selected right now.
        guard build.brief.sessionID == context.sessionID?.uuidString else {
            appendFailure("The selection changed. Choose a session and try again.")
            return
        }
        // And exactly the current disclosure and evidence publication — checked
        // again here so no caller path can send a brief the gate did not cover.
        guard briefIsCurrent(for: context) else {
            approvedFingerprint = nil
            appendFailure(Self.staleBriefReason)
            return
        }

        lastContext = context
        composerText = ""
        let answerID = UUID()
        appendMessage(AssistantMessage(role: .user, text: prompt, state: .complete), key: context.conversationKey)
        appendMessage(
            AssistantMessage(id: answerID, role: .assistant, text: "", state: .streaming),
            key: context.conversationKey
        )

        requestID &+= 1
        let run = AssistantRun(
            requestID: requestID,
            context: context,
            endpoint: endpoint.displayText,
            model: selectedModelID,
            disclosure: disclosure,
            kind: kind,
            messageID: answerID
        )
        activeRun = run
        isStreaming = true

        let provider = providerFactory(endpoint)
        let request = AssistantChatRequest(
            model: run.model,
            systemPrompt: Self.systemPrompt,
            userPrompt: prompt,
            briefJSON: briefJSON
        )
        streamTask = Task { [weak self] in
            await self?.consume(provider.stream(request, kind: kind), run: run, coordinator: coordinator)
        }
    }

    private func consume(
        _ stream: AsyncThrowingStream<AssistantStreamEvent, Error>,
        run: AssistantRun,
        coordinator: MainContentCoordinator
    )
        async
    {
        do {
            for try await event in stream {
                guard adopt(run, coordinator: coordinator) else {
                    abandon(run, reason: Self.boundaryReason)
                    return
                }
                switch event {
                case let .token(text):
                    update(run) { $0.text += text }
                case let .completed(reason):
                    update(run) { message in
                        message.state = Self.finalState(for: reason, text: message.text)
                    }
                    finish(run)
                    return
                case let .truncated(reason):
                    update(run) { $0.state = .incomplete(reason: Self.copy(for: reason)) }
                    finish(run)
                    return
                }
            }
            guard adopt(run, coordinator: coordinator) else {
                abandon(run, reason: Self.boundaryReason)
                return
            }
            update(run) { message in
                if message.state.isStreaming {
                    message.state = message.text.isEmpty
                        ? .failed(message: "The local model returned no text.")
                        : .complete
                }
            }
            finish(run)
        } catch is CancellationError {
            // A stop or an invalidation already set the message's state.
        } catch {
            guard adopt(run, coordinator: coordinator) else {
                abandon(run, reason: Self.boundaryReason)
                return
            }
            let message = (error as? AssistantError)?.message ?? AssistantError.unreachable.message
            update(run) { $0.state = .failed(message: message) }
            finish(run)
        }
    }

    /// The complete adoption guard. Every one of these must still hold, or the
    /// streamed text describes something the user is no longer looking at.
    private func adopt(_ run: AssistantRun, coordinator: MainContentCoordinator) -> Bool {
        guard run.requestID == requestID,
              activeRun?.requestID == run.requestID,
              coordinator.assistantContext == run.context,
              endpointText == run.endpoint,
              selectedModelID == run.model,
              disclosure == run.disclosure else
        {
            return false
        }
        switch status {
        case let .ready(kind):
            return kind == run.kind
        case .checking:
            // A re-check of the *same* endpoint is in flight. The run is pinned to
            // that endpoint and its discovered kind; a check that ends anywhere
            // other than `.ready(run.kind)` retires it on the next event.
            return true
        case .notConfigured,
             .unavailable:
            return false
        }
    }

    private func finish(_ run: AssistantRun) {
        guard activeRun?.requestID == run.requestID else {
            return
        }
        activeRun = nil
        streamTask = nil
        isStreaming = false
    }

    /// Retire a run whose scope no longer holds. Whatever text arrived is kept
    /// and explicitly marked incomplete — a stale answer must never be left
    /// spinning, and must never read as a conclusion about the new scope.
    private func abandon(_ run: AssistantRun, reason: String) {
        update(run) { message in
            if message.state.isStreaming {
                message.state = .incomplete(reason: reason)
            }
        }
        cancelRun()
        isStreaming = false
    }

    private func cancelRun() {
        streamTask?.cancel()
        streamTask = nil
        activeRun = nil
        requestID &+= 1
    }

    private func retireActiveRunForConfigurationChange() {
        guard let run = activeRun else {
            return
        }
        abandon(run, reason: Self.boundaryReason)
    }

    private func update(_ run: AssistantRun, transform: (inout AssistantMessage) -> Void) {
        conversations[run.context.conversationKey]?.update(id: run.messageID, transform: transform)
    }

    private func appendMessage(_ message: AssistantMessage, key: AssistantConversationKey) {
        var conversation = conversations[key] ?? AssistantConversation()
        conversation.append(message)
        conversations[key] = conversation
    }

    private func appendFailure(_ text: String) {
        guard let key = currentKey else {
            return
        }
        appendMessage(
            AssistantMessage(role: .assistant, text: "", state: .failed(message: text)),
            key: key
        )
    }
}
