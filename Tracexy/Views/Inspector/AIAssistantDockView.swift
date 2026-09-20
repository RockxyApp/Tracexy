import SwiftUI

// MARK: - AIAssistantDockView

/// The right Context Dock's **AI Assistant** mode.
///
/// It is a real conversation surface over a real local model, and it is built so
/// the trust boundary is visible rather than promised: the attached context is
/// always exactly the selected session, the redaction state is on screen next to
/// the composer, the literal JSON is reviewable before the first send, and every
/// citation the model produces resolves to a frame this capture actually holds.
///
/// It owns no evidence and performs no read. State lives in
/// ``AssistantSessionModel``; navigation goes through the coordinator's existing
/// evidence-navigation route.
struct AIAssistantDockView: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var assistant = coordinator.assistant

        VStack(spacing: 0) {
            VStack(spacing: 0) {
                conversationHeader
                Divider()
                attachedContextHeader
            }
            .background(.bar)

            Divider()
            transcript
                .tracexySoftScrollEdge()
            Divider()

            promptComposer
                .background(.bar)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task(id: briefRefreshIdentity) {
            await coordinator.assistant.refreshBrief(coordinator: coordinator)
        }
        .onAppear {
            coordinator.assistant.discoverIfNeeded()
        }
        .sheet(isPresented: $assistant.isReviewPresented) {
            AssistantReviewDataSheet(coordinator: coordinator)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("AI Assistant")
    }

    // MARK: Private

    private static let transcriptBottomID = "assistant.transcript.bottom"

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var assistant: AssistantSessionModel {
        coordinator.assistant
    }

    /// The identity the brief must be rebuilt for. Recomputing on this exact value
    /// is what keeps the attached context honest across selection, Project,
    /// workspace and evidence-publication changes.
    private var briefRefreshIdentity: AssistantBriefRefreshIdentity {
        AssistantBriefRefreshIdentity(
            context: coordinator.assistantContext,
            disclosure: assistant.disclosure
        )
    }

    private var redactionSummary: String {
        guard let redaction = assistant.brief?.brief.redaction else {
            return "Read-only"
        }
        var families: [String] = []
        if redaction.includesProcess {
            families.append("process")
        }
        if redaction.includesHost {
            families.append("host")
        }
        if redaction.includesEndpoints {
            families.append("endpoints")
        }
        guard !families.isEmpty else {
            return "Minimum disclosure"
        }
        return "Includes \(families.joined(separator: ", "))"
    }

    // MARK: Header

    private var conversationHeader: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(assistant.messages.isEmpty ? "New Conversation" : "Conversation")
                .font(Theme.Typography.bodyEmphasis)
                .lineLimit(1)

            statusChip

            Spacer(minLength: 0)

            Button {
                assistant.newConversation()
            } label: {
                Image(systemName: "square.and.pencil")
            }
            .buttonStyle(.borderless)
            .disabled(assistant.messages.isEmpty && !assistant.isStreaming)
            .help("Start a new conversation")
            .accessibilityLabel("New conversation")
            .accessibilityIdentifier("assistant.newConversation")
        }
        .padding(.horizontal, Theme.Metrics.assistantContentPadding)
        .frame(minHeight: Theme.Metrics.assistantHeaderHeight)
    }

    private var statusChip: some View {
        Group {
            switch assistant.status {
            case .checking:
                Label("Checking…", systemImage: "arrow.triangle.2.circlepath")
                    .foregroundStyle(.secondary)
            case let .ready(kind):
                Label(kind.label, systemImage: "cpu")
                    .foregroundStyle(.secondary)
            case .notConfigured,
                 .unavailable:
                Label("Not connected", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
            }
        }
        .font(Theme.Typography.micro)
        .lineLimit(1)
        .accessibilityIdentifier("assistant.status")
    }

    // MARK: Attached context

    @ViewBuilder private var attachedContextHeader: some View {
        if let session = coordinator.selectedSession {
            HStack(spacing: Theme.Metrics.spacingM) {
                Image(systemName: session.status.systemImage)
                    .font(.system(size: Theme.Icon.medium))
                    .foregroundStyle(Theme.color(for: session.status))
                    .accessibilityHidden(true)
                Text(contextSummary(for: session))
                    .font(Theme.Typography.monoSmall)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 0)
                if let brief = assistant.brief?.brief {
                    Label("\(brief.citations.count)", systemImage: "link")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .help("Citable frames in the attached evidence")
                }
            }
            .padding(.horizontal, Theme.Metrics.assistantContentPadding)
            .frame(minHeight: Theme.Metrics.assistantContextHeight)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Attached session: \(contextSummary(for: session))")
            .accessibilityIdentifier("assistant.contextChip")
        } else {
            HStack(spacing: Theme.Metrics.spacingM) {
                Image(systemName: "paperclip")
                    .foregroundStyle(.secondary)
                Text("Select a session to attach context")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Theme.Metrics.assistantContentPadding)
            .frame(minHeight: Theme.Metrics.assistantContextHeight)
            .accessibilityIdentifier("assistant.contextChip")
        }
    }

    // MARK: Transcript

    private var transcript: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: Theme.Metrics.assistantContentPadding) {
                    if coordinator.selectedSession == nil {
                        noSelectionEmptyState
                    } else if assistant.messages.isEmpty {
                        readyEmptyState
                    } else {
                        if assistant.droppedMessageCount > 0 {
                            Text("\(assistant.droppedMessageCount) earlier turns were dropped to stay bounded.")
                                .font(Theme.Typography.micro)
                                .foregroundStyle(.secondary)
                        }
                        ForEach(assistant.messages) { message in
                            AssistantMessageRow(
                                message: message,
                                citationIDs: message.citationIDs(knownIDs: assistant.knownCitationIDs),
                                onCitation: { id in
                                    assistant.navigate(toCitation: id, coordinator: coordinator)
                                }
                            )
                            .id(message.id)
                        }
                    }
                    if let briefError = assistant.briefError {
                        inlineMessage(briefError, symbol: "exclamationmark.triangle")
                    }
                    Color.clear
                        .frame(height: 0)
                        .id(Self.transcriptBottomID)
                }
                .padding(Theme.Metrics.assistantContentPadding)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .onChange(of: assistant.messages.last?.text) { _, _ in
                scrollToTranscriptBottom(proxy)
            }
            .onChange(of: assistant.messages.last?.state) { _, _ in
                scrollToTranscriptBottom(proxy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var noSelectionEmptyState: some View {
        VStack(spacing: Theme.Metrics.controlSpacing) {
            Text("Investigate captured traffic")
                .font(Theme.Typography.bodyEmphasis)
            Text("Select a session. Only that session's bounded evidence is ever attached.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
    }

    private var readyEmptyState: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            switch assistant.status {
            case .ready:
                Text("Ask about this session")
                    .font(Theme.Typography.bodyEmphasis)
                ForEach(AssistantSessionModel.suggestedPrompts, id: \.self) { prompt in
                    Button {
                        assistant.composerText = prompt
                    } label: {
                        Text(prompt)
                            .font(Theme.Typography.caption)
                            .multilineTextAlignment(.leading)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("assistant.suggestion")
                }
            case .checking:
                ProgressView("Checking the local model…")
                    .controlSize(.small)
                    .font(Theme.Typography.caption)
            case let .notConfigured(message),
                 let .unavailable(message):
                setupCard(message)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Composer

    private var promptComposer: some View {
        @Bindable var assistant = coordinator.assistant

        return VStack(alignment: .leading, spacing: Theme.Metrics.controlSpacing) {
            if !assistant.availableModels.isEmpty {
                modelPicker
            }

            HStack(alignment: .bottom, spacing: Theme.Metrics.spacingM) {
                TextField("Ask about this session…", text: $assistant.composerText, axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(Theme.Typography.body)
                    .lineLimit(1 ... 4)
                    .disabled(!assistant.status.isReady || assistant.brief == nil)
                    .onSubmit {
                        Task { await assistant.send(coordinator: coordinator) }
                    }
                    .accessibilityLabel("Message the assistant")
                    .accessibilityIdentifier("assistant.composer")

                if assistant.isStreaming {
                    Button {
                        assistant.stop()
                    } label: {
                        Image(systemName: "stop.fill")
                            .font(Theme.Typography.bodyEmphasis)
                            .frame(width: 16, height: 16)
                    }
                    .tracexyGlassButtonStyle(prominent: true)
                    .controlSize(.small)
                    .help("Stop the answer")
                    .accessibilityLabel("Stop")
                    .accessibilityIdentifier("assistant.stop")
                } else {
                    Button {
                        Task { await assistant.send(coordinator: coordinator) }
                    } label: {
                        Image(systemName: "arrow.up")
                            .font(Theme.Typography.bodyEmphasis)
                            .frame(width: 16, height: 16)
                    }
                    .tracexyGlassButtonStyle(prominent: true)
                    .controlSize(.small)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!assistant.canSend)
                    .help(assistant.canSend ? "Send" : "Connect a local model and select a session first")
                    .accessibilityLabel("Send message")
                    .accessibilityIdentifier("assistant.send")
                }
            }
            .padding(.leading, Theme.Metrics.assistantContentPadding)
            .padding(.trailing, Theme.Metrics.controlSpacing)
            .padding(.vertical, Theme.Metrics.controlSpacing)
            .tracexyGlassEffect(
                interactive: true,
                in: RoundedRectangle(
                    cornerRadius: Theme.Metrics.assistantComposerCornerRadius,
                    style: .continuous
                )
            )

            composerFooter
        }
        .padding(.horizontal, Theme.Metrics.assistantContentPadding)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private var modelPicker: some View {
        @Bindable var assistant = coordinator.assistant

        return Picker("Model", selection: Binding(
            get: { assistant.selectedModelID },
            set: { assistant.selectModel($0) }
        )) {
            ForEach(assistant.availableModels) { model in
                Text(model.name).tag(model.id)
            }
        }
        .labelsHidden()
        .pickerStyle(.menu)
        .controlSize(.small)
        .font(Theme.Typography.micro)
        .help("Which local model answers")
        .accessibilityLabel("Local model")
        .accessibilityIdentifier("assistant.modelPicker")
    }

    private var composerFooter: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Button {
                assistant.isReviewPresented = true
            } label: {
                Label(redactionSummary, systemImage: "lock.shield")
            }
            .buttonStyle(.borderless)
            .controlSize(.mini)
            .font(Theme.Typography.micro)
            .foregroundStyle(.secondary)
            .disabled(assistant.brief == nil)
            .help("Review exactly what would be sent")
            .accessibilityLabel("Review data. \(redactionSummary)")
            .accessibilityIdentifier("assistant.reviewData")

            Spacer(minLength: Theme.Metrics.spacingS)

            Button {
                Task { await assistant.retry(coordinator: coordinator) }
            } label: {
                Label("Retry", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .controlSize(.mini)
            .font(Theme.Typography.micro)
            .foregroundStyle(.secondary)
            .disabled(!assistant.canRetry)
            .help("Send the last prompt again")
            .accessibilityIdentifier("assistant.retry")
        }
    }

    private func setupCard(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Label("No local model connected", systemImage: "cpu")
                .font(Theme.Typography.bodyEmphasis)
            Text(message)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Tracexy only sends to an endpoint on this Mac. Nothing leaves the machine.")
                .font(Theme.Typography.micro)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Check Local Model") {
                Task { await assistant.checkLocalModel() }
            }
            .accessibilityIdentifier("assistant.checkLocalModel")
        }
        .padding(Theme.Metrics.assistantContentPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous))
    }

    private func inlineMessage(_ text: String, symbol: String) -> some View {
        Label(text, systemImage: symbol)
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func contextSummary(for session: SessionSummary) -> String {
        let protocolLabel = session.primaryProtocol.label
        return "\(protocolLabel) · \(session.host) · \(session.destinationEndpoint)"
    }

    private func scrollToTranscriptBottom(_ proxy: ScrollViewProxy) {
        if reduceMotion {
            proxy.scrollTo(Self.transcriptBottomID, anchor: .bottom)
        } else {
            withAnimation(.easeOut(duration: 0.15)) {
                proxy.scrollTo(Self.transcriptBottomID, anchor: .bottom)
            }
        }
    }
}

// MARK: - AssistantBriefRefreshIdentity

/// View-local identity for rebuilding the literal review payload. Disclosure is
/// intentionally separate from ``AssistantContext`` because it is a user choice,
/// not evidence identity, but either changing must refresh the sheet immediately.
private struct AssistantBriefRefreshIdentity: Equatable {
    let context: AssistantContext
    let disclosure: AutomationDisclosure
}

// MARK: - AssistantMessageRow

/// One transcript turn. An incomplete answer is always labelled as incomplete —
/// there is no presentation in which partial text reads as a conclusion.
private struct AssistantMessageRow: View {
    // MARK: Internal

    let message: AssistantMessage
    let citationIDs: [String]
    let onCitation: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.controlSpacing) {
            HStack(spacing: Theme.Metrics.spacingS) {
                Image(systemName: message.role == .user ? "person.crop.circle" : "sparkles")
                    .font(.system(size: Theme.Icon.medium))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text(message.role == .user ? "You" : "Assistant")
                    .font(Theme.Typography.microEmphasis)
                    .foregroundStyle(.secondary)
                if message.state.isStreaming {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityLabel("Answering")
                }
                Spacer(minLength: 0)
            }

            if !message.text.isEmpty {
                Text(message.text)
                    .font(Theme.Typography.body)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            switch message.state {
            case let .incomplete(reason):
                Label(reason, systemImage: "exclamationmark.circle")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("assistant.incompleteBadge")
            case let .failed(text):
                Label(text, systemImage: "exclamationmark.triangle")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("assistant.errorBadge")
            case .complete,
                 .streaming:
                EmptyView()
            }

            if !citationIDs.isEmpty {
                citationRow
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
    }

    // MARK: Private

    private var citationRow: some View {
        // A wrapping row of citations stays legible at the dock's narrow width,
        // where a single line would truncate the evidence away.
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Theme.Metrics.spacingS) {
                citationButtons
            }
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                citationButtons
            }
        }
    }

    private var citationButtons: some View {
        ForEach(citationIDs, id: \.self) { id in
            Button {
                onCitation(id)
            } label: {
                Label(id, systemImage: "scope")
                    .font(Theme.Typography.monoMicro)
            }
            .buttonStyle(.bordered)
            .controlSize(.mini)
            .help("Show this frame in the evidence inspector")
            .accessibilityLabel("Show cited frame \(id)")
            .accessibilityIdentifier("assistant.citation")
        }
    }
}
