import SwiftUI

// MARK: - AIAssistantDockView

/// A native conversation shell for Tracexy's future assistant.
///
/// The hierarchy is deliberately production-shaped — conversation header,
/// compact attached context, transcript, and a pinned composer — while the
/// capability remains honest. Tracexy has no assistant backend yet, so it does
/// not invent messages, model choices, history, recipes, or streaming states.
struct AIAssistantDockView: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator

    var body: some View {
        conversationTranscript
            .tracexySoftScrollEdge()
            .tracexySafeAreaBar(edge: .top) {
                VStack(spacing: 0) {
                    conversationHeader
                    attachedContextHeader
                }
            }
            .tracexySafeAreaBar(edge: .bottom) {
                promptComposer
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("AI Assistant")
    }

    // MARK: Private

    @State private var isTrustPopoverPresented = false

    private var conversationHeader: some View {
        HStack(spacing: 8) {
            Text("New Conversation")
                .font(Theme.Typography.bodyEmphasis)
                .lineLimit(1)
            Spacer(minLength: 0)
            Button {
                // Conversation history arrives with the assistant subsystem.
            } label: {
                Image(systemName: "clock.arrow.circlepath")
            }
            .buttonStyle(.borderless)
            .disabled(true)
            .help("Conversation history is available after an assistant is connected")
            .accessibilityLabel("Conversation history")

            Button {
                // A conversation cannot be created before a backend exists.
            } label: {
                Image(systemName: "square.and.pencil")
            }
            .buttonStyle(.borderless)
            .disabled(true)
            .help("New conversations are available after an assistant is connected")
            .accessibilityLabel("New conversation")
        }
        .padding(.horizontal, Theme.Metrics.assistantContentPadding)
        .frame(minHeight: Theme.Metrics.assistantHeaderHeight)
    }

    @ViewBuilder private var attachedContextHeader: some View {
        if let session = coordinator.selectedSession {
            HStack(spacing: 8) {
                Image(systemName: session.status.systemImage)
                    .font(.system(size: Theme.Icon.medium))
                    .foregroundStyle(Theme.color(for: session.status))
                    .accessibilityHidden(true)
                Text(contextSummary(for: session))
                    .font(Theme.Typography.monoSmall)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 0)
                Label("1", systemImage: "paperclip")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, Theme.Metrics.assistantContentPadding)
            .frame(minHeight: Theme.Metrics.assistantContextHeight)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Attached session: \(contextSummary(for: session))")
        } else {
            HStack(spacing: 8) {
                Image(systemName: "paperclip")
                    .foregroundStyle(.secondary)
                Text("Select a session to add context")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Theme.Metrics.assistantContentPadding)
            .frame(minHeight: Theme.Metrics.assistantContextHeight)
        }
    }

    private var conversationTranscript: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.Metrics.assistantContentPadding) {
                if coordinator.selectedSession == nil {
                    noSelectionEmptyState
                } else {
                    selectedSessionEmptyState
                }
            }
            .padding(Theme.Metrics.assistantContentPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var noSelectionEmptyState: some View {
        VStack(spacing: 6) {
            Text("Investigate captured traffic")
                .font(Theme.Typography.bodyEmphasis)
            Text("Select a session to inspect the context available to an assistant.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
    }

    private var selectedSessionEmptyState: some View {
        VStack(spacing: Theme.Metrics.spacingL) {
            Image(systemName: "sparkles")
                .font(.system(size: Theme.Icon.hero))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Start an investigation")
                .font(Theme.Typography.bodyEmphasis)
            Text("The session is ready as read-only context. Connect an assistant to begin a conversation.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
    }

    private var promptComposer: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .bottom, spacing: 8) {
                TextField("Ask Tracexy AI Assistant…", text: .constant(""), axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(Theme.Typography.body)
                    .lineLimit(1 ... 4)
                    .disabled(true)
                    .accessibilityLabel("Message the assistant")

                Button {
                    // Intentionally inert: there is no assistant backend.
                } label: {
                    Image(systemName: "arrow.up")
                        .font(Theme.Typography.bodyEmphasis)
                        .frame(width: 16, height: 16)
                }
                .tracexyGlassButtonStyle(prominent: true)
                .controlSize(.small)
                .disabled(true)
                .help("Assistant not connected")
                .accessibilityLabel("Send message")
            }
            .padding(.leading, Theme.Metrics.assistantContentPadding)
            .padding(.trailing, 6)
            .padding(.vertical, 6)
            .tracexyGlassEffect(
                interactive: true,
                in: RoundedRectangle(
                    cornerRadius: Theme.Metrics.assistantComposerCornerRadius,
                    style: .continuous
                )
            )

            HStack(spacing: 8) {
                Label("Not connected", systemImage: "cpu")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 4)
                Button {
                    isTrustPopoverPresented.toggle()
                } label: {
                    Label("Read-only", systemImage: "lock.shield")
                }
                .buttonStyle(.borderless)
                .controlSize(.mini)
                .font(Theme.Typography.micro)
                .foregroundStyle(.secondary)
                .help("Review the AI Assistant trust boundary")
                .accessibilityLabel("Read-only Assistant privacy details")
                .popover(isPresented: $isTrustPopoverPresented, arrowEdge: .trailing) {
                    trustBoundary
                }
            }
        }
        .padding(.horizontal, Theme.Metrics.assistantContentPadding)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private var trustBoundary: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            Label("Read-only by design", systemImage: "lock.shield")
                .font(Theme.Typography.surfaceTitle)
            Text(
                "Selected capture context stays on this Mac. Tracexy does not send data or run a model because an assistant is not connected."
            )
            .font(Theme.Typography.body)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            Divider()
            Label("Selected session only", systemImage: "scope")
                .font(Theme.Typography.captionMedium)
            Label("No network or model access", systemImage: "network.slash")
                .font(Theme.Typography.captionMedium)
        }
        .padding(14)
        .frame(width: Theme.Metrics.assistantPopoverWidth, alignment: .leading)
    }

    private func contextSummary(for session: SessionSummary) -> String {
        let protocolLabel = session.primaryProtocol.label
        return "\(protocolLabel) · \(session.host) · \(session.destinationEndpoint)"
    }
}
