import SwiftUI

// MARK: - AssistantReviewDataSheet

/// The mandatory review gate.
///
/// It shows the *literal* bytes that would be sent — not a summary of them —
/// beside the destination, the model, the disclosure decision and the coverage
/// limits that bound any answer. Nothing is sent until Send is pressed here, and
/// an approval covers exactly one Project, session, disclosure, endpoint and
/// model; changing any of them brings this sheet back.
struct AssistantReviewDataSheet: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
                    destinationSection
                    disclosureSection
                    coverageSection
                    payloadSection
                }
                .padding(Theme.Metrics.contextTableOuterPadding)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            footer
        }
        .frame(minWidth: 560, idealWidth: 640, minHeight: 460, idealHeight: 560)
        .accessibilityIdentifier("assistant.reviewSheet")
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss

    private var assistant: AssistantSessionModel {
        coordinator.assistant
    }

    private var providerLabel: String {
        guard case let .ready(kind) = assistant.status else {
            return "Not connected"
        }
        return kind.label
    }

    private var neverIncludedSummary: String {
        AssistantRedaction.neverIncludedFamilies.joined(separator: ", ")
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Label("Review data before sending", systemImage: "lock.shield")
                .font(Theme.Typography.surfaceTitle)
            Text(
                """
                This is exactly what leaves Tracexy, and it goes only to the local endpoint below. \
                No packet bytes, payload bodies, URLs, file paths or credentials are included. The optional \
                Host field can contain a DNS- or SNI-derived display name.
                """
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(Theme.Metrics.contextTableOuterPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var destinationSection: some View {
        section("Destination") {
            SettingsDetailGrid {
                SettingsDetailRow("Provider", value: providerLabel)
                SettingsDetailRow("Endpoint", value: assistant.endpointText, monospaced: true)
                SettingsDetailRow(
                    "Model",
                    value: assistant.selectedModelID.isEmpty ? "—" : assistant.selectedModelID,
                    monospaced: true
                )
                SettingsDetailRow("Leaves this Mac", value: "No")
            }
        }
    }

    private var disclosureSection: some View {
        section("Included fields") {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                disclosureToggle(
                    "Process name",
                    isOn: assistant.disclosure.includesProcess,
                    identifier: "assistant.disclosure.process"
                ) { value in
                    var next = assistant.disclosure
                    next.includesProcess = value
                    return next
                }
                disclosureToggle(
                    "Host (SNI or DNS-derived name)",
                    isOn: assistant.disclosure.includesHost,
                    identifier: "assistant.disclosure.host"
                ) { value in
                    var next = assistant.disclosure
                    next.includesHost = value
                    return next
                }
                disclosureToggle(
                    "Source and destination endpoints",
                    isOn: assistant.disclosure.includesEndpoints,
                    identifier: "assistant.disclosure.endpoints"
                ) { value in
                    var next = assistant.disclosure
                    next.includesEndpoints = value
                    return next
                }

                Text("Never included, at any setting: \(neverIncludedSummary).")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var coverageSection: some View {
        section("Coverage limits") {
            if let coverage = assistant.brief?.brief.coverage {
                SettingsDetailGrid {
                    SettingsDetailRow(
                        "Connection evidence omitted",
                        value: "\(coverage.connectionOmittedSummaryCount) capture-wide"
                    )
                    SettingsDetailRow(
                        "TLS observations omitted",
                        value: "\(coverage.tlsOmittedObservationCount) capture-wide"
                    )
                    SettingsDetailRow(
                        "Findings omitted",
                        value: "\(coverage.connectionFindingsOmittedCount + coverage.datagramFindingsOmittedCount)"
                    )
                    SettingsDetailRow(
                        "Trimmed for this brief",
                        value: """
                        \(coverage.briefOmittedConnectionCount) connections, \
                        \(coverage.briefOmittedFindingCount) findings, \
                        \(coverage.briefOmittedCitationCount) citations
                        """
                    )
                }
                Text(
                    """
                    These are capture-wide counters. They never prove anything about this one session, \
                    and an answer can only be as complete as the evidence above.
                    """
                )
                .font(Theme.Typography.micro)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("No session evidence is attached.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var payloadSection: some View {
        section("Exact payload") {
            ScrollView([.horizontal, .vertical]) {
                Text(assistant.briefJSON)
                    .font(Theme.Typography.monoMicro)
                    .textSelection(.enabled)
                    .padding(Theme.Metrics.spacingM)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("assistant.reviewPayloadText")
            }
            .frame(minHeight: 160, maxHeight: 260)
            .background(
                .quaternary,
                in: RoundedRectangle(cornerRadius: Theme.Metrics.contextTableCornerRadius, style: .continuous)
            )
            .accessibilityLabel("Exact payload JSON")
            .accessibilityIdentifier("assistant.reviewPayload")
        }
    }

    private var footer: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            if let prompt = assistant.pendingPrompt {
                Text("Prompt: \(prompt)")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            Button("Cancel", role: .cancel) {
                assistant.cancelReview()
                dismiss()
            }
            .keyboardShortcut(.cancelAction)
            .accessibilityIdentifier("assistant.reviewCancel")

            Button("Send to Local Model") {
                Task { await assistant.approveReviewAndSend(coordinator: coordinator) }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(assistant.brief == nil || assistant.pendingPrompt == nil)
            .accessibilityIdentifier("assistant.reviewSend")
        }
        .padding(Theme.Metrics.contextTableOuterPadding)
    }

    private func disclosureToggle(
        _ title: String,
        isOn: Bool,
        identifier: String,
        transform: @escaping (Bool) -> AutomationDisclosure
    )
        -> some View
    {
        Toggle(title, isOn: Binding(
            get: { isOn },
            set: { value in
                let next = transform(value)
                assistant.setDisclosure(next)
                Task { await assistant.refreshBrief(coordinator: coordinator) }
            }
        ))
        .toggleStyle(.checkbox)
        .font(Theme.Typography.body)
        .accessibilityIdentifier(identifier)
    }

    private func section(_ title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            SettingsSectionTitle(title)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
