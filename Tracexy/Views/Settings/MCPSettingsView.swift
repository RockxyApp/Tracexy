import SwiftUI

// MARK: - MCPSettingsView

/// The **MCP & Assistant** pane.
///
/// Two independent surfaces share one pane because they share one principle, not
/// one mechanism. The MCP boundary hands a bounded, read-only History projection
/// to a client the user starts; the Assistant sends a bounded evidence brief to a
/// local model the user chose. Neither opens a port, and neither is on until the
/// user turns it on here.
struct MCPSettingsView: View {
    // MARK: Lifecycle

    init(
        scope: @escaping @MainActor () -> MCPGrantScope? = { nil },
        assistant: AssistantSessionModel,
        access: MCPAccessModel? = nil
    ) {
        scopeProvider = scope
        self.assistant = assistant
        _access = State(initialValue: access ?? MCPAccessModel())
    }

    // MARK: Internal

    var body: some View {
        SettingsPane {
            mcpSection
            assistantSection
        }
        .task {
            repeat {
                access.refresh()
                try? await Task.sleep(for: .seconds(1))
            } while !Task.isCancelled
        }
    }

    // MARK: Private

    @State private var access: MCPAccessModel
    @State private var maxPageSize = MCPAccessModel.defaultMaxPageSize
    @State private var disclosure = AutomationDisclosure.minimum
    @State private var endpointDraft = ""
    @State private var hasLoadedGrantDefaults = false

    private let scopeProvider: @MainActor () -> MCPGrantScope?
    private let assistant: AssistantSessionModel

    /// Resolve the live Project at render and grant time. Settings can open before
    /// Project hydration finishes; retaining a nil snapshot would strand Grant.
    private var scope: MCPGrantScope? {
        scopeProvider()
    }

    // MARK: MCP

    private var mcpSection: some View {
        SettingsSection("MCP Server") {
            grantBanner

            SettingsIndented {
                SettingsFootnote(
                    """
                    Tracexy never opens a network port. The bundled TracexyMCP command speaks JSON-RPC over \
                    stdin and stdout to a client you start, exposes three read-only tools, and can read only \
                    the one Project you grant below.
                    """
                )
            }

            SettingsDivider()

            SettingsRow(label: "Project") {
                Text(scope?.projectName ?? "Projects are still loading")
                    .font(Theme.Typography.body)
                    .accessibilityIdentifier("mcp.projectName")
            }

            SettingsRow(label: "Disclosed fields") {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                    Toggle("Process name", isOn: $disclosure.includesProcess)
                        .accessibilityIdentifier("mcp.disclosure.process")
                    Toggle("Host (SNI or DNS-derived name)", isOn: $disclosure.includesHost)
                        .accessibilityIdentifier("mcp.disclosure.host")
                    Toggle("Source and destination endpoints", isOn: $disclosure.includesEndpoints)
                        .accessibilityIdentifier("mcp.disclosure.endpoints")
                }
                .toggleStyle(.checkbox)
            }

            SettingsRow(label: "Maximum rows") {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                    Stepper(
                        value: $maxPageSize,
                        in: 1 ... MCPGrantLimits.maxPageSize,
                        step: 25
                    ) {
                        Text("\(maxPageSize) rows per request")
                            .font(Theme.Typography.body)
                    }
                    .accessibilityIdentifier("mcp.maxRows")
                    SettingsFootnote("One request reads one page. There is no way to ask for the whole database.")
                }
            }

            SettingsIndented {
                HStack(spacing: Theme.Metrics.spacingM) {
                    Button(access.status.document == nil ? "Grant Access" : "Re-issue Grant") {
                        guard let scope else {
                            return
                        }
                        access.grant(scope: scope, disclosure: disclosure, maxPageSize: maxPageSize)
                    }
                    .disabled(scope == nil)
                    .accessibilityIdentifier("mcp.grant")

                    Button("Revoke", role: .destructive) {
                        access.revoke()
                    }
                    .disabled(access.status == .notGranted)
                    .accessibilityIdentifier("mcp.revoke")
                }
            }

            if let errorMessage = access.errorMessage {
                SettingsIndented {
                    SettingsInlineMessage(errorMessage, tone: .warning)
                }
            }

            SettingsDivider()

            clientConfiguration

            SettingsDivider()

            auditTrail
        }
    }

    @ViewBuilder private var grantBanner: some View {
        switch access.status {
        case .notGranted:
            SettingsStatusBanner(
                symbol: "lock.shield",
                tint: .secondary,
                title: "Off — no client can read anything",
                detail: "MCP is free and always available, and it stays closed until you grant one Project.",
                titleIdentifier: "mcp.statusTitle"
            ) {
                EmptyView()
            }
        case let .granted(document):
            SettingsStatusBanner(
                symbol: "checkmark.shield",
                tint: .green,
                title: grantedTitle(document),
                detail: "Read-only, stdio only, one Project, \(document.maxPageSize) rows per request.",
                titleIdentifier: "mcp.statusTitle"
            ) {
                EmptyView()
            }
        case let .invalid(error):
            SettingsStatusBanner(
                symbol: "exclamationmark.triangle",
                tint: .orange,
                title: "The current grant will be refused",
                detail: Self.copy(for: error),
                titleIdentifier: "mcp.statusTitle"
            ) {
                EmptyView()
            }
        }
    }

    private var clientConfiguration: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            SettingsRow(label: "Inside Tracexy.app") {
                Text("Contents/MacOS/TracexyMCP")
                    .font(Theme.Typography.monoSmall)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("mcp.commandPath")
            }
            SettingsIndented {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                    SettingsFootnote(
                        """
                        This is the location inside the Tracexy app on your Mac. Copying the client configuration \
                        inserts the full path to this installation so your MCP client can launch it. That path may \
                        include your Mac account name: keep the copied JSON in your local client settings and copy \
                        it again if you move the app.
                        """
                    )
                    Button("Copy Client Configuration") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(access.clientConfigurationSnippet, forType: .string)
                    }
                    .disabled(access.clientConfigurationSnippet.isEmpty)
                    .accessibilityIdentifier("mcp.copyConfig")
                }
            }
        }
    }

    private var auditTrail: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            SettingsSectionTitle("Recent activity")
            if access.recentAudit.isEmpty {
                SettingsIndented {
                    SettingsFootnote("No client has called a tool yet.")
                }
            } else {
                SettingsIndented {
                    VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                        ForEach(Array(access.recentAudit.reversed().enumerated()), id: \.offset) { _, record in
                            auditRow(record)
                        }
                    }
                    .accessibilityIdentifier("mcp.auditList")
                }
            }
            SettingsIndented {
                SettingsFootnote(
                    """
                    The trail records the time, the tool, the outcome, the Project and which filter fields were \
                    used — never the values a client searched for, and never anything it read back.
                    """
                )
            }
        }
    }

    // MARK: Assistant

    private var assistantSection: some View {
        SettingsSection("AI Assistant") {
            assistantBanner

            SettingsRow(label: "Local endpoint") {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                    TextField("http://127.0.0.1:11434", text: $endpointDraft)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 320)
                        .accessibilityIdentifier("assistant.endpointField")
                    Button("Check Local Model") {
                        Task { await assistant.applyEndpoint(endpointDraft) }
                    }
                    .accessibilityIdentifier("assistant.settingsCheck")
                    SettingsFootnote(
                        """
                        Only 127.0.0.1, ::1 and localhost are accepted. A remote address, an embedded user name \
                        or password, or a redirect off this Mac is refused before anything is sent.
                        """
                    )
                }
            }

            if !assistant.availableModels.isEmpty {
                SettingsRow(label: "Model") {
                    Picker("Model", selection: Binding(
                        get: { assistant.selectedModelID },
                        set: { assistant.selectModel($0) }
                    )) {
                        ForEach(assistant.availableModels) { model in
                            Text(model.name).tag(model.id)
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: 320)
                    .accessibilityIdentifier("assistant.settingsModelPicker")
                }
            }

            SettingsRow(label: "Included fields") {
                VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                    Toggle("Process name", isOn: assistantDisclosureBinding(\.includesProcess))
                        .accessibilityIdentifier("assistant.settings.process")
                    Toggle(
                        "Host (SNI or DNS-derived name)",
                        isOn: assistantDisclosureBinding(\.includesHost)
                    )
                    .accessibilityIdentifier("assistant.settings.host")
                    Toggle("Source and destination endpoints", isOn: assistantDisclosureBinding(\.includesEndpoints))
                        .accessibilityIdentifier("assistant.settings.endpoints")
                }
                .toggleStyle(.checkbox)
            }

            SettingsIndented {
                SettingsFootnote(
                    """
                    Everything off is the default. Packet bytes, payload bodies, URLs, file paths and credentials \
                    are never included. Host can contain a DNS- or SNI-derived display name when you turn it on. \
                    You review the exact JSON before the first send.
                    """
                )
            }
        }
        .onAppear {
            endpointDraft = assistant.endpointText
            loadGrantDefaultsIfNeeded()
        }
    }

    @ViewBuilder private var assistantBanner: some View {
        switch assistant.status {
        case let .notConfigured(message):
            SettingsStatusBanner(
                symbol: "cpu",
                tint: .secondary,
                title: "No local model connected",
                detail: message,
                titleIdentifier: "assistant.settingsStatusTitle"
            ) {
                EmptyView()
            }
        case .checking:
            SettingsStatusBanner(
                symbol: "arrow.triangle.2.circlepath",
                tint: .secondary,
                title: "Checking the local endpoint…",
                isBusy: true,
                titleIdentifier: "assistant.settingsStatusTitle"
            ) {
                EmptyView()
            }
        case let .ready(kind):
            SettingsStatusBanner(
                symbol: "checkmark.circle",
                tint: .green,
                title: "Connected to \(kind.label)",
                detail: "\(assistant.availableModels.count) model(s) available on this Mac.",
                titleIdentifier: "assistant.settingsStatusTitle"
            ) {
                EmptyView()
            }
        case let .unavailable(message):
            SettingsStatusBanner(
                symbol: "exclamationmark.triangle",
                tint: .orange,
                title: "The local endpoint didn’t answer",
                detail: message,
                titleIdentifier: "assistant.settingsStatusTitle"
            ) {
                EmptyView()
            }
        }
    }

    private func auditRow(_ record: MCPAuditRecord) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: Self.symbol(for: record.result))
                .foregroundStyle(Self.tint(for: record.result))
                .accessibilityHidden(true)
            Text(Self.timestamp(record.time))
                .font(Theme.Typography.monoMicro)
                .foregroundStyle(.secondary)
            Text(record.tool)
                .font(Theme.Typography.monoMicro)
                .lineLimit(1)
            if !record.filterFields.isEmpty {
                Text("filters: \(record.filterFields.joined(separator: ", "))")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    private static func timestamp(_ value: Double) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: Date(timeIntervalSinceReferenceDate: value))
    }

    private static func symbol(for result: MCPAuditResult) -> String {
        switch result {
        case .ok: "checkmark.circle"
        case .denied: "hand.raised"
        case .invalid: "exclamationmark.circle"
        case .unavailable: "questionmark.circle"
        }
    }

    private static func tint(for result: MCPAuditResult) -> Color {
        switch result {
        case .ok: .green
        case .denied: .orange
        case .invalid,
             .unavailable: .secondary
        }
    }

    private static func copy(for error: MCPGrantError) -> String {
        switch error {
        case .absent: "No grant exists."
        case .notRegularFile: "The grant file is not a regular file. Re-issue it."
        case .notOwnerOnly: "The grant file is readable by other users. Re-issue it."
        case .tooLarge: "The grant file is larger than a grant can be. Re-issue it."
        case .malformed: "The grant file could not be read. Re-issue it."
        case .unsupportedSchema: "The grant was written by a different version of Tracexy. Re-issue it."
        case .invalidRevision,
             .invalidPageSize,
             .invalidIssuanceTime: "The grant is not valid. Re-issue it."
        case .stale: "The grant has expired. Re-issue it."
        case .databaseUnavailable: "The granted Project’s History database is not available."
        case .superseded,
             .projectMismatch: "The grant now names a different Project. Re-issue it."
        }
    }

    private func assistantDisclosureBinding(
        _ keyPath: WritableKeyPath<AutomationDisclosure, Bool>
    )
        -> Binding<Bool>
    {
        Binding(
            get: { assistant.disclosure[keyPath: keyPath] },
            set: { value in
                var next = assistant.disclosure
                next[keyPath: keyPath] = value
                assistant.setDisclosure(next)
            }
        )
    }

    /// Seed the grant editors from the grant that already exists, so re-issuing
    /// does not silently narrow or widen what the user previously authorized.
    private func loadGrantDefaultsIfNeeded() {
        guard !hasLoadedGrantDefaults else {
            return
        }
        hasLoadedGrantDefaults = true
        guard let document = access.status.document else {
            return
        }
        disclosure = document.disclosure
        maxPageSize = document.maxPageSize
    }

    private func grantedTitle(_ document: MCPGrantDocument) -> String {
        guard let scope, scope.projectID == document.projectID else {
            return "Granted to another Project"
        }
        return "Granted to \(scope.projectName)"
    }
}

#Preview {
    MCPSettingsView(assistant: AssistantSessionModel())
}
