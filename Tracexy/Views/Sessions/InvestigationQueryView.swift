import SwiftUI

// MARK: - InvestigationQueryEditorView

/// Native, capture-local structured query editor. It edits a draft only; Apply is the
/// sole path that can replace the last accepted query/results.
struct InvestigationQueryEditorView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator
    @Bindable var workspace: WorkspaceState

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            editableContent
            if workspace.investigationDraft.mode == .rows,
               let error = workspace.investigationQueryError,
               error.rowID == nil
            {
                errorText(error.message)
            }
        }
        .padding(Theme.Metrics.spacingL)
        .tracexyDenseScrollEdge()
        .tracexySafeAreaBar(edge: .top) {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                header
                modePicker
                if workspace.investigationDraft.mode == .rows {
                    combinationPicker
                }
            }
            .padding(Theme.Metrics.spacingL)
        }
        .tracexySafeAreaBar(edge: .bottom) {
            actions
                .padding(Theme.Metrics.spacingM)
        }
        .frame(width: 720)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Investigation query editor")
    }

    // MARK: Private

    private static let expressionExample =
        "tcp and destination.port == 443 and not host contains \"example\""

    /// The complete accepted vocabulary, stated once so an unsupported spelling is a
    /// visible omission rather than a guess. Deliberately not a display-filter dialect.
    private static let expressionReference = """
    Protocols: ipv4, ipv6, arp, icmp, icmpv6, tcp, udp, dns, tls, http, http2, quic, websocket, stun.
    Comparisons: ip / source.ip / destination.ip == address, ip in cidr, \
    port / source.port / destination.port == number, host contains "text", process contains "text", \
    bytes == / >= / <= number, finding == reset | retransmission | overlap | outOfOrder | dnsTruncation.
    Operators: not or !, and or &&, or or ||, and parentheses.
    """

    private var header: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Label("Investigate Sessions", systemImage: "scope")
                .font(Theme.Typography.title)
            Text("Build a typed query for this capture. Existing search, filters, and Focus Sets stay unchanged.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
        }
    }

    /// The two editable representations. Switching never discards the other draft;
    /// only the selected one is compiled by Apply.
    @ViewBuilder private var editableContent: some View {
        switch workspace.investigationDraft.mode {
        case .rows: rows
        case .expression: expressionEditor
        }
    }

    private var modePicker: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text("Editor")
                .font(Theme.Typography.bodyEmphasis)
            Picker("Editor mode", selection: $workspace.investigationDraft.mode) {
                ForEach(InvestigationQueryDraft.Mode.allCases) { mode in
                    Text(mode.label).tag(mode)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(width: 200)
            .accessibilityLabel("Investigation editor mode")
            Spacer()
        }
    }

    private var expressionEditor: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            TextEditor(text: $workspace.investigationDraft.expression)
                .font(Theme.Typography.mono)
                .scrollContentBackground(.hidden)
                .frame(minHeight: 96, maxHeight: 160)
                .padding(Theme.Metrics.spacingS)
                .tracexyContentSurface(
                    in: RoundedRectangle(
                        cornerRadius: Theme.Metrics.pillCornerRadius,
                        style: .continuous
                    )
                )
                .accessibilityLabel("Session expression")

            if let error = workspace.investigationQueryError, error.rowID == nil {
                errorText(error.message)
            }

            Text(Self.expressionExample)
                .font(Theme.Typography.monoSmall)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .accessibilityLabel("Example session expression: \(Self.expressionExample)")

            Text(
                "Session expressions match whole sessions, not individual packets. "
                    + "“source” and “destination” are this session’s endpoints."
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            Text(Self.expressionReference)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var combinationPicker: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text("Match")
                .font(Theme.Typography.bodyEmphasis)
            Picker("Match rows", selection: $workspace.investigationDraft.combination) {
                ForEach(InvestigationQueryDraft.Combination.allCases) { combination in
                    Text(combination.label).tag(combination)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(width: 150)
            Text("of the following")
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
            Spacer()
            Text("\(workspace.investigationDraft.rows.count)/\(InvestigationQueryDraftCompiler.maximumRows)")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
    }

    private var rows: some View {
        ScrollView {
            VStack(spacing: Theme.Metrics.spacingS) {
                ForEach($workspace.investigationDraft.rows) { $row in
                    draftRow($row)
                }
            }
            .padding(.vertical, 1)
        }
        .frame(maxHeight: 360)
    }

    private var actions: some View {
        HStack {
            if workspace.investigationDraft.mode == .rows {
                Button {
                    workspace.investigationDraft.rows.append(InvestigationQueryDraftRow())
                } label: {
                    Label("Add Row", systemImage: "plus")
                }
                .tracexyGlassButtonStyle()
                .disabled(workspace.investigationDraft.rows.count >= InvestigationQueryDraftCompiler.maximumRows)
            }

            if workspace.hasActiveInvestigationQuery {
                Button("Clear Query") {
                    coordinator.clearInvestigationQuery(in: workspace)
                }
                .tracexyGlassButtonStyle()
            }
            Spacer()
            if workspace.isEvaluatingInvestigationQuery {
                ProgressView()
                    .controlSize(.small)
                    .accessibilityLabel("Evaluating investigation query")
            }
            Button("Apply") {
                coordinator.applyInvestigationQuery(workspace.investigationDraft, in: workspace)
            }
            .tracexyGlassButtonStyle(prominent: true)
            .keyboardShortcut(.defaultAction)
            .disabled(workspace.isEvaluatingInvestigationQuery)
        }
    }

    private func draftRow(_ row: Binding<InvestigationQueryDraftRow>) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            HStack(spacing: Theme.Metrics.spacingS) {
                Toggle("Not", isOn: row.isNegated)
                    .toggleStyle(.checkbox)
                    .fixedSize()
                    .help("Negate this row")

                Picker("Field", selection: fieldBinding(row)) {
                    ForEach(InvestigationDraftField.allCases) { field in
                        Text(field.label).tag(field)
                    }
                }
                .labelsHidden()
                .frame(width: 125)
                .accessibilityLabel("Investigation field")

                predicateControls(row)
                    .frame(maxWidth: .infinity, alignment: .leading)

                Button {
                    remove(row.wrappedValue.id)
                } label: {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.borderless)
                .disabled(workspace.investigationDraft.rows.count == 1)
                .help("Remove query row")
                .accessibilityLabel("Remove query row")
            }
            if let error = workspace.investigationQueryError,
               error.rowID == row.wrappedValue.id
            {
                errorText(error.message)
                    .padding(.leading, 154)
            }
        }
        .padding(Theme.Metrics.spacingS)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius, style: .continuous)
        )
    }

    @ViewBuilder
    private func predicateControls(_ row: Binding<InvestigationQueryDraftRow>) -> some View {
        switch row.wrappedValue.predicate {
        case .processContains:
            TextField("Process contains", text: textBinding(row, case: .process))
                .accessibilityLabel("Process contains")
        case .hostContains:
            TextField("Host contains", text: textBinding(row, case: .host))
                .accessibilityLabel("Host contains")
        case .ipEquals:
            HStack {
                scopePicker(scopeBinding(row))
                TextField("192.0.2.1 or 2001:db8::1", text: textBinding(row, case: .ip))
                    .accessibilityLabel("Exact IP address")
            }
        case .cidrContains:
            HStack {
                scopePicker(scopeBinding(row))
                TextField("192.0.2.0/24 or 2001:db8::/32", text: textBinding(row, case: .cidr))
                    .accessibilityLabel("CIDR block")
            }
        case .portInRange:
            HStack {
                scopePicker(scopeBinding(row))
                TextField("From", text: lowerTextBinding(row))
                    .frame(width: 74)
                    .accessibilityLabel("Minimum port")
                Text("to").foregroundStyle(.secondary)
                TextField("To", text: upperTextBinding(row))
                    .frame(width: 74)
                    .accessibilityLabel("Maximum port")
            }
        case .protocolStackContains:
            Picker("Protocol", selection: protocolBinding(row)) {
                ForEach(ProtocolKind.allCases.filter { $0 != .ethernet && $0 != .linuxCooked }) { value in
                    Text(value.label).tag(value)
                }
            }
            .labelsHidden()
            .accessibilityLabel("Protocol")
        case .statusEquals:
            Picker("Status", selection: statusBinding(row)) {
                ForEach(SessionStatus.allCases, id: \.self) { value in
                    Text(value.label).tag(value)
                }
            }
            .labelsHidden()
            .accessibilityLabel("Session status")
        case .findingKind:
            Picker("Finding", selection: findingBinding(row)) {
                ForEach(QueryFindingKind.allCases, id: \.self) { value in
                    Text(value.label).tag(value)
                }
            }
            .labelsHidden()
            .accessibilityLabel("Finding kind")
        case .startDateInRange:
            HStack {
                DatePicker("From", selection: lowerDateBinding(row))
                    .labelsHidden()
                    .accessibilityLabel("Start time from")
                Text("to").foregroundStyle(.secondary)
                DatePicker("To", selection: upperDateBinding(row))
                    .labelsHidden()
                    .accessibilityLabel("Start time to")
            }
        case .totalBytesInRange:
            HStack {
                TextField("Minimum bytes", text: lowerTextBinding(row))
                    .accessibilityLabel("Minimum total bytes")
                Text("to").foregroundStyle(.secondary)
                TextField("Maximum bytes", text: upperTextBinding(row))
                    .accessibilityLabel("Maximum total bytes")
            }
        case .hasEvidence:
            Picker("Evidence", selection: evidenceBinding(row)) {
                ForEach(QueryEvidenceField.allCases, id: \.self) { value in
                    Text(value.label).tag(value)
                }
            }
            .labelsHidden()
            .accessibilityLabel("Evidence field")
        }
    }

    private func scopePicker(_ binding: Binding<EndpointScope>) -> some View {
        Picker("Endpoint", selection: binding) {
            ForEach([EndpointScope.source, .destination, .either], id: \.self) { scope in
                Text(scope.label).tag(scope)
            }
        }
        .labelsHidden()
        .frame(width: 105)
        .accessibilityLabel("Endpoint scope")
    }

    private func errorText(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle")
            .font(Theme.Typography.caption)
            .foregroundStyle(.orange)
            .accessibilityLabel("Query error: \(message)")
            .accessibilityIdentifier("investigation-query-error")
    }

    private func fieldBinding(_ row: Binding<InvestigationQueryDraftRow>)
        -> Binding<InvestigationDraftField>
    {
        Binding(
            get: { row.wrappedValue.predicate.field },
            set: { row.wrappedValue.predicate = .initialValue(for: $0) }
        )
    }

    private func textBinding(
        _ row: Binding<InvestigationQueryDraftRow>,
        case field: InvestigationDraftField
    )
        -> Binding<String>
    {
        Binding(
            get: {
                switch row.wrappedValue.predicate {
                case let .processContains(value),
                     let .hostContains(value),
                     let .ipEquals(value, _),
                     let .cidrContains(value, _): value
                default: ""
                }
            },
            set: { value in
                switch field {
                case .process: row.wrappedValue.predicate = .processContains(value)
                case .host: row.wrappedValue.predicate = .hostContains(value)
                case .ip: row.wrappedValue.predicate = .ipEquals(value, scope: scopeBinding(row).wrappedValue)
                case .cidr: row.wrappedValue.predicate = .cidrContains(value, scope: scopeBinding(row).wrappedValue)
                default: break
                }
            }
        )
    }

    private func scopeBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<EndpointScope> {
        Binding(
            get: {
                switch row.wrappedValue.predicate {
                case let .ipEquals(_, scope),
                     let .cidrContains(_, scope),
                     let .portInRange(_, _, scope): scope
                default: .either
                }
            },
            set: { scope in
                switch row.wrappedValue.predicate {
                case let .ipEquals(value, _): row.wrappedValue.predicate = .ipEquals(value, scope: scope)
                case let .cidrContains(value, _): row.wrappedValue.predicate = .cidrContains(value, scope: scope)
                case let .portInRange(lower, upper, _):
                    row.wrappedValue.predicate = .portInRange(lower: lower, upper: upper, scope: scope)
                default: break
                }
            }
        )
    }

    private func lowerTextBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<String> {
        Binding(
            get: {
                switch row.wrappedValue.predicate {
                case let .portInRange(lower, _, _),
                     let .totalBytesInRange(lower, _): lower
                default: ""
                }
            },
            set: { value in
                switch row.wrappedValue.predicate {
                case let .portInRange(_, upper, scope):
                    row.wrappedValue.predicate = .portInRange(lower: value, upper: upper, scope: scope)
                case let .totalBytesInRange(_, upper):
                    row.wrappedValue.predicate = .totalBytesInRange(lower: value, upper: upper)
                default: break
                }
            }
        )
    }

    private func upperTextBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<String> {
        Binding(
            get: {
                switch row.wrappedValue.predicate {
                case let .portInRange(_, upper, _),
                     let .totalBytesInRange(_, upper): upper
                default: ""
                }
            },
            set: { value in
                switch row.wrappedValue.predicate {
                case let .portInRange(lower, _, scope):
                    row.wrappedValue.predicate = .portInRange(lower: lower, upper: value, scope: scope)
                case let .totalBytesInRange(lower, _):
                    row.wrappedValue.predicate = .totalBytesInRange(lower: lower, upper: value)
                default: break
                }
            }
        )
    }

    private func protocolBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<ProtocolKind> {
        Binding(
            get: {
                if case let .protocolStackContains(value) = row.wrappedValue.predicate {
                    return value
                }
                return .tcp
            },
            set: { row.wrappedValue.predicate = .protocolStackContains($0) }
        )
    }

    private func statusBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<SessionStatus> {
        Binding(
            get: {
                if case let .statusEquals(value) = row.wrappedValue.predicate {
                    return value
                }
                return .warning
            },
            set: { row.wrappedValue.predicate = .statusEquals($0) }
        )
    }

    private func findingBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<QueryFindingKind> {
        Binding(
            get: {
                if case let .findingKind(value) = row.wrappedValue.predicate {
                    return value
                }
                return .reset
            },
            set: { row.wrappedValue.predicate = .findingKind($0) }
        )
    }

    private func evidenceBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<QueryEvidenceField> {
        Binding(
            get: {
                if case let .hasEvidence(value) = row.wrappedValue.predicate {
                    return value
                }
                return .anyFinding
            },
            set: { row.wrappedValue.predicate = .hasEvidence($0) }
        )
    }

    private func lowerDateBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<Date> {
        Binding(
            get: {
                if case let .startDateInRange(lower, _) = row.wrappedValue.predicate {
                    return lower
                }
                return Date()
            },
            set: { value in
                let upper = upperDateBinding(row).wrappedValue
                row.wrappedValue.predicate = .startDateInRange(lower: value, upper: upper)
            }
        )
    }

    private func upperDateBinding(_ row: Binding<InvestigationQueryDraftRow>) -> Binding<Date> {
        Binding(
            get: {
                if case let .startDateInRange(_, upper) = row.wrappedValue.predicate {
                    return upper
                }
                return Date()
            },
            set: { value in
                let lower = lowerDateBinding(row).wrappedValue
                row.wrappedValue.predicate = .startDateInRange(lower: lower, upper: value)
            }
        )
    }

    private func remove(_ id: UUID) {
        guard workspace.investigationDraft.rows.count > 1 else {
            return
        }
        workspace.investigationDraft.rows.removeAll { $0.id == id }
        if workspace.investigationQueryError?.rowID == id {
            workspace.investigationQueryError = nil
        }
    }
}

// MARK: - InvestigationQueryChip

struct InvestigationQueryChip: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator
    @Bindable var workspace: WorkspaceState
    @Binding var showsCoverage: Bool

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: workspace.isEvaluatingInvestigationQuery ? "clock.arrow.circlepath" : "scope")
                .accessibilityHidden(true)
            Text(label)
                .monospacedDigit()
            if hasCoverageAffordance {
                Button {
                    showsCoverage.toggle()
                } label: {
                    Image(systemName: "exclamationmark.triangle")
                }
                .buttonStyle(.borderless)
                .help("Show incomplete evidence details")
                .accessibilityLabel("Show incomplete Investigation results")
                .popover(isPresented: $showsCoverage) {
                    coveragePopover
                }
            }
            Button {
                coordinator.clearInvestigationQuery(in: workspace)
            } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
            .help("Clear Investigation query")
            .accessibilityLabel("Clear Investigation query")
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(Color.accentColor)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Color.accentColor.opacity(0.13))
        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .fixedSize()
        .accessibilityElement(children: .contain)
    }

    // MARK: Private

    private var label: String {
        InvestigationQueryChipModel.label(
            isEvaluating: workspace.isEvaluatingInvestigationQuery,
            hasActiveQuery: workspace.hasActiveInvestigationQuery,
            matchedCount: workspace.investigationMatchedSessionIDs.count,
            incompleteCount: workspace.investigationIndeterminateSessionIDs.count
        )
    }

    private var hasCoverageAffordance: Bool {
        InvestigationQueryChipModel.showsCoverage(
            incompleteCount: workspace.investigationIndeterminateSessionIDs.count,
            coverageReasonCount: workspace.investigationCoverageReasons.count
        )
    }

    private var coveragePopover: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Label("Incomplete Evidence", systemImage: "exclamationmark.triangle")
                .font(Theme.Typography.bodyEmphasis)
            Text(
                "\(workspace.investigationIndeterminateSessionIDs.count) session(s) could not be decided and are not included in matches."
            )
            .font(Theme.Typography.body)
            Text("Unavailable evidence stays unknown, including under negation.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            ForEach(workspace.investigationCoverageReasons.sorted(by: { $0.label < $1.label }), id: \.self) { reason in
                Label(reason.label, systemImage: "circle.fill")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(Theme.Metrics.spacingL)
        .frame(width: 330)
    }
}

// MARK: - InvestigationQueryChipModel

enum InvestigationQueryChipModel {
    static func label(
        isEvaluating: Bool,
        hasActiveQuery: Bool,
        matchedCount: Int,
        incompleteCount: Int
    )
        -> String
    {
        if isEvaluating {
            return hasActiveQuery
                ? "Investigation · updating"
                : "Investigation · evaluating"
        }
        return incompleteCount > 0
            ? "Investigation · \(matchedCount) matched · \(incompleteCount) incomplete"
            : "Investigation · \(matchedCount) matched"
    }

    static func showsCoverage(incompleteCount: Int, coverageReasonCount: Int) -> Bool {
        incompleteCount > 0 || coverageReasonCount > 0
    }
}

// MARK: - Query presentation labels

private extension EndpointScope {
    var label: String {
        switch self {
        case .source: "Source"
        case .destination: "Destination"
        case .either: "Either"
        }
    }
}

private extension QueryFindingKind {
    var label: String {
        switch self {
        case .reset: "TCP reset observed"
        case .retransmission: "Retransmission observed"
        case .overlap: "Overlap observed"
        case .outOfOrder: "Out-of-order observed"
        case .dnsTruncation: "DNS truncation indicated"
        }
    }
}

private extension QueryEvidenceField {
    var label: String {
        switch self {
        case .processAttribution: "Process attribution"
        case .latency: "Latency"
        case .dnsQuery: "DNS query"
        case .dnsAnswer: "DNS answer"
        case .serverNameIndication: "Server name indication"
        case .sourceEndpoint: "Typed source endpoint"
        case .destinationEndpoint: "Typed destination endpoint"
        case .anyFinding: "Any retained finding"
        }
    }
}

private extension QueryCoverageReason {
    var label: String {
        switch self {
        case .connectionSummaryOmission: "Connection summaries were omitted"
        case .connectionFindingOmission: "Connection findings or citations were omitted"
        case .connectionEventOrStateLimitation: "Connection event or sequence state was limited"
        case .datagramObservationOmission: "Datagram observations were incomplete"
        case .datagramFindingOmission: "Datagram findings or citations were omitted"
        case .excludedTCPDNSInput: "TCP DNS evidence was excluded"
        case .capacityReached: "An evidence capacity bound was reached"
        case .captureLossReported: "Capture loss was reported"
        case .captureLossUnknown: "Capture loss is unknown"
        case .counterOverflow: "An evidence counter overflowed"
        case .unknownSessionStartTime: "Some sessions have no capture time, so date rows can’t decide them"
        }
    }
}

private extension InvestigationQueryDraftError {
    var message: String {
        switch reason {
        case .emptyDraft: "Add at least one query row."
        case let .tooManyRows(limit): "Use at most \(limit) query rows."
        case .invalidIPAddress: "Enter a standalone IPv4 or IPv6 address."
        case .invalidCIDR: "Enter a valid IPv4 or IPv6 CIDR block."
        case .invalidPort: "Ports must be whole numbers from 0 through 65535, in ascending order."
        case .invalidByteCount: "Byte bounds must be non-negative whole numbers in ascending order."
        case let .expression(error): error.message
        case let .core(error): error.message
        }
    }
}

// MARK: - SessionQueryParseError + message

private extension SessionQueryParseError {
    /// A concise diagnostic that names the position and the offending token only. The
    /// expression itself is never echoed back.
    var message: String {
        "\(explanation) (character \(position))"
    }

    private var explanation: String {
        switch reason {
        case .emptyExpression: "Enter a session expression."
        case let .inputTooLong(limit): "Keep the expression within \(limit) UTF-8 bytes."
        case let .tokenLimitExceeded(limit): "Use at most \(limit) terms and operators."
        case let .depthLimitExceeded(limit): "Nesting exceeds the depth limit of \(limit)."
        case .unexpectedCharacter: "This character can’t start a term."
        case .unterminatedString: "This quoted value has no closing quote."
        case .unsupportedEscape: "Only \\\" and \\\\ are supported inside quotes."
        case .controlCharacterInText: "Remove the control character from this quoted value."
        case let .unknownName(name): "“\(name)” isn’t a supported session name."
        case let .unsupportedOperator(text): "“\(text)” isn’t a supported operator."
        case let .operatorNotSupportedForField(field, operatorText):
            "“\(field)” doesn’t support “\(operatorText)”."
        case .expectedValue: "A value is expected here."
        case .expectedExpression: "A term or parenthesized group is expected here."
        case .unbalancedParenthesis: "A closing parenthesis is expected here."
        case .unexpectedTrailingInput: "Extra input follows the expression."
        case .invalidIPAddress: "Enter a standalone IPv4 or IPv6 address."
        case .invalidCIDR: "Enter a valid IPv4 or IPv6 CIDR block."
        case .invalidPort: "Ports must be whole numbers from 0 through 65535."
        case .invalidByteCount: "Byte counts must be non-negative whole numbers."
        }
    }
}

private extension QueryValidationError {
    var message: String {
        switch self {
        case .emptyGroup: "Add at least one query row."
        case let .nodeCountExceeded(limit): "The query exceeds the \(limit)-node limit."
        case let .depthExceeded(limit): "The query exceeds the depth limit of \(limit)."
        case let .childCountExceeded(limit): "A group exceeds the \(limit)-row limit."
        case .emptyText: "Enter a value for this field."
        case .controlCharacterInText: "Remove control characters from this value."
        case let .textTooLong(limit): "Keep this value within \(limit) UTF-8 bytes."
        case .reversedRange: "The lower bound must not exceed the upper bound."
        case .negativeByteBound: "Byte bounds cannot be negative."
        case .nonFiniteDate: "Choose finite start and end dates."
        }
    }
}
