import SwiftUI

// MARK: - ExpressionLibrarySheetView

/// Routes the controller's sheet.
struct ExpressionLibrarySheetView: View {
    let sheet: ExpressionLibrarySheet
    let controller: ExpressionLibraryController

    var body: some View {
        switch sheet {
        case let .buttonEditor(button, isNew):
            FilterButtonEditorSheet(controller: controller, original: button, isNew: isNew)
        case .manageButtons:
            FilterButtonsManagerSheet(controller: controller)
        case .macros:
            ExpressionMacrosSheet(controller: controller)
        }
    }
}

// MARK: - ExpressionLibraryIssue

/// One warning line, in the orange the Session Expression editor uses.
private struct ExpressionLibraryIssue: View {
    let message: String

    var body: some View {
        Label {
            Text(verbatim: message)
        } icon: {
            Image(systemName: "exclamationmark.triangle")
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.orange)
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityIdentifier("expressionLibrary.issue")
    }
}

// MARK: - FilterButtonEditorSheet

/// Add or edit one filter button.
struct FilterButtonEditorSheet: View {
    // MARK: Lifecycle

    init(controller: ExpressionLibraryController, original: FilterButton, isNew: Bool) {
        self.controller = controller
        self.original = original
        self.isNew = isNew
        _label = State(initialValue: original.label)
        _expression = State(initialValue: original.expression)
        _comment = State(initialValue: original.comment)
    }

    // MARK: Internal

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Form {
                Section {
                    TextField(text: $label, prompt: Text("Web//TLS")) {
                        Text("Label")
                    }
                    .accessibilityLabel(Text("Label"))
                    .accessibilityIdentifier("filterButtonEditor.label")
                    LabeledContent {
                        TextField(text: $expression, prompt: Text(verbatim: "tls and port == 443")) {
                            Text("Session Expression")
                        }
                        .labelsHidden()
                        .font(Theme.Typography.mono)
                        .multilineTextAlignment(.trailing)
                        .accessibilityLabel(Text("Session Expression"))
                        .accessibilityIdentifier("filterButtonEditor.expression")
                    } label: {
                        Text("Session Expression")
                    }
                    TextField(
                        text: $comment,
                        prompt: Text("Shown when the pointer rests on the button")
                    ) {
                        Text("Comment")
                    }
                    .accessibilityLabel(Text("Comment"))
                    .accessibilityIdentifier("filterButtonEditor.comment")
                } header: {
                    if isNew {
                        Text("Add Filter Button")
                    } else {
                        Text("Edit Filter Button")
                    }
                } footer: {
                    footer
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)

            HStack {
                Spacer()
                Button {
                    controller.sheet = nil
                } label: {
                    Text("Cancel")
                }
                .keyboardShortcut(.cancelAction)
                Button {
                    save()
                } label: {
                    if isNew {
                        Text("Add")
                    } else {
                        Text("Save")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(problem != nil)
                .accessibilityIdentifier("filterButtonEditor.save")
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 16)
        }
        .frame(width: 500)
    }

    // MARK: Private

    @State private var label: String
    @State private var expression: String
    @State private var comment: String

    private let controller: ExpressionLibraryController
    private let original: FilterButton
    private let isNew: Bool

    private var candidate: FilterButton {
        FilterButton(
            id: original.id,
            label: label.trimmingCharacters(in: .whitespaces),
            expression: expression.trimmingCharacters(in: .whitespacesAndNewlines),
            comment: comment.trimmingCharacters(in: .whitespaces)
        )
    }

    private var problem: String? {
        if isNew, !controller.canAddButton {
            return String(localized: "New filter buttons can be added up to \(controller.buttonLimit) per Project.")
        }
        if let problem = ExpressionLibraryLimits.buttonProblem(candidate), problem != .emptyExpression,
           problem != .expressionTooLong
        {
            return ExpressionLibraryLimits.message(for: problem)
        }
        return controller.expressionProblem(candidate.expression)
    }

    @ViewBuilder private var footer: some View {
        let trimmedExpression = candidate.expression
        if candidate.label.isEmpty, problem == ExpressionLibraryLimits.message(for: .emptyLabel) {
            Text("Write Group//Label to put the button in a pull-down named Group.")
                .foregroundStyle(.secondary)
        } else if let problem {
            ExpressionLibraryIssue(message: problem)
        } else if let expanded = controller.expandedText(trimmedExpression) {
            Text("Expands to \(Text(verbatim: expanded))")
                .font(Theme.Typography.monoSmall)
                .foregroundStyle(.secondary)
                .lineLimit(3)
        } else {
            Text("Write Group//Label to put the button in a pull-down named Group.")
                .foregroundStyle(.secondary)
        }
    }

    private func save() {
        guard problem == nil, controller.commit(candidate) else {
            return
        }
        controller.sheet = nil
    }
}

// MARK: - FilterButtonsManagerSheet

/// Every filter button of the Project in one table: edit in place, add, remove,
/// and reorder by dragging or with Move Up / Move Down. Nothing is kept until Save.
struct FilterButtonsManagerSheet: View {
    // MARK: Lifecycle

    init(controller: ExpressionLibraryController) {
        self.controller = controller
        _rows = State(initialValue: controller.buttons)
    }

    // MARK: Internal

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text("Filter Buttons")
                .font(Theme.Typography.title)
                .accessibilityAddTraits(.isHeader)

            if rows.isEmpty {
                ContentUnavailableView {
                    Label {
                        Text("No Filter Buttons")
                    } icon: {
                        Image(systemName: "line.3.horizontal.decrease.circle")
                    }
                } description: {
                    Text("Add one to apply a Session Expression with a single click.")
                }
                .frame(maxWidth: .infinity, minHeight: 220)
            } else {
                table
                detail
            }

            controls
        }
        .padding(20)
        .frame(width: 760, height: 540)
    }

    // MARK: Private

    @State private var rows: [FilterButton]
    @State private var selection: FilterButton.ID?

    private let controller: ExpressionLibraryController

    private var issues: [UUID: String] {
        var issues: [UUID: String] = [:]
        var labels: Set<String> = []
        for row in rows {
            if let problem = ExpressionLibraryLimits.buttonProblem(row), problem != .emptyExpression,
               problem != .expressionTooLong
            {
                issues[row.id] = ExpressionLibraryLimits.message(for: problem)
            } else if let problem = controller.expressionProblem(row.expression) {
                issues[row.id] = problem
            } else if !labels.insert(row.label.lowercased()).inserted {
                issues[row.id] = String(localized: "Another filter button has this label.")
            }
        }
        if !controller.admits(buttons: rows) {
            let stored = Set(controller.buttons.map(\.id))
            for row in rows where !stored.contains(row.id) && issues[row.id] == nil {
                issues[row.id] = String(
                    localized: "New filter buttons can be added up to \(controller.buttonLimit) per Project."
                )
            }
        }
        return issues
    }

    private var table: some View {
        let issues = issues
        return Table(of: FilterButton.self, selection: $selection) {
            TableColumn(Text("Label")) { row in
                HStack(spacing: 4) {
                    if issues[row.id] != nil {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                            .help(issues[row.id] ?? "")
                            .accessibilityLabel(Text("Problem"))
                    }
                    Text(verbatim: row.label)
                        .lineLimit(1)
                }
            }
            .width(min: 120, ideal: 170)
            TableColumn(Text("Session Expression")) { row in
                Text(verbatim: row.expression)
                    .font(Theme.Typography.monoSmall)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(row.expression)
            }
            .width(min: 200, ideal: 320)
            TableColumn(Text("Comment")) { row in
                Text(verbatim: row.comment)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(row.comment)
            }
            .width(min: 100, ideal: 180)
        } rows: {
            ForEach(rows) { row in
                TableRow(row)
                    .draggable(row.id.uuidString)
            }
            .dropDestination(for: String.self) { index, ids in
                moveRows(ids, to: index)
            }
        }
        .accessibilityIdentifier("filterButtons.table")
    }

    /// The selected button's fields. The table is for choosing and ordering; this
    /// is where a button is written.
    @ViewBuilder private var detail: some View {
        if let selection, rows.contains(where: { $0.id == selection }) {
            Grid(
                alignment: .leading,
                horizontalSpacing: Theme.Metrics.spacingM,
                verticalSpacing: Theme.Metrics.spacingS
            ) {
                GridRow {
                    Text("Label")
                        .gridColumnAlignment(.trailing)
                    TextField(text: binding(selection, \.label), prompt: Text("Web//TLS")) {
                        Text("Label")
                    }
                    .labelsHidden()
                    .accessibilityLabel(Text("Label"))
                    .accessibilityIdentifier("filterButtons.detail.label")
                }
                GridRow {
                    Text("Session Expression")
                    TextField(text: binding(selection, \.expression), prompt: Text(verbatim: "tls and port == 443")) {
                        Text("Session Expression")
                    }
                    .labelsHidden()
                    .font(Theme.Typography.mono)
                    .accessibilityLabel(Text("Session Expression"))
                    .accessibilityIdentifier("filterButtons.detail.expression")
                }
                GridRow {
                    Text("Comment")
                    TextField(
                        text: binding(selection, \.comment),
                        prompt: Text("Shown when the pointer rests on the button")
                    ) {
                        Text("Comment")
                    }
                    .labelsHidden()
                    .accessibilityLabel(Text("Comment"))
                    .accessibilityIdentifier("filterButtons.detail.comment")
                }
            }
        } else {
            Text("Select a filter button to change it. Drag rows to reorder them.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, minHeight: 84)
        }
    }

    private var controls: some View {
        let issues = issues
        return HStack(spacing: Theme.Metrics.spacingM) {
            ControlGroup {
                Button {
                    let button = FilterButton(label: "", expression: controller.currentExpression())
                    rows.append(button)
                    selection = button.id
                } label: {
                    Image(systemName: "plus")
                }
                .help(Text("Add a filter button"))
                .accessibilityLabel(Text("Add"))
                .disabled(rows.count >= controller.buttonLimit)
                Button {
                    rows.removeAll { $0.id == selection }
                    selection = nil
                } label: {
                    Image(systemName: "minus")
                }
                .help(Text("Remove the selected filter button"))
                .accessibilityLabel(Text("Remove"))
                .disabled(selection == nil)
            }
            .fixedSize()
            ControlGroup {
                Button {
                    moveSelection(by: -1)
                } label: {
                    Image(systemName: "chevron.up")
                }
                .help(Text("Move Up"))
                .accessibilityLabel(Text("Move Up"))
                .disabled(!canMoveSelection(by: -1))
                Button {
                    moveSelection(by: 1)
                } label: {
                    Image(systemName: "chevron.down")
                }
                .help(Text("Move Down"))
                .accessibilityLabel(Text("Move Down"))
                .disabled(!canMoveSelection(by: 1))
            }
            .fixedSize()

            if let first = rows.first(where: { issues[$0.id] != nil }), let message = issues[first.id] {
                ExpressionLibraryIssue(message: first.label.isEmpty ? message : "\(first.label): \(message)")
                    .lineLimit(2)
            }
            Spacer(minLength: 0)
            Button {
                controller.sheet = nil
            } label: {
                Text("Cancel")
            }
            .keyboardShortcut(.cancelAction)
            Button {
                // Checked again at Save: a limit can fall while the sheet is open.
                guard controller.admits(buttons: rows) else {
                    return
                }
                controller.setButtons(rows.map(Self.trimmed))
                controller.sheet = nil
            } label: {
                Text("Save")
            }
            .keyboardShortcut(.defaultAction)
            .disabled(!issues.isEmpty || rows == controller.buttons)
            .accessibilityIdentifier("filterButtons.save")
        }
    }

    nonisolated private static func trimmed(_ button: FilterButton) -> FilterButton {
        FilterButton(
            id: button.id,
            label: button.label.trimmingCharacters(in: .whitespaces),
            expression: button.expression.trimmingCharacters(in: .whitespacesAndNewlines),
            comment: button.comment.trimmingCharacters(in: .whitespaces)
        )
    }

    private func binding(_ id: UUID, _ keyPath: WritableKeyPath<FilterButton, String>) -> Binding<String> {
        Binding(
            get: { rows.first { $0.id == id }?[keyPath: keyPath] ?? "" },
            set: { value in
                if let index = rows.firstIndex(where: { $0.id == id }) {
                    rows[index][keyPath: keyPath] = value
                }
            }
        )
    }

    private func canMoveSelection(by offset: Int) -> Bool {
        guard let index = rows.firstIndex(where: { $0.id == selection }) else {
            return false
        }
        return rows.indices.contains(index + offset)
    }

    private func moveSelection(by offset: Int) {
        guard let index = rows.firstIndex(where: { $0.id == selection }), rows.indices.contains(index + offset) else {
            return
        }
        rows.swapAt(index, index + offset)
    }

    private func moveRows(_ ids: [String], to destination: Int) {
        let moving = IndexSet(ids.compactMap { id in rows.firstIndex { $0.id.uuidString == id } })
        guard !moving.isEmpty else {
            return
        }
        rows.move(fromOffsets: moving, toOffset: min(destination, rows.count))
    }
}

// MARK: - ExpressionMacrosSheet

/// The Project's macros: a name, the expression it stands for with `$1` … `$9`
/// for values, and how many values a use gives. Nothing is kept until Save.
struct ExpressionMacrosSheet: View {
    // MARK: Lifecycle

    init(controller: ExpressionLibraryController) {
        self.controller = controller
        _rows = State(initialValue: controller.macros)
    }

    // MARK: Internal

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text("Macros")
                .font(Theme.Typography.title)
                .accessibilityAddTraits(.isHeader)
            Text(
                "Write $name, $name(a, b) or ${name:a;b} in a Session Expression. $1 to $9 in a macro take the values in order."
            )
            .font(Theme.Typography.body)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            if rows.isEmpty {
                ContentUnavailableView {
                    Label {
                        Text("No Macros")
                    } icon: {
                        Image(systemName: "dollarsign")
                    }
                } description: {
                    Text("Add one to name a piece of a Session Expression.")
                }
                .frame(maxWidth: .infinity, minHeight: 200)
            } else {
                table
                detail
            }
            controls
        }
        .padding(20)
        .frame(width: 720, height: 520)
    }

    // MARK: Private

    @State private var rows: [ExpressionMacro]
    @State private var selection: ExpressionMacro.ID?

    private let controller: ExpressionLibraryController

    private var issues: [UUID: String] {
        let trimmed = rows.map(Self.trimmed)
        var issues = ExpressionMacroValidation.problems(in: trimmed).mapValues(ExpressionMacroValidation.message)
        let names = Set(trimmed.map(\.name))
        for macro in trimmed where issues[macro.id] == nil {
            if let missing = ExpressionMacroExpander.referencedNames(in: macro.text)
                .first(where: { !names.contains($0) })
            {
                issues[macro.id] = ExpressionMacroError(position: 1, kind: .unknownMacro(missing)).message
            }
        }
        if !controller.admits(macros: rows) {
            let stored = Set(controller.macros.map(\.id))
            for macro in rows where !stored.contains(macro.id) && issues[macro.id] == nil {
                issues[macro.id] =
                    String(localized: "New macros can be added up to \(controller.macroLimit) per Project.")
            }
        }
        return issues
    }

    private var table: some View {
        let issues = issues
        return Table(rows, selection: $selection) {
            TableColumn(Text("Name")) { row in
                HStack(spacing: 2) {
                    if issues[row.id] != nil {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                            .help(issues[row.id] ?? "")
                            .accessibilityLabel(Text("Problem"))
                    }
                    Text(verbatim: "$" + row.name)
                        .font(Theme.Typography.monoSmall)
                        .lineLimit(1)
                }
            }
            .width(min: 120, ideal: 160)
            TableColumn(Text("Stands For")) { row in
                Text(verbatim: row.text)
                    .font(Theme.Typography.monoSmall)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(row.text)
            }
            .width(min: 240, ideal: 400)
            TableColumn(Text("Values")) { row in
                Text(row.arity, format: .number)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            .width(56)
        }
        .accessibilityIdentifier("macros.table")
    }

    /// The selected macro's fields.
    @ViewBuilder private var detail: some View {
        if let selection, rows.contains(where: { $0.id == selection }) {
            Grid(
                alignment: .leading,
                horizontalSpacing: Theme.Metrics.spacingM,
                verticalSpacing: Theme.Metrics.spacingS
            ) {
                GridRow {
                    Text("Name")
                        .gridColumnAlignment(.trailing)
                    TextField(text: binding(selection, \.name), prompt: Text(verbatim: "web")) {
                        Text("Name")
                    }
                    .labelsHidden()
                    .font(Theme.Typography.mono)
                    .accessibilityLabel(Text("Name"))
                    .accessibilityIdentifier("macros.detail.name")
                }
                GridRow {
                    Text("Stands For")
                    TextField(text: binding(selection, \.text), prompt: Text(verbatim: "tcp and port in {$1}")) {
                        Text("Stands For")
                    }
                    .labelsHidden()
                    .font(Theme.Typography.mono)
                    .accessibilityLabel(Text("Stands For"))
                    .accessibilityIdentifier("macros.detail.text")
                }
            }
        } else {
            Text("Select a macro to change it.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, minHeight: 56)
        }
    }

    private var controls: some View {
        let issues = issues
        return HStack(spacing: Theme.Metrics.spacingM) {
            ControlGroup {
                Button {
                    let macro = ExpressionMacro(name: nextName(), text: "")
                    rows.append(macro)
                    selection = macro.id
                } label: {
                    Image(systemName: "plus")
                }
                .help(Text("Add a macro"))
                .accessibilityLabel(Text("Add"))
                .disabled(rows.count >= controller.macroLimit)
                Button {
                    rows.removeAll { $0.id == selection }
                    selection = nil
                } label: {
                    Image(systemName: "minus")
                }
                .help(Text("Remove the selected macro"))
                .accessibilityLabel(Text("Remove"))
                .disabled(selection == nil)
            }
            .fixedSize()
            if let first = rows.first(where: { issues[$0.id] != nil }), let message = issues[first.id] {
                ExpressionLibraryIssue(message: "$\(first.name): \(message)")
                    .lineLimit(2)
            }
            Spacer(minLength: 0)
            Button {
                controller.sheet = nil
            } label: {
                Text("Cancel")
            }
            .keyboardShortcut(.cancelAction)
            Button {
                guard controller.admits(macros: rows) else {
                    return
                }
                controller.setMacros(rows.map(Self.trimmed))
                controller.sheet = nil
            } label: {
                Text("Save")
            }
            .keyboardShortcut(.defaultAction)
            .disabled(!issues.isEmpty || rows == controller.macros)
            .accessibilityIdentifier("macros.save")
        }
    }

    nonisolated private static func trimmed(_ macro: ExpressionMacro) -> ExpressionMacro {
        ExpressionMacro(
            id: macro.id,
            name: macro.name.trimmingCharacters(in: .whitespaces),
            text: macro.text.trimmingCharacters(in: .whitespaces)
        )
    }

    private func nextName() -> String {
        let names = Set(rows.map(\.name))
        var number = rows.count + 1
        while names.contains("macro\(number)") {
            number += 1
        }
        return "macro\(number)"
    }

    private func binding(_ id: UUID, _ keyPath: WritableKeyPath<ExpressionMacro, String>) -> Binding<String> {
        Binding(
            get: { rows.first { $0.id == id }?[keyPath: keyPath] ?? "" },
            set: { value in
                if let index = rows.firstIndex(where: { $0.id == id }) {
                    rows[index][keyPath: keyPath] = value
                }
            }
        )
    }
}
