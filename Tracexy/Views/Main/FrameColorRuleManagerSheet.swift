import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - FrameColorRuleManagerSheet

/// Ordered Project-local coloring rules. The first rule that can be decided wins.
struct FrameColorRuleManagerSheet: View {
    // MARK: Lifecycle

    init(library: FrameColorRuleLibrary, expectedProjectID: UUID?) {
        self.library = library
        self.expectedProjectID = expectedProjectID
        _rules = State(initialValue: library.rules)
    }

    // MARK: Internal

    let library: FrameColorRuleLibrary
    let expectedProjectID: UUID?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Frame Coloring Rules").font(Theme.Typography.surfaceTitle)
            Text(
                "Rules belong to this Project. The first matching rule colors a frame; an unknown higher rule blocks lower rules."
            )
            .foregroundStyle(.secondary)
            List {
                ForEach($rules) { $rule in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Toggle("Enable \(rule.name)", isOn: $rule.isEnabled)
                                .labelsHidden()
                            TextField("Rule name", text: $rule.name).frame(width: 150)
                                .focused($focusedRuleName, equals: rule.id)
                            Spacer()
                            ColorPicker(
                                "Text",
                                selection: colorBinding(rule.id, foreground: true),
                                supportsOpacity: false
                            )
                            ColorPicker(
                                "Background",
                                selection: colorBinding(rule.id, foreground: false),
                                supportsOpacity: false
                            )
                            Button("Move Up", systemImage: "chevron.up") { move(rule.id, offset: -1) }
                                .labelStyle(.iconOnly)
                                .disabled(rules.first?.id == rule.id)
                                .accessibilityLabel("Move \(rule.name) up")
                            Button("Move Down", systemImage: "chevron.down") { move(rule.id, offset: 1) }
                                .labelStyle(.iconOnly)
                                .disabled(rules.last?.id == rule.id)
                                .accessibilityLabel("Move \(rule.name) down")
                            Button("Duplicate Rule", systemImage: "plus.square.on.square") { duplicate(rule.id) }
                                .labelStyle(.iconOnly)
                                .disabled(rules.count >= FrameColorRuleLibrary.maximumRules)
                                .accessibilityLabel("Duplicate \(rule.name)")
                            Button(
                                "Remove", systemImage: "minus.circle", role: .destructive
                            ) { rules.removeAll { $0.id == rule.id } }
                                .labelStyle(.iconOnly)
                                .accessibilityLabel("Remove \(rule.name)")
                        }
                        TextField("Frame Expression", text: $rule.expression)
                            .textFieldStyle(.roundedBorder)
                        if !FrameColorRuleLibrary.isValid(rule) || !hasUniqueName(rule) {
                            Text("Use a unique name, valid expression and colors with at least 4.5:1 contrast.")
                                .font(Theme.Typography.micro).foregroundStyle(.orange)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .listStyle(.inset)
            if let message {
                Text(message).foregroundStyle(.red)
            }
            if let importReport {
                ScrollView {
                    Text(importReport)
                        .font(Theme.Typography.micro)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 100)
                .padding(8)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
            HStack {
                Button("Add Rule", systemImage: "plus") { addRule() }
                    .disabled(rules.count >= FrameColorRuleLibrary.maximumRules)
                Button("Import Wireshark Rules…", systemImage: "square.and.arrow.down") { isImporting = true }
                    .disabled(rules.count >= FrameColorRuleLibrary.maximumRules)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!isValid)
            }
        }
        .padding(20)
        .frame(minWidth: 860, minHeight: 500)
        // Typing starts in the first rule's name rather than nowhere.
        .task { focusedRuleName = rules.first?.id }
        .fileImporter(
            isPresented: $isImporting,
            allowedContentTypes: [.json, .plainText, .data, UTType(filenameExtension: "jsonc") ?? .plainText],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case let .success(urls):
                guard let url = urls.first else {
                    return
                }
                importWiresharkRules(from: url)
            case .failure:
                message = "Could not open the selected rule file."
            }
        }
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var rules: [FrameColorRule]
    @State private var message: String?
    @State private var importReport: String?
    @State private var isImporting = false
    @FocusState private var focusedRuleName: UUID?

    private var isValid: Bool {
        rules.count <= FrameColorRuleLibrary.maximumRules
            && rules.allSatisfy(FrameColorRuleLibrary.isValid)
            && Set(rules.map { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }).count == rules
            .count
    }

    private func addRule() {
        var name = "New Rule"
        var suffix = 1
        let names = Set(rules.map { $0.name.lowercased() })
        while names.contains(name.lowercased()) {
            suffix += 1
            name = "New Rule \(suffix)"
        }
        rules.append(FrameColorRule(
            name: name, expression: "tcp.flags.reset", foregroundRGB: 0xFFFFFF, backgroundRGB: 0x7F1D1D
        ))
    }

    private func importWiresharkRules(from url: URL) {
        let hasSecurityScope = url.startAccessingSecurityScopedResource()
        defer {
            if hasSecurityScope {
                url.stopAccessingSecurityScopedResource()
            }
        }
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let limit = WiresharkColorRuleImporter.maximumFileBytes
            let data = try handle.read(upToCount: limit + 1) ?? Data()
            guard data.count <= limit else {
                throw WiresharkColorRuleImportError.fileTooLarge
            }
            let parsed = try WiresharkColorRuleImporter.parse(data)
            var names = Set(rules.map { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
            var added: [FrameColorRule] = []
            var skipped = parsed.skipped
            for rule in parsed.rules {
                let normalizedName = rule.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard !names.contains(normalizedName) else {
                    skipped.append("\(rule.name): duplicate name; existing Project rule kept.")
                    continue
                }
                guard rules.count + added.count < FrameColorRuleLibrary.maximumRules else {
                    skipped
                        .append("\(rule.name): Project limit of \(FrameColorRuleLibrary.maximumRules) rules reached.")
                    continue
                }
                names.insert(normalizedName)
                added.append(rule)
            }
            rules.append(contentsOf: added)
            let summary = "Imported \(added.count) of \(parsed.sourceRuleCount) source rules into the draft. Nothing is saved until you select Save."
            importReport = ([summary] + skipped).joined(separator: "\n")
            message = nil
        } catch let error as WiresharkColorRuleImportError {
            message = switch error {
            case .fileTooLarge: "Rule file exceeds the 1 MiB import limit."
            case .malformedFile: "The selected file is not a supported Wireshark coloring-rules file."
            case .tooManyRules: "The selected file exceeds the 256-rule import limit."
            }
            importReport = nil
        } catch {
            message = "Could not import the selected rule file."
            importReport = nil
        }
    }

    private func move(_ id: UUID, offset: Int) {
        guard let index = rules.firstIndex(where: { $0.id == id }) else {
            return
        }
        let destination = index + offset
        guard rules.indices.contains(destination) else {
            return
        }
        rules.swapAt(index, destination)
    }

    private func duplicate(_ id: UUID) {
        guard let index = rules.firstIndex(where: { $0.id == id }),
              let copy = FrameColorRuleLibrary.duplicate(rules[index], among: rules) else
        {
            return
        }
        rules.insert(copy, at: index + 1)
    }

    private func hasUniqueName(_ rule: FrameColorRule) -> Bool {
        rules.filter { $0.id != rule.id }.allSatisfy { $0.name.caseInsensitiveCompare(rule.name) != .orderedSame }
    }

    private func colorBinding(_ id: UUID, foreground: Bool) -> Binding<Color> {
        Binding {
            guard let rule = rules.first(where: { $0.id == id }) else {
                return .white
            }
            return color(ruleRGB: foreground ? rule.foregroundRGB : rule.backgroundRGB)
        } set: { selected in
            guard let rgb = packedRGB(selected), let index = rules.firstIndex(where: { $0.id == id }) else {
                return
            }
            if foreground {
                rules[index].foregroundRGB = rgb
            } else {
                rules[index].backgroundRGB = rgb
            }
        }
    }

    private func color(ruleRGB rgb: UInt32) -> Color {
        Color(
            red: Double((rgb >> 16) & 0xFF) / 255,
            green: Double((rgb >> 8) & 0xFF) / 255,
            blue: Double(rgb & 0xFF) / 255
        )
    }

    private func packedRGB(_ color: Color) -> UInt32? {
        guard let rgb = NSColor(color).usingColorSpace(.deviceRGB) else {
            return nil
        }
        let red = UInt32((rgb.redComponent * 255).rounded())
        let green = UInt32((rgb.greenComponent * 255).rounded())
        let blue = UInt32((rgb.blueComponent * 255).rounded())
        return (red << 16) | (green << 8) | blue
    }

    private func save() {
        let cleaned = rules.map {
            FrameColorRule(
                id: $0.id, name: $0.name.trimmingCharacters(in: .whitespacesAndNewlines),
                expression: $0.expression.trimmingCharacters(in: .whitespacesAndNewlines),
                foregroundRGB: $0.foregroundRGB, backgroundRGB: $0.backgroundRGB, isEnabled: $0.isEnabled
            )
        }
        guard library.replaceAll(cleaned, expectedProjectID: expectedProjectID) else {
            message = "This Project changed or its coloring rules could not be saved."
            return
        }
        dismiss()
    }
}
