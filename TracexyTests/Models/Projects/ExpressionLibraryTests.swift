import Foundation
import Testing
@testable import Tracexy

// MARK: - ExpressionMacroTests

@Suite("Expression macros")
struct ExpressionMacroTests {
    // MARK: Internal

    @Test("A macro without values expands and is grouped so precedence holds")
    func plainExpansion() throws {
        let expansion = try expand("$web and dns")
        #expect(expansion.text == "(tcp or udp) and dns")
        #expect(expansion.usedMacros)
    }

    @Test("Values fill $1 … $n in all three spellings")
    func valueSpellings() throws {
        #expect(try expand("$port_or(443, 8443)").text == "(port == 443 or port == 8443)")
        #expect(try expand("${port_or:443;8443}").text == "(port == 443 or port == 8443)")
        #expect(try expand("${web}").text == "(tcp or udp)")
        #expect(try expand("$web()").text == "(tcp or udp)")
    }

    @Test("A fragment that is not a whole expression is inserted as written")
    func fragmentsAreNotWrapped() throws {
        let expansion = try expand("port in {$ports}")
        #expect(expansion.text == "port in {80, 443}")
        #expect(try SessionQueryParser().parse(expansion.text) == SessionQueryParser().parse("port in {80, 443}"))
    }

    @Test("Values may hold sets and brackets; commas inside them do not split values")
    func nestedValueSeparators() throws {
        let expansion = try expand("$ports_in({80, 443})")
        #expect(expansion.text == "(port in {80, 443})")
    }

    @Test("Macros nest, and a value may use a macro")
    func nestedMacros() throws {
        #expect(try expand("$secure_web").text == "((tcp or udp) and tls)")
        #expect(try expand("$port_or($one, 8443)").text == "(port == 443 or port == 8443)")
        // Using a macro inside the value of the same macro is not a cycle.
        #expect(try expand("$both($both(tcp, udp), dns)").text == "((tcp and udp) and dns)")
    }

    @Test("Quoted text is left alone, and a value placed inside quotes is escaped")
    func quoting() throws {
        #expect(try expand("host contains \"$web\"").text == "host contains \"$web\"")
        #expect(try expand("$host_has(a\\b)").text == "(host contains \"a\\\\b\")")
    }

    @Test("An unknown macro is reported at its use")
    func unknownMacro() {
        let error = expansionError("tcp and $nope")
        #expect(error?.kind == .unknownMacro("nope"))
        #expect(error?.position == 9)
        #expect(error?.parseError.reason == .unknownName("$nope"))
    }

    @Test("Too few or too many values is reported at the use")
    func arityMismatch() {
        let few = expansionError("dns or $port_or(443)")
        #expect(few?.kind == .wrongValueCount(name: "port_or", expected: 2, given: 1))
        #expect(few?.position == 8)
        let many = expansionError("$web(1)")
        #expect(many?.kind == .wrongValueCount(name: "web", expected: 0, given: 1))
        #expect(many?.position == 1)
        guard case .operatorNotSupportedForField(field: "$web", _) = many?.parseError.reason else {
            Issue.record("Arity mismatch should read as an unsupported use of the macro")
            return
        }
    }

    @Test("A macro that reaches itself is a cycle, directly or through another")
    func cycles() {
        let macros = [
            ExpressionMacro(name: "a", text: "tcp and $b"),
            ExpressionMacro(name: "b", text: "udp or $a"),
            ExpressionMacro(name: "me", text: "$me"),
        ]
        let indirect = expansionError("dns and $a", macros: macros)
        #expect(indirect?.kind == .cycle("a"))
        #expect(indirect?.position == 9)
        #expect(indirect?.parseError.reason == .depthLimitExceeded(limit: 8))
        #expect(expansionError("$me", macros: macros)?.kind == .cycle("me"))
        #expect(ExpressionMacroValidation.macrosInCycles(macros).count == 3)
    }

    @Test("Nesting deeper than eight is refused")
    func depthLimit() throws {
        var macros = [ExpressionMacro(name: "m0", text: "tcp")]
        for level in 1 ... 9 {
            macros.append(ExpressionMacro(name: "m\(level)", text: "$m\(level - 1)"))
        }
        #expect(try ExpressionMacroExpander(macros: macros).expand("$m7").text.contains("tcp"))
        #expect(expansionError("$m9", macros: macros)?.kind == .tooDeep)
    }

    @Test("Exponential expansion stops at the byte ceiling")
    func expansionIsBounded() {
        var macros = [ExpressionMacro(name: "x0", text: "tcp or udp or dns or tls")]
        for level in 1 ... 7 {
            macros.append(ExpressionMacro(
                name: "x\(level)",
                text: "$x\(level - 1) or $x\(level - 1) or $x\(level - 1)"
            ))
        }
        let error = expansionError("$x7", macros: macros)
        #expect(error?.kind == .tooLong)
        #expect(error?.position == 1)
    }

    @Test("Unclosed values and a bare ${ are positioned errors")
    func malformedUses() {
        #expect(expansionError("dns or $port_or(443, 8443")?.kind == .unclosedValues(brace: false))
        #expect(expansionError("${port_or:443;8443")?.kind == .unclosedValues(brace: true))
        #expect(expansionError("${}")?.kind == .missingName)
        #expect(expansionError("${}")?.parseError.reason == .unexpectedCharacter)
    }

    @Test("A parse error in the expanded text points back at what was typed")
    func positionsMapBack() {
        let result = ExpressionLibraryPreprocessing.preprocess("$web and and", macros: Self.macros)
        guard case let .failure(error) = result, case let .expression(parseError) = error.reason else {
            Issue.record("Expected a positioned expression error")
            return
        }
        // "$web and and": the second `and` is at character 10 of what was typed.
        #expect(parseError.position == 10)
        #expect(parseError.reason == .expectedExpression)

        let inside = ExpressionLibraryPreprocessing.preprocess(
            "tcp and $p(x)",
            macros: [ExpressionMacro(name: "p", text: "port == $1")]
        )
        guard case let .failure(insideError) = inside, case let .expression(insideParse) = insideError.reason else {
            Issue.record("Expected a positioned expression error")
            return
        }
        #expect(insideParse.position == 9)
    }

    @Test("Text without a $ outside quotes passes through untouched")
    func passThrough() {
        #expect(ExpressionLibraryPreprocessing
            .preprocess("tcp and port == 443", macros: []) == .success("tcp and port == 443"))
        #expect(ExpressionLibraryPreprocessing
            .preprocess("host contains \"$x\"", macros: []) == .success("host contains \"$x\""))
        // A lone `$` is left for the parser, which rejects it as it always has.
        #expect(ExpressionLibraryPreprocessing.preprocess("$ tcp", macros: []) == .success("$ tcp"))
    }

    @Test("Definitions are checked: names, duplicates, placeholders, cycles")
    func definitionValidation() {
        let first = ExpressionMacro(name: "ok", text: "tcp")
        let duplicate = ExpressionMacro(name: "ok", text: "udp")
        let badName = ExpressionMacro(name: "1st", text: "tcp")
        let zero = ExpressionMacro(name: "zero", text: "port == $0")
        let ten = ExpressionMacro(name: "ten", text: "port == $10")
        let empty = ExpressionMacro(name: "empty", text: "  ")
        let problems = ExpressionMacroValidation.problems(in: [first, duplicate, badName, zero, ten, empty])
        #expect(problems[first.id] == nil)
        #expect(problems[duplicate.id] == .duplicateName)
        #expect(problems[badName.id] == .invalidName)
        #expect(problems[zero.id] == .tooManyValues)
        #expect(problems[ten.id] == .tooManyValues)
        #expect(problems[empty.id] == .emptyText)
        #expect(ExpressionMacro(name: "p", text: "port == $2 or port == $1").arity == 2)
        #expect(!ExpressionMacro.isValidName("has space"))
        #expect(!ExpressionMacro.isValidName(String(repeating: "a", count: 33)))
        #expect(ExpressionMacro.isValidName("_web2"))
    }

    // MARK: Private

    private static let macros = [
        ExpressionMacro(name: "web", text: "tcp or udp"),
        ExpressionMacro(name: "one", text: "443"),
        ExpressionMacro(name: "ports", text: "80, 443"),
        ExpressionMacro(name: "port_or", text: "port == $1 or port == $2"),
        ExpressionMacro(name: "ports_in", text: "port in $1"),
        ExpressionMacro(name: "secure_web", text: "$web and tls"),
        ExpressionMacro(name: "both", text: "$1 and $2"),
        ExpressionMacro(name: "host_has", text: "host contains \"$1\""),
    ]

    private func expand(_ text: String, macros: [ExpressionMacro] = Self.macros) throws -> ExpressionMacroExpansion {
        try ExpressionMacroExpander(macros: macros).expand(text)
    }

    private func expansionError(_ text: String, macros: [ExpressionMacro] = Self.macros) -> ExpressionMacroError? {
        do {
            _ = try ExpressionMacroExpander(macros: macros).expand(text)
            return nil
        } catch {
            return error as? ExpressionMacroError
        }
    }
}

// MARK: - FilterButtonGroupingTests

@Suite("Filter button grouping and storage")
struct FilterButtonGroupingTests {
    @Test("Group//Label makes pull-downs in order of first appearance, nested by further //")
    func grouping() {
        let a = FilterButton(label: "All TLS", expression: "tls")
        let b = FilterButton(label: "Web // HTTP", expression: "http")
        let c = FilterButton(label: "DNS", expression: "dns")
        let d = FilterButton(label: "Web//QUIC", expression: "quic")
        let e = FilterButton(label: "Lab//Hosts//Printer", expression: "host contains \"printer\"")
        let items = FilterButtonItem.build([a, b, c, d, e])
        #expect(items == [
            .button(a, title: "All TLS"),
            .group(name: "Web", items: [.button(b, title: "HTTP"), .button(d, title: "QUIC")]),
            .button(c, title: "DNS"),
            .group(name: "Lab", items: [.group(name: "Hosts", items: [.button(e, title: "Printer")])]),
        ])
        #expect(b.title == "HTTP")
        #expect(b.helpText == "http")
        #expect(FilterButton(label: "x", expression: "tcp", comment: "Why").helpText == "Why")
    }

    @Test("Empty path parts are dropped and deep paths stop nesting")
    func edgePaths() {
        let odd = FilterButton(label: "//Web////TLS//", expression: "tls")
        #expect(odd.path == ["Web", "TLS"])
        let deep = FilterButton(label: "a//b//c//d//e//f", expression: "tcp")
        let items = FilterButtonItem.build([deep])
        guard case let .group("a", level2) = items.first,
              case let .group("b", level3) = level2.first,
              case let .group("c", level4) = level3.first,
              case let .button(_, title) = level4.first else
        {
            Issue.record("Expected three levels of groups")
            return
        }
        #expect(title == "d // e // f")
    }

    @Test("Stored lists drop entries that fail their checks and keep the storage ceiling")
    func storeSanitizes() throws {
        let suite = "ExpressionLibraryTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        var buttons = (0 ..< FilterButton.maximumButtons + 20).map { FilterButton(label: "B\($0)", expression: "tcp") }
        buttons.insert(FilterButton(label: "", expression: "tcp"), at: 0)
        buttons.insert(FilterButton(label: "bell\u{7}", expression: "tcp"), at: 0)
        ExpressionLibraryStore.save(buttons, to: defaults)
        let loaded = ExpressionLibraryStore.loadButtons(from: defaults)
        #expect(loaded.count == FilterButton.maximumButtons)
        #expect(loaded.first?.label == "B0")

        ExpressionLibraryStore.save(
            [
                ExpressionMacro(name: "ok", text: "tcp"),
                ExpressionMacro(name: "ok", text: "udp"),
                ExpressionMacro(name: "bad name", text: "tcp")
            ],
            to: defaults
        )
        #expect(ExpressionLibraryStore.loadMacros(from: defaults).map(\.text) == ["tcp"])

        defaults.set(Data("not json".utf8), forKey: ExpressionLibraryStore.buttonsKey)
        #expect(ExpressionLibraryStore.loadButtons(from: defaults).isEmpty)
    }
}

// MARK: - ExpressionLibraryWorkflowTests

/// The library on the real Session Expression path: macros expand before parsing,
/// what the user typed is what is accepted and remembered, and a filter button
/// applies exactly as typing its expression would.
@MainActor
@Suite("Expression library workflow")
struct ExpressionLibraryWorkflowTests {
    // MARK: Internal

    @Test("Macros expand before parsing; the typed text is accepted and remembered")
    func macrosExpand() async throws {
        let isolation = ProjectIsolationEnvironment(name: "expression-library-workflow")
        defer { isolation.tearDown() }
        let coordinator = try await Self.openCapture(isolation)
        let controller = coordinator.filterLibrary
        controller.attach(to: coordinator)
        controller.setMacros([ExpressionMacro(name: "proto", text: "$1")])
        let workspace = coordinator.activeWorkspace

        coordinator.applySessionExpression("$proto(tcp)")
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(workspace.investigationQueryError == nil)
        #expect(workspace.acceptedInvestigationDraft?.expression == "$proto(tcp)")
        #expect(coordinator.expressionLibrary.recent.first == "$proto(tcp)")
        let tcpIDs = Set(coordinator.sessions.filter { $0.protocolStack.contains(.tcp) }.map(\.id))
        #expect(!tcpIDs.isEmpty)
        #expect(workspace.investigationMatchedSessionIDs == tcpIDs)
        #expect(controller.acceptedExpansion()?.expanded == "(tcp)")

        // An unknown macro takes the ordinary positioned error path and keeps the
        // accepted query in place.
        coordinator.applySessionExpression("tcp and $missing")
        await coordinator.waitForInvestigationQuery(in: workspace)
        guard case let .expression(parseError) = workspace.investigationQueryError?.reason else {
            Issue.record("Expected a positioned expression error")
            return
        }
        #expect(parseError.position == 9)
        #expect(parseError.reason == .unknownName("$missing"))
        #expect(workspace.acceptedInvestigationDraft?.expression == "$proto(tcp)")
        #expect(coordinator.expressionLibrary.recent.first == "$proto(tcp)")
    }

    @Test("A filter button applies like typing its expression and choosing Apply")
    func buttonApplies() async throws {
        let isolation = ProjectIsolationEnvironment(name: "expression-library-button")
        defer { isolation.tearDown() }
        let coordinator = try await Self.openCapture(isolation)
        let controller = coordinator.filterLibrary
        controller.attach(to: coordinator)
        let workspace = coordinator.activeWorkspace
        workspace.sidebarSelection = .history

        let button = FilterButton(label: "Only TCP", expression: "tcp")
        #expect(controller.commit(button))
        controller.apply(button)
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.acceptedInvestigationDraft?.expression == "tcp")
        #expect(workspace.investigationDraft.mode == .expression)
        #expect(coordinator.expressionLibrary.recent.first == "tcp")

        // A rejected expression opens the editor on its error.
        let broken = FilterButton(label: "Broken", expression: "port in {")
        controller.apply(broken)
        await coordinator.waitForInvestigationQuery(in: workspace)
        for _ in 0 ..< 20 where !workspace.isInvestigationEditorPresented {
            await Task.yield()
        }
        #expect(workspace.investigationQueryError != nil)
        #expect(workspace.isInvestigationEditorPresented)
        #expect(workspace.acceptedInvestigationDraft?.expression == "tcp")
    }

    @Test("Buttons and macros belong to the Project they were made in")
    func projectIsolation() async {
        let isolation = ProjectIsolationEnvironment(name: "expression-library-projects")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let controller = coordinator.filterLibrary
        controller.attach(to: coordinator)
        let first = coordinator.projectStore.activeProjectID
        controller.commit(FilterButton(label: "A", expression: "tcp"))
        controller.setMacros([ExpressionMacro(name: "a", text: "tcp")])

        _ = coordinator.createProject(named: "Second")
        #expect(await coordinator.waitForProjectTransition())
        controller.syncProject()
        #expect(coordinator.projectStore.activeProjectID != first)
        #expect(controller.buttons.isEmpty)
        #expect(controller.macros.isEmpty)

        #expect(coordinator.switchToProject(id: first))
        #expect(await coordinator.waitForProjectTransition())
        controller.syncProject()
        #expect(controller.buttons.map(\.label) == ["A"])
        #expect(controller.macros.map(\.name) == ["a"])
    }

    @Test("Adding stops at the policy limit; a list already above it stays whole and editable")
    func growthLimits() async {
        let isolation = ProjectIsolationEnvironment(name: "expression-library-limits")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator(policy: LibraryPolicy(
            maxFilterButtons: 30,
            maxExpressionMacros: 30
        ))
        await coordinator.hydrateProjectsOnLaunch()
        let controller = coordinator.filterLibrary
        controller.attach(to: coordinator)
        for index in 0 ..< 30 {
            #expect(controller.commit(FilterButton(label: "B\(index)", expression: "tcp")))
        }
        #expect(!controller.commit(FilterButton(label: "B30", expression: "tcp")))
        controller.setMacros((0 ..< 30).map { ExpressionMacro(name: "m\($0)", text: "tcp") })

        coordinator.applyPolicy(LibraryPolicy())
        #expect(controller.buttonLimit == 10)
        #expect(controller.macroLimit == 10)
        #expect(controller.buttons.count == 30)
        #expect(controller.macros.count == 30)
        #expect(!controller.canAddButton)
        #expect(!controller.canAddMacro)
        #expect(!controller.commit(FilterButton(label: "New", expression: "udp")))

        var edited = controller.buttons[29]
        edited.label = "Edited"
        #expect(controller.commit(edited))
        #expect(controller.buttons[29].label == "Edited")
        controller.delete(controller.buttons[0])
        #expect(controller.buttons.count == 29)

        // A relaunch under the lower limit reads the whole list back.
        controller.syncProject()
        #expect(ExpressionLibraryStore.loadButtons(from: coordinator.activeProjectDefaults).count == 29)
        #expect(ExpressionLibraryStore.loadMacros(from: coordinator.activeProjectDefaults).count == 30)
    }

    @Test("The default limits are ten buttons and ten macros; the ceilings bound any policy")
    func defaultLimits() {
        let coordinator = MainContentCoordinator()
        coordinator.filterLibrary.attach(to: coordinator)
        #expect(coordinator.filterLibrary.buttonLimit == 10)
        #expect(coordinator.filterLibrary.macroLimit == 10)
        coordinator.applyPolicy(LibraryPolicy(maxFilterButtons: 1_000_000, maxExpressionMacros: 1_000_000))
        #expect(coordinator.filterLibrary.buttonLimit == ProjectLimits.maximumFilterButtons)
        #expect(coordinator.filterLibrary.macroLimit == ProjectLimits.maximumExpressionMacros)
    }

    // MARK: Private

    private static func openCapture(_ isolation: ProjectIsolationEnvironment) async throws -> MainContentCoordinator {
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("library.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "library", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        return coordinator
    }
}

// MARK: - LibraryPolicy

private struct LibraryPolicy: AppPolicy {
    var maxFilterButtons = 10
    var maxExpressionMacros = 10
}
