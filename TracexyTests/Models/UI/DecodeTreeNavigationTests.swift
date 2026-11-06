import Foundation
import Testing
@testable import Tracexy

/// Layers keyboard: ↑ ↓ step through the rows shown, ← folds a layer or goes to its
/// parent, → unfolds or enters it, ⌘→ / ⌘← unfold or fold everything.
struct DecodeTreeNavigationTests {
    // MARK: Internal

    @Test
    func arrowsMoveAndFoldAsWiresharkDetailsDo() throws {
        let tcp = DecodedLayer(
            proto: .tcp, title: "Transmission Control Protocol", summary: "",
            fields: [Self.field("Source Port", 34 ..< 36), Self.field("Destination Port", 36 ..< 38)],
            byteRange: 34 ..< 54
        )
        let ip = DecodedLayer(
            proto: .ipv4, title: "Internet Protocol v4", summary: "",
            fields: [Self.field("TTL", 22 ..< 23)], byteRange: 14 ..< 34
        )
        let layers = [ip, tcp]
        let press = { (key: DecodeTreeNavigation.Key, selection: Range<Int>?, collapsed: Set<String>) in
            DecodeTreeNavigation.press(key, layers: layers, selection: selection, collapsed: collapsed)
        }
        #expect(DecodeTreeNavigation.rows(layers, collapsed: []).map(\.range) == [
            14 ..< 34, 22 ..< 23, 34 ..< 54, 34 ..< 36, 36 ..< 38,
        ])
        // ↓ from nothing selects the first row; ↓ steps; ↑ at the top does nothing.
        #expect(press(.down, nil, [])?.selection == 14 ..< 34)
        #expect(press(.down, 22 ..< 23, [])?.selection == 34 ..< 54)
        #expect(press(.up, 14 ..< 34, []) == nil)
        // ← on an open layer folds it; again, a field goes to its layer.
        #expect(press(.left, 34 ..< 54, [])?.collapsed == [tcp.title])
        #expect(press(.left, 36 ..< 38, [])?.selection == 34 ..< 54)
        // A folded layer's fields are skipped; → unfolds it, then enters it.
        #expect(press(.down, 14 ..< 34, [ip.title])?.selection == 34 ..< 54)
        #expect(press(.right, 14 ..< 34, [ip.title])?.collapsed.isEmpty == true)
        #expect(press(.right, 14 ..< 34, [])?.selection == 22 ..< 23)
        // ⌘← folds everything and keeps the selection on the field's layer; ⌘→ opens all.
        let folded = try #require(press(.collapseAll, 36 ..< 38, []))
        #expect(folded.collapsed == [ip.title, tcp.title])
        #expect(folded.selection == 34 ..< 54)
        #expect(press(.expandAll, 34 ..< 54, [ip.title, tcp.title])?.collapsed.isEmpty == true)
    }

    @Test
    func subtreeCommandsRecursivelyExpandAndCollapseOnlyTheSelectedLayer() throws {
        let grandchild = DecodedLayer(proto: .tls, title: "TLS", byteRange: 20 ..< 30)
        let child = DecodedLayer(proto: .tcp, title: "TCP", children: [grandchild], byteRange: 10 ..< 20)
        let root = DecodedLayer(proto: .ipv4, title: "IPv4", children: [child], byteRange: 0 ..< 10)
        let sibling = DecodedLayer(proto: .udp, title: "UDP", byteRange: 30 ..< 40)
        let layers = [root, sibling]

        let expanded = try #require(DecodeTreeNavigation.press(
            .expandSubtree, layers: layers, selection: root.byteRange,
            collapsed: [root.title, child.title, grandchild.title, sibling.title, "Unrelated"]
        ))
        #expect(expanded.selection == root.byteRange)
        #expect(expanded.collapsed == [sibling.title, "Unrelated"])

        let collapsed = try #require(DecodeTreeNavigation.press(
            .collapseSubtree, layers: layers, selection: root.byteRange, collapsed: [sibling.title, "Unrelated"]
        ))
        #expect(collapsed.collapsed == [root.title, child.title, grandchild.title, sibling.title, "Unrelated"])
        #expect(collapsed.selection == root.byteRange)

        let alreadyOpenParent = try #require(DecodeTreeNavigation.press(
            .expandSubtree, layers: layers, selection: root.byteRange,
            collapsed: [child.title, grandchild.title, sibling.title]
        ))
        #expect(alreadyOpenParent.collapsed == [sibling.title])
    }

    @Test
    func subtreeCommandsRequireAVisibleLayerHeaderAndKeepArrowCommandsDistinct() throws {
        let child = DecodedLayer(proto: .tcp, title: "TCP", byteRange: 10 ..< 20)
        let root = DecodedLayer(
            proto: .ipv4, title: "IPv4", fields: [Self.field("TTL", 2 ..< 3)],
            children: [child], byteRange: 0 ..< 10
        )
        let layers = [root]
        #expect(DecodeTreeNavigation.press(
            .expandSubtree, layers: layers, selection: 2 ..< 3, collapsed: [root.title, child.title]
        ) == nil)
        let wholeTree = try #require(DecodeTreeNavigation.press(
            .expandAll, layers: layers, selection: root.byteRange, collapsed: [root.title, child.title]
        ))
        #expect(wholeTree.collapsed.isEmpty)
        let oneLayer = try #require(DecodeTreeNavigation.press(
            .right, layers: layers, selection: root.byteRange, collapsed: [root.title, child.title]
        ))
        #expect(oneLayer.collapsed == [child.title])
    }

    @Test
    func shiftAndCommandArrowModifiersSelectSubtreeAndWholeTreeCommands() {
        #expect(DecodeTreeNavigation.key(for: .right, command: false, shift: false) == .right)
        #expect(DecodeTreeNavigation.key(for: .left, command: false, shift: false) == .left)
        #expect(DecodeTreeNavigation.key(for: .right, command: false, shift: true) == .expandSubtree)
        #expect(DecodeTreeNavigation.key(for: .left, command: false, shift: true) == .collapseSubtree)
        #expect(DecodeTreeNavigation.key(for: .right, command: true, shift: false) == .expandAll)
        #expect(DecodeTreeNavigation.key(for: .left, command: true, shift: false) == .collapseAll)
        #expect(DecodeTreeNavigation.key(for: .right, command: true, shift: true) == .expandAll)
        #expect(DecodeTreeNavigation.key(for: .left, command: true, shift: true) == .collapseAll)
    }

    @Test
    func subtreeCommandsKeepExistingSharedTitleFoldBehavior() throws {
        let nested = DecodedLayer(proto: .tcp, title: "Shared", byteRange: 10 ..< 20)
        let root = DecodedLayer(proto: .ipv4, title: "Root", children: [nested], byteRange: 0 ..< 10)
        let sibling = DecodedLayer(proto: .udp, title: "Shared", byteRange: 30 ..< 40)
        let collapsed = try #require(DecodeTreeNavigation.press(
            .collapseSubtree, layers: [root, sibling], selection: root.byteRange, collapsed: []
        ))
        #expect(collapsed.collapsed == [root.title, "Shared"])

        let expanded = try #require(DecodeTreeNavigation.press(
            .expandSubtree, layers: [root, sibling], selection: root.byteRange, collapsed: collapsed.collapsed
        ))
        #expect(expanded.collapsed.isEmpty)
    }

    // MARK: Private

    private static func field(_ name: String, _ range: Range<Int>) -> DecodedField {
        DecodedField(name: name, value: "1", byteRange: range)
    }
}
