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

    // MARK: Private

    private static func field(_ name: String, _ range: Range<Int>) -> DecodedField {
        DecodedField(name: name, value: "1", byteRange: range)
    }
}
