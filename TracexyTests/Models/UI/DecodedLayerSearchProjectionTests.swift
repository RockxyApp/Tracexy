import Testing
@testable import Tracexy

@Suite("Decoded layer search projection")
struct DecodedLayerSearchProjectionTests {
    // MARK: Internal

    @Test("Empty query preserves the original tree")
    func emptyQuery() {
        let layers = Self.fixture()
        let whitespace = DecodedLayerSearchProjection.filter(layers, query: "  ")
        let empty = DecodedLayerSearchProjection.filter(layers, query: "")
        #expect(whitespace == layers)
        #expect(empty.first?.id == layers.first?.id)
    }

    @Test("Field match retains matching ancestors and exact field ranges")
    func fieldMatchPreservesRangesAndMetadata() throws {
        let source = try #require(Self.fixture().first)
        let projection = try #require(DecodedLayerSearchProjection.filter([source], query: "API.EXAMPLE").first)
        let projectedTCP = try #require(projection.children.first)
        let projectedDNS = try #require(projectedTCP.children.first)
        let field = try #require(projectedDNS.fields.first)

        #expect(projection.title == source.title)
        #expect(projection.proto == source.proto)
        #expect(projection.byteRange == source.byteRange)
        #expect(projection.id == source.id)
        #expect(projectedTCP.byteRange == source.children[0].byteRange)
        #expect(projectedTCP.id == source.children[0].id)
        #expect(projectedDNS.summary == source.children[0].children[0].summary)
        #expect(field.value == "api.example.test")
        #expect(field.byteRange == 50 ..< 66)
        #expect(projection.fields.isEmpty)
        #expect(projectedTCP.fields.isEmpty)
    }

    @Test("Layer title match preserves its complete subtree")
    func layerMatchKeepsCompleteSubtree() throws {
        let source = try #require(Self.fixture().first)
        let sourceTCP = try #require(source.children.first)
        let projection = try #require(DecodedLayerSearchProjection.filter([sourceTCP], query: "443").first)

        #expect(projection.title == sourceTCP.title)
        #expect(projection.fields == sourceTCP.fields)
        #expect(projection.children == sourceTCP.children)
    }

    @Test("No matches return an empty projection")
    func noMatch() {
        let projection = DecodedLayerSearchProjection.filter(Self.fixture(), query: "absent-value")
        #expect(projection.first == nil)
    }

    @Test("Tree navigation uses the filtered projection rather than hidden source rows")
    func navigationRowsFollowProjection() throws {
        let projected = DecodedLayerSearchProjection.filter(Self.fixture(), query: "api.example")
        let rows = DecodeTreeNavigation.rows(projected, collapsed: [])
        #expect(rows.contains { $0.range == 50 ..< 66 })
        #expect(!rows.contains { $0.range == 22 ..< 23 })
        #expect(!rows.contains { $0.range == 34 ..< 36 })
        let next = try #require(DecodeTreeNavigation.press(
            .down, layers: projected, selection: 22 ..< 23, collapsed: []
        ))
        #expect(next.selection == rows.first?.range)
    }

    @Test("Byte owners remain exact when visible and stay hidden when filtered out")
    func byteOwnerProjectionAndAncestorExpansion() throws {
        let source = Self.fixture()
        let sourceOwner = try #require(DecodedByteMap.owner(ofByte: 50, in: source))
        let visible = DecodedLayerSearchProjection.filter(source, query: "api.example")
        #expect(DecodedByteMap.owner(ofByte: 50, in: visible) == sourceOwner)

        let hidden = DecodedLayerSearchProjection.filter(source, query: "64")
        #expect(DecodedByteMap.owner(ofByte: 50, in: hidden) == nil)

        var collapsed: Set = ["Internet Protocol v4", "Transmission Control Protocol", "Unrelated"]
        collapsed.subtract(sourceOwner.path.dropLast())
        #expect(collapsed == ["Unrelated"])
    }

    // MARK: Private

    private static func fixture() -> [DecodedLayer] {
        let dns = DecodedLayer(
            proto: .dns, title: "Domain Name System", summary: "query",
            fields: [DecodedField(name: "Query", value: "api.example.test", byteRange: 50 ..< 66)],
            byteRange: 46 ..< 82
        )
        let tcp = DecodedLayer(
            proto: .tcp, title: "Transmission Control Protocol", summary: "443 → 50000",
            fields: [DecodedField(name: "Source Port", value: "443", byteRange: 34 ..< 36)],
            children: [dns], byteRange: 34 ..< 46
        )
        return [DecodedLayer(
            proto: .ipv4, title: "Internet Protocol v4", summary: "192.0.2.1 → 192.0.2.2",
            fields: [DecodedField(name: "TTL", value: "64", byteRange: 22 ..< 23)],
            children: [tcp], byteRange: 14 ..< 34
        )]
    }
}
