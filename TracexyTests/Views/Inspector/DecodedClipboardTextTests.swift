import Testing
@testable import Tracexy

@Suite("Decoded inspector clipboard text")
struct DecodedClipboardTextTests {
    @Test("Field actions preserve the decoded name and value verbatim")
    func fieldText() {
        let field = DecodedField(name: "Server Name", value: "api.example.test")

        #expect(DecodedClipboardText.value(field) == "api.example.test")
        #expect(DecodedClipboardText.name(field) == "Server Name")
        #expect(DecodedClipboardText.nameValue(field) == "Server Name: api.example.test")
    }

    @Test("Layer summary mirrors the visible header without duplicating its fields")
    func layerSummary() {
        let summarized = DecodedLayer(
            proto: .tls,
            title: "Transport Layer Security",
            summary: "TLS 1.3",
            fields: [DecodedField(name: "Server Name", value: "api.example.test")]
        )
        let titleOnly = DecodedLayer(proto: .tcp, title: "Transmission Control Protocol")

        #expect(DecodedClipboardText.layerSummary(summarized) == "Transport Layer Security: TLS 1.3")
        #expect(DecodedClipboardText.layerSummary(titleOnly) == "Transmission Control Protocol")
    }

    @Test("Visible subtree copy preserves displayed order and hierarchy")
    func visibleSubtreeOrderAndIndentation() {
        let tls = DecodedLayer(
            proto: .tls, title: "Transport Layer Security", summary: "TLS 1.3",
            fields: [DecodedField(name: "server_name", value: "api.example.test")]
        )
        let tcp = DecodedLayer(
            proto: .tcp, title: "Transmission Control Protocol", summary: "443 → 50000",
            fields: [DecodedField(name: "Flags", value: "ACK")], children: [tls]
        )
        let ip = DecodedLayer(
            proto: .ipv4, title: "Internet Protocol v4", summary: "192.0.2.1 → 192.0.2.2",
            fields: [DecodedField(name: "Don't Fragment", value: "Yes")], children: [tcp]
        )

        #expect(DecodedClipboardText.visibleSubtree(ip, collapsed: []) == """
        Internet Protocol v4: 192.0.2.1 → 192.0.2.2
          Don't Fragment: Yes
          Transmission Control Protocol: 443 → 50000
            Flags: ACK
            Transport Layer Security: TLS 1.3
              server_name: api.example.test
        """)
    }

    @Test("Collapsed layers copy their visible header and exclude descendants")
    func visibleSubtreeRespectsCollapsedLayers() {
        let child = DecodedLayer(
            proto: .tcp, title: "Transmission Control Protocol", summary: "443 → 50000",
            fields: [DecodedField(name: "Flags", value: "ACK")]
        )
        let parent = DecodedLayer(
            proto: .ipv4, title: "Internet Protocol v4", summary: "192.0.2.1 → 192.0.2.2",
            fields: [DecodedField(name: "TTL", value: "64")], children: [child]
        )

        #expect(DecodedClipboardText.visibleSubtree(parent, collapsed: [parent.title]) ==
            "Internet Protocol v4: 192.0.2.1 → 192.0.2.2")
        #expect(DecodedClipboardText.visibleSubtree(parent, collapsed: [child.title]) == """
        Internet Protocol v4: 192.0.2.1 → 192.0.2.2
          TTL: 64
          Transmission Control Protocol: 443 → 50000
        """)
    }

    @Test("Subtree copy uses only the supplied projection and keeps multiline Unicode readable")
    func visibleSubtreeUsesSuppliedProjection() {
        let projected = DecodedLayer(
            proto: .dns, title: "Domain Name System", summary: "域名查询",
            fields: [DecodedField(name: "Visible field", value: "α.example\nsecond line")]
        )

        let copied = DecodedClipboardText.visibleSubtree(projected, collapsed: [])
        #expect(copied == "Domain Name System: 域名查询\n  Visible field: α.example\n    second line")
        #expect(!copied.contains("Removed by search"))
    }
}
