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
}
