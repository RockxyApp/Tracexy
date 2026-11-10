import Foundation
import Testing
@testable import Tracexy

/// All Frames ▸ Copy: Wireshark's Summary as Text, …as CSV, …as YAML and …as HTML
/// layouts for one row, with CSV quotes doubled and HTML escaped.
struct FrameSummaryCopyTests {
    @Test
    func formatsLikeWiresharksPacketListCopy() {
        let values = ["7", "0.250000", "192.0.2.10", "198.51.100.80", "HTTP", "93", "GET /a?x=\"1\"&y=<2> HTTP/1.1"]
        let copy = { FrameSummaryCopy.copy(values, format: $0, rowIndex: 6, captureName: "/tmp/http.pcap") }

        #expect(copy(.text).text == values.joined(separator: "\t") + "\n")
        #expect(copy(.text).html == nil)
        #expect(copy(.csv).text == "\"7\",\"0.250000\",\"192.0.2.10\",\"198.51.100.80\",\"HTTP\",\"93\","
            + "\"GET /a?x=\"\"1\"\"&y=<2> HTTP/1.1\"\n")
        #expect(copy(.yaml).text == "---\n# Packet 6 from http.pcap\n- \"7\"\n- \"0.250000\"\n- \"192.0.2.10\"\n"
            + "- \"198.51.100.80\"\n- \"HTTP\"\n- \"93\"\n"
            + "- \"GET /a?x=\\\"1\\\"&y=<2> HTTP/1.1\"\n")

        let html = copy(.html)
        #expect(html.text == copy(.text).text)
        let markup = html.html ?? ""
        #expect(markup.hasPrefix("<style>table{"))
        #expect(markup
            .contains(
                "<table>\n<tr><td style=\"text-align:right;\">7</td><td style=\"text-align:left;\">0.250000</td>"
            ))
        #expect(markup.contains("<td style=\"text-align:right;\">93</td>"))
        #expect(markup.contains("GET /a?x=&quot;1&quot;&amp;y=&lt;2&gt; HTTP/1.1</td></tr>\n</table>"))
    }

    @Test
    func copiedCSVGuardsCaptureDerivedFormulaText() {
        let copied = FrameSummaryCopy.copy(
            ["8", "  =HYPERLINK(\"url\")", "@cmd"], format: .csv, rowIndex: 7, captureName: "capture"
        )
        #expect(copied.text == "\"8\",\"'  =HYPERLINK(\"\"url\"\")\",\"'@cmd\"\n")
    }

    @Test
    func yamlQuotesMultilineAndColonValuesWithoutEmbeddingLocalPaths() {
        let copied = FrameSummaryCopy.copy(
            ["key: value", "line one\nInjected: value", "quote \" and slash \\"],
            format: .yaml, rowIndex: 3, captureName: "/tmp/example/private/capture.pcapng"
        )
        #expect(copied.text == "---\n# Packet 3 from capture.pcapng\n"
            + "- \"key: value\"\n- \"line one\\nInjected: value\"\n"
            + "- \"quote \\\" and slash \\\\\"\n")
    }

    @Test
    func yamlCaptureCommentCannotInjectLines() {
        let copied = FrameSummaryCopy.copy(
            ["frame"], format: .yaml, rowIndex: 20_001, captureName: "/tmp/capture\nInjected: true"
        )
        #expect(copied.text == "---\n# Packet 20001 from capture Injected: true\n- \"frame\"\n")
    }
}
