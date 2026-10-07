import Foundation

// MARK: - FrameSummaryCopy

/// Wireshark's Copy ▸ Summary as Text, …as CSV, …as YAML and …as HTML for a row of
/// the packet list: the columns as shown, tab-separated, quoted and comma-separated,
/// as a YAML list under a comment naming the packet, or as an HTML table row with the
/// text alongside for plain-text paste. Unlike Wireshark, a quote inside a CSV field
/// is doubled and HTML text is escaped, so the result stays well formed.
nonisolated enum FrameSummaryCopy {
    // MARK: Internal

    enum Format: String, CaseIterable, Identifiable {
        case text
        case csv
        case yaml
        case html

        // MARK: Internal

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .text: String(localized: "Summary as Text")
            case .csv: String(localized: "…as CSV")
            case .yaml: String(localized: "…as YAML")
            case .html: String(localized: "…as HTML")
            }
        }
    }

    /// The columns Wireshark's default packet list shows, in its order.
    static let columns = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
    /// Columns drawn right-aligned (the numbers).
    static let rightAligned: Set<Int> = [0, 5]

    /// The text to copy and, for HTML, the markup to put beside it.
    static func copy(
        _ values: [String],
        format: Format,
        rowIndex: Int,
        captureName: String
    )
        -> (text: String, html: String?)
    {
        switch format {
        case .text:
            return (values.joined(separator: "\t") + "\n", nil)
        case .csv:
            return (
                values.map { "\"" + $0.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
                    .joined(separator: ",") + "\n",
                nil
            )
        case .yaml:
            return ("----\n# Packet \(rowIndex) from \(captureName)\n- " + values.joined(separator: "\n- ") + "\n", nil)
        case .html:
            let cells = values.enumerated().map { index, value in
                "<td style=\"text-align:\(rightAligned.contains(index) ? "right" : "left");\">\(escaped(value))</td>"
            }.joined()
            let html = [
                "<style>table{font-family:-apple-system,Helvetica;font-size:12pt;}"
                    + "th{background-color:#000000;color:#ffffff;text-align:left;}th,td{padding:6pt}</style>",
                "<table>",
                "<tr>\(cells)</tr>",
                "</table>",
            ].joined(separator: "\n")
            return (values.joined(separator: "\t") + "\n", html)
        }
    }

    // MARK: Private

    private static func escaped(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
    }
}
