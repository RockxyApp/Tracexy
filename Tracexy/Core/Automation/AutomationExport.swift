import Foundation

// MARK: - AutomationExport

/// Pure, deterministic serialization of N5A automation values into two neutral
/// transports: `sortedKeys` JSON (captures or sessions, including page
/// metadata/cursor) and an RFC-4180 session-page CSV table. It works only over
/// already-projected ``AutomationCapturePage``/``AutomationSessionPage`` values —
/// it never reads the store, applies no locale-dependent numeric/date formatting,
/// and returns `Data` with no stdout/stderr or process-exit behavior.
nonisolated enum AutomationExport {
    // MARK: Internal

    /// The fixed CSV header. Column order is stable regardless of disclosure;
    /// undisclosed/absent values render as empty cells.
    static let sessionCSVHeader = [
        "session_id",
        "start_time",
        "duration",
        "protocols",
        "status",
        "latency_ms",
        "bytes_up",
        "bytes_down",
        "process_name",
        "host",
        "source_endpoint",
        "destination_endpoint",
    ]

    /// Deterministic JSON for a capture page (sorted keys, no escaped slashes).
    static func json(capturePage: AutomationCapturePage) throws -> Data {
        try encoder().encode(capturePage)
    }

    /// Deterministic JSON for a session page (sorted keys, no escaped slashes).
    static func json(sessionPage: AutomationSessionPage) throws -> Data {
        try encoder().encode(sessionPage)
    }

    /// Deterministic RFC-4180 CSV for a session page: one fixed header row, then
    /// one row per matched session. Records are separated by CRLF and every field
    /// is quoted when it contains a comma, quote, CR or LF. Undisclosed/absent
    /// values are empty cells.
    static func csv(sessionPage page: AutomationSessionPage) -> Data {
        var rows = [encodeRow(sessionCSVHeader)]
        for session in page.sessions {
            rows.append(encodeRow([
                session.sessionID.uuidString,
                number(session.startTime),
                number(session.duration),
                session.protocols.joined(separator: " "),
                session.status.rawValue,
                session.latencyMilliseconds.map(number) ?? "",
                String(session.bytesUp),
                String(session.bytesDown),
                spreadsheetSafe(session.processName ?? ""),
                spreadsheetSafe(session.host ?? ""),
                spreadsheetSafe(session.sourceEndpoint ?? ""),
                spreadsheetSafe(session.destinationEndpoint ?? ""),
            ]))
        }
        // RFC-4180 permits a trailing CRLF; emit one for byte-stable output.
        let text = rows.joined(separator: "\r\n") + "\r\n"
        return Data(text.utf8)
    }

    // MARK: Private

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        // No `dateEncodingStrategy`: every value is already a numeric/string, so
        // output carries no locale-dependent date/number copy.
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    /// A locale-independent numeric spelling. `String(_:)` on `Double` never uses
    /// the host locale (no thousands separators, `.` decimal), so the CSV stays
    /// byte-stable across environments.
    private static func number(_ value: Double) -> String {
        String(value)
    }

    private static func encodeRow(_ fields: [String]) -> String {
        fields.map(escapeField).joined(separator: ",")
    }

    /// Prevent disclosed capture-derived text from being interpreted as a
    /// formula when the otherwise-neutral CSV is opened in a spreadsheet.
    /// Leading whitespace is considered because spreadsheet importers may trim
    /// it before checking for a formula marker.
    private static func spreadsheetSafe(_ field: String) -> String {
        let firstMeaningfulCharacter = field.first { !$0.isWhitespace }
        guard let firstMeaningfulCharacter,
              ["=", "+", "-", "@"].contains(firstMeaningfulCharacter) else
        {
            return field
        }
        return "'\(field)"
    }

    /// RFC-4180 field quoting: quote when the field contains a comma, double
    /// quote, CR or LF, and escape embedded quotes by doubling them.
    private static func escapeField(_ field: String) -> String {
        let needsQuoting = field.contains(",")
            || field.contains("\"")
            || field.contains("\r")
            || field.contains("\n")
        guard needsQuoting else {
            return field
        }
        let escaped = field.replacingOccurrences(of: "\"", with: "\"\"")
        return "\"\(escaped)\""
    }
}
