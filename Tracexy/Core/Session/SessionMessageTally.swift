import Foundation

// MARK: - SessionMessageTally

/// Per-session counts of the application messages whose first line the decoder
/// read: HTTP/1 requests by method, HTTP/1 responses by status code, and DHCP
/// messages by type. Counted once per decoded frame, like Wireshark's HTTP and
/// DHCP packet counters; a message whose first line was not in a captured frame's
/// first 512 bytes is not counted. Bounded: each table keeps at most `keyCap`
/// distinct keys, and any further key's messages are counted in `omitted`.
/// Carries names and numbers only — never a path, header value or address.
nonisolated struct SessionMessageTally: Hashable, Sendable {
    // MARK: Internal

    static let keyCap = 16

    private(set) var httpRequests: [String: Int] = [:]
    private(set) var httpResponses: [Int: Int] = [:]
    private(set) var dhcpMessages: [String: Int] = [:]
    /// Messages whose key did not fit under `keyCap`.
    private(set) var omitted = 0

    var isEmpty: Bool {
        httpRequests.isEmpty && httpResponses.isEmpty && dhcpMessages.isEmpty && omitted == 0
    }

    var httpRequestCount: Int {
        httpRequests.values.reduce(0, +)
    }

    var httpResponseCount: Int {
        httpResponses.values.reduce(0, +)
    }

    /// The method token of an HTTP/1 request line (`GET /x HTTP/1.1` → `GET`), or
    /// `nil` when the line does not start with an RFC 9110 token of at most 16
    /// upper-case letters followed by a space.
    static func httpMethod(fromRequestLine line: String) -> String? {
        guard let space = line.firstIndex(of: " ") else {
            return nil
        }
        let token = line[..<space]
        guard (1 ... 16).contains(token.count), token.allSatisfy({ $0.isASCII && $0.isUppercase }) else {
            return nil
        }
        return String(token)
    }

    /// The code of an HTTP/1 status field (`404 Not Found` → 404), only for 100…599.
    static func httpStatus(fromStatus value: String) -> Int? {
        guard let code = Int(value.prefix { $0.isNumber }.prefix(3)), (100 ... 599).contains(code) else {
            return nil
        }
        return code
    }

    /// The message type of a decoded DHCP layer summary (`DHCP Offer 192.0.2.7` →
    /// `Offer`, `DHCP type 13` → `Type 13`), or `nil` for a summary without a type.
    static func dhcpMessageKind(fromSummary summary: String) -> String? {
        let words = summary.split(separator: " ").map(String.init)
        guard words.count >= 2, words[0] == "DHCP" else {
            return nil
        }
        if words[1] == "type", words.count >= 3 {
            return "Type \(words[2])"
        }
        return words[1]
    }

    mutating func record(_ packet: DecodedPacket) {
        for layer in packet.layers {
            switch layer.proto {
            case .http:
                if let line = layer.fields.first(where: { $0.name == "Request" })?.value,
                   let method = Self.httpMethod(fromRequestLine: line)
                {
                    Self.increment(&httpRequests, method, omitted: &omitted)
                } else if let status = layer.fields.first(where: { $0.name == "Status" })?.value,
                          let code = Self.httpStatus(fromStatus: status)
                {
                    Self.increment(&httpResponses, code, omitted: &omitted)
                }
            case .dhcp where layer.title == "Dynamic Host Configuration Protocol":
                if let kind = Self.dhcpMessageKind(fromSummary: layer.summary) {
                    Self.increment(&dhcpMessages, kind, omitted: &omitted)
                }
            default:
                continue
            }
        }
    }

    // MARK: Private

    private static func increment<Key: Hashable>(_ table: inout [Key: Int], _ key: Key, omitted: inout Int) {
        if table[key] != nil || table.count < keyCap {
            table[key, default: 0] += 1
        } else {
            omitted += 1
        }
    }
}
