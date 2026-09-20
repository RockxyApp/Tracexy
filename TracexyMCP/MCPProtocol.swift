import Foundation

// This file declares the newline-delimited JSON-RPC 2.0 wire boundary for the
// bundled read-only MCP executable: how a line is framed and bounded, how a
// request is parsed, and how exactly one response object is spelled. It performs
// no I/O and holds no state beyond the framer's own bounded buffer, so every rule
// here is testable without a process, a socket or a database.
//
// There is no TCP path anywhere in this file — the transport is stdin/stdout and
// nothing else.

// MARK: - MCPProtocolLimits

/// The fixed wire bounds. A request that violates one is answered with a
/// controlled error and never parsed further.
nonisolated enum MCPProtocolLimits {
    /// The largest single request line accepted, in bytes.
    static let maxLineBytes = 1_048_576

    /// The largest response the server will emit, in bytes. A result that would
    /// exceed it is replaced by an internal error rather than a truncated object.
    static let maxResponseBytes = 4_194_304
}

// MARK: - MCPRequestID

/// A JSON-RPC id, echoed back byte-for-byte in kind. JSON-RPC permits a string, a
/// number or null; anything else is not an id.
nonisolated enum MCPRequestID: Sendable, Equatable {
    case number(Int64)
    case string(String)
    case null

    // MARK: Lifecycle

    /// Parse an id from a decoded JSON value. Returns `nil` when the value is
    /// present but is not a permitted id kind.
    init?(json value: Any) {
        switch value {
        case is NSNull:
            self = .null
        case let text as String:
            self = .string(text)
        case let number as NSNumber:
            // `NSNumber` also carries booleans; a boolean is not a JSON-RPC id.
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return nil
            }
            // JSON-RPC discourages fractional numeric ids. Accept only values we
            // can echo exactly as an Int64; silently rounding 1.5 to 1 would pair
            // a response with a request the client never made.
            let value = number.doubleValue
            guard value.isFinite,
                  value.rounded(.towardZero) == value,
                  value >= Double(Int64.min),
                  value < Double(Int64.max) else
            {
                return nil
            }
            self = .number(number.int64Value)
        default:
            return nil
        }
    }

    // MARK: Internal

    /// The value to place in a response envelope.
    var jsonValue: Any {
        switch self {
        case let .number(value): value
        case let .string(value): value
        case .null: NSNull()
        }
    }
}

// MARK: - MCPErrorCode

/// The JSON-RPC error codes this server emits. The set is deliberately closed:
/// an unexpected internal condition is an `internalError`, never a bespoke code
/// that could describe the host's state.
nonisolated enum MCPErrorCode: Int, Sendable, Equatable {
    case parseError = -32_700
    case invalidRequest = -32_600
    case methodNotFound = -32_601
    case invalidParams = -32_602
    case internalError = -32_603
}

// MARK: - MCPRequest

/// One parsed JSON-RPC request or notification.
///
/// Deliberately **not** `Sendable`: `params` is a decoded JSON object, and the
/// only correct place to read it is the handler that parsed it. Keeping it
/// non-`Sendable` is what stops a raw request object from being handed to another
/// isolation domain.
nonisolated struct MCPRequest {
    /// Absent for a notification, which is answered with nothing.
    let id: MCPRequestID?
    let method: String
    /// The raw `params` object, or an empty dictionary when absent. Only object
    /// params are accepted; positional params are not part of this surface.
    let params: [String: Any]

    var isNotification: Bool {
        id == nil
    }
}

// MARK: - MCPParseFailure

/// Why one line could not become a request. Each maps to a fixed JSON-RPC error;
/// none carries host state.
nonisolated enum MCPParseFailure: Error, Sendable, Equatable {
    /// The line exceeded ``MCPProtocolLimits/maxLineBytes``.
    case lineTooLong(byteCount: Int)
    /// The bytes were not valid JSON, or not a JSON object.
    case notJSONObject
    /// `jsonrpc` was missing or was not exactly `"2.0"`.
    case badVersion
    /// `method` was missing, empty, or not a string.
    case badMethod
    /// `id` was present but was neither a string, a number nor null.
    case badID
    /// `params` was present but was not an object.
    case badParams

    // MARK: Internal

    var code: MCPErrorCode {
        switch self {
        case .lineTooLong,
             .notJSONObject: .parseError
        case .badID,
             .badMethod,
             .badVersion: .invalidRequest
        case .badParams: .invalidParams
        }
    }

    /// Neutral, host-free copy for the error object.
    var message: String {
        switch self {
        case .lineTooLong: "Request line exceeds the supported size."
        case .notJSONObject: "Request is not a JSON object."
        case .badVersion: "Request is not JSON-RPC 2.0."
        case .badMethod: "Request has no method name."
        case .badID: "Request id must be a string, a number or null."
        case .badParams: "Request params must be an object."
        }
    }
}

// MARK: - MCPMessage

/// The complete wire codec: line → request, and result/error → one line of JSON.
nonisolated enum MCPMessage {
    // MARK: Internal

    /// Parse one complete line into a request.
    static func parse(line: Data) throws -> MCPRequest {
        guard line.count <= MCPProtocolLimits.maxLineBytes else {
            throw MCPParseFailure.lineTooLong(byteCount: line.count)
        }
        guard let object = try? JSONSerialization.jsonObject(with: line),
              let dictionary = object as? [String: Any] else
        {
            throw MCPParseFailure.notJSONObject
        }
        guard (dictionary["jsonrpc"] as? String) == "2.0" else {
            throw MCPParseFailure.badVersion
        }
        guard let method = dictionary["method"] as? String, !method.isEmpty else {
            throw MCPParseFailure.badMethod
        }

        var id: MCPRequestID?
        if let rawID = dictionary["id"] {
            guard let parsed = MCPRequestID(json: rawID) else {
                throw MCPParseFailure.badID
            }
            id = parsed
        }

        var params: [String: Any] = [:]
        if let rawParams = dictionary["params"], !(rawParams is NSNull) {
            guard let object = rawParams as? [String: Any] else {
                throw MCPParseFailure.badParams
            }
            params = object
        }

        return MCPRequest(id: id, method: method, params: params)
    }

    /// Encode one success response. Returns `nil` when the payload could not be
    /// serialized or exceeded ``MCPProtocolLimits/maxResponseBytes``; the caller
    /// answers with an internal error instead of emitting a partial object.
    static func encodeResult(id: MCPRequestID, result: [String: Any]) -> Data? {
        encode(["jsonrpc": "2.0", "id": id.jsonValue, "result": result])
    }

    /// Encode one error response. It is intentionally impossible to attach
    /// arbitrary data: an error carries a fixed code and neutral message only.
    static func encodeError(id: MCPRequestID, code: MCPErrorCode, message: String) -> Data? {
        encode([
            "jsonrpc": "2.0",
            "id": id.jsonValue,
            "error": ["code": code.rawValue, "message": message],
        ])
    }

    // MARK: Private

    private static func encode(_ object: [String: Any]) -> Data? {
        guard let data = try? JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) else {
            return nil
        }
        guard data.count <= MCPProtocolLimits.maxResponseBytes else {
            return nil
        }
        return data
    }
}

// MARK: - MCPLineFramer

/// A bounded newline framer over an arbitrarily chunked byte stream.
///
/// It never buffers more than ``MCPProtocolLimits/maxLineBytes`` bytes: once a
/// pending line passes the bound it is reported as ``MCPLineFramer/Line/oversize``
/// exactly once and the remaining bytes of that line are discarded up to the next
/// newline, so one hostile line cannot exhaust memory or desynchronize the stream.
nonisolated struct MCPLineFramer {
    // MARK: Internal

    /// One framed outcome.
    enum Line: Sendable, Equatable {
        /// A complete line within the bound.
        case complete(Data)
        /// A line that exceeded the bound; its bytes were discarded.
        case oversize(byteCount: Int)
    }

    /// Consume a chunk and return every line it completed, in order.
    mutating func consume(_ chunk: Data) -> [Line] {
        var lines: [Line] = []
        for byte in chunk {
            guard byte != 0x0A else {
                // A blank line frames nothing. Tolerating it keeps a client that
                // pads its stream from being answered with a parse error.
                if let line = finishLine() {
                    lines.append(line)
                }
                continue
            }
            if isDiscarding {
                discardedCount += 1
                continue
            }
            pending.append(byte)
            if pending.count > MCPProtocolLimits.maxLineBytes {
                // Report once, then swallow the rest of this line.
                isDiscarding = true
                discardedCount = pending.count
                pending.removeAll(keepingCapacity: false)
            }
        }
        return lines
    }

    /// Flush a final unterminated line, if any. A stream that ends without a
    /// newline still delivers its last request.
    mutating func flush() -> Line? {
        finishLine()
    }

    // MARK: Private

    private var pending = Data()
    private var isDiscarding = false
    private var discardedCount = 0

    private mutating func finishLine() -> Line? {
        if isDiscarding {
            let count = discardedCount
            isDiscarding = false
            discardedCount = 0
            pending.removeAll(keepingCapacity: false)
            return .oversize(byteCount: count)
        }
        guard !pending.isEmpty else {
            return nil
        }
        let line = pending
        pending.removeAll(keepingCapacity: true)
        // A carriage return before the newline is tolerated so a client that
        // writes CRLF is not silently rejected as malformed JSON.
        if line.last == 0x0D {
            return .complete(line.dropLast())
        }
        return .complete(line)
    }
}
