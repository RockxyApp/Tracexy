import Foundation
import Testing
@testable import Tracexy

// MARK: - MCPProtocolTests

@Suite("MCP wire: framing bounds, JSON-RPC parsing and deterministic responses")
struct MCPProtocolTests {
    @Test("Chunked input frames the same lines regardless of chunk boundaries")
    func framingIsChunkIndependent() {
        let payload = Data("{\"a\":1}\n{\"b\":2}\n{\"c\":3}".utf8)
        var whole = MCPLineFramer()
        var lines = whole.consume(payload)
        if let last = whole.flush() {
            lines.append(last)
        }

        var byByte = MCPLineFramer()
        var split: [MCPLineFramer.Line] = []
        for byte in payload {
            split.append(contentsOf: byByte.consume(Data([byte])))
        }
        if let last = byByte.flush() {
            split.append(last)
        }

        #expect(lines == split)
        #expect(lines.count == 3)
    }

    @Test("Blank lines frame nothing")
    func blankLinesAreIgnored() {
        var framer = MCPLineFramer()
        let lines = framer.consume(Data("\n\n{\"a\":1}\n\n".utf8))
        #expect(lines == [.complete(Data("{\"a\":1}".utf8))])
    }

    @Test("A CRLF terminator is tolerated")
    func carriageReturnIsStripped() {
        var framer = MCPLineFramer()
        let lines = framer.consume(Data("{\"a\":1}\r\n".utf8))
        #expect(lines == [.complete(Data("{\"a\":1}".utf8))])
    }

    @Test("An oversized line is reported once and never buffered whole")
    func oversizedLineIsDiscarded() {
        var framer = MCPLineFramer()
        var payload = Data(repeating: 0x41, count: MCPProtocolLimits.maxLineBytes + 512)
        payload.append(0x0A)
        payload.append(contentsOf: Data("{\"a\":1}\n".utf8))

        let lines = framer.consume(payload)
        #expect(lines.count == 2)
        guard case let .oversize(byteCount) = lines[0] else {
            Issue.record("Expected an oversize line first")
            return
        }
        #expect(byteCount == MCPProtocolLimits.maxLineBytes + 512)
        // The stream resynchronizes: the next line still parses.
        #expect(lines[1] == .complete(Data("{\"a\":1}".utf8)))
    }

    @Test("Parse failures map to the fixed JSON-RPC codes")
    func parseFailures() {
        #expect(throws: MCPParseFailure.notJSONObject) {
            try MCPMessage.parse(line: Data("[1,2,3]".utf8))
        }
        #expect(throws: MCPParseFailure.badVersion) {
            try MCPMessage.parse(line: Data("{\"jsonrpc\":\"1.0\",\"method\":\"ping\"}".utf8))
        }
        #expect(throws: MCPParseFailure.badMethod) {
            try MCPMessage.parse(line: Data("{\"jsonrpc\":\"2.0\"}".utf8))
        }
        #expect(throws: MCPParseFailure.badID) {
            try MCPMessage.parse(line: Data("{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":{}}".utf8))
        }
        #expect(throws: MCPParseFailure.badParams) {
            try MCPMessage.parse(line: Data("{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1,\"params\":5}".utf8))
        }
        #expect(MCPParseFailure.notJSONObject.code == .parseError)
        #expect(MCPParseFailure.badVersion.code == .invalidRequest)
        #expect(MCPParseFailure.badParams.code == .invalidParams)
    }

    @Test("A boolean id is not an id")
    func booleanIDIsRejected() {
        #expect(MCPRequestID(json: true) == nil)
        #expect(MCPRequestID(json: NSNumber(value: 1.5)) == nil)
        #expect(MCPRequestID(json: NSNumber(value: Double.greatestFiniteMagnitude)) == nil)
        #expect(MCPRequestID(json: NSNull()) == .null)
        #expect(MCPRequestID(json: "abc") == .string("abc"))
        #expect(MCPRequestID(json: NSNumber(value: 7)) == .number(7))
    }

    @Test("A request without an id is a notification and is answered with nothing")
    func notificationsHaveNoID() throws {
        let request = try MCPMessage.parse(
            line: Data("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}".utf8)
        )
        #expect(request.isNotification)
        #expect(request.method == "notifications/initialized")
    }

    @Test("Responses are deterministic, single-line and echo the id kind")
    func responsesAreDeterministic() throws {
        let first = try #require(MCPMessage.encodeResult(id: .string("abc"), result: ["b": 2, "a": 1]))
        let second = try #require(MCPMessage.encodeResult(id: .string("abc"), result: ["a": 1, "b": 2]))
        #expect(first == second)

        let text = try #require(String(data: first, encoding: .utf8))
        #expect(!text.contains("\n"))
        #expect(text.contains("\"id\":\"abc\""))
        #expect(text.contains("\"jsonrpc\":\"2.0\""))

        let error = try #require(MCPMessage.encodeError(id: .number(3), code: .methodNotFound, message: "no"))
        let errorText = try #require(String(data: error, encoding: .utf8))
        #expect(errorText.contains("\"code\":-32601"))
        #expect(errorText.contains("\"id\":3"))
    }

    @Test("A result past the response bound is refused rather than truncated")
    func oversizedResultIsRefused() {
        let huge = String(repeating: "x", count: MCPProtocolLimits.maxResponseBytes + 16)
        #expect(MCPMessage.encodeResult(id: .number(1), result: ["text": huge]) == nil)
    }
}
