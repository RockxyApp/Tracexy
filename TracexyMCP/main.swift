import Foundation

// The bundled, read-only Tracexy MCP executable.
//
// It speaks newline-delimited JSON-RPC 2.0 over stdin/stdout and nothing else: it
// binds no socket, opens no port, accepts no path/scope argument and reads no
// environment override. Diagnostics go to stderr so stdout stays protocol-only.
//
// Authorization is the single app-written grant at the identity-derived
// Application Support location. If no grant exists, the process still starts and
// still answers — every call simply fails closed.

// MARK: - MCPStdioMain

/// The composition root and blocking stdio pump.
enum MCPStdioMain {
    // MARK: Internal

    static func run() async {
        let identity = TracexyIdentity(bundle: .main)
        let server = MCPServer(
            grantReader: MCPGrantReader(url: MCPGrantLocation.grantURL(identity: identity)),
            audit: MCPAuditTrail(url: MCPGrantLocation.auditURL(identity: identity)),
            info: MCPServerInfo(version: bundleVersion())
        )

        note("Tracexy MCP ready on stdio. No network port is opened.")
        // Naming the grant path on stderr is the one operator diagnostic that
        // makes a misconfigured client debuggable: it says where authorization is
        // read from without disclosing anything about a capture. It is not an
        // input — the path is identity-derived and cannot be overridden.
        note("\(MCPGrantLocation.diagnosticPrefix)\(MCPGrantLocation.grantURL(identity: identity).path)")

        var framer = MCPLineFramer()
        let input = FileHandle.standardInput
        while true {
            let chunk = input.availableData
            if chunk.isEmpty {
                break
            }
            for line in framer.consume(chunk) {
                await dispatch(line, to: server)
            }
        }
        if let line = framer.flush() {
            await dispatch(line, to: server)
        }
    }

    // MARK: Private

    private static func dispatch(_ line: MCPLineFramer.Line, to server: MCPServer) async {
        switch line {
        case let .complete(data):
            if let response = await server.handle(line: data) {
                emit(response)
            }
        case let .oversize(byteCount):
            note("Discarded an oversized request line (\(byteCount) bytes).")
            if let response = await server.respondToOversizeLine(byteCount: byteCount) {
                emit(response)
            }
        }
    }

    /// Write exactly one response line to stdout. Nothing else in this process
    /// ever writes there.
    private static func emit(_ data: Data) {
        var line = data
        line.append(0x0A)
        FileHandle.standardOutput.write(line)
    }

    /// Diagnostics, stderr only.
    private static func note(_ message: String) {
        FileHandle.standardError.write(Data("[TracexyMCP] \(message)\n".utf8))
    }

    private static func bundleVersion() -> String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = (info["CFBundleShortVersionString"] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let version, !version.isEmpty else {
            return "0"
        }
        return version
    }
}

await MCPStdioMain.run()
