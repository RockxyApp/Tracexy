import Foundation
import Network
@testable import Tracexy

// MARK: - LoopbackHTTPServer

/// A tiny, deliberately dumb HTTP/1.1 server bound to `127.0.0.1` on an
/// ephemeral port, used to exercise the local assistant adapter against a real
/// socket: real status codes, real redirects, real chunk boundaries.
///
/// It is a test fixture, not a server: it reads the request line, hands the path
/// to a closure, writes the scripted bytes and closes. Everything it serves is
/// documentation-range fixture text.
final class LoopbackHTTPServer: @unchecked Sendable {
    // MARK: Lifecycle

    init(respond: @escaping @Sendable (String) -> Reply) {
        self.respond = respond
    }

    deinit {
        stop()
    }

    // MARK: Internal

    /// One scripted reply. `chunks` are written in order with `chunkDelay`
    /// between them, so a test can prove incremental parsing rather than
    /// whole-body parsing.
    struct Reply: Sendable {
        // MARK: Lifecycle

        init(
            status: Int = 200,
            headers: [String: String] = ["Content-Type": "application/json"],
            chunks: [String] = [],
            chunkDelay: Duration = .milliseconds(5),
            closeWithoutResponse: Bool = false
        ) {
            self.status = status
            self.headers = headers
            self.chunks = chunks
            self.chunkDelay = chunkDelay
            self.closeWithoutResponse = closeWithoutResponse
        }

        // MARK: Internal

        let status: Int
        let headers: [String: String]
        let chunks: [String]
        let chunkDelay: Duration
        /// Accept the connection and close it without writing anything, which is
        /// how an endpoint that is not a model API is simulated.
        let closeWithoutResponse: Bool

        static func json(_ body: String) -> Reply {
            Reply(chunks: [body])
        }
    }

    /// The number of requests the server has accepted, by path.
    private(set) var requestedPaths: [String] = []

    /// Start listening and return the validated loopback endpoint.
    ///
    /// It returns only once the listener is *ready* and a real TCP connection to
    /// it has been accepted. Returning on the state callback alone was not enough:
    /// a listener that failed to bind still reports a port, and a client would
    /// then be refused — which is indistinguishable from an unreachable endpoint
    /// and made every discovery assertion flaky under parallel load.
    func start() throws -> AssistantLocalEndpoint {
        let listener = try NWListener(using: .tcp, on: .any)
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        let ready = DispatchSemaphore(value: 0)
        let state = Box()
        listener.stateUpdateHandler = { update in
            switch update {
            case .ready:
                state.isReady = true
                ready.signal()
            case .failed,
                 .cancelled:
                state.isReady = false
                ready.signal()
            default:
                break
            }
        }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 10)
        guard state.isReady, let port = listener.port?.rawValue else {
            throw LoopbackHTTPServerError.notListening
        }
        guard acceptsConnections(port: port) else {
            throw LoopbackHTTPServerError.notListening
        }
        return try AssistantLocalEndpoint.validate("http://127.0.0.1:\(port)")
    }

    func stop() {
        listener?.cancel()
        listener = nil
        lock.withLock {
            for connection in connections {
                connection.cancel()
            }
            connections.removeAll()
        }
    }

    // MARK: Private

    /// A mutable flag shared with the listener's callback queue.
    private final class Box: @unchecked Sendable {
        var isReady = false
    }

    private let respond: @Sendable (String) -> Reply
    private let queue = DispatchQueue(label: "tracexy.tests.loopback-http")
    private let lock = NSLock()
    private var listener: NWListener?
    private var connections: [NWConnection] = []

    private static func path(fromRequest text: String) -> String {
        let firstLine = text.split(separator: "\r\n", maxSplits: 1).first ?? ""
        let parts = firstLine.split(separator: " ")
        guard parts.count >= 2 else {
            return ""
        }
        return String(parts[1])
    }

    private static func reason(_ status: Int) -> String {
        switch status {
        case 200: "OK"
        case 302: "Found"
        case 404: "Not Found"
        case 500: "Internal Server Error"
        default: "Status"
        }
    }

    /// Prove the listener really accepts a TCP connection before any test uses it.
    /// The probe speaks no HTTP, so it never reaches the scripted handler.
    private func acceptsConnections(port: UInt16) -> Bool {
        for _ in 0 ..< 5 {
            let endpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port) ?? .any)
            let connection = NWConnection(to: endpoint, using: .tcp)
            let ready = DispatchSemaphore(value: 0)
            let state = Box()
            connection.stateUpdateHandler = { update in
                switch update {
                case .ready:
                    state.isReady = true
                    ready.signal()
                case .failed,
                     .cancelled:
                    ready.signal()
                default:
                    break
                }
            }
            connection.start(queue: queue)
            _ = ready.wait(timeout: .now() + 3)
            connection.cancel()
            if state.isReady {
                return true
            }
        }
        return false
    }

    private func accept(_ connection: NWConnection) {
        lock.withLock { connections.append(connection) }
        connection.start(queue: queue)
        receive(connection, buffer: Data())
    }

    /// Read until the end of the request headers, then reply. The request body is
    /// deliberately ignored: nothing here needs to interpret it.
    private func receive(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, _ in
            guard let self else {
                return
            }
            var next = buffer
            if let data {
                next.append(data)
            }
            guard let text = String(data: next, encoding: .utf8), text.contains("\r\n\r\n") else {
                if isComplete {
                    connection.cancel()
                } else {
                    self.receive(connection, buffer: next)
                }
                return
            }
            let path = Self.path(fromRequest: text)
            self.lock.withLock { self.requestedPaths.append(path) }
            self.write(self.respond(path), to: connection)
        }
    }

    private func write(_ reply: Reply, to connection: NWConnection) {
        guard !reply.closeWithoutResponse else {
            connection.cancel()
            return
        }
        var head = "HTTP/1.1 \(reply.status) \(Self.reason(reply.status))\r\n"
        for (name, value) in reply.headers.sorted(by: { $0.key < $1.key }) {
            head += "\(name): \(value)\r\n"
        }
        // A single-chunk reply is a complete body, so it is framed by
        // `Content-Length` the way a real non-streaming endpoint frames one. A
        // multi-chunk reply is deliberately EOF-framed, which is the shape a
        // streaming local model uses.
        if reply.chunks.count <= 1 {
            let length = reply.chunks.first.map(\.utf8.count) ?? 0
            head += "Content-Length: \(length)\r\n"
        }
        head += "Connection: close\r\n\r\n"
        connection.send(content: Data(head.utf8), completion: .contentProcessed { _ in })

        Task { [chunks = reply.chunks, delay = reply.chunkDelay] in
            for chunk in chunks {
                connection.send(content: Data(chunk.utf8), completion: .contentProcessed { _ in })
                try? await Task.sleep(for: delay)
            }
            connection.send(content: nil, isComplete: true, completion: .contentProcessed { _ in
                connection.cancel()
            })
        }
    }
}

// MARK: - LoopbackHTTPServerError

enum LoopbackHTTPServerError: Error {
    case notListening
}
