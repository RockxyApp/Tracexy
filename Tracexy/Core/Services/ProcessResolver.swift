import AppKit
import Darwin
import Foundation

/// Maps a local socket port → the owning app name, by reading the socket table
/// with `lsof` (the user's own sockets, no root needed). This is how Tracexy
/// attributes a captured session to an app without pktap. Runs `lsof` off the main thread, throttled.
@MainActor
final class ProcessResolver {
    // MARK: Internal

    struct ResolvedProcess: Equatable {
        let pid: Int32
        let command: String
    }

    static let shared = ProcessResolver()

    // MARK: - Parsing (pure, testable)

    /// Parses `lsof -F pcn` field output into `[localPort: (pid, command)]`.
    /// Field lines: `p<pid>`, `c<command>` (per process), `n<name>` (per socket,
    /// e.g. `10.0.0.2:50467->1.2.3.4:443` or `*:5353`).
    nonisolated static func parse(_ output: String) -> [UInt16: ResolvedProcess] {
        var result: [UInt16: ResolvedProcess] = [:]
        var pid: Int32 = 0
        var command = ""
        for rawLine in output.split(whereSeparator: \.isNewline) {
            guard let tag = rawLine.first else {
                continue
            }
            let value = String(rawLine.dropFirst())
            switch tag {
            case "p":
                pid = Int32(value) ?? 0
            case "c":
                command = value
            case "n":
                let local = value.split(separator: ">", maxSplits: 1).first.map(String.init) ?? value
                let trimmed = local.hasSuffix("-") ? String(local.dropLast()) : local
                if let port = port(from: trimmed) {
                    result[port] = ResolvedProcess(pid: pid, command: command)
                }
            default:
                break
            }
        }
        return result
    }

    /// Extracts the port from an "ip:port" string (handles IPv6's inner colons
    /// and bracketed forms like "[::1]:443").
    nonisolated static func port(from endpoint: String) -> UInt16? {
        guard let portSlice = endpoint.split(separator: ":").last else {
            return nil
        }
        let digits = portSlice.prefix { $0.isNumber }
        return UInt16(digits)
    }

    /// The app owning a session, found by matching either endpoint's local port.
    func appName(forEndpoints source: String, _ destination: String) -> String? {
        if let port = Self.port(from: source), let app = portToApp[port] {
            return app
        }
        if let port = Self.port(from: destination), let app = portToApp[port] {
            return app
        }
        return nil
    }

    /// Refreshes the port→app map (throttled to ~2s). `lsof` runs off-main; the
    /// map updates on the main actor when done.
    func refresh(force: Bool = false) {
        let now = Date()
        guard !isRefreshing, force || now.timeIntervalSince(lastRefresh) > 2 else {
            return
        }
        isRefreshing = true
        lastRefresh = now
        Task.detached(priority: .utility) {
            let parsed = Self.parse(Self.runLsof())
            await MainActor.run {
                self.portToApp = self.resolveNames(parsed)
                self.isRefreshing = false
            }
        }
    }

    // MARK: Private

    private var portToApp: [UInt16: String] = [:]
    private var lastRefresh = Date.distantPast
    private var isRefreshing = false

    /// PID → display name: a running app's localized name, else the `.app`
    /// bundle name from its executable path, else the `lsof` command.
    private static func resolveAppName(pid: Int32, command: String) -> String {
        if pid > 0, let app = NSRunningApplication(processIdentifier: pid),
           let name = app.localizedName, !name.isEmpty
        {
            return name
        }
        if pid > 0 {
            var buffer = [CChar](repeating: 0, count: 4_096)
            if proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 {
                let name = PktapHeader.appName(fromExecutablePath: String(cString: buffer))
                if !name.isEmpty {
                    return name
                }
            }
        }
        return command
    }

    nonisolated private static func runLsof() -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-nP", "+c", "0", "-Fpcn", "-iTCP", "-iUDP"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return ""
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func resolveNames(_ parsed: [UInt16: ResolvedProcess]) -> [UInt16: String] {
        var nameByPID: [Int32: String] = [:]
        var map: [UInt16: String] = [:]
        for (port, info) in parsed {
            if let cached = nameByPID[info.pid] {
                map[port] = cached
                continue
            }
            let name = Self.resolveAppName(pid: info.pid, command: info.command)
            nameByPID[info.pid] = name
            map[port] = name
        }
        return map
    }
}
