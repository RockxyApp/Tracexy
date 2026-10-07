import Foundation

// MARK: - ApplicationMessageNode

/// One row of Statistics ▸ Message Counts: a group (HTTP requests, HTTP responses, a
/// status class, DHCP) or a single method, status code or DHCP type, with how many
/// messages were counted and in how many sessions. `term` is the Session Expression
/// term that finds those sessions, so every row leads back to them.
nonisolated struct ApplicationMessageNode: Identifiable, Hashable, Sendable {
    let id: String
    let title: String
    let messageCount: Int
    let sessionCount: Int
    let term: String?
    var children: [ApplicationMessageNode]?
}

// MARK: - ApplicationMessageCounts

/// Folds the sessions in view into the Wireshark-style HTTP and DHCP packet
/// counters, from each session's bounded ``SessionMessageTally``.
nonisolated enum ApplicationMessageCounts {
    // MARK: Internal

    static func roots(of sessions: [SessionSummary]) -> [ApplicationMessageNode] {
        var methods: [String: (messages: Int, sessions: Int)] = [:]
        var statuses: [Int: (messages: Int, sessions: Int)] = [:]
        var dhcp: [String: (messages: Int, sessions: Int)] = [:]
        var requestSessions = 0
        var responseSessions = 0
        var dhcpSessions = 0
        for session in sessions {
            let tally = session.messageTally
            guard !tally.isEmpty else {
                continue
            }
            for (method, count) in tally.httpRequests {
                methods[method, default: (0, 0)].messages += count
                methods[method, default: (0, 0)].sessions += 1
            }
            for (code, count) in tally.httpResponses {
                statuses[code, default: (0, 0)].messages += count
                statuses[code, default: (0, 0)].sessions += 1
            }
            for (kind, count) in tally.dhcpMessages {
                dhcp[kind, default: (0, 0)].messages += count
                dhcp[kind, default: (0, 0)].sessions += 1
            }
            requestSessions += tally.httpRequests.isEmpty ? 0 : 1
            responseSessions += tally.httpResponses.isEmpty ? 0 : 1
            dhcpSessions += tally.dhcpMessages.isEmpty ? 0 : 1
        }

        var roots: [ApplicationMessageNode] = []
        if !methods.isEmpty {
            let children = methods
                .map { method, value in
                    ApplicationMessageNode(
                        id: "http.method.\(method)", title: method, messageCount: value.messages,
                        sessionCount: value.sessions, term: "http.method == \(method)", children: nil
                    )
                }
                .sorted(by: largestFirst)
            roots.append(ApplicationMessageNode(
                id: "http.requests", title: "HTTP requests", messageCount: children.reduce(0) { $0 + $1.messageCount },
                sessionCount: requestSessions, term: nil, children: children
            ))
        }
        if !statuses.isEmpty {
            let classes = Dictionary(grouping: statuses.keys) { $0 / 100 }
            let children = classes.keys.sorted().map { hundred -> ApplicationMessageNode in
                let codes = (classes[hundred] ?? []).sorted().map { code -> ApplicationMessageNode in
                    let value = statuses[code] ?? (0, 0)
                    return ApplicationMessageNode(
                        id: "http.status.\(code)",
                        title: "\(code) \(reasonPhrase(code))".trimmingCharacters(in: .whitespaces),
                        messageCount: value.messages, sessionCount: value.sessions,
                        term: "http.status == \(code)", children: nil
                    )
                }
                return ApplicationMessageNode(
                    id: "http.class.\(hundred)", title: "\(hundred)xx \(className(hundred))",
                    messageCount: codes.reduce(0) { $0 + $1.messageCount },
                    sessionCount: sessionCount(in: sessions) { tally in
                        tally.httpResponses.keys.contains { $0 / 100 == hundred }
                    },
                    term: "http.status in \(hundred)00..\(hundred)99", children: codes
                )
            }
            roots.append(ApplicationMessageNode(
                id: "http.responses", title: "HTTP responses",
                messageCount: children.reduce(0) { $0 + $1.messageCount },
                sessionCount: responseSessions, term: nil, children: children
            ))
        }
        if !dhcp.isEmpty {
            let children = dhcp
                .map { kind, value in
                    ApplicationMessageNode(
                        id: "dhcp.\(kind)", title: kind, messageCount: value.messages, sessionCount: value.sessions,
                        term: kind.contains(" ") ? nil : "dhcp.message == \(kind)", children: nil
                    )
                }
                // The exchange order (Discover, Offer, Request, ACK, …) reads as the
                // conversation did; counts are all visible in their column.
                .sorted { (dhcpOrder($0.title), $0.title) < (dhcpOrder($1.title), $1.title) }
            roots.append(ApplicationMessageNode(
                id: "dhcp", title: "DHCP messages", messageCount: children.reduce(0) { $0 + $1.messageCount },
                sessionCount: dhcpSessions, term: nil, children: children
            ))
        }
        return roots
    }

    /// Messages the bounded tallies of the sessions in view could not name.
    static func omittedCount(of sessions: [SessionSummary]) -> Int {
        sessions.reduce(0) { $0 + $1.messageTally.omitted }
    }

    static func className(_ hundred: Int) -> String {
        switch hundred {
        case 1: "Informational"
        case 2: "Success"
        case 3: "Redirection"
        case 4: "Client Error"
        case 5: "Server Error"
        default: ""
        }
    }

    /// The RFC 9110 reason phrase for the common codes; others show the number only.
    static func reasonPhrase(_ code: Int) -> String {
        switch code {
        case 100: "Continue"
        case 101: "Switching Protocols"
        case 200: "OK"
        case 201: "Created"
        case 202: "Accepted"
        case 204: "No Content"
        case 206: "Partial Content"
        case 301: "Moved Permanently"
        case 302: "Found"
        case 303: "See Other"
        case 304: "Not Modified"
        case 307: "Temporary Redirect"
        case 308: "Permanent Redirect"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 408: "Request Timeout"
        case 409: "Conflict"
        case 413: "Content Too Large"
        case 429: "Too Many Requests"
        case 500: "Internal Server Error"
        case 501: "Not Implemented"
        case 502: "Bad Gateway"
        case 503: "Service Unavailable"
        case 504: "Gateway Timeout"
        default: ""
        }
    }

    // MARK: Private

    private static func dhcpOrder(_ kind: String) -> Int {
        ["Discover", "Offer", "Request", "Decline", "ACK", "NAK", "Release", "Inform"].firstIndex(of: kind) ?? 99
    }

    private static func largestFirst(_ lhs: ApplicationMessageNode, _ rhs: ApplicationMessageNode) -> Bool {
        (lhs.messageCount, rhs.title) > (rhs.messageCount, lhs.title)
    }

    private static func sessionCount(
        in sessions: [SessionSummary],
        where predicate: (SessionMessageTally) -> Bool
    )
        -> Int
    {
        sessions.count { predicate($0.messageTally) }
    }
}
