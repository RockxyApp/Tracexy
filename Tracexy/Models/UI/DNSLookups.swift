import Foundation

// MARK: - DNSLookupRow

/// One name the capture looked up over unicast DNS, with what happened to those
/// lookups. Counts are of DNS sessions (one per client port and server), the unit
/// the Sessions table lists.
nonisolated struct DNSLookupRow: Identifiable, Hashable, Sendable {
    let name: String
    let lookupCount: Int
    let answeredCount: Int
    let noSuchNameCount: Int
    let failedCount: Int
    let unansweredCount: Int
    /// Distinct addresses the answers named.
    let addressCount: Int
    /// Median measured query-to-answer interval, when any was measured.
    let medianResponseTime: TimeInterval?

    var id: String {
        name
    }

    var problemCount: Int {
        noSuchNameCount + failedCount + unansweredCount
    }

    /// What happened, in words, largest first; only outcomes that occurred.
    var outcome: String {
        var parts: [String] = []
        if answeredCount > 0 {
            parts.append("\(answeredCount.formatted()) answered")
        }
        if noSuchNameCount > 0 {
            parts.append("\(noSuchNameCount.formatted()) no such name")
        }
        if failedCount > 0 {
            parts.append("\(failedCount.formatted()) server failure")
        }
        if unansweredCount > 0 {
            parts.append("\(unansweredCount.formatted()) unanswered")
        }
        // Every lookup is accounted for: those with no answer and no finding are
        // named as such rather than left out of the sentence.
        let accounted = answeredCount + noSuchNameCount + failedCount + unansweredCount
        if parts.isEmpty {
            return "No answer retained"
        }
        if lookupCount > accounted {
            parts.append("\((lookupCount - accounted).formatted()) without an answer")
        }
        return parts.joined(separator: ", ")
    }
}

// MARK: - DNSLookups

/// The DNS names in a scope, derived from its sessions, the datagram findings that
/// name DNS outcomes, and the measured DNS response times. Holds nothing new.
nonisolated enum DNSLookups {
    // MARK: Internal

    static func rows(
        sessions: [SessionSummary],
        findings: [DatagramAnalysisFinding],
        responseTimes: [SessionTimingMeasurement]
    )
        -> [DNSLookupRow]
    {
        var outcomes: [UUID: Set<DatagramAnalysisFindingKind>] = [:]
        for finding in findings {
            outcomes[finding.sessionID, default: []].insert(finding.kind)
        }
        var times: [UUID: [TimeInterval]] = [:]
        for measurement in responseTimes where measurement.kind == .dnsResponse {
            times[measurement.sessionID, default: []].append(measurement.elapsed)
        }

        struct Tally {
            /// Each spelling the queries used, with how often, so the row shows and
            /// routes by a spelling the sessions actually carry.
            var spellings: [String: Int] = [:]
            var lookups = 0
            var answered = 0
            var noSuchName = 0
            var failed = 0
            var unanswered = 0
            var addresses: Set<String> = []
            var times: [TimeInterval] = []
        }
        var tallies: [String: Tally] = [:]
        for session in sessions where session.protocolStack.contains(.dns) && !session.protocolStack.contains(.mdns) {
            guard let spelled = session.dnsQuery?.trimmingCharacters(in: .whitespaces), !spelled.isEmpty else {
                continue
            }
            let query = spelled.lowercased()
            var tally = tallies[query] ?? Tally()
            tally.spellings[session.host == spelled ? spelled : session.host, default: 0] += 1
            tally.lookups += 1
            let kinds = outcomes[session.id] ?? []
            let addresses = session.dnsAnswers.filter { IPAddressValue(parsing: $0) != nil }
            if !session.dnsAnswers.isEmpty {
                tally.answered += 1
            }
            if kinds.contains(.dnsNameErrorObserved) {
                tally.noSuchName += 1
            }
            if kinds.contains(.dnsServerFailureObserved) {
                tally.failed += 1
            }
            if kinds.contains(.dnsQueryUnansweredObserved) {
                tally.unanswered += 1
            }
            tally.addresses.formUnion(addresses)
            tally.times += times[session.id] ?? []
            tallies[query] = tally
        }
        return tallies.map { key, tally in
            // The most used spelling (ties: the lowest), as the sessions' hosts carry it.
            let name = tally.spellings.max { lhs, rhs in
                lhs.value != rhs.value ? lhs.value < rhs.value : lhs.key > rhs.key
            }?.key ?? key
            return DNSLookupRow(
                name: name,
                lookupCount: tally.lookups,
                answeredCount: tally.answered,
                noSuchNameCount: tally.noSuchName,
                failedCount: tally.failed,
                unansweredCount: tally.unanswered,
                addressCount: tally.addresses.count,
                medianResponseTime: median(tally.times)
            )
        }
        .sorted { lhs, rhs in
            if lhs.problemCount != rhs.problemCount {
                return lhs.problemCount > rhs.problemCount
            }
            if lhs.lookupCount != rhs.lookupCount {
                return lhs.lookupCount > rhs.lookupCount
            }
            return lhs.name < rhs.name
        }
    }

    // MARK: Private

    private static func median(_ values: [TimeInterval]) -> TimeInterval? {
        guard !values.isEmpty else {
            return nil
        }
        let sorted = values.sorted()
        let middle = sorted.count / 2
        return sorted.count.isMultiple(of: 2) ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle]
    }
}
