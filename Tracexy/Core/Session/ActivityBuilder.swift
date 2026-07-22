import Foundation

/// Groups sessions into `Activity` values — one user-visible action each.
///
/// Deliberately a pure function over already-decoded sessions: grouping is
/// inference layered on top of decoding, never part of it, so it can be revised,
/// switched off, or disagreed with without touching the capture path.
///
/// The evidence is weighted rather than keyed on a single field. A single
/// grouping key (TCP Viewer uses TLS SNI) fails on everything that is not TLS,
/// loses DNS entirely, and cannot express doubt. Here each link carries the
/// reason it was made, and contested attributions stay contested.
enum ActivityBuilder {
    // MARK: Internal

    struct Result: Sendable {
        /// Grouped actions, newest first.
        var activities: [Activity] = []
        /// Sessions no evidence could attribute. A first-class outcome: hiding
        /// them inside a guessed group would be the worst available answer.
        var ungrouped: [SessionSummary] = []
    }

    /// How long after a DNS answer a connection may still be attributed to it.
    /// Real TTLs vary wildly and resolvers cache beyond them, so this is a
    /// deliberately short causal window rather than an attempt to model TTL.
    static let dnsCausalWindow: TimeInterval = 30

    static func build(from sessions: [SessionSummary], window: TimeInterval = dnsCausalWindow) -> Result {
        guard !sessions.isEmpty else {
            return Result()
        }
        let ordered = sessions.sorted { $0.startTime < $1.startTime }

        // Which names claimed which address, so a contested address can be
        // detected instead of silently resolved to whichever came first.
        var claimants: [String: Set<String>] = [:]
        for session in ordered {
            let name = session.dnsQuery ?? session.host
            for address in session.dnsAnswers where !address.isEmpty {
                claimants[address, default: []].insert(name)
            }
        }

        // Candidate connections bucketed by the address they dialled. Without
        // this the DNS pass rescans every session for every answer — O(dns × n),
        // which is fine for a fixture and ruinous for a real capture.
        var byAddress: [String: [SessionSummary]] = [:]
        for session in ordered {
            if let address = Self.address(of: session) {
                byAddress[address, default: []].append(session)
            }
        }

        var result = Result()
        var consumed: Set<UUID> = []

        for dns in ordered where !dns.dnsAnswers.isEmpty {
            if consumed.contains(dns.id) {
                continue
            }
            let name = dns.dnsQuery ?? dns.host
            let answers = Set(dns.dnsAnswers.filter { !$0.isEmpty })
            guard !answers.isEmpty else {
                continue
            }

            // Connections that dialled one of the answered addresses, inside the
            // causal window, after the answer arrived.
            var followers: [SessionSummary] = []
            var seenFollowers: Set<UUID> = []
            for answer in answers {
                for candidate in byAddress[answer] ?? [] {
                    guard candidate.id != dns.id,
                          !consumed.contains(candidate.id),
                          !seenFollowers.contains(candidate.id) else
                    {
                        continue
                    }
                    let delta = candidate.startTime.timeIntervalSince(dns.startTime)
                    if delta >= 0, delta <= window {
                        seenFollowers.insert(candidate.id)
                        followers.append(candidate)
                    }
                }
            }
            followers.sort { $0.startTime < $1.startTime }
            guard !followers.isEmpty else {
                continue
            }

            let members = [dns] + followers
            var evidence: [ActivityEvidence] = []
            if let address = Self.address(of: followers[0]) {
                evidence.append(.dnsAnswerToConnection(name: name, address: address))
            }
            if let process = Self.sharedProcess(members) {
                evidence.append(.sameProcessAtConnect(process: process))
            }
            if let canonical = Self.canonicalName(members) {
                evidence.append(.canonicalNameMatch(name: canonical))
            }

            // Every other name that also resolved to an address this activity
            // used. Non-empty means we cannot tell which name owns the traffic.
            let contested = answers
                .flatMap { claimants[$0] ?? [] }
                .filter { $0 != name }
            let competing = Array(Set(contested)).sorted()

            result.activities.append(
                Activity(sessions: members, evidence: evidence, competingNames: competing)
            )
            members.forEach { consumed.insert($0.id) }
        }

        // Second pass: sessions with no DNS link, but the same process talking to
        // the same name close together. Strong, not causal — no observed step
        // ties them, only agreeing identifiers.
        let remaining = ordered.filter { !consumed.contains($0.id) }
        var buckets: [String: [SessionSummary]] = [:]
        for session in remaining {
            let key = "\(session.processName ?? "—")\u{1}\(Self.canonicalName([session]) ?? session.host)"
            buckets[key, default: []].append(session)
        }

        for (_, bucket) in buckets {
            guard bucket.count > 1 else {
                result.ungrouped.append(contentsOf: bucket)
                continue
            }
            // Only group what is actually adjacent in time; a process talking to
            // one host all day is not one action.
            for run in Self.runs(in: bucket, window: window) {
                if run.count == 1 {
                    result.ungrouped.append(contentsOf: run)
                    continue
                }
                var evidence: [ActivityEvidence] = []
                if let process = Self.sharedProcess(run) {
                    evidence.append(.sameProcessAtConnect(process: process))
                }
                if let canonical = Self.canonicalName(run) {
                    evidence.append(.canonicalNameMatch(name: canonical))
                }
                let spread = run[run.count - 1].startTime.timeIntervalSince(run[0].startTime)
                evidence.append(.temporalAdjacency(seconds: spread))

                // Temporal adjacency alone never groups anything.
                guard evidence.contains(where: { $0.tier > .weak }) else {
                    result.ungrouped.append(contentsOf: run)
                    continue
                }
                result.activities.append(Activity(sessions: run, evidence: evidence))
            }
        }

        result.activities.sort { $0.startTime > $1.startTime }
        result.ungrouped.sort { $0.startTime > $1.startTime }
        return result
    }

    // MARK: Private

    /// Destination address without the port. Endpoints are formatted `ip:port`,
    /// and IPv6 literals carry more than one colon, so split from the right.
    private static func address(of session: SessionSummary) -> String? {
        let endpoint = session.destinationEndpoint
        guard let separator = endpoint.lastIndex(of: ":") else {
            return endpoint.isEmpty ? nil : endpoint
        }
        let host = String(endpoint[endpoint.startIndex ..< separator])
        return host.isEmpty ? nil : host
    }

    private static func sharedProcess(_ sessions: [SessionSummary]) -> String? {
        let names = Set(sessions.compactMap(\.processName))
        return names.count == 1 ? names.first : nil
    }

    /// A name all sessions agree on, drawn from DNS query, TLS SNI and host.
    private static func canonicalName(_ sessions: [SessionSummary]) -> String? {
        var candidates: Set<String> = []
        for session in sessions {
            let names = [session.dnsQuery, session.sni, session.host]
                .compactMap { $0 }
                .filter { !$0.isEmpty && $0.contains(where: \.isLetter) }
            candidates.formUnion(names)
        }
        return candidates.count == 1 ? candidates.first : nil
    }

    /// Splits a time-ordered bucket wherever the gap exceeds the window.
    private static func runs(in bucket: [SessionSummary], window: TimeInterval) -> [[SessionSummary]] {
        let ordered = bucket.sorted { $0.startTime < $1.startTime }
        var runs: [[SessionSummary]] = []
        var current: [SessionSummary] = []
        for session in ordered {
            if let last = current.last, session.startTime.timeIntervalSince(last.startTime) > window {
                runs.append(current)
                current = []
            }
            current.append(session)
        }
        if !current.isEmpty {
            runs.append(current)
        }
        return runs
    }
}
