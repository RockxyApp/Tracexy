import Foundation

/// Groups sessions into `Activity` values — one user-visible action each.
///
/// Deliberately a pure function over already-decoded sessions: grouping is
/// inference layered on top of decoding, never part of it, so it can be revised,
/// switched off, or disagreed with without touching the capture path.
///
/// The evidence is weighted rather than keyed on a single field. A TLS-only
/// grouping key fails on everything that is not TLS, loses DNS entirely, and
/// cannot express doubt. Here each link carries the reason it was made, and
/// contested attributions stay contested.
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

    /// How close in time two identifier-only sessions must sit to be treated as
    /// one action. The second pass has *no* observed causal step — only agreeing
    /// process and name — so it earns a far tighter window than the DNS pass: a
    /// process talking to a host every few seconds is many actions, not one.
    static let sameIdentityAdjacencyWindow: TimeInterval = 2

    static func build(from sessions: [SessionSummary], window: TimeInterval = dnsCausalWindow) -> Result {
        guard !sessions.isEmpty else {
            return Result()
        }
        // Correlation is entirely time-dependent: both passes ask "how long after".
        // A session whose start time is unknown therefore cannot be correlated at
        // all — it is reported ungrouped rather than attached on a guessed instant.
        let ordered = sessions.sorted(by: SessionChronology.ascending)

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
            // No known answer instant means no causal window can be applied.
            guard let dnsStart = dns.startTime else {
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
                          !seenFollowers.contains(candidate.id),
                          // An untimed connection cannot be placed inside the window.
                          let candidateStart = candidate.startTime else
                    {
                        continue
                    }
                    let delta = candidateStart.timeIntervalSince(dnsStart)
                    if delta >= 0, delta <= window {
                        seenFollowers.insert(candidate.id)
                        followers.append(candidate)
                    }
                }
            }
            followers.sort(by: SessionChronology.ascending)
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
        // ties them, only agreeing identifiers. Because the only signal here is
        // identity, the bar is deliberately high: a session needs a *real*
        // observed process AND a shared canonical name to even be a candidate.
        // Sessions whose process attribution is nil/empty are never second-pass
        // grouped — an absent process is not a matching process.
        let remaining = ordered.filter { !consumed.contains($0.id) }
        var buckets: [String: [SessionSummary]] = [:]
        for session in remaining {
            guard let process = Self.attributedProcess(of: session),
                  let canonical = Self.canonicalName([session]),
                  // The second pass is adjacency-gated, so an unknown start time
                  // disqualifies the session from grouping rather than widening it.
                  session.startTime != nil else
            {
                result.ungrouped.append(session)
                continue
            }
            let key = "\(process)\u{1}\(canonical)"
            buckets[key, default: []].append(session)
        }

        for (_, bucket) in buckets {
            guard bucket.count > 1 else {
                result.ungrouped.append(contentsOf: bucket)
                continue
            }
            // Only group what is actually adjacent in time; a process talking to
            // one host all day is not one action.
            for run in Self.runs(in: bucket, window: Self.sameIdentityAdjacencyWindow) {
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
                // Every run member was gated on a known start above, so this spread
                // is measured from real instants only.
                if let last = run[run.count - 1].startTime, let first = run[0].startTime {
                    evidence.append(.temporalAdjacency(seconds: last.timeIntervalSince(first)))
                }

                // Temporal adjacency alone never groups anything.
                guard evidence.contains(where: { $0.tier > .weak }) else {
                    result.ungrouped.append(contentsOf: run)
                    continue
                }
                result.activities.append(Activity(sessions: run, evidence: evidence))
            }
        }

        result.activities.sort { Self.activityPrecedes($0, $1) }
        result.ungrouped.sort(by: SessionChronology.descending)
        return result
    }

    // MARK: Private

    /// Newest action first. Every grouped action has at least one known member
    /// start (both passes require one), so this compares real instants and falls
    /// back to the stable action id only on an exact tie.
    private static func activityPrecedes(_ lhs: Activity, _ rhs: Activity) -> Bool {
        switch (lhs.startTime, rhs.startTime) {
        case let (left?, right?):
            if left != right {
                return left > right
            }
        case (.some, .none):
            return true
        case (.none, .some):
            return false
        case (.none, .none):
            break
        }
        return lhs.id.uuidString < rhs.id.uuidString
    }

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

    /// A session's process attribution, only when it is a real non-empty name.
    /// A nil or empty `processName` is unknown, not a value to correlate on.
    private static func attributedProcess(of session: SessionSummary) -> String? {
        guard let rawName = session.processName else {
            return nil
        }
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            return nil
        }
        return name
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

    /// Splits a time-ordered bucket wherever the gap exceeds the window. Every
    /// member is known-timed (the caller gates on that), so the gap is measured
    /// from real instants and never inferred across a missing one.
    private static func runs(in bucket: [SessionSummary], window: TimeInterval) -> [[SessionSummary]] {
        let ordered = bucket.sorted(by: SessionChronology.ascending)
        var runs: [[SessionSummary]] = []
        var current: [SessionSummary] = []
        for session in ordered {
            if let last = current.last?.startTime,
               let start = session.startTime,
               start.timeIntervalSince(last) > window
            {
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
