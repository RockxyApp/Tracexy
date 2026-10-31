import Foundation

// MARK: - ServiceResponseTime

/// Statistics ▸ Service Response Time: for each procedure, how many replies were
/// paired with their request and how long they took — the minimum, maximum, mean and
/// sum — as Wireshark's SRT tables (`tshark -z smb2,srt`, `ldap,srt`, `kerberos,srt`)
/// count them in one pass, each protocol pairing within its session:
///
/// - SMB2: a reply pairs with the request of its message ID once; an asynchronous
///   STATUS_PENDING reply waits for the final one, and Cancel and Oplock Break are
///   left out.
/// - LDAP: every reply to a message ID pairs with that request, so a search counts
///   each entry and its result.
/// - Kerberos: a reply pairs with the message just before it when that was the
///   request — AS-REP or an error after AS-REQ, TGS-REP or an error after TGS-REQ.
nonisolated enum ServiceResponseTime {
    // MARK: Internal

    enum Service: String, CaseIterable, Identifiable {
        case smb2
        case ldap
        case kerberos
        case icmp
        case icmpv6

        // MARK: Internal

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .smb2: "SMB2"
            case .ldap: "LDAP"
            case .kerberos: "Kerberos"
            case .icmp: "ICMP"
            case .icmpv6: "ICMPv6"
            }
        }

        /// ICMP and ICMPv6 time echo replies as one summary, not per procedure.
        var isEcho: Bool {
            self == .icmp || self == .icmpv6
        }

        /// Wireshark's heading for the procedure column.
        var procedureTitle: String {
            self == .smb2 ? String(localized: "Command") : String(localized: "Procedure")
        }
    }

    enum ScanError: LocalizedError {
        case sourceUnavailable(String)
        case incomplete

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case let .sourceUnavailable(reason): reason
            case .incomplete: String(localized: "The capture ended before the complete response-time scan finished.")
            }
        }
    }

    struct Row: Identifiable, Hashable, Sendable {
        let index: Int
        let procedure: String
        let calls: Int
        let minimum: TimeInterval
        let maximum: TimeInterval
        let sum: TimeInterval

        var id: Int {
            index
        }

        var average: TimeInterval {
            sum / Double(calls)
        }
    }

    /// Capture-order SMB2 SRT reducer. It retains only unmatched request timestamps
    /// and per-command aggregates, so large captures do not need a frame-row array.
    struct StreamingSMB2Accumulator: Sendable {
        // MARK: Lifecycle

        init(maximumPendingRequests: Int = Self.maximumPendingRequests) {
            self.maximumPendingRequests = min(max(maximumPendingRequests, 0), Self.maximumPendingRequests)
        }

        // MARK: Internal

        struct Result: Sendable {
            let rows: [Row]
            let omittedRequests: Int
        }

        static let maximumPendingRequests = 200_000

        private(set) var omittedRequests = 0

        mutating func record(_ row: CaptureFrameRow) {
            guard let session = row.sessionID, let time = row.provenance.timestamp,
                  case let .smb2(messageID, command, isResponse, isInterim) = row.srt else
            {
                return
            }
            guard command != 0x0C, command != 0x12 else {
                return
            }
            let key = RequestKey(session: session, messageID: messageID)
            if !isResponse {
                if pending[key] != nil {
                    pending[key] = time
                } else if pending.count < maximumPendingRequests {
                    pending[key] = time
                } else {
                    omittedRequests += 1
                }
            } else if !isInterim, let start = pending.removeValue(forKey: key) {
                let duration = microseconds(from: start, to: time)
                var aggregate = aggregates[command, default: Aggregate()]
                aggregate.calls += 1
                aggregate.minimum = min(aggregate.minimum, duration)
                aggregate.maximum = max(aggregate.maximum, duration)
                aggregate.sum += duration
                aggregates[command] = aggregate
            }
        }

        func result() -> Result {
            let rows = aggregates.keys.sorted().compactMap { command -> Row? in
                guard let aggregate = aggregates[command], aggregate.calls > 0 else {
                    return nil
                }
                return Row(
                    index: command, procedure: procedureName(.smb2, command), calls: aggregate.calls,
                    minimum: aggregate.minimum / 1e6, maximum: aggregate.maximum / 1e6,
                    sum: aggregate.sum / 1e6
                )
            }
            return Result(rows: rows, omittedRequests: omittedRequests)
        }

        // MARK: Private

        private struct RequestKey: Hashable, Sendable {
            let session: UUID
            let messageID: UInt64
        }

        private struct Aggregate {
            var calls = 0
            var minimum = Double.infinity
            var maximum = -Double.infinity
            var sum = 0.0
        }

        private var pending: [RequestKey: Date] = [:]
        private var aggregates: [Int: Aggregate] = [:]
        private let maximumPendingRequests: Int
    }

    /// Bounded capture-order LDAP/Kerberos reducer. LDAP Search keeps its request
    /// correlation through every entry/reference/intermediate reply; Kerberos only
    /// retains the latest AS/TGS request per session.
    struct StreamingAccumulator: Sendable {
        // MARK: Lifecycle

        init(service: Service, maximumCorrelations: Int = Self.maximumCorrelations) {
            self.service = service
            self.maximumCorrelations = min(max(maximumCorrelations, 0), Self.maximumCorrelations)
        }

        // MARK: Internal

        struct Result: Sendable {
            let rows: [Row]
            let omittedCorrelations: Int
        }

        static let maximumCorrelations = 200_000

        private(set) var omittedCorrelations = 0

        mutating func record(_ row: CaptureFrameRow) {
            guard let session = row.sessionID, let time = row.provenance.timestamp, let fact = row.srt else {
                return
            }
            switch (service, fact) {
            case let (.ldap, .ldap(messageID, operation)):
                recordLDAP(session: session, time: time, messageID: messageID, operation: operation)
            case let (.kerberos, .kerberos(type)):
                recordKerberos(session: session, time: time, type: type)
            default:
                break
            }
        }

        func result() -> Result {
            let rows = aggregates.keys.sorted().compactMap { index -> Row? in
                guard let aggregate = aggregates[index], aggregate.calls > 0 else {
                    return nil
                }
                return Row(
                    index: index, procedure: procedureName(service, index), calls: aggregate.calls,
                    minimum: aggregate.minimum / 1e6, maximum: aggregate.maximum / 1e6,
                    sum: aggregate.sum / 1e6
                )
            }
            return Result(rows: rows, omittedCorrelations: omittedCorrelations)
        }

        // MARK: Private

        private struct RequestKey: Hashable, Sendable {
            let session: UUID
            let messageID: Int
        }

        private struct Request: Sendable {
            let time: Date
            let procedure: Int
        }

        private struct Aggregate: Sendable {
            var calls = 0
            var minimum = Double.infinity
            var maximum = -Double.infinity
            var sum = 0.0
        }

        private let service: Service
        private let maximumCorrelations: Int
        private var ldapRequests: [RequestKey: Request] = [:]
        private var kerberosRequests: [UUID: (Date, Int)] = [:]
        private var aggregates: [Int: Aggregate] = [:]

        private mutating func recordLDAP(session: UUID, time: Date, messageID: Int, operation: Int) {
            let key = RequestKey(session: session, messageID: messageID)
            if ldapProcedures[operation] != nil {
                if ldapRequests[key] != nil || ldapRequests.count < maximumCorrelations {
                    ldapRequests[key] = Request(time: time, procedure: operation)
                } else {
                    omittedCorrelations += 1
                }
                return
            }
            guard ldapResponses.contains(operation), let request = ldapRequests[key] else {
                return
            }
            addSample(request.procedure, microseconds(from: request.time, to: time))
            // Search requests finish only at SearchResultDone. IntermediateResponse
            // is never terminal for a request.
            if request.procedure == 3 ? operation == 5 : operation != 25 {
                ldapRequests.removeValue(forKey: key)
            }
        }

        private mutating func recordKerberos(session: UUID, time: Date, type: Int) {
            guard [10, 11, 12, 13, 30].contains(type) else {
                return
            }
            if type == 10 || type == 12 {
                if kerberosRequests[session] != nil || kerberosRequests.count < maximumCorrelations {
                    kerberosRequests[session] = (time, type)
                } else {
                    omittedCorrelations += 1
                }
                return
            }
            guard let (start, request) = kerberosRequests.removeValue(forKey: session),
                  let index = kerberosIndex(request: request, reply: type) else
            {
                return
            }
            addSample(index, microseconds(from: start, to: time))
        }

        private mutating func addSample(_ index: Int, _ duration: Double) {
            var aggregate = aggregates[index, default: Aggregate()]
            aggregate.calls += 1
            aggregate.minimum = min(aggregate.minimum, duration)
            aggregate.maximum = max(aggregate.maximum, duration)
            aggregate.sum += duration
            aggregates[index] = aggregate
        }
    }

    static func table(_ service: Service, rows: [CaptureFrameRow]) -> [Row] {
        var samples: [Int: [Double]] = [:]
        let frames = rows.compactMap { row -> (UUID, Date, SRTFrameFact)? in
            guard let session = row.sessionID, let time = row.provenance.timestamp, let fact = row.srt else {
                return nil
            }
            return (session, time, fact)
        }
        switch service {
        case .smb2:
            var pending: [UUID: [UInt64: Date]] = [:]
            for (session, time, fact) in frames {
                guard case let .smb2(messageID, command, isResponse, isInterim) = fact else {
                    continue
                }
                guard command != 0x0C, command != 0x12 else {
                    continue
                }
                if !isResponse {
                    pending[session, default: [:]][messageID] = time
                } else if !isInterim, let start = pending[session]?.removeValue(forKey: messageID) {
                    samples[command, default: []].append(microseconds(from: start, to: time))
                }
            }
        case .ldap:
            var requests: [UUID: [Int: (Date, Int)]] = [:]
            for (session, time, fact) in frames {
                guard case let .ldap(messageID, operation) = fact else {
                    continue
                }
                if ldapProcedures[operation] != nil {
                    requests[session, default: [:]][messageID] = (time, operation)
                } else if ldapResponses.contains(operation), let (start, request) = requests[session]?[messageID] {
                    samples[request, default: []].append(microseconds(from: start, to: time))
                    if request == 3 ? operation == 5 : operation != 25 {
                        requests[session]?.removeValue(forKey: messageID)
                    }
                }
            }
        case .kerberos:
            var previous: [UUID: (Date, Int)] = [:]
            for (session, time, fact) in frames {
                guard case let .kerberos(type) = fact else {
                    continue
                }
                guard [10, 11, 12, 13, 30].contains(type) else {
                    continue
                }
                if type == 10 || type == 12 {
                    previous[session] = (time, type)
                    continue
                }
                if let (start, request) = previous.removeValue(forKey: session),
                   let index = kerberosIndex(request: request, reply: type)
                {
                    samples[index, default: []].append(microseconds(from: start, to: time))
                }
            }
        case .icmp,
             .icmpv6:
            return []
        }
        return samples.keys.sorted().compactMap { index in
            guard let times = samples[index], let low = times.min(), let high = times.max() else {
                return nil
            }
            return Row(
                index: index, procedure: procedureName(service, index), calls: times.count,
                minimum: low / 1e6, maximum: high / 1e6, sum: times.reduce(0, +) / 1e6
            )
        }
    }

    /// Seconds with six decimals, as tshark prints them.
    static func seconds(_ value: TimeInterval) -> String {
        String(format: "%.6f", value)
    }

    static func csv(_ service: Service, _ rows: [Row], omittedRequests: Int = 0) -> String {
        let header = ["Index", service.procedureTitle, "Calls", "Min SRT", "Max SRT", "Avg SRT", "Sum SRT"]
            + (omittedRequests > 0 ? [service == .smb2 ? "Omitted pending requests" : "Omitted correlations"] : [])
        var lines = rows.map { row in
            let cells = [
                String(row.index), row.procedure, String(row.calls), seconds(row.minimum), seconds(row.maximum),
                seconds(row.average), seconds(row.sum),
            ]
            return omittedRequests > 0 ? cells + [String(omittedRequests)] : cells
        }
        if lines.isEmpty, omittedRequests > 0 {
            lines.append(["", "No paired replies", "0", "", "", "", "", String(omittedRequests)])
        }
        return ([header] + lines).map { $0.map(csvField).joined(separator: ",") }
            .joined(separator: "\r\n") + "\r\n"
    }

    // MARK: Private

    private static let ldapProcedures: [Int: String] = [
        0: "Bind", 3: "Search", 6: "Modify", 8: "Add", 10: "Delete", 12: "Modrdn", 14: "Compare", 23: "Extended",
    ]
    /// Bind, search entry, search reference, search done, modify, add, delete,
    /// modify DN, compare and extended responses, and intermediate responses.
    private static let ldapResponses: Set<Int> = [1, 4, 19, 5, 7, 9, 11, 13, 15, 24, 25]
    private static let smb2Commands = [
        "Negotiate Protocol", "Session Setup", "Session Logoff", "Tree Connect", "Tree Disconnect", "Create",
        "Close", "Flush", "Read", "Write", "Lock", "Ioctl", "Cancel", "KeepAlive", "Find", "Notify", "GetInfo",
        "SetInfo", "Break",
    ]

    /// Whole microseconds between two frame times — the resolution of a pcap time.
    /// Keep the bounded wire-time range in Double so distant, valid PCAPNG times do
    /// not trap while narrowing to Int64 or summing multiple service samples.
    private static func microseconds(from start: Date, to end: Date) -> Double {
        (end.timeIntervalSince(start) * 1e6).rounded()
    }

    private static func csvField(_ text: String) -> String {
        guard text.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" }) else {
            return text
        }
        return "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    private static func kerberosIndex(request: Int, reply: Int) -> Int? {
        switch (request, reply) {
        case (10, 11): 0
        case (10, 30): 1
        case (12, 13): 2
        case (12, 30): 3
        default: nil
        }
    }

    private static func procedureName(_ service: Service, _ index: Int) -> String {
        switch service {
        case .smb2: smb2Commands.indices.contains(index) ? smb2Commands[index] : "<unknown>"
        case .ldap: ldapProcedures[index] ?? "<unknown>"
        case .kerberos: ["AS-REP", "AS-ERROR", "TGS-REP", "TGS-ERROR"][index]
        case .icmp,
             .icmpv6: "<unknown>"
        }
    }
}

// MARK: - EchoResponseTime

/// Statistics ▸ Service Response Time ▸ ICMP and ICMPv6: echo requests and the replies
/// paired with them, the requests left unanswered, and the reply times in
/// milliseconds — minimum, maximum, mean, median and sample standard deviation, with
/// the frames of the fastest and slowest reply — as `tshark -z icmp,srt` prints them.
/// A reply pairs, inside its session, with the latest request of the same identifier,
/// sequence number and matching checksum, once.
nonisolated struct EchoResponseTime: Equatable, Sendable {
    // MARK: Lifecycle

    init(rows: [CaptureFrameRow], ipv6: Bool) {
        var pending: [EchoResponseTimePendingKey: Date] = [:]
        var requests = 0
        var times: [(milliseconds: Double, frame: UInt64)] = []
        for row in rows {
            guard case let .echo(isV6, isRequest, key) = row.srt, isV6 == ipv6, let session = row.sessionID,
                  let time = row.provenance.timestamp, let ip = row.ip else
            {
                continue
            }
            let pendingKey = EchoResponseTimePendingKey(
                session: session,
                echoKey: key,
                source: isRequest ? ip.source : ip.destination,
                destination: isRequest ? ip.destination : ip.source
            )
            if isRequest {
                requests += 1
                pending[pendingKey] = time
            } else if let start = pending.removeValue(forKey: pendingKey) {
                let microseconds = (time.timeIntervalSince(start) * 1e6).rounded()
                times.append((microseconds / 1e3, row.ordinal))
            }
        }
        self.init(requests: requests, replies: times.count, times: times)
    }

    fileprivate init(requests: Int, replies: Int, times: [(milliseconds: Double, frame: UInt64)]) {
        self.requests = requests
        self.replies = replies
        let sorted = times.map(\.milliseconds).sorted()
        let low = sorted.first ?? 0
        let high = sorted.last ?? 0
        minimum = low
        maximum = high
        // tshark keeps the first reply that set a new minimum or maximum.
        minimumFrame = times.first { $0.milliseconds == low }?.frame
        maximumFrame = times.first { $0.milliseconds == high }?.frame
        let average = sorted.isEmpty ? 0 : sorted.reduce(0, +) / Double(sorted.count)
        mean = average
        median = sorted.isEmpty ? 0 : sorted.count.isMultiple(of: 2)
            ? (sorted[sorted.count / 2 - 1] + sorted[sorted.count / 2]) / 2 : sorted[sorted.count / 2]
        standardDeviation = sorted.count > 1
            ? (sorted.map { ($0 - average) * ($0 - average) }.reduce(0, +) / Double(sorted.count - 1)).squareRoot()
            : 0
    }

    // MARK: Internal

    /// tshark's column headings, and this summary's values under them.
    static let columns = [
        "Requests", "Replies", "Lost", "% Loss", "Minimum", "Maximum", "Mean", "Median", "SDeviation", "Min Frame",
        "Max Frame",
    ]

    let requests: Int
    let replies: Int
    let minimum: Double
    let maximum: Double
    let mean: Double
    let median: Double
    let standardDeviation: Double
    let minimumFrame: UInt64?
    let maximumFrame: UInt64?

    var lost: Int {
        max(0, requests - replies)
    }

    var lossPercent: Double {
        requests == 0 ? 0 : 100 * Double(lost) / Double(requests)
    }

    var values: [String] {
        [
            String(requests), String(replies), String(lost), String(format: "%.1f", lossPercent),
            Self.milliseconds(minimum), Self.milliseconds(maximum), Self.milliseconds(mean), Self.milliseconds(median),
            Self.milliseconds(standardDeviation), minimumFrame.map(String.init) ?? "",
            maximumFrame.map(String.init) ?? "",
        ]
    }

    var csv: String {
        [Self.columns, values].map { $0.joined(separator: ",") }.joined(separator: "\r\n") + "\r\n"
    }

    /// Milliseconds with three decimals, as tshark prints them.
    static func milliseconds(_ value: Double) -> String {
        String(format: "%.3f", value)
    }
}

// MARK: - EchoResponseTimeStreamingAccumulator

/// Capture-order echo SRT reducer. It keeps only request timestamps and paired
/// durations, never frame rows. Both collections have hard ceilings so a very
/// large or adversarial capture fails explicitly instead of exhausting RAM.
nonisolated struct EchoResponseTimeStreamingAccumulator: Sendable {
    // MARK: Lifecycle

    init(ipv6: Bool) {
        self.ipv6 = ipv6
    }

    // MARK: Internal

    enum Failure: LocalizedError, Equatable, Sendable {
        case pendingLimit
        case sampleLimit
        case incompleteEchoFacts

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case .pendingLimit:
                String(localized: "ICMP SRT cannot track more than 200,000 pending echo requests.")
            case .sampleLimit:
                String(localized: "ICMP SRT cannot retain more than 200,000 reply-time samples.")
            case .incompleteEchoFacts:
                String(localized: "ICMP SRT is unavailable because an echo frame lacks a timestamp or session address.")
            }
        }
    }

    static let maximumRecords = 200_000

    private(set) var requests = 0
    private(set) var replies = 0
    private(set) var failure: Failure?

    mutating func record(_ row: CaptureFrameRow) {
        guard failure == nil else {
            return
        }
        guard case let .echo(isV6, isRequest, key) = row.srt, isV6 == ipv6 else {
            return
        }
        guard let session = row.sessionID, let time = row.provenance.timestamp, let ip = row.ip else {
            failure = .incompleteEchoFacts
            return
        }
        let pendingKey = EchoResponseTimePendingKey(
            session: session,
            echoKey: key,
            source: isRequest ? ip.source : ip.destination,
            destination: isRequest ? ip.destination : ip.source
        )
        if isRequest {
            requests += 1
            if pending[pendingKey] != nil {
                pending[pendingKey] = time
            } else if pendingCount < Self.maximumRecords {
                pending[pendingKey] = time
                pendingCount += 1
            } else {
                failure = .pendingLimit
            }
            return
        }
        guard let start = pending.removeValue(forKey: pendingKey) else {
            return
        }
        pendingCount -= 1
        replies += 1
        guard times.count < Self.maximumRecords else {
            failure = .sampleLimit
            return
        }
        let milliseconds = (time.timeIntervalSince(start) * 1e6).rounded() / 1e3
        times.append((milliseconds, row.ordinal))
    }

    func result() -> EchoResponseTime {
        EchoResponseTime(requests: requests, replies: replies, times: times)
    }

    // MARK: Private

    private let ipv6: Bool
    private var pending: [EchoResponseTimePendingKey: Date] = [:]
    private var pendingCount = 0
    private var times: [(milliseconds: Double, frame: UInt64)] = []
}

// MARK: - EchoResponseTimePendingKey

private struct EchoResponseTimePendingKey: Hashable, Sendable {
    let session: UUID
    let echoKey: UInt64
    let source: String
    let destination: String
}
