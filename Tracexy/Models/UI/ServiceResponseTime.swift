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

    static func table(_ service: Service, rows: [CaptureFrameRow]) -> [Row] {
        var samples: [Int: [Int64]] = [:]
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
                if !isResponse {
                    pending[session, default: [:]][messageID] = time
                } else if !isInterim, let start = pending[session]?.removeValue(forKey: messageID),
                          command != 0x0C, command != 0x12
                {
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
                }
            }
        case .kerberos:
            var previous: [UUID: (Date, Int)] = [:]
            for (session, time, fact) in frames {
                guard case let .kerberos(type) = fact else {
                    continue
                }
                if let (start, request) = previous[session], let index = kerberosIndex(request: request, reply: type) {
                    samples[index, default: []].append(microseconds(from: start, to: time))
                }
                previous[session] = (time, type)
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
                minimum: Double(low) / 1e6, maximum: Double(high) / 1e6, sum: Double(times.reduce(0, +)) / 1e6
            )
        }
    }

    /// Seconds with six decimals, as tshark prints them.
    static func seconds(_ value: TimeInterval) -> String {
        String(format: "%.6f", value)
    }

    static func csv(_ service: Service, _ rows: [Row]) -> String {
        let header = ["Index", service.procedureTitle, "Calls", "Min SRT", "Max SRT", "Avg SRT", "Sum SRT"]
        let lines = rows.map { row in
            [
                String(row.index), row.procedure, String(row.calls), seconds(row.minimum), seconds(row.maximum),
                seconds(row.average), seconds(row.sum),
            ]
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

    /// Whole microseconds between two frame times — the resolution of a pcap time —
    /// so sums do not drift.
    private static func microseconds(from start: Date, to end: Date) -> Int64 {
        Int64((end.timeIntervalSince(start) * 1e6).rounded())
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
        var pending: [UUID: [UInt64: Date]] = [:]
        var requests = 0
        var times: [(milliseconds: Double, frame: UInt64)] = []
        for row in rows {
            guard case let .echo(isV6, isRequest, key) = row.srt, isV6 == ipv6, let session = row.sessionID,
                  let time = row.provenance.timestamp else
            {
                continue
            }
            if isRequest {
                requests += 1
                pending[session, default: [:]][key] = time
            } else if let start = pending[session]?.removeValue(forKey: key) {
                let microseconds = (time.timeIntervalSince(start) * 1e6).rounded()
                times.append((microseconds / 1e3, row.ordinal))
            }
        }
        self.requests = requests
        replies = times.count
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
