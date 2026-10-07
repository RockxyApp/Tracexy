import Foundation

// MARK: - SIPStatistics

/// Statistics ▸ SIP, as Wireshark's SIP Statistics (`tshark -z sip,stat`): the
/// messages, the resent ones, the status codes and request methods, and the call
/// setup time — INVITE to the ACK of its answer — measured as `packet-sip.c` does.
nonisolated enum SIPStatistics {
    // MARK: Internal

    static func tree(rows: [CaptureFrameRow]) -> [StatsTreeNode] {
        let frames = rows.compactMap { row in row.sip.map { (row, $0) } }
        guard !frames.isEmpty else {
            return []
        }
        var transactions: [String: Transaction] = [:]
        var resent = 0
        var setupTimes: [Double] = []
        var codes: [Int: (reason: String, count: Int)] = [:]
        var methods: [String: Int] = [:]
        for (row, fact) in frames {
            let message = fact.message
            if let code = message.statusCode {
                codes[code, default: (reasonPhrase(code) ?? message.reason ?? "", 0)].count += 1
            } else if let method = message.method {
                methods[method, default: 0] += 1
            }
            guard let callID = message.callID, let cseq = message.cseqNumber, let cseqMethod = message.cseqMethod,
                  let time = row.provenance.timestamp else
            {
                continue
            }
            let key = "\(callID)|\(fact.source.display)|\(fact.destination.display)"
            // Setup time: an ACK reads its own direction's entry before the resend check.
            if message.method == "ACK", let request = transactions[key]?.requestTime {
                setupTimes.append(Double(milliseconds(from: request, to: time)))
            }
            if isResend(message, cseq: cseq, method: cseqMethod, key: key, time: time, in: &transactions) {
                resent += 1
            }
        }
        var nodes = [
            StatsTreeNode(id: "messages", title: String(localized: "SIP messages"), count: frames.count),
            StatsTreeNode(id: "resent", title: String(localized: "Resent messages"), count: resent),
        ]
        nodes.append(StatsTreeNode(
            id: "codes", title: String(localized: "Status codes"), count: codes.values.reduce(0) { $0 + $1.count },
            children: codes.sorted { $0.key < $1.key }.map {
                StatsTreeNode(id: "codes/\($0.key)", title: "\($0.key) \($0.value.reason)", count: $0.value.count)
            }
        ))
        nodes.append(StatsTreeNode(
            id: "methods", title: String(localized: "Request methods"), count: methods.values.reduce(0, +),
            children: methods.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }.map {
                StatsTreeNode(id: "methods/\($0.key)", title: $0.key, count: $0.value)
            }
        ))
        let counted = setupTimes.filter { $0 > 0 }
        nodes.append(StatsTreeNode(
            id: "setup", title: String(localized: "Setup time (ms)"), count: counted.count,
            average: counted.isEmpty ? nil : Double(Int(counted.reduce(0, +)) / counted.count),
            minimum: counted.min(), maximum: counted.max()
        ))
        return nodes
    }

    /// The reason phrase Wireshark prints for a status code.
    static func reasonPhrase(_ code: Int) -> String? {
        switch code {
        case 100: "Trying"
        case 180: "Ringing"
        case 181: "Call Is Being Forwarded"
        case 182: "Queued"
        case 183: "Session Progress"
        case 200: "OK"
        case 202: "Accepted"
        case 301: "Moved Permanently"
        case 302: "Moved Temporarily"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 407: "Proxy Authentication Required"
        case 408: "Request Timeout"
        case 480: "Temporarily Unavailable"
        case 481: "Call/Transaction Does Not Exist"
        case 486: "Busy Here"
        case 487: "Request Terminated"
        case 488: "Not Acceptable Here"
        case 500: "Server Internal Error"
        case 503: "Service Unavailable"
        case 603: "Decline"
        default: nil
        }
    }

    // MARK: Private

    private enum TransactionState {
        case nothing
        case request
        case provisional
        case finalResponse
    }

    private struct Transaction {
        var cseq: UInt32
        var method: String
        var state = TransactionState.nothing
        var responseCode = 0
        var requestTime: Date?
    }

    /// `sip_is_packet_resend`: a request repeated while its transaction still waits
    /// (never ACK or CANCEL), or a final response repeated with the same code.
    private static func isResend(
        _ message: SIPMessageFacts,
        cseq: UInt32,
        method: String,
        key: String,
        time: Date,
        in transactions: inout [String: Transaction]
    )
        -> Bool
    {
        let isRequest = message.method != nil
        var entry = transactions[key] ?? Transaction(cseq: cseq, method: method, requestTime: isRequest ? time : nil)
        let compared = transactions[key] == nil ? 0 : entry.cseq
        if transactions[key] != nil, cseq != entry.cseq {
            entry = Transaction(cseq: cseq, method: method, requestTime: isRequest ? time : entry.requestTime)
        }
        var isResent = false
        if isRequest, cseq == compared, entry.state == .request, method == entry.method, method != "ACK",
           method != "CANCEL"
        {
            isResent = true
        }
        if let code = message.statusCode, cseq == compared, entry.state == .finalResponse, method == entry.method,
           code >= 200, code == entry.responseCode
        {
            isResent = true
        }
        entry.cseq = cseq
        if isRequest {
            entry.state = .request
            if !isResent {
                entry.requestTime = time
            }
        } else if let code = message.statusCode {
            if code >= 200 {
                entry.responseCode = code
                entry.state = .finalResponse
            } else {
                entry.state = .provisional
            }
        }
        transactions[key] = entry
        return isResent
    }

    /// Whole milliseconds between two instants, as `packet-sip.c` computes them:
    /// seconds × 1000 plus the nanosecond difference truncated to milliseconds.
    private static func milliseconds(from start: Date, to end: Date) -> Int {
        func split(_ date: Date) -> (Int, Int) {
            let value = date.timeIntervalSince1970
            let seconds = value.rounded(.down)
            // Rounded to the microsecond a capture records, so a Double's last bit
            // cannot pull a whole millisecond down.
            return (Int(seconds), Int(((value - seconds) * 1_000_000).rounded()) * 1_000)
        }
        let (startSeconds, startNanos) = split(start)
        let (endSeconds, endNanos) = split(end)
        return (endSeconds - startSeconds) * 1_000 + (endNanos - startNanos) / 1_000_000
    }
}
