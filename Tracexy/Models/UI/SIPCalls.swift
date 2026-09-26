import Foundation

// MARK: - SIPCallState

/// Where a call got to, as Wireshark's VoIP Calls names it.
nonisolated enum SIPCallState: Hashable, Sendable {
    case setup
    case ringing
    case inCall
    case completed
    case rejected(Int)
    case cancelled

    // MARK: Internal

    var title: String {
        switch self {
        case .setup: String(localized: "Call setup")
        case .ringing: String(localized: "Ringing")
        case .inCall: String(localized: "In call")
        case .completed: String(localized: "Completed")
        case let .rejected(code): String(localized: "Rejected (\(code))")
        case .cancelled: String(localized: "Cancelled")
        }
    }
}

// MARK: - SIPCallRow

/// One SIP call (one Call-ID that carried an INVITE) for Statistics ▸ VoIP Calls.
nonisolated struct SIPCallRow: Identifiable, Hashable, Sendable {
    let callID: String
    let from: String
    let to: String
    let start: Date?
    let stop: Date?
    let state: SIPCallState
    let messages: Int
    let firstFrame: UInt64
    let source: IPEndpoint
    let destination: IPEndpoint

    var id: String {
        callID
    }

    var duration: TimeInterval? {
        guard let start, let stop else {
            return nil
        }
        return stop.timeIntervalSince(start)
    }

    /// The signalling session's Session Expression.
    var term: String {
        "ip == \(source.ip) and ip == \(destination.ip) and port == \(source.port) and port == \(destination.port)"
    }
}

// MARK: - SIPCalls

/// Statistics ▸ VoIP Calls: every Call-ID that carried an INVITE, with where it got
/// to — ringing on a 18x, in call on a 2xx to the INVITE, completed when a BYE is
/// answered, rejected on a final 3xx–6xx to the INVITE, cancelled by CANCEL.
nonisolated enum SIPCalls {
    static func calls(rows: [CaptureFrameRow]) -> [SIPCallRow] {
        var order: [String] = []
        var calls: [String: SIPCallRow] = [:]
        for row in rows {
            guard let fact = row.sip, let callID = fact.message.callID else {
                continue
            }
            let message = fact.message
            guard let current = calls[callID] else {
                guard message.method == "INVITE" else {
                    continue
                }
                order.append(callID)
                calls[callID] = SIPCallRow(
                    callID: callID, from: message.from ?? "", to: message.to ?? "",
                    start: row.provenance.timestamp, stop: row.provenance.timestamp, state: .setup, messages: 1,
                    firstFrame: row.ordinal, source: fact.source, destination: fact.destination
                )
                continue
            }
            calls[callID] = SIPCallRow(
                callID: callID, from: current.from, to: current.to, start: current.start,
                stop: row.provenance.timestamp ?? current.stop, state: next(current.state, message),
                messages: current.messages + 1,
                firstFrame: current.firstFrame, source: current.source, destination: current.destination
            )
        }
        return order.compactMap { calls[$0] }
    }

    static func next(_ state: SIPCallState, _ message: SIPMessageFacts) -> SIPCallState {
        switch (message.method, message.statusCode, message.cseqMethod) {
        case ("CANCEL", _, _) where state == .setup || state == .ringing:
            .cancelled
        case (nil, let code?, "INVITE") where (180 ..< 200).contains(code) && state == .setup:
            .ringing
        case (nil, let code?, "INVITE") where (200 ..< 300).contains(code) && (state == .setup || state == .ringing):
            .inCall
        case (nil, let code?, "INVITE") where code >= 300 && (state == .setup || state == .ringing):
            code == 487 ? .cancelled : .rejected(code)
        case (nil, let code?, "BYE") where (200 ..< 300).contains(code) && state == .inCall:
            .completed
        default:
            state
        }
    }
}
