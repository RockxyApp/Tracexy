import Foundation

// MARK: - SessionLadder

/// The ladder diagram of one session: its two endpoints as lanes and one arrow per
/// retained step, in capture order. It draws only what the retained evidence holds —
/// SYN, SYN+ACK, the first data each way, FIN and RST, runs of retransmissions,
/// TLS records, DNS and ICMP messages — and says how many further steps it left out,
/// so a long conversation stays readable without pretending to be complete.
struct SessionLadder: Equatable {
    struct Step: Equatable, Identifiable {
        let id: String
        /// `nil` for an observation with no direction (a state eviction).
        let direction: ConnectionDirection?
        let label: String
        /// Seconds since the first step; `nil` when either frame is untimed.
        let offset: TimeInterval?
        let provenance: SessionFrameProvenance?
        /// A step that reports trouble (reset, retransmission, alert, DNS error).
        let isAttention: Bool
    }

    static let maximumSteps = 80

    let leftEndpoint: String
    let rightEndpoint: String
    let steps: [Step]
    /// Steps the evidence holds beyond ``maximumSteps``.
    let omittedStepCount: Int

    var isEmpty: Bool {
        steps.isEmpty
    }

    static func build(_ selection: SessionEvidenceSelection) -> SessionLadder {
        let tuple = selection.connections.first?.tuple ?? selection.tls?.tuple ?? selection.datagrams?.tuple
        var raw: [(ordinal: FrameOrdinal, rank: Int, step: Step)] = []

        for connection in selection.connections {
            var dataSeen: Set<ConnectionDirection> = []
            var retransmissionRun: (direction: ConnectionDirection?, count: Int, first: ConnectionEvent)?
            func flushRun() {
                guard let run = retransmissionRun else {
                    return
                }
                let label = run.count == 1 ? "Retransmission" : "\(run.count) retransmissions"
                raw.append(entry(run.first, label: label, attention: true, suffix: "rtx"))
                retransmissionRun = nil
            }
            func entry(_ event: ConnectionEvent, label: String, attention: Bool, suffix: String = "")
                -> (FrameOrdinal, Int, Step)
            {
                (event.occurrenceOrdinal, 0, Step(
                    id: "c-\(connection.id.rawValue.uuidString)-\(event.occurrenceOrdinal.rawValue)-\(label)\(suffix)",
                    direction: event.direction,
                    label: label,
                    offset: nil,
                    provenance: event.provenance.last,
                    isAttention: attention
                ))
            }
            for event in connection.events {
                if event.kind == .retransmission {
                    if let run = retransmissionRun, run.direction == event.direction {
                        retransmissionRun = (run.direction, run.count + 1, run.first)
                    } else {
                        flushRun()
                        retransmissionRun = (event.direction, 1, event)
                    }
                    continue
                }
                let label: String?
                var attention = false
                switch event.kind {
                case .syn: label = "SYN"
                case .synAck: label = "SYN, ACK"
                case .fin: label = "FIN"
                case .rst:
                    label = "RST"
                    attention = true
                case .payloadObserved:
                    guard let direction = event.direction, dataSeen.insert(direction).inserted else {
                        label = nil
                        break
                    }
                    label = "Data"
                case .zeroWindow:
                    label = "Zero window"
                    attention = true
                case .keepAlive: label = "Keep-alive"
                default: label = nil
                }
                guard let label else {
                    continue
                }
                flushRun()
                raw.append(entry(event, label: label, attention: attention))
            }
            flushRun()
        }

        if let tls = selection.tls {
            for (index, observation) in tls.observations.enumerated() {
                let title = SessionEvidenceCopy.tlsRecordTitle(observation.fact)
                    .replacingOccurrences(of: "TLS ", with: "")
                    .replacingOccurrences(of: " record", with: "")
                // Application data records repeat; the ladder keeps the handshake shape.
                guard observation.fact.contentType != 23 else {
                    continue
                }
                raw.append((observation.provenance.ordinal, 1, Step(
                    id: "t-\(observation.provenance.ordinal.rawValue)-\(index)",
                    direction: observation.direction,
                    label: "TLS \(title)",
                    offset: nil,
                    provenance: observation.provenance,
                    isAttention: observation.fact.contentType == 21
                )))
            }
        }

        if let datagrams = selection.datagrams {
            for (index, observation) in datagrams.observations.enumerated() {
                let label: String
                var attention = false
                switch observation.kind {
                case let .dns(facts):
                    if facts.isResponse {
                        let code = FollowDatagramPresentation.responseCodeName(facts.responseCode)
                        label = "DNS response \(code)"
                        attention = facts.responseCode != 0
                    } else {
                        label = "DNS query"
                    }
                case let .icmp(facts):
                    label = SessionEvidenceCopy.icmpMessageTitle(facts)
                    attention = true
                }
                raw.append((observation.provenance.ordinal, 2, Step(
                    id: "d-\(observation.provenance.ordinal.rawValue)-\(index)",
                    direction: observation.direction,
                    label: label,
                    offset: nil,
                    provenance: observation.provenance,
                    isAttention: attention
                )))
            }
        }

        let ordered = raw.sorted { lhs, rhs in
            lhs.ordinal != rhs.ordinal ? lhs.ordinal < rhs.ordinal : lhs.rank < rhs.rank
        }
        let firstTime = ordered.lazy.compactMap(\.step.provenance?.timestamp).first
        let steps = ordered.prefix(maximumSteps).map { item in
            let step = item.step
            let offset: TimeInterval? = if let first = firstTime, let time = step.provenance?.timestamp {
                time.timeIntervalSince(first)
            } else {
                nil
            }
            return Step(
                id: step.id, direction: step.direction, label: step.label, offset: offset,
                provenance: step.provenance, isAttention: step.isAttention
            )
        }
        return SessionLadder(
            leftEndpoint: tuple?.a.display ?? "",
            rightEndpoint: tuple?.b.display ?? "",
            steps: steps,
            omittedStepCount: max(0, ordered.count - maximumSteps)
        )
    }
}
