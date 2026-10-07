import Foundation

// MARK: - TCPCompleteness

/// Which stages of a TCP conversation the capture showed, with Wireshark's
/// `tcp.completeness` bit values so a number reads the same in both tools:
/// SYN 1, SYN-ACK 2, ACK (of the SYN-ACK, from the SYN's sender) 4, DATA 8,
/// FIN 16, RST 32. It records what frames were seen, not what the endpoints did:
/// a stage the capture missed is simply absent.
nonisolated struct TCPCompleteness: OptionSet, Hashable, Sendable {
    static let syn = TCPCompleteness(rawValue: 1)
    static let synAck = TCPCompleteness(rawValue: 2)
    static let ack = TCPCompleteness(rawValue: 4)
    static let data = TCPCompleteness(rawValue: 8)
    static let fin = TCPCompleteness(rawValue: 16)
    static let rst = TCPCompleteness(rawValue: 32)

    let rawValue: UInt8

    /// Wireshark's "Complete": the three-way handshake and a FIN or RST were seen.
    var isComplete: Bool {
        isSuperset(of: [.syn, .synAck, .ack]) && !isDisjoint(with: [.fin, .rst])
    }

    /// Wireshark's `tcp.completeness.str` style: the stages seen, most significant
    /// first, e.g. "R·F·D·A·S·S" for everything, "·····S" for a lone SYN.
    var stageString: String {
        let stages: [(TCPCompleteness, String)] = [
            (.rst, "R"), (.fin, "F"), (.data, "D"), (.ack, "A"), (.synAck, "S"), (.syn, "S"),
        ]
        return stages.map { contains($0.0) ? $0.1 : "·" }.joined()
    }

    /// A short label for a table cell: "Complete, with data", "Incomplete".
    var label: String {
        if isComplete {
            return contains(.data) ? String(localized: "Complete, with data") : String(localized: "Complete, no data")
        }
        if isEmpty {
            return String(localized: "Nothing seen")
        }
        return contains(.data) ? String(localized: "Incomplete, with data") : String(localized: "Incomplete")
    }
}
