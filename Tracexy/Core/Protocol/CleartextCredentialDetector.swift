import Foundation

// MARK: - CleartextCredentialKind

/// A way a login secret was seen crossing the wire unencrypted. The kind is all
/// Tracexy keeps: the user name and secret themselves are never read out, stored or
/// shown (Wireshark's Tools ▸ Credentials lists them; Tracexy deliberately does not).
nonisolated enum CleartextCredentialKind: String, CaseIterable, Hashable, Sendable {
    /// An HTTP `Authorization: Basic` (or `Proxy-Authorization: Basic`) header.
    case httpBasic
    /// An FTP `PASS` command.
    case ftp
    /// A POP3 `PASS` command.
    case pop3
    /// An IMAP `LOGIN` command.
    case imap
    /// An SMTP `AUTH PLAIN` or `AUTH LOGIN` exchange.
    case smtp

    // MARK: Internal

    var label: String {
        switch self {
        case .httpBasic: "HTTP Basic authorization"
        case .ftp: "FTP PASS command"
        case .pop3: "POP3 PASS command"
        case .imap: "IMAP LOGIN command"
        case .smtp: "SMTP AUTH PLAIN/LOGIN"
        }
    }
}

// MARK: - CleartextCredentialDetector

/// Recognizes a login secret at the start of a line in one TCP segment's payload.
/// Pure and bounded: it reads at most ``scanLimit`` bytes, matches only fixed
/// command/header shapes at line starts, and returns the kind — never the value.
/// The mail and file-transfer shapes are matched only on their standard server
/// ports, so an arbitrary payload that happens to start with `PASS ` elsewhere is
/// not a finding.
nonisolated enum CleartextCredentialDetector {
    // MARK: Internal

    static let scanLimit = 2_048

    static func detect(payload: [UInt8], sourcePort: UInt16, destinationPort: UInt16) -> CleartextCredentialKind? {
        guard !payload.isEmpty else {
            return nil
        }
        let window = payload.prefix(scanLimit)
        let ports: Set<UInt16> = [sourcePort, destinationPort]
        for line in lines(of: window) {
            let upper = line.uppercased()
            if upper.hasPrefix("AUTHORIZATION: BASIC ") || upper.hasPrefix("PROXY-AUTHORIZATION: BASIC ") {
                return .httpBasic
            }
            if upper.hasPrefix("PASS "), ports.contains(21) {
                return .ftp
            }
            if upper.hasPrefix("PASS "), ports.contains(110) {
                return .pop3
            }
            if ports.contains(143), isIMAPLogin(upper) {
                return .imap
            }
            if ports.contains(25) || ports.contains(587),
               upper.hasPrefix("AUTH PLAIN") || upper.hasPrefix("AUTH LOGIN")
            {
                return .smtp
            }
        }
        return nil
    }

    // MARK: Private

    /// Lines of printable ASCII, split on CR/LF; a line with other bytes ends the scan
    /// of that line (binary payload is not a command).
    private static func lines(of bytes: ArraySlice<UInt8>) -> [String] {
        var result: [String] = []
        var current: [UInt8] = []
        var printable = true
        for byte in bytes {
            if byte == 0x0A || byte == 0x0D {
                if printable, !current.isEmpty, let line = String(bytes: current, encoding: .ascii) {
                    result.append(line)
                }
                current.removeAll(keepingCapacity: true)
                printable = true
            } else {
                printable = printable && (0x20 ... 0x7E).contains(byte)
                current.append(byte)
            }
        }
        return result
    }

    /// `<tag> LOGIN <user> <password>` — three fields after the tag.
    private static func isIMAPLogin(_ upper: String) -> Bool {
        let fields = upper.split(separator: " ", omittingEmptySubsequences: true)
        return fields.count >= 4 && fields[1] == "LOGIN"
    }
}
