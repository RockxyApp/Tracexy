import Foundation

// MARK: - TLSCertificateExtraction

/// The certificates one direction of a followed TCP stream sent in the clear, read
/// from that direction's leading bytes on demand.
///
/// Extraction policy (the rules that make an absence honest):
/// 1. Only the direction's **first retained run** is read, and only when it starts at
///    the direction's first observed payload byte. A handshake cannot be read from the
///    middle of a stream, so a stream that does not open with a TLS record is
///    `notTLS`, never "no certificate".
/// 2. Records are walked strictly in order. `ChangeCipherSpec` or `ApplicationData`
///    ends the plaintext handshake: everything after it is encrypted. Reaching that
///    point without a Certificate message is `encryptedBeforeCertificate` — the normal
///    TLS 1.3 case, where certificates travel encrypted — not a missing certificate.
/// 3. Running out of contiguous bytes first is `incomplete`: the capture holds too
///    little of the stream to say.
/// 4. A certificate is listed only when its DER parses completely
///    (``X509CertificateSummary``). One that does not is counted, never guessed at.
/// 5. Nothing here judges trust, expiry, the name asked for, or the chain's order.
///    The certificates are shown as sent, in the order sent.
nonisolated enum TLSCertificateExtraction: Sendable, Equatable {
    /// The direction's opening bytes are not a TLS record.
    case notTLS
    /// No payload was retained in this direction.
    case noPayload
    /// The bytes ended (or a gap began) before the handshake could be read far enough.
    case incomplete
    /// The handshake switched to encryption before any Certificate message.
    case encryptedBeforeCertificate
    /// A Certificate message was read. `unparsedCount` counts entries whose DER did
    /// not parse; `omittedCount` counts entries beyond the per-message bound.
    case certificates([X509CertificateSummary], unparsedCount: Int, omittedCount: Int)

    // MARK: Internal

    /// Largest handshake prefix walked, and most certificates kept, per direction.
    static let maximumHandshakeBytes = 256 << 10
    static let maximumCertificates = 16

    /// The certificates, or an empty list for every other outcome.
    var certificates: [X509CertificateSummary] {
        if case let .certificates(list, _, _) = self {
            return list
        }
        return []
    }

    /// Read `snapshot` under the policy above.
    static func extract(from snapshot: FollowStreamDirectionSnapshot) -> Self {
        guard let anchor = snapshot.anchorSequence, let first = snapshot.runs.first else {
            return .noPayload
        }
        guard first.sequenceAnchor == anchor else {
            return .incomplete
        }
        return extract(fromStreamPrefix: first.bytes)
    }

    /// Walk the contiguous leading bytes of one direction.
    static func extract(fromStreamPrefix bytes: [UInt8]) -> Self {
        walk(bytes).outcome
    }

    /// As ``extract(fromStreamPrefix:)``, with the offset just past the TLS record in
    /// which the Certificate message was completed — where Wireshark dissects it.
    static func walk(_ bytes: [UInt8]) -> (outcome: Self, certificateRecordEnd: Int?) {
        var handshake: [UInt8] = []
        var offset = 0
        var sawRecord = false
        while offset + 5 <= bytes.count {
            let type = bytes[offset]
            let major = bytes[offset + 1]
            let length = Int(bytes[offset + 3]) << 8 | Int(bytes[offset + 4])
            // RFC 8446 §5.1/§5.2: content types 20–24, legacy major version 3, and a
            // record never longer than 2^14 + 2048 bytes.
            guard (20 ... 24).contains(type), major == 3, length <= (1 << 14) + 2_048 else {
                return (sawRecord ? .incomplete : .notTLS, nil)
            }
            sawRecord = true
            let bodyStart = offset + 5
            guard bodyStart + length <= bytes.count else {
                // The record header is intact but its body was not all retained.
                return (parse(handshake) ?? .incomplete, nil)
            }
            switch type {
            case 22:
                guard handshake.count + length <= maximumHandshakeBytes else {
                    return (parse(handshake) ?? .incomplete, nil)
                }
                handshake += bytes[bodyStart ..< bodyStart + length]
                if let outcome = parse(handshake) {
                    return (outcome, bodyStart + length)
                }
            case 20,
                 23:
                return (parse(handshake) ?? .encryptedBeforeCertificate, nil)
            default:
                break // Alert or heartbeat: neither carries a certificate.
            }
            offset = bodyStart + length
        }
        if !sawRecord {
            return (bytes.count >= 5 ? .notTLS : .incomplete, nil)
        }
        return (parse(handshake) ?? .incomplete, nil)
    }

    // MARK: Private

    /// Walk whole handshake messages and return the first Certificate message's
    /// reading, or `nil` when none has been completed yet.
    private static func parse(_ handshake: [UInt8]) -> Self? {
        var offset = 0
        while offset + 4 <= handshake.count {
            let type = handshake[offset]
            let length = Int(handshake[offset + 1]) << 16 | Int(handshake[offset + 2]) << 8
                | Int(handshake[offset + 3])
            let bodyStart = offset + 4
            guard bodyStart + length <= handshake.count else {
                return nil
            }
            if type == 11 {
                return certificateList(Array(handshake[bodyStart ..< bodyStart + length]))
            }
            offset = bodyStart + length
        }
        return nil
    }

    /// RFC 5246 §7.4.2: `opaque ASN.1Cert<1..2^24-1>; ASN.1Cert certificate_list<0..2^24-1>;`
    private static func certificateList(_ body: [UInt8]) -> Self {
        guard body.count >= 3 else {
            return .certificates([], unparsedCount: 1, omittedCount: 0)
        }
        let listLength = Int(body[0]) << 16 | Int(body[1]) << 8 | Int(body[2])
        guard 3 + listLength <= body.count else {
            return .certificates([], unparsedCount: 1, omittedCount: 0)
        }
        var certificates: [X509CertificateSummary] = []
        var unparsed = 0
        var omitted = 0
        var offset = 3
        let end = 3 + listLength
        while offset + 3 <= end {
            let length = Int(body[offset]) << 16 | Int(body[offset + 1]) << 8 | Int(body[offset + 2])
            let start = offset + 3
            guard start + length <= end else {
                unparsed += 1
                break
            }
            if certificates.count >= maximumCertificates {
                omitted += 1
            } else if let summary = X509CertificateSummary(der: Array(body[start ..< start + length])) {
                certificates.append(summary)
            } else {
                unparsed += 1
            }
            offset = start + length
        }
        return .certificates(certificates, unparsedCount: unparsed, omittedCount: omitted)
    }
}
