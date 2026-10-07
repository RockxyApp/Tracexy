import CryptoKit
import Foundation

// MARK: - X509DistinguishedName

/// The readable attributes of one X.509 `Name`, in wire order. Only the attributes a
/// person uses to recognise a certificate are named; every other attribute is kept
/// as its dotted OID so nothing the certificate said is silently dropped.
nonisolated struct X509DistinguishedName: Sendable, Equatable {
    nonisolated struct Attribute: Sendable, Equatable {
        /// A short label ("CN", "O", "OU", "C", "L", "ST") or the dotted OID.
        let label: String
        let value: String
    }

    let attributes: [Attribute]

    var commonName: String? {
        attributes.last { $0.label == "CN" }?.value
    }

    var organization: String? {
        attributes.first { $0.label == "O" }?.value
    }

    /// RFC 4514-style one-line rendering, most specific attribute first.
    var displayString: String {
        attributes.reversed().map { "\($0.label)=\($0.value)" }.joined(separator: ", ")
    }
}

// MARK: - X509CertificateSummary

/// What a certificate observed in a TLS handshake says about itself: the fields a
/// person reads to recognise it, and the SHA-256 fingerprint that identifies it.
///
/// It is a *reading*, not a verdict. Nothing here checks a signature, a trust
/// anchor, revocation, or whether the certificate is valid for the name the client
/// asked for — the capture cannot prove any of that, so no field claims it.
nonisolated struct X509CertificateSummary: Sendable, Equatable {
    // MARK: Lifecycle

    /// Parse the DER encoding. Returns `nil` for anything that is not a structurally
    /// complete X.509 certificate within the bounds; a partial reading is never
    /// returned.
    init?(der: [UInt8]) {
        guard !der.isEmpty, der.count <= Self.maximumEncodedLength,
              let parsed = try? X509Parser(der).parse() else
        {
            return nil
        }
        self.der = der
        version = parsed.version
        serialNumber = parsed.serial
        issuer = parsed.issuer
        subject = parsed.subject
        notBefore = parsed.notBefore
        notAfter = parsed.notAfter
        subjectAlternativeNames = parsed.alternativeNames
        omittedAlternativeNameCount = parsed.omittedAlternativeNames
        isSelfIssued = parsed.issuerDER == parsed.subjectDER
        sha256Fingerprint = Array(SHA256.hash(data: der))
    }

    // MARK: Internal

    /// The largest encoding accepted. Real leaf and intermediate certificates are a
    /// few KiB; the bound keeps one malformed length from becoming an allocation.
    static let maximumEncodedLength = 64 << 10
    /// Subject alternative names kept per certificate; the rest are counted.
    static let maximumAlternativeNames = 64

    let der: [UInt8]
    /// The X.509 version (1, 2 or 3).
    let version: Int
    /// The serial number's big-endian bytes, leading zero sign octet removed.
    let serialNumber: [UInt8]
    let issuer: X509DistinguishedName
    let subject: X509DistinguishedName
    let notBefore: Date
    let notAfter: Date
    /// DNS names and IP addresses from the subjectAltName extension, in wire order.
    let subjectAlternativeNames: [String]
    let omittedAlternativeNameCount: Int
    /// The issuer and subject names are byte-identical. That is what "self-issued"
    /// means (RFC 5280 §3.2); it says nothing about who signed it.
    let isSelfIssued: Bool
    let sha256Fingerprint: [UInt8]

    var serialNumberHex: String {
        serialNumber.isEmpty ? "00" : serialNumber.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    var fingerprintHex: String {
        sha256Fingerprint.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    /// The name a person recognises: the subject CN, else its organisation, else
    /// the first alternative name, else the full subject.
    var displayName: String {
        subject.commonName ?? subject.organization ?? subjectAlternativeNames.first ?? subject.displayString
    }

    /// PEM armour (RFC 7468) of the exact observed bytes.
    var pem: String {
        let body = Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
    }
}

// MARK: - X509Parser

/// A bounded, fail-closed DER walk over exactly the `TBSCertificate` fields the
/// summary reads. Every length is checked against its enclosing element before use;
/// any surprise throws and the caller keeps nothing.
nonisolated private struct X509Parser {
    // MARK: Lifecycle

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    // MARK: Internal

    struct Parsed {
        var version = 1
        var serial: [UInt8] = []
        var issuer = X509DistinguishedName(attributes: [])
        var issuerDER: ArraySlice<UInt8> = []
        var subject = X509DistinguishedName(attributes: [])
        var subjectDER: ArraySlice<UInt8> = []
        var notBefore = Date.distantPast
        var notAfter = Date.distantPast
        var alternativeNames: [String] = []
        var omittedAlternativeNames = 0
    }

    func parse() throws -> Parsed {
        var outer = DERCursor(bytes, 0 ..< bytes.count)
        let certificate = try outer.read(tag: 0x30)
        guard outer.isAtEnd else {
            throw X509ParseError.trailingBytes
        }
        var certificateCursor = DERCursor(bytes, certificate.content)
        let tbs = try certificateCursor.read(tag: 0x30)
        _ = try certificateCursor.read(tag: 0x30) // signatureAlgorithm
        _ = try certificateCursor.read(tag: 0x03) // signatureValue
        guard certificateCursor.isAtEnd else {
            throw X509ParseError.trailingBytes
        }

        var parsed = Parsed()
        var cursor = DERCursor(bytes, tbs.content)
        if cursor.peekTag == 0xA0 {
            let explicit = try cursor.read(tag: 0xA0)
            var inner = DERCursor(bytes, explicit.content)
            let value = try inner.read(tag: 0x02)
            guard value.content.count == 1, let raw = bytes[value.content].first, raw <= 2 else {
                throw X509ParseError.unsupported
            }
            parsed.version = Int(raw) + 1
        }
        let serial = try cursor.read(tag: 0x02)
        guard !serial.content.isEmpty, serial.content.count <= 32 else {
            throw X509ParseError.unsupported
        }
        parsed.serial = Array(bytes[serial.content].drop { $0 == 0 })
        _ = try cursor.read(tag: 0x30) // signature AlgorithmIdentifier
        let issuer = try cursor.read(tag: 0x30)
        parsed.issuerDER = bytes[issuer.content]
        parsed.issuer = try name(issuer.content)
        let validity = try cursor.read(tag: 0x30)
        var validityCursor = DERCursor(bytes, validity.content)
        parsed.notBefore = try time(validityCursor.readAny())
        parsed.notAfter = try time(validityCursor.readAny())
        let subject = try cursor.read(tag: 0x30)
        parsed.subjectDER = bytes[subject.content]
        parsed.subject = try name(subject.content)
        _ = try cursor.read(tag: 0x30) // subjectPublicKeyInfo
        while !cursor.isAtEnd {
            let element = try cursor.readAny()
            guard element.tag == 0xA3 else {
                continue // issuerUniqueID / subjectUniqueID
            }
            try extensions(element.content, into: &parsed)
        }
        return parsed
    }

    // MARK: Private

    private static let attributeLabels: [[UInt8]: String] = [
        [0x55, 0x04, 0x03]: "CN",
        [0x55, 0x04, 0x06]: "C",
        [0x55, 0x04, 0x07]: "L",
        [0x55, 0x04, 0x08]: "ST",
        [0x55, 0x04, 0x0A]: "O",
        [0x55, 0x04, 0x0B]: "OU",
    ]
    private static let subjectAltNameOID: [UInt8] = [0x55, 0x1D, 0x11]
    private static let maximumNameAttributes = 32

    private let bytes: [UInt8]

    private static func address(_ raw: [UInt8]) -> String? {
        switch raw.count {
        case 4:
            return raw.map(String.init).joined(separator: ".")
        case 16:
            var storage = in6_addr()
            withUnsafeMutableBytes(of: &storage) { $0.copyBytes(from: raw) }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &storage, &buffer, socklen_t(buffer.count)) != nil else {
                return nil
            }
            return String(cString: buffer)
        default:
            return nil
        }
    }

    private static func dottedOID(_ raw: [UInt8]) -> String {
        guard let first = raw.first else {
            return "OID"
        }
        var parts = [first < 80 ? Int(first) / 40 : 2, first < 80 ? Int(first) % 40 : Int(first) - 80]
        var value = 0
        for byte in raw.dropFirst() {
            value = (value << 7) | Int(byte & 0x7F)
            if byte & 0x80 == 0 {
                parts.append(value)
                value = 0
            }
        }
        return parts.map(String.init).joined(separator: ".")
    }

    private func name(_ range: Range<Int>) throws -> X509DistinguishedName {
        var attributes: [X509DistinguishedName.Attribute] = []
        var rdns = DERCursor(bytes, range)
        while !rdns.isAtEnd {
            let set = try rdns.read(tag: 0x31)
            var members = DERCursor(bytes, set.content)
            while !members.isAtEnd {
                let pair = try members.read(tag: 0x30)
                var fields = DERCursor(bytes, pair.content)
                let oid = try fields.read(tag: 0x06)
                let value = try fields.readAny()
                guard attributes.count < Self.maximumNameAttributes else {
                    throw X509ParseError.unsupported
                }
                let oidBytes = Array(bytes[oid.content])
                let label = Self.attributeLabels[oidBytes] ?? Self.dottedOID(oidBytes)
                try attributes.append(.init(label: label, value: string(value)))
            }
        }
        return X509DistinguishedName(attributes: attributes)
    }

    private func string(_ element: DERElement) throws -> String {
        let content = Array(bytes[element.content])
        switch element.tag {
        case 0x0C,
             0x13,
             0x16,
             0x14,
             0x12:
            // UTF8String, PrintableString, IA5String, T61String, NumericString. T61 is
            // read as Latin-1, which is what every certificate in practice means by it.
            guard let text = String(bytes: content, encoding: element.tag == 0x14 ? .isoLatin1 : .utf8) else {
                throw X509ParseError.malformed
            }
            return text
        case 0x1E:
            guard content.count.isMultiple(of: 2) else {
                throw X509ParseError.malformed
            }
            let units = stride(from: 0, to: content.count, by: 2).map {
                UInt16(content[$0]) << 8 | UInt16(content[$0 + 1])
            }
            return String(decoding: units, as: UTF16.self)
        default:
            return content.map { String(format: "%02X", $0) }.joined()
        }
    }

    private func time(_ element: DERElement) throws -> Date {
        let raw = Array(bytes[element.content])
        guard raw.last == UInt8(ascii: "Z") else {
            throw X509ParseError.malformed
        }
        let digits = raw.dropLast().map { Int($0) - Int(UInt8(ascii: "0")) }
        let yearDigits: Int
        switch element.tag {
        case 0x17: yearDigits = 2
        case 0x18: yearDigits = 4
        default: throw X509ParseError.malformed
        }
        // RFC 5280 §4.1.2.5: seconds are mandatory and fractions are not allowed.
        guard digits.count == yearDigits + 10, digits.allSatisfy({ (0 ... 9).contains($0) }) else {
            throw X509ParseError.malformed
        }
        func number(_ start: Int, _ count: Int) -> Int {
            digits[start ..< start + count].reduce(0) { $0 * 10 + $1 }
        }
        var year = number(0, yearDigits)
        if yearDigits == 2 {
            year += year >= 50 ? 1_900 : 2_000
        }
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(secondsFromGMT: 0)
        components.year = year
        components.month = number(yearDigits, 2)
        components.day = number(yearDigits + 2, 2)
        components.hour = number(yearDigits + 4, 2)
        components.minute = number(yearDigits + 6, 2)
        components.second = number(yearDigits + 8, 2)
        guard components.isValidDate, let date = components.date else {
            throw X509ParseError.malformed
        }
        return date
    }

    private func extensions(_ range: Range<Int>, into parsed: inout Parsed) throws {
        var outer = DERCursor(bytes, range)
        let list = try outer.read(tag: 0x30)
        var cursor = DERCursor(bytes, list.content)
        while !cursor.isAtEnd {
            let entry = try cursor.read(tag: 0x30)
            var fields = DERCursor(bytes, entry.content)
            let oid = try fields.read(tag: 0x06)
            if fields.peekTag == 0x01 {
                _ = try fields.read(tag: 0x01) // critical
            }
            let value = try fields.read(tag: 0x04)
            guard Array(bytes[oid.content]) == Self.subjectAltNameOID else {
                continue
            }
            var names = DERCursor(bytes, value.content)
            let sequence = try names.read(tag: 0x30)
            var generalNames = DERCursor(bytes, sequence.content)
            while !generalNames.isAtEnd {
                let generalName = try generalNames.readAny()
                let rendered: String? = switch generalName.tag {
                case 0x82: String(bytes: bytes[generalName.content], encoding: .ascii)
                case 0x87: Self.address(Array(bytes[generalName.content]))
                default: nil
                }
                guard let rendered else {
                    continue
                }
                if parsed.alternativeNames.count < X509CertificateSummary.maximumAlternativeNames {
                    parsed.alternativeNames.append(rendered)
                } else {
                    parsed.omittedAlternativeNames += 1
                }
            }
        }
    }
}

// MARK: - X509ParseError

nonisolated private enum X509ParseError: Error {
    case malformed
    case unsupported
    case trailingBytes
}

// MARK: - DERElement

nonisolated private struct DERElement {
    let tag: UInt8
    let content: Range<Int>
}

// MARK: - DERCursor

/// A cursor over one constructed element's content. Reads never leave `range`.
nonisolated private struct DERCursor {
    // MARK: Lifecycle

    init(_ bytes: [UInt8], _ range: Range<Int>) {
        self.bytes = bytes
        position = range.lowerBound
        end = range.upperBound
    }

    // MARK: Internal

    var isAtEnd: Bool {
        position >= end
    }

    var peekTag: UInt8? {
        position < end ? bytes[position] : nil
    }

    mutating func read(tag expected: UInt8) throws -> DERElement {
        let element = try readAny()
        guard element.tag == expected else {
            throw X509ParseError.malformed
        }
        return element
    }

    mutating func readAny() throws -> DERElement {
        guard position + 2 <= end else {
            throw X509ParseError.malformed
        }
        let tag = bytes[position]
        // High-tag-number form never occurs in the fields read here.
        guard tag & 0x1F != 0x1F else {
            throw X509ParseError.unsupported
        }
        var cursor = position + 1
        let first = bytes[cursor]
        cursor += 1
        var length = 0
        if first & 0x80 == 0 {
            length = Int(first)
        } else {
            let count = Int(first & 0x7F)
            // DER forbids the indefinite form and a certificate never needs more
            // than four length octets.
            guard (1 ... 4).contains(count), cursor + count <= end else {
                throw X509ParseError.malformed
            }
            for _ in 0 ..< count {
                length = (length << 8) | Int(bytes[cursor])
                cursor += 1
            }
        }
        guard length >= 0, cursor + length <= end else {
            throw X509ParseError.malformed
        }
        position = cursor + length
        return DERElement(tag: tag, content: cursor ..< cursor + length)
    }

    // MARK: Private

    private let bytes: [UInt8]
    private var position: Int
    private let end: Int
}
