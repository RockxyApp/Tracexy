// MARK: - TLSFactsDecoder

/// Builds neutral, typed `TLSRecordFact` values from a bounds-checked TLS record view.
/// This keeps the new structural parsing out of the overlength `PacketDecoder` while
/// reusing the same bounds-before-read discipline: every read goes through
/// `PacketBuffer`, and any short/malformed read collapses to reduced facts rather than
/// trapping. Nothing here decrypts, reassembles, or produces a policy verdict.
nonisolated enum TLSFactsDecoder {
    // MARK: Internal

    /// Content-based TLS record recognition (RFC 8446 §5.1), independent of port. A
    /// recognized record needs a *complete* 5-byte record header: a defined content type
    /// (20…24 — CCS/Alert/Handshake/ApplicationData/Heartbeat), record-layer major version
    /// 3, a plausible minor (SSL 3.0 … TLS 1.3), and a declared body length within the
    /// 2^14 + 2048 ciphertext allowance. The declared body is deliberately *not* required
    /// to be fully present — TCP reassembly does not exist, so a packet may carry only a
    /// record fragment. Rejecting invalid type/version/length bounds false positives on
    /// arbitrary TCP payloads.
    static func isTLSRecord(_ buf: PacketBuffer) -> Bool {
        guard buf.length >= 5,
              let type = try? buf.u8(0), (20 ... 24).contains(type),
              let major = try? buf.u8(1), major == 0x03,
              let minor = try? buf.u8(2), minor <= 0x04,
              let length = try? Int(buf.u16(3)),
              length >= 1, length <= maxRecordLength else
        {
            return false
        }
        return true
    }

    /// Neutral facts for one TLS record. `record` must be positioned at the 5-byte record
    /// header (the caller has already recognized it as TLS, so the header reads succeed).
    /// Returns `nil` only when even the fixed header cannot be read.
    static func recordFact(_ record: PacketBuffer) -> TLSRecordFact? {
        guard let contentType = try? record.u8(0),
              let legacyRecordVersion = try? record.u16(1),
              let declaredBody = try? Int(record.u16(3)) else
        {
            return nil
        }
        let recordLength = 5 + declaredBody
        let capturedBody = max(0, min(recordLength, record.length) - 5)
        // A handshake message is read only for a Handshake (22) record, mirroring the
        // renderer's gate: a handshake byte is never interpreted for Alert / Application
        // Data / Change Cipher Spec / Heartbeat records.
        // Never let a handshake parser consume bytes belonging to a following
        // coalesced record. The view ends at this record's declared/captured boundary.
        let boundedRecord = try? record.subset(from: 0, count: min(recordLength, record.length))
        let handshake = contentType == 22 ? boundedRecord.flatMap(handshakeFact) : nil
        return TLSRecordFact(
            contentType: contentType,
            legacyRecordVersion: legacyRecordVersion,
            declaredBodyLength: declaredBody,
            capturedBodyLength: capturedBody,
            handshake: handshake
        )
    }

    // MARK: Private

    /// Largest plausible TLS record body: the 2^14 plaintext limit plus the
    /// ciphertext-expansion allowance (RFC 5246 §6.2.3 / RFC 8446 §5.2), i.e. 2^14 + 2048.
    /// A declared length beyond this cannot be a real TLS record, so it is rejected.
    private static let maxRecordLength = 16_384 + 2_048

    /// RFC 8446 §4.1.2/§4.1.3 `supported_versions` extension identifier.
    private static let supportedVersionsExtension: UInt16 = 0x002B
    /// Hard cap on retained ClientHello offered versions; overflow is counted, not stored.
    private static let offeredVersionCap = 16
    /// Guard on the extension-list walk so a malformed length can never spin unbounded.
    private static let extensionWalkCap = 64

    /// RFC 8446 §4.1.3 HelloRetryRequest sentinel: the SHA-256 of "HelloRetryRequest"
    /// placed in the ServerHello random. An HRR is not a final negotiation outcome.
    private static let helloRetryRandom: [UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ]

    /// Reads a 24-bit big-endian value without widening `PacketBuffer`'s API. `nil` on OOB.
    private static func u24(_ buf: PacketBuffer, _ offset: Int) -> Int? {
        guard let hi = try? buf.u8(offset),
              let mid = try? buf.u8(offset + 1),
              let lo = try? buf.u8(offset + 2) else
        {
            return nil
        }
        return Int(hi) << 16 | Int(mid) << 8 | Int(lo)
    }

    /// Dispatches a Handshake record to a ClientHello/ServerHello fact. Other handshake
    /// message types (Certificate, Finished, …) intentionally produce no handshake fact.
    private static func handshakeFact(_ record: PacketBuffer) -> TLSHandshakeFact? {
        guard let handshakeType = try? record.u8(5),
              let handshakeLength = u24(record, 6),
              let boundedHandshake = try? record.subset(
                  from: 0, count: min(9 + handshakeLength, record.length)
              ) else
        {
            return nil
        }
        switch handshakeType {
        case 0x01:
            return clientHelloFact(boundedHandshake).map(TLSHandshakeFact.clientHello)
        case 0x02:
            return serverHelloFact(boundedHandshake).map(TLSHandshakeFact.serverHello)
        default:
            return nil
        }
    }

    /// Parses ClientHello facts. Requires at least a readable `legacy_version`; the offered
    /// versions are added only when the `supported_versions` extension is reached intact.
    /// A truncated body simply yields fewer facts, never a crash or a negotiation claim.
    private static func clientHelloFact(_ record: PacketBuffer) -> TLSClientHelloFact? {
        // Handshake header: type(1) len(3); body: version(2) random(32) sessionIdLen(1) …
        guard let handshakeLength = u24(record, 6),
              let legacyVersion = try? record.u16(9) else
        {
            return nil
        }
        let handshakeBodyEnd = 9 + handshakeLength
        let handshakeComplete = handshakeBodyEnd <= record.length
        var offset = 5 + 4 + 2 + 32 // past record header, handshake header, version, random
        guard let sessionIdLen = try? Int(record.u8(offset)) else {
            return incompleteClientHello(legacyVersion)
        }
        offset += 1 + sessionIdLen
        guard let cipherLen = try? Int(record.u16(offset)) else {
            return incompleteClientHello(legacyVersion)
        }
        offset += 2 + cipherLen
        guard let compLen = try? Int(record.u8(offset)) else {
            return incompleteClientHello(legacyVersion)
        }
        offset += 1 + compLen
        if handshakeComplete, offset == handshakeBodyEnd {
            return TLSClientHelloFact(
                legacyVersion: legacyVersion, offeredVersions: [],
                offeredVersionsOmittedCount: 0, extensionsComplete: true
            )
        }
        guard let extTotal = try? Int(record.u16(offset)) else {
            return incompleteClientHello(legacyVersion)
        }
        offset += 2
        let extEnd = offset + extTotal
        guard handshakeComplete, extEnd == handshakeBodyEnd, extEnd <= record.length else {
            return incompleteClientHello(legacyVersion)
        }
        var offered: [UInt16] = []
        var omitted = 0
        var guardCount = 0
        var supportedVersionsSeen = false
        while offset < extEnd, guardCount < extensionWalkCap {
            guard offset + 4 <= extEnd else {
                return incompleteClientHello(legacyVersion)
            }
            guardCount += 1
            guard let extType = try? record.u16(offset),
                  let extLen = try? Int(record.u16(offset + 2)) else
            {
                return incompleteClientHello(legacyVersion)
            }
            let extData = offset + 4
            guard extData + extLen <= extEnd else {
                return incompleteClientHello(legacyVersion)
            }
            if extType == supportedVersionsExtension {
                guard !supportedVersionsSeen,
                      let parsed = clientOfferedVersions(record, at: extData, extLength: extLen) else
                {
                    return incompleteClientHello(legacyVersion)
                }
                supportedVersionsSeen = true
                (offered, omitted) = parsed
            }
            offset = extData + extLen
        }
        guard offset == extEnd else {
            return incompleteClientHello(legacyVersion)
        }
        return TLSClientHelloFact(
            legacyVersion: legacyVersion, offeredVersions: offered,
            offeredVersionsOmittedCount: omitted, extensionsComplete: true
        )
    }

    private static func incompleteClientHello(_ legacyVersion: UInt16) -> TLSClientHelloFact {
        TLSClientHelloFact(
            legacyVersion: legacyVersion, offeredVersions: [],
            offeredVersionsOmittedCount: 0, extensionsComplete: false
        )
    }

    /// Reads the ClientHello `supported_versions` body: a 1-byte list length followed by
    /// 2-byte versions. Bounded to `offeredVersionCap`; further entries are counted.
    private static func clientOfferedVersions(
        _ record: PacketBuffer, at start: Int, extLength: Int
    )
        -> ([UInt16], Int)?
    {
        guard extLength >= 3,
              let listLen = try? Int(record.u8(start)),
              listLen >= 2,
              listLen.isMultiple(of: 2),
              listLen + 1 == extLength else
        {
            return nil
        }
        var versions: [UInt16] = []
        var omitted = 0
        var offset = start + 1
        let end = start + extLength
        while offset + 2 <= end {
            guard let version = try? record.u16(offset) else {
                return nil
            }
            if versions.count < offeredVersionCap {
                versions.append(version)
            } else {
                omitted += 1
            }
            offset += 2
        }
        return offset == end ? (versions, omitted) : nil
    }

    /// Parses ServerHello facts. Requires the fixed fields through `cipher_suite`. A
    /// selected version is published only after the complete handshake message and its
    /// extension region were captured and well-formed, and never for an HRR.
    private static func serverHelloFact(_ record: PacketBuffer) -> TLSServerHelloFact? {
        guard let handshakeLength = u24(record, 6),
              let legacyVersion = try? record.u16(9) else
        {
            return nil
        }
        let isHRR = isHelloRetryRandom(record, at: 11)
        var offset = 5 + 4 + 2 + 32 // sessionIdLen position
        guard let sessionIdLen = try? Int(record.u8(offset)) else {
            return nil
        }
        offset += 1 + sessionIdLen
        guard let cipher = try? record.u16(offset) else {
            return nil
        }
        offset += 2 // cipher_suite
        // Without a captured compression_method byte the message cannot be complete.
        guard (try? record.u8(offset)) != nil else {
            return TLSServerHelloFact(
                legacyVersion: legacyVersion, selectedCipher: cipher, isHelloRetryRequest: isHRR,
                extensionsComplete: false, selectedVersion: nil
            )
        }
        offset += 1 // compression_method
        let handshakeBodyEnd = 9 + handshakeLength
        var extensionsComplete = false
        var supportedVersion: UInt16?
        // The whole handshake message must be captured before any completeness claim.
        if handshakeBodyEnd <= record.length {
            if offset == handshakeBodyEnd {
                // A legacy (≤ TLS 1.2) ServerHello may carry no extensions block at all.
                extensionsComplete = true
            } else if let extTotal = try? Int(record.u16(offset)) {
                let extStart = offset + 2
                let extEnd = extStart + extTotal
                if extEnd == handshakeBodyEnd, extEnd <= record.length,
                   let parsed = parseServerExtensions(record, start: extStart, end: extEnd)
                {
                    extensionsComplete = true
                    supportedVersion = parsed
                }
            }
        }
        // Publish a negotiated version only for a complete, well-formed, non-HRR message.
        let selectedVersion = (extensionsComplete && !isHRR) ? (supportedVersion ?? legacyVersion) : nil
        return TLSServerHelloFact(
            legacyVersion: legacyVersion, selectedCipher: cipher, isHelloRetryRequest: isHRR,
            extensionsComplete: extensionsComplete, selectedVersion: selectedVersion
        )
    }

    /// Finds the ServerHello `supported_versions` value: a single 2-byte version in the
    /// extension body (RFC 8446 §4.2.1). `nil` when the extension is absent or malformed.
    private static func parseServerExtensions(
        _ record: PacketBuffer, start: Int, end: Int
    )
        -> UInt16??
    {
        var offset = start
        var guardCount = 0
        var selectedVersion: UInt16?
        var supportedVersionsSeen = false
        while offset < end, guardCount < extensionWalkCap {
            guard offset + 4 <= end else {
                return nil
            }
            guardCount += 1
            guard let extType = try? record.u16(offset),
                  let extLen = try? Int(record.u16(offset + 2)) else
            {
                return nil
            }
            let extData = offset + 4
            guard extData + extLen <= end else {
                return nil
            }
            if extType == supportedVersionsExtension {
                guard !supportedVersionsSeen, extLen == 2,
                      let version = try? record.u16(extData) else
                {
                    return nil
                }
                supportedVersionsSeen = true
                selectedVersion = version
            }
            offset = extData + extLen
        }
        guard offset == end else {
            return nil
        }
        return .some(selectedVersion)
    }

    /// Whether the 32 random bytes at `offset` equal the HelloRetryRequest sentinel.
    private static func isHelloRetryRandom(_ record: PacketBuffer, at offset: Int) -> Bool {
        guard let random = try? record.bytes(offset, 32) else {
            return false
        }
        return random == helloRetryRandom
    }
}
