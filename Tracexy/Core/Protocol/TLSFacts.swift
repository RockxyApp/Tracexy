// MARK: - TLSHandshakeFact

/// The one structurally-complete handshake message a record fact can carry. Only
/// ClientHello and ServerHello are surfaced; every other handshake message leaves
/// the record fact's `handshake` nil. These are neutral wire facts — no SNI,
/// certificate material, raw payload, or negotiation verdict lives here.
nonisolated enum TLSHandshakeFact: Hashable, Sendable {
    case clientHello(TLSClientHelloFact)
    case serverHello(TLSServerHelloFact)
}

// MARK: - TLSClientHelloFact

/// Neutral facts read from a ClientHello body. `legacyVersion` and `offeredVersions`
/// both express *client intent* (RFC 8446 §4.1.2) and never a negotiated outcome. The
/// offered-version vector is hard-capped; `offeredVersionsOmittedCount` records how many
/// well-formed entries in the `supported_versions` extension were dropped past the cap.
nonisolated struct TLSClientHelloFact: Hashable, Sendable {
    /// The `legacy_version` field (offset 9 of the record). In TLS 1.3 this is pinned to
    /// 0x0303 for back-compat and is not a version the client can be said to have chosen.
    let legacyVersion: UInt16
    /// Versions from the `supported_versions` (0x002b) extension, in wire order, capped.
    /// Empty when the extension is absent, truncated, or the body is structurally short.
    let offeredVersions: [UInt16]
    /// Count of additional well-formed offered versions beyond the retention cap. An
    /// occurrence count, not a claim of exact cardinality.
    let offeredVersionsOmittedCount: Int
    /// Whether the declared ClientHello reached its exact end and every extension was
    /// structurally walked within the bounded parser. `false` distinguishes a truncated,
    /// malformed, or over-cap extension region from a complete hello with no
    /// `supported_versions` extension.
    let extensionsComplete: Bool
}

// MARK: - TLSServerHelloFact

/// Neutral facts read from a ServerHello body (RFC 8446 §4.1.3). Keeps the legacy
/// version, selected cipher, HRR detection and extension completeness separate so a
/// selected version is published only when it is safe to.
nonisolated struct TLSServerHelloFact: Hashable, Sendable {
    /// The `legacy_version` field. In TLS 1.3 this is 0x0303 framing, not the outcome;
    /// seeing it alone must never become a "TLS 1.2" conclusion.
    let legacyVersion: UInt16
    /// The single `cipher_suite` the server selected (raw wire value).
    let selectedCipher: UInt16
    /// Whether the RFC 8446 §4.1.3 HelloRetryRequest sentinel random was observed. An HRR
    /// is not a final negotiation outcome and never yields a `selectedVersion`.
    let isHelloRetryRequest: Bool
    /// Whether the whole handshake message and its extension region were captured and
    /// structurally well-formed. A selected version is publishable only when this is true.
    let extensionsComplete: Bool
    /// The negotiated version — present ONLY for a complete, well-formed, non-HRR
    /// ServerHello: the `supported_versions` (0x002b) value when present, otherwise the
    /// legacy value. `nil` whenever the extension region is incomplete or the message is
    /// an HRR, so a truncated legacy-0x0303 ServerHello yields no selected version.
    let selectedVersion: UInt16?
}

// MARK: - TLSRecordFact

/// One TLS record's neutral, decode-derived facts (RFC 8446 §5.1). Carries only numeric
/// wire values and completeness flags — never a policy label, severity, URL, raw payload,
/// SNI or certificate material. Content type, legacy record version, declared/captured
/// body length and body completeness are kept separate; the optional handshake fact
/// exists only for a structurally-complete ClientHello/ServerHello.
nonisolated struct TLSRecordFact: Hashable, Sendable {
    /// Raw record content type (20…24: CCS/Alert/Handshake/ApplicationData/Heartbeat).
    /// For an Alert (21) this is presence only — the body is opaque and never decoded.
    let contentType: UInt8
    /// The record-layer `legacy_record_version` (offset 1). Framing, not the negotiated
    /// version in TLS 1.3.
    let legacyRecordVersion: UInt16
    /// The record's declared body length (offset 3), as written on the wire.
    let declaredBodyLength: Int
    /// Bytes of the body actually captured. Less than `declaredBodyLength` for a record
    /// fragment (no TCP reassembly exists, so records legitimately arrive split).
    let capturedBodyLength: Int
    /// Structurally-complete handshake facts, when the record is a Handshake (22) carrying
    /// a ClientHello or ServerHello whose claimed fields were fully present. `nil` for any
    /// other content type, other handshake messages, or a too-truncated handshake.
    let handshake: TLSHandshakeFact?

    /// Whether the declared body was fully captured. Derived, not stored.
    var bodyComplete: Bool {
        capturedBodyLength >= declaredBodyLength
    }
}
