import Foundation

// MARK: - DecodedField

nonisolated struct DecodedField: Hashable, Sendable {
    // MARK: Lifecycle

    init(name: String, value: String, byteRange: Range<Int>? = nil) {
        self.name = name
        self.value = value
        self.byteRange = byteRange
    }

    // MARK: Internal

    let name: String
    let value: String
    /// Absolute byte range of this field within the frame's `rawBytes`, for
    /// hex highlighting. `nil` when the field isn't backed by contiguous bytes.
    var byteRange: Range<Int>?

    /// Identity is name + value; `byteRange` is positional metadata and is
    /// deliberately excluded so golden-fixture equality in tests stays stable.
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.name == rhs.name && lhs.value == rhs.value
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(name)
        hasher.combine(value)
    }
}

// MARK: - DecodedLayer

/// One protocol layer in the decode tree (Eth → IP → TCP → TLS …).
nonisolated struct DecodedLayer: Hashable, Identifiable, Sendable {
    // MARK: Lifecycle

    init(
        proto: ProtocolKind,
        title: String,
        summary: String = "",
        fields: [DecodedField] = [],
        children: [DecodedLayer] = [],
        byteRange: Range<Int>? = nil
    ) {
        self.proto = proto
        self.title = title
        self.summary = summary
        self.fields = fields
        self.children = children
        self.byteRange = byteRange
    }

    // MARK: Internal

    let id = UUID()
    let proto: ProtocolKind
    let title: String
    var summary: String
    var fields: [DecodedField]
    var children: [DecodedLayer]
    /// Absolute byte range of this whole layer within the frame's `rawBytes`.
    var byteRange: Range<Int>?

    /// Identity is the decoded content, not the per-instance `id`. Two decodes of
    /// the same bytes produce structurally equal layers with *different* random
    /// ids; excluding `id` here keeps golden-fixture and session-equivalence
    /// comparisons stable (the same reasoning `DecodedField` applies to
    /// `byteRange`). `id` remains for SwiftUI `Identifiable` diffing.
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.proto == rhs.proto
            && lhs.title == rhs.title
            && lhs.summary == rhs.summary
            && lhs.fields == rhs.fields
            && lhs.children == rhs.children
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(proto)
        hasher.combine(title)
        hasher.combine(summary)
        hasher.combine(fields)
        hasher.combine(children)
    }
}

// MARK: - DecodedPacket

nonisolated struct DecodedPacket {
    // MARK: Lifecycle

    init(timestamp: Date, originalLength: Int) {
        self.timestamp = timestamp
        self.originalLength = originalLength
        layers = []
        dnsAnswers = []
    }

    // MARK: Internal

    var timestamp: Date
    var originalLength: Int
    /// The captured on-wire bytes of this packet (≤ snaplen), retained for the
    /// inspector's hex pane. Empty if not built from a real frame.
    var rawBytes: [UInt8] = []
    /// Originating process (from pktap), propagated to the session. nil = unknown.
    var processName: String?
    var layers: [DecodedLayer]
    var fiveTuple: FiveTuple?
    var transport: ProtocolKind?
    var appProtocol: ProtocolKind?
    var sni: String?
    var dnsQuery: String?
    var dnsAnswers: [String]
    var sourceEndpoint: IPEndpoint?
    var destinationEndpoint: IPEndpoint?
    /// Sequence number of the first TCP payload byte and its captured bytes.
    /// Session accumulation uses this bounded handoff for metadata-only stream
    /// reassembly; packet decoding itself remains stateless.
    var tcpPayloadSequence: UInt32?
    var tcpPayloadBytes: [UInt8] = []

    /// Protocol stack outer→inner, e.g. [.tcp, .tls]. Used by the session list.
    var protocolStack: [ProtocolKind] {
        var seen = Set<ProtocolKind>()
        return layers.map(\.proto).filter { $0 != .ethernet && seen.insert($0).inserted }
    }
}
