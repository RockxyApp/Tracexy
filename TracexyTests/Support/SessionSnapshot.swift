import Foundation
@testable import Tracexy

// MARK: - RangeSnapshot

/// A byte range preserved verbatim in a snapshot. Offsets are *not* normalised
/// away — a drifted or false range must change the snapshot and fail a golden.
struct RangeSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ range: Range<Int>) {
        lowerBound = range.lowerBound
        upperBound = range.upperBound
    }

    // MARK: Internal

    let lowerBound: Int
    let upperBound: Int
}

// MARK: - FieldSnapshot

struct FieldSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ field: DecodedField) {
        name = field.name
        value = field.value
        byteRange = field.byteRange.map(RangeSnapshot.init)
    }

    // MARK: Internal

    let name: String
    let value: String
    let byteRange: RangeSnapshot?
}

// MARK: - LayerSnapshot

/// A decoded protocol layer, preserving every semantic field, child and byte range.
/// The only thing deliberately excluded is `DecodedLayer.id`, which is a random
/// per-instance `UUID` used solely for SwiftUI diffing — two decodes of the same
/// bytes differ only there, so keeping it would make every snapshot non-reproducible
/// while carrying no decode information.
struct LayerSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ layer: DecodedLayer) {
        proto = layer.proto.rawValue
        title = layer.title
        summary = layer.summary
        byteRange = layer.byteRange.map(RangeSnapshot.init)
        fields = layer.fields.map(FieldSnapshot.init)
        children = layer.children.map(LayerSnapshot.init)
    }

    // MARK: Internal

    let proto: String
    let title: String
    let summary: String
    let byteRange: RangeSnapshot?
    let fields: [FieldSnapshot]
    let children: [LayerSnapshot]
}

// MARK: - RawEvidenceSnapshot

/// The representative raw bytes as a deterministic count plus hex plus digest —
/// never normalised away. A batch/live snapshot fills this from the in-memory
/// representative bytes; a saved snapshot fills it from bytes exact-read back
/// through `CaptureEvidenceReader`, so the two are directly comparable.
struct RawEvidenceSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ bytes: [UInt8]) {
        byteCount = bytes.count
        hex = bytes.map { String(format: "%02x", $0) }.joined()
        digest = Self.fnv1a(bytes)
    }

    // MARK: Internal

    let byteCount: Int
    let hex: String
    /// A deterministic FNV-1a-64 digest of the bytes, so a golden can pin evidence
    /// compactly without inlining a whole frame's hex by hand.
    let digest: String

    // MARK: Private

    private static func fnv1a(_ bytes: [UInt8]) -> String {
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in bytes {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        return String(format: "%016llx", hash)
    }
}

// MARK: - SessionSnapshot

/// A test-only, stable, Codable snapshot of one ``SessionSummary``.
///
/// It preserves every semantic field the summary carries — id, ordering position
/// (via array order), endpoints, host/process, protocol stack, status, byte
/// counts, DNS/SNI/answers, integer-microsecond timing, every decoded layer /
/// field / child, every byte range, and the representative raw evidence. Times are
/// integer microseconds so serialisation is exact and byte-order-independent. The
/// only exclusion is the random layer presentation `id`.
///
/// Two snapshots compare `Equatable`; ``SessionSnapshot/sortedJSON(_:)`` renders an
/// array as sorted, pretty JSON for reviewable goldens.
struct SessionSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ summary: SessionSummary) {
        id = summary.id.uuidString
        startMicros = Self.micros(summary.startTime.timeIntervalSince1970)
        durationMicros = Self.micros(summary.duration)
        processName = summary.processName
        host = summary.host
        source = summary.sourceEndpoint
        destination = summary.destinationEndpoint
        protocolStack = summary.protocolStack.map(\.rawValue)
        status = summary.status.rawValue
        latencyMicros = summary.latencyMilliseconds.map { Int64(($0 * 1_000).rounded()) }
        bytesUp = summary.bytesUp
        bytesDown = summary.bytesDown
        sni = summary.sni
        dnsQuery = summary.dnsQuery
        dnsAnswers = summary.dnsAnswers
        dnsAnswersOmittedCount = summary.dnsAnswersOmittedCount
        layers = summary.decodedLayers.map(LayerSnapshot.init)
        representative = RawEvidenceSnapshot(summary.representativeBytes)
    }

    // MARK: Internal

    let id: String
    let startMicros: Int64
    let durationMicros: Int64
    let processName: String?
    let host: String
    let source: String
    let destination: String
    let protocolStack: [String]
    let status: String
    let latencyMicros: Int64?
    let bytesUp: Int
    let bytesDown: Int
    let sni: String?
    let dnsQuery: String?
    let dnsAnswers: [String]
    let dnsAnswersOmittedCount: Int
    let layers: [LayerSnapshot]
    let representative: RawEvidenceSnapshot

    /// Snapshot a whole ordered summary list, preserving first-seen order.
    static func snapshots(_ summaries: [SessionSummary]) -> [SessionSnapshot] {
        summaries.map(SessionSnapshot.init)
    }

    /// Render snapshots as sorted, pretty JSON — the canonical golden text. Sorted
    /// keys and stable field ordering make the output reproducible and diffable.
    static func sortedJSON(_ snapshots: [SessionSnapshot]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(snapshots), let text = String(data: data, encoding: .utf8) else {
            return ""
        }
        return text
    }

    /// Compact pin for the complete canonical JSON. The semantic verifier keeps
    /// failures readable; this digest makes any unlisted field or range drift fail.
    static func digest(_ json: String) -> String {
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in json.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        return String(format: "%016llx", hash)
    }

    // MARK: Private

    /// Round a seconds value to whole microseconds. Deterministic for the corpus's
    /// fixed whole-second instants, and stable for any derived duration/latency.
    private static func micros(_ seconds: TimeInterval) -> Int64 {
        Int64((seconds * 1_000_000).rounded())
    }
}

// MARK: - FrameDecodeSnapshot

/// A thin per-frame decode snapshot for the decoder-tree matrix: the protocol
/// stack, the classified application protocol, and the layer tree with all byte
/// ranges preserved. Catches decoder drift frame by frame, independent of session
/// folding, and (like ``SessionSnapshot``) excludes only the random layer id.
struct FrameDecodeSnapshot: Codable, Equatable {
    // MARK: Lifecycle

    init(_ packet: DecodedPacket) {
        protocolStack = packet.protocolStack.map(\.rawValue)
        appProtocol = packet.appProtocol?.rawValue
        layers = packet.layers.map(LayerSnapshot.init)
    }

    // MARK: Internal

    let protocolStack: [String]
    let appProtocol: String?
    let layers: [LayerSnapshot]

    /// Render a per-frame decode matrix as sorted, pretty JSON.
    static func sortedJSON(_ frames: [FrameDecodeSnapshot]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(frames), let text = String(data: data, encoding: .utf8) else {
            return ""
        }
        return text
    }
}
