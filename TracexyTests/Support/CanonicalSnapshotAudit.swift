import Foundation
@testable import Tracexy

// MARK: - CanonicalSnapshotAudit

/// Test-only change control for the canonical snapshot schema. A golden digest may
/// only move when the delta is explained, so this audit answers two questions the
/// digest cannot: is the audit's own re-encoder faithful, and is the schema change
/// additive? The full set of layer titles and field names is pinned, and removing
/// exactly the decoder's declared additive packet facts must leave the schema the
/// reviewed baseline emitted — so a rename or a removal fails even though the
/// digest alone would only say "something moved".
///
/// It deliberately does *not* try to reproduce the baseline's exact canonical bytes
/// from current output. Doing so would require the test to replay every value
/// formatting decision ever made, which is unsound: a filter that no longer matches
/// history is indistinguishable from a real regression. Value-level fidelity is
/// held by `ReplayGoldens.conversationSnapshotDigest` on the current source
/// instead. Nothing here is production behaviour.
enum CanonicalSnapshotAudit {
    // MARK: Internal

    enum CanonicalSnapshotJSON: Codable {
        case object([String: CanonicalSnapshotJSON])
        case array([CanonicalSnapshotJSON])
        case string(String)
        case integer(Int64)
        case number(Double)
        case boolean(Bool)
        case null

        // MARK: Lifecycle

        init(from decoder: Decoder) throws {
            if let keyed = try? decoder.container(keyedBy: DynamicKey.self) {
                var values: [String: CanonicalSnapshotJSON] = [:]
                for key in keyed.allKeys {
                    values[key.stringValue] = try keyed.decode(CanonicalSnapshotJSON.self, forKey: key)
                }
                self = .object(values)
            } else if var unkeyed = try? decoder.unkeyedContainer() {
                var values: [CanonicalSnapshotJSON] = []
                while !unkeyed.isAtEnd {
                    try values.append(unkeyed.decode(CanonicalSnapshotJSON.self))
                }
                self = .array(values)
            } else {
                let single = try decoder.singleValueContainer()
                if single.decodeNil() {
                    self = .null
                } else if let value = try? single.decode(Bool.self) {
                    self = .boolean(value)
                } else if let value = try? single.decode(Int64.self) {
                    self = .integer(value)
                } else if let value = try? single.decode(Double.self) {
                    self = .number(value)
                } else {
                    self = try .string(single.decode(String.self))
                }
            }
        }

        // MARK: Internal

        func encode(to encoder: Encoder) throws {
            switch self {
            case let .object(values):
                var container = encoder.container(keyedBy: DynamicKey.self)
                for (key, value) in values {
                    try container.encode(value, forKey: DynamicKey(stringValue: key))
                }
            case let .array(values):
                var container = encoder.unkeyedContainer()
                for value in values {
                    try container.encode(value)
                }
            case let .string(value):
                var container = encoder.singleValueContainer()
                try container.encode(value)
            case let .integer(value):
                var container = encoder.singleValueContainer()
                try container.encode(value)
            case let .number(value):
                var container = encoder.singleValueContainer()
                try container.encode(value)
            case let .boolean(value):
                var container = encoder.singleValueContainer()
                try container.encode(value)
            case .null:
                var container = encoder.singleValueContainer()
                try container.encodeNil()
            }
        }

        /// Drop exactly the packet facts this branch added, leaving the schema the
        /// reviewed baseline emitted. Names only: no value is rewritten, because a
        /// rewritten value would hide the drift this audit exists to catch.
        func removingAdditivePacketFacts() -> CanonicalSnapshotJSON {
            switch self {
            case let .object(values):
                var cleaned = values.mapValues { $0.removingAdditivePacketFacts() }
                if case let .array(fields)? = values["fields"] {
                    cleaned["fields"] = .array(fields.filter { field in
                        guard case let .object(attributes) = field,
                              case let .string(name)? = attributes["name"] else
                        {
                            return true
                        }
                        return !CanonicalSnapshotAudit.additivePacketFactNames.contains(name)
                            && !name.hasPrefix("SACK Block ")
                    })
                }
                return .object(cleaned)
            case let .array(values):
                return .array(values.map { $0.removingAdditivePacketFacts() })
            default:
                return self
            }
        }

        /// Collect `title` and `name` strings from every object in the tree, so a
        /// digest mismatch can name the exact surface that drifted.
        func collectSchemaNames(into names: inout Set<String>) {
            switch self {
            case let .object(values):
                if case let .string(title)? = values["title"] {
                    names.insert("layer:\(title)")
                }
                if case let .string(name)? = values["name"] {
                    names.insert("field:\(name)")
                }
                for value in values.values {
                    value.collectSchemaNames(into: &names)
                }
            case let .array(values):
                for value in values {
                    value.collectSchemaNames(into: &names)
                }
            default:
                break
            }
        }
    }

    struct DynamicKey: CodingKey, Hashable {
        // MARK: Lifecycle

        init(stringValue: String) {
            self.stringValue = stringValue
            intValue = nil
        }

        init(intValue: Int) {
            stringValue = String(intValue)
            self.intValue = intValue
        }

        // MARK: Internal

        let stringValue: String
        let intValue: Int?
    }

    /// Packet facts this branch adds to the decode tree. Every name here is a new
    /// field, never a renamed or re-valued one, which is what makes the schema
    /// delta additive and the golden refresh reviewable.
    static let additivePacketFactNames: Set<String> = [
        "More Fragments", "Don't Fragment", "Transaction ID", "Truncated (TC)",
        "FIN", "SYN", "RST", "PSH", "Acknowledgment (ACK)", "URG", "ECE", "CWR",
    ]

    /// Every layer title and field name the replay conversation corpus decodes to,
    /// on this source. An undeclared addition, rename or removal fails here.
    static let conversationSchema: [String] = [
        "field:Ack", "field:Acknowledgment (ACK)", "field:Answers", "field:CWR", "field:Checksum",
        "field:Cipher Suites", "field:Code", "field:Content Type", "field:Destination", "field:Destination CID",
        "field:Destination Port", "field:Differentiated Services", "field:Don't Fragment", "field:ECE",
        "field:FIN", "field:Flags", "field:Flow Label", "field:Fragment Offset", "field:Header Checksum",
        "field:Header Length", "field:Hop Limit", "field:Host", "field:Identification", "field:Length",
        "field:Magic Cookie", "field:Message Length", "field:Message Type", "field:More Fragments",
        "field:Next Header", "field:Operation", "field:PSH", "field:Packet Type", "field:Payload Length",
        "field:Protocol", "field:Query", "field:RST", "field:Record Length", "field:Request", "field:SYN",
        "field:Sender IP", "field:Sender MAC", "field:Seq", "field:Source", "field:Source CID",
        "field:Source Port", "field:TTL", "field:Target IP", "field:Target MAC", "field:Total Length",
        "field:Traffic Class", "field:Transaction ID", "field:Truncated (TC)", "field:Type", "field:URG",
        "field:Urgent Pointer", "field:Version", "field:Window", "field:server_name",
        "layer:Address Resolution Protocol", "layer:Domain Name System", "layer:Ethernet II",
        "layer:Handshake: Client Hello", "layer:Hypertext Transfer Protocol",
        "layer:Internet Control Message Protocol", "layer:Internet Protocol v4", "layer:Internet Protocol v6",
        "layer:QUIC", "layer:Session Traversal Utilities for NAT", "layer:Transmission Control Protocol",
        "layer:Transport Layer Security", "layer:User Datagram Protocol"
    ]

    /// The same inventory with ``additivePacketFactNames`` removed: the schema the
    /// reviewed baseline emitted for this corpus. Equality proves the change is
    /// additive — nothing the baseline carried was dropped or renamed.
    static let conversationBaselineSchema: [String] = [
        "field:Ack", "field:Answers", "field:Checksum", "field:Cipher Suites", "field:Code", "field:Content Type",
        "field:Destination", "field:Destination CID", "field:Destination Port", "field:Differentiated Services",
        "field:Flags", "field:Flow Label", "field:Fragment Offset", "field:Header Checksum", "field:Header Length",
        "field:Hop Limit", "field:Host", "field:Identification", "field:Length", "field:Magic Cookie",
        "field:Message Length", "field:Message Type", "field:Next Header", "field:Operation", "field:Packet Type",
        "field:Payload Length", "field:Protocol", "field:Query", "field:Record Length", "field:Request",
        "field:Sender IP", "field:Sender MAC", "field:Seq", "field:Source", "field:Source CID",
        "field:Source Port", "field:TTL", "field:Target IP", "field:Target MAC", "field:Total Length",
        "field:Traffic Class", "field:Type", "field:Urgent Pointer", "field:Version", "field:Window",
        "field:server_name", "layer:Address Resolution Protocol", "layer:Domain Name System", "layer:Ethernet II",
        "layer:Handshake: Client Hello", "layer:Hypertext Transfer Protocol",
        "layer:Internet Control Message Protocol", "layer:Internet Protocol v4", "layer:Internet Protocol v6",
        "layer:QUIC", "layer:Session Traversal Utilities for NAT", "layer:Transmission Control Protocol",
        "layer:Transport Layer Security", "layer:User Datagram Protocol"
    ]

    /// Re-encode the canonical tree with no filtering at all. This isolates the
    /// audit's own encoder from the schema question it is meant to answer.
    static func digestOfCanonicalRoundTrip(_ json: String) throws -> String {
        let root = try JSONDecoder().decode(CanonicalSnapshotJSON.self, from: Data(json.utf8))
        return try SessionSnapshot.digest(canonicalText(root))
    }

    /// Every layer title and field name the canonical tree carries, sorted.
    static func schemaNames(_ json: String) throws -> [String] {
        try sortedNames(of: decoded(json))
    }

    /// The same inventory after dropping this branch's additive packet facts.
    static func schemaNamesWithoutAdditivePacketFacts(_ json: String) throws -> [String] {
        try sortedNames(of: decoded(json).removingAdditivePacketFacts())
    }

    static func canonicalText(_ root: CanonicalSnapshotJSON) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(root)
        guard let canonical = String(data: data, encoding: .utf8) else {
            throw CocoaError(.fileReadInapplicableStringEncoding)
        }
        return canonical
    }

    // MARK: Private

    private static func decoded(_ json: String) throws -> CanonicalSnapshotJSON {
        try JSONDecoder().decode(CanonicalSnapshotJSON.self, from: Data(json.utf8))
    }

    private static func sortedNames(of root: CanonicalSnapshotJSON) -> [String] {
        var names: Set<String> = []
        root.collectSchemaNames(into: &names)
        return names.sorted()
    }
}
