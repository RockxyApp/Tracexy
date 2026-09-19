import Foundation

// MARK: - CaptureBoundedText

/// A file-authored string retained under a byte cap. pcapng options carry
/// arbitrary UTF-8 (comments, interface names, capture filters, application
/// names); the reader keeps at most ``CaptureBoundedText/maxBytes`` bytes of each,
/// decodes lossily, and records that a longer or non-UTF-8 value was seen rather
/// than throwing away the fact that the option existed.
nonisolated struct CaptureBoundedText: Sendable, Equatable, Hashable {
    // MARK: Lifecycle

    /// Decode `bytes` (already bounded to at most ``maxBytes`` by the reader),
    /// treating `declaredLength` beyond the retained count as truncation. A NUL
    /// terminator — which some writers include — is stripped and not counted as
    /// content.
    init(bytes: [UInt8], declaredLength: Int) {
        var trimmed = bytes
        if let nul = trimmed.firstIndex(of: 0) {
            trimmed.removeSubrange(nul...)
        }
        let truncated = declaredLength > bytes.count
        if let exact = String(bytes: trimmed, encoding: .utf8) {
            text = exact
            isLossy = false
        } else {
            // `String(decoding:as:)` never fails; it substitutes U+FFFD. Trim a
            // dangling partial scalar introduced by the byte cut so a truncated
            // valid string does not read as lossy.
            var candidate = trimmed
            if truncated {
                while !candidate.isEmpty, String(bytes: candidate, encoding: .utf8) == nil,
                      candidate.count > bytes.count - 4
                {
                    candidate.removeLast()
                }
            }
            if let recovered = String(bytes: candidate, encoding: .utf8) {
                text = recovered
                isLossy = false
            } else {
                // Deliberately lossy: the option existed but was not UTF-8. The
                // replacement-character decode is the honest rendering of that.
                // swiftlint:disable:next optional_data_string_conversion
                text = String(decoding: trimmed, as: UTF8.self)
                isLossy = true
            }
        }
        isTruncated = truncated
    }

    init(text: String, isTruncated: Bool = false, isLossy: Bool = false) {
        self.text = text
        self.isTruncated = isTruncated
        self.isLossy = isLossy
    }

    // MARK: Internal

    /// Byte cap applied before decoding. Values longer than this are cut at a
    /// UTF-8 scalar boundary and flagged.
    static let maxBytes = 256

    let text: String
    /// The source value was longer than ``maxBytes``; `text` is a prefix.
    let isTruncated: Bool
    /// The source bytes were not valid UTF-8; `text` is a lossy decode.
    let isLossy: Bool
}

// MARK: - CaptureBoundedTextList

/// A bounded list of file-authored strings with an explicit count of values that
/// arrived after the bound was full.
nonisolated struct CaptureBoundedTextList: Sendable, Equatable {
    static let maxCount = 16
    static let empty = CaptureBoundedTextList(values: [], omittedCount: 0)

    private(set) var values: [CaptureBoundedText]
    private(set) var omittedCount: Int

    var isEmpty: Bool {
        values.isEmpty && omittedCount == 0
    }

    mutating func append(_ value: CaptureBoundedText) {
        if values.count < Self.maxCount {
            values.append(value)
        } else {
            omittedCount += 1
        }
    }
}

// MARK: - CaptureContainerFacts

/// Container-level facts that only the on-disk format can state.
nonisolated enum CaptureContainerFacts: Sendable, Equatable {
    /// Classic libpcap: one global header for the whole file.
    case pcap(ClassicPcapFacts)
    /// pcapng: facts live per section and per interface (see ``CaptureFileProperties/sections``).
    case pcapng
}

// MARK: - ClassicPcapFacts

nonisolated struct ClassicPcapFacts: Sendable, Equatable {
    let littleEndian: Bool
    let nanosecondResolution: Bool
    let snapLength: UInt32
    /// The `DLT_*` value from the low 16 bits of the link-type word.
    let linkType: UInt32
    /// The complete 32-bit link-type word as written.
    let rawLinkTypeWord: UInt32

    /// The FCS length in 16-bit words when the writer set the "FCS length present"
    /// flag (bit 27), otherwise `nil`. Only the fact that a hint exists is
    /// recorded; frames are never reinterpreted from it.
    var fcsLengthWords: UInt8? {
        guard rawLinkTypeWord & 0x08000000 != 0 else {
            return nil
        }
        return UInt8((rawLinkTypeWord >> 28) & 0xF)
    }
}

// MARK: - CaptureInterfaceStatistics

/// The last Interface Statistics Block seen for one interface in one section.
/// Every counter is optional because each is an optional pcapng option.
nonisolated struct CaptureInterfaceStatistics: Sendable, Equatable {
    var startTime: Date?
    var endTime: Date?
    var received: UInt64?
    var dropped: UInt64?
    var filterAccepted: UInt64?
    var osDropped: UInt64?
    var delivered: UInt64?
    /// How many statistics blocks referenced this interface; the values above are
    /// from the last one.
    var blockCount: Int = 0
}

// MARK: - CaptureInterface

/// One Interface Description Block plus everything folded onto it afterwards.
nonisolated struct CaptureInterface: Sendable, Equatable, Identifiable {
    nonisolated struct ID: Hashable, Sendable {
        let sectionIndex: Int
        let interfaceID: Int
    }

    let id: ID
    let linkType: UInt32
    let snapLength: UInt32
    /// Timestamp ticks per second (`if_tsresol`; 10⁶ when absent).
    let ticksPerSecond: UInt64
    /// Signed seconds added to every timestamp (`if_tsoffset`; 0 when absent).
    let timestampOffsetSeconds: Int64
    var name: CaptureBoundedText?
    var interfaceDescription: CaptureBoundedText?
    /// `if_filter` with its leading filter-type byte removed; `filterKind` keeps it.
    var filter: CaptureBoundedText?
    /// The `if_filter` type byte (0 = libpcap string, 1 = BPF bytecode).
    var filterKind: UInt8?
    var operatingSystem: CaptureBoundedText?
    var hardware: CaptureBoundedText?
    var fcsLength: UInt8?
    var speedBitsPerSecond: UInt64?
    var comments: CaptureBoundedTextList = .empty
    /// Frames (Enhanced or Simple Packet Blocks) attributed to this interface.
    var frameCount: Int = 0
    /// Frames on this interface whose source carried no capture time.
    var untimedFrameCount: Int = 0
    var statistics: CaptureInterfaceStatistics?

    var displayName: String {
        if let name, !name.text.isEmpty {
            return name.text
        }
        return String(localized: "Interface \(id.interfaceID)")
    }
}

// MARK: - CaptureSecretsBlockSummary

/// One Decryption Secrets Block: its declared type and size only. The secrets
/// themselves are never read into memory.
nonisolated struct CaptureSecretsBlockSummary: Sendable, Equatable {
    let secretsType: UInt32
    let secretsLength: UInt64

    var kindLabel: String {
        switch secretsType {
        case 0x544C4B4C: String(localized: "TLS key log")
        case 0x57474B4C: String(localized: "WireGuard keys")
        case 0x5A4E574B: String(localized: "ZigBee NWK key")
        case 0x5A415053: String(localized: "ZigBee APS key")
        case 0x55414B4C: String(localized: "OPC UA key log")
        default: String(localized: "Secrets type 0x\(String(secretsType, radix: 16, uppercase: true))")
        }
    }
}

// MARK: - CaptureBlockInventory

/// Counts of blocks Tracexy sees but does not interpret, so the Info window can
/// say what a file carries without pretending to have read it.
nonisolated struct CaptureBlockInventory: Sendable, Equatable {
    static let maxUnknownTypes = 8

    static let maxDecryptionSecrets = 32

    var nameResolutionBlockCount = 0
    var interfaceStatisticsBlockCount = 0
    var decryptionSecrets: [CaptureSecretsBlockSummary] = []
    var decryptionSecretsOmittedCount = 0
    var customBlockCount = 0
    /// Obsolete Packet Blocks (type 2) — not decoded as frames.
    var obsoletePacketBlockCount = 0
    var systemdJournalBlockCount = 0
    /// Block types this build does not recognise, with how many were seen.
    var unknownBlockTypes: [UInt32: Int] = [:]
    var unknownBlockOverflowCount = 0

    mutating func noteUnknown(type: UInt32) {
        if unknownBlockTypes[type] != nil || unknownBlockTypes.count < Self.maxUnknownTypes {
            unknownBlockTypes[type, default: 0] += 1
        } else {
            unknownBlockOverflowCount += 1
        }
    }

    mutating func noteSecrets(_ summary: CaptureSecretsBlockSummary) {
        if decryptionSecrets.count < Self.maxDecryptionSecrets {
            decryptionSecrets.append(summary)
        } else {
            decryptionSecretsOmittedCount += 1
        }
    }
}

// MARK: - CaptureSection

/// One pcapng section (Section Header Block) and the interfaces it declared.
/// Classic pcap is represented as a single synthetic section with one interface so
/// the Info window has one shape to render.
nonisolated struct CaptureSection: Sendable, Equatable, Identifiable {
    static let maxInterfaces = 64

    let id: Int
    let littleEndian: Bool
    let majorVersion: UInt16
    let minorVersion: UInt16
    var hardware: CaptureBoundedText?
    var operatingSystem: CaptureBoundedText?
    var application: CaptureBoundedText?
    var comments: CaptureBoundedTextList = .empty
    var interfaces: [CaptureInterface] = []
    /// Interface Description Blocks seen after ``maxInterfaces`` were retained.
    /// Their frames are still read; they are counted as ``unattributedFrameCount``.
    var interfaceOverflowCount = 0
    var blocks = CaptureBlockInventory()
    var frameCount = 0
    /// Frames referencing an interface beyond the retained bound.
    var unattributedFrameCount = 0
}

// MARK: - CaptureFileProperties

/// The bounded, immutable inventory of one capture file's container: what the
/// file *says about itself*, as distinct from what Tracexy decoded from its
/// frames. Folded once during the streaming read; never requires a second pass.
///
/// Everything here is either a small fixed value or bounded by the caps on the
/// nested types. No packet bytes, secrets, name-resolution records, or per-frame
/// history are retained.
nonisolated struct CaptureFileProperties: Sendable, Equatable {
    static let maxSections = 16

    let container: CaptureContainerFacts
    let sections: [CaptureSection]
    /// Section Header Blocks seen after ``maxSections`` were retained.
    let sectionOverflowCount: Int
    let fileSize: UInt64
    let totalFrames: Int
    let untimedFrameCount: Int
    /// Frames carrying at least one `opt_comment`.
    let commentedFrameCount: Int
    let firstTimestamp: Date?
    let lastTimestamp: Date?
    /// Frames whose timestamp was earlier than the previous timed frame's.
    let outOfOrderFrameCount: Int

    var isStrictlyTimeOrdered: Bool {
        outOfOrderFrameCount == 0
    }

    var elapsed: TimeInterval? {
        guard let firstTimestamp, let lastTimestamp else {
            return nil
        }
        return lastTimestamp.timeIntervalSince(firstTimestamp)
    }

    var interfaceCount: Int {
        sections.reduce(0) { $0 + $1.interfaces.count }
    }

    var allInterfaces: [CaptureInterface] {
        sections.flatMap(\.interfaces)
    }

    var blockInventory: CaptureBlockInventory {
        sections.reduce(into: CaptureBlockInventory()) { total, section in
            total.nameResolutionBlockCount += section.blocks.nameResolutionBlockCount
            total.interfaceStatisticsBlockCount += section.blocks.interfaceStatisticsBlockCount
            for secrets in section.blocks.decryptionSecrets {
                total.noteSecrets(secrets)
            }
            total.decryptionSecretsOmittedCount += section.blocks.decryptionSecretsOmittedCount
            total.customBlockCount += section.blocks.customBlockCount
            total.obsoletePacketBlockCount += section.blocks.obsoletePacketBlockCount
            total.systemdJournalBlockCount += section.blocks.systemdJournalBlockCount
            for (type, count) in section.blocks.unknownBlockTypes.sorted(by: { $0.key < $1.key }) {
                for _ in 0 ..< count {
                    total.noteUnknown(type: type)
                }
            }
            total.unknownBlockOverflowCount += section.blocks.unknownBlockOverflowCount
        }
    }

    /// Whether any file-authored text (comments, names, filters, hardware, OS,
    /// application) was retained — the Info window's privacy note keys off this.
    var carriesFileAuthoredText: Bool {
        sections.contains { section in
            section.hardware != nil || section.operatingSystem != nil || section.application != nil
                || !section.comments.isEmpty
                || section.interfaces.contains { interface in
                    interface.name != nil || interface.interfaceDescription != nil || interface.filter != nil
                        || interface.operatingSystem != nil || interface.hardware != nil || !interface.comments.isEmpty
                }
        } || commentedFrameCount > 0
    }
}

// MARK: - CaptureFilePropertiesAccumulator

/// Mutable fold owned by a stream reader. Readers call the `note…` methods as they
/// parse blocks and frames; the loader takes ``snapshot(fileSize:)`` once at the
/// terminal. Bounds are enforced here so no reader can grow the inventory.
nonisolated struct CaptureFilePropertiesAccumulator: Sendable {
    // MARK: Lifecycle

    init(container: CaptureContainerFacts) {
        self.container = container
    }

    // MARK: Internal

    private(set) var sections: [CaptureSection] = []
    private(set) var sectionOverflowCount = 0

    /// Begin a section. Returns `false` when the section bound is full; the reader
    /// still parses the section's frames but their interface facts are not retained.
    @discardableResult
    mutating func beginSection(littleEndian: Bool, majorVersion: UInt16, minorVersion: UInt16) -> Bool {
        guard sections.count < CaptureFileProperties.maxSections else {
            sectionOverflowCount += 1
            currentSectionRetained = false
            return false
        }
        sections.append(CaptureSection(
            id: sections.count,
            littleEndian: littleEndian,
            majorVersion: majorVersion,
            minorVersion: minorVersion
        ))
        currentSectionRetained = true
        return true
    }

    mutating func updateCurrentSection(_ body: (inout CaptureSection) -> Void) {
        guard currentSectionRetained, !sections.isEmpty else {
            return
        }
        body(&sections[sections.count - 1])
    }

    /// Register an interface for the current section. Returns `false` when the
    /// per-section interface bound is full.
    @discardableResult
    mutating func addInterface(_ interface: CaptureInterface) -> Bool {
        guard currentSectionRetained, !sections.isEmpty else {
            return false
        }
        let index = sections.count - 1
        guard sections[index].interfaces.count < CaptureSection.maxInterfaces else {
            sections[index].interfaceOverflowCount += 1
            return false
        }
        sections[index].interfaces.append(interface)
        return true
    }

    mutating func updateInterface(_ interfaceID: Int, _ body: (inout CaptureInterface) -> Void) {
        guard currentSectionRetained, !sections.isEmpty else {
            return
        }
        let index = sections.count - 1
        guard sections[index].interfaces.indices.contains(interfaceID) else {
            return
        }
        body(&sections[index].interfaces[interfaceID])
    }

    mutating func updateBlocks(_ body: (inout CaptureBlockInventory) -> Void) {
        guard currentSectionRetained, !sections.isEmpty else {
            return
        }
        body(&sections[sections.count - 1].blocks)
    }

    /// Fold one accepted frame.
    mutating func noteFrame(interfaceID: Int, timestamp: Date?, hasComment: Bool) {
        totalFrames += 1
        if hasComment {
            commentedFrameCount += 1
        }
        if let timestamp {
            if let last = lastTimestamp, timestamp < last {
                outOfOrderFrameCount += 1
            }
            firstTimestamp = firstTimestamp.map { min($0, timestamp) } ?? timestamp
            lastTimestamp = lastTimestamp.map { max($0, timestamp) } ?? timestamp
            previousTimestamp = timestamp
        } else {
            untimedFrameCount += 1
        }
        guard currentSectionRetained, !sections.isEmpty else {
            return
        }
        let index = sections.count - 1
        sections[index].frameCount += 1
        if sections[index].interfaces.indices.contains(interfaceID) {
            sections[index].interfaces[interfaceID].frameCount += 1
            if timestamp == nil {
                sections[index].interfaces[interfaceID].untimedFrameCount += 1
            }
        } else {
            sections[index].unattributedFrameCount += 1
        }
    }

    func snapshot(fileSize: UInt64) -> CaptureFileProperties {
        CaptureFileProperties(
            container: container,
            sections: sections,
            sectionOverflowCount: sectionOverflowCount,
            fileSize: fileSize,
            totalFrames: totalFrames,
            untimedFrameCount: untimedFrameCount,
            commentedFrameCount: commentedFrameCount,
            firstTimestamp: firstTimestamp,
            lastTimestamp: lastTimestamp,
            outOfOrderFrameCount: outOfOrderFrameCount
        )
    }

    // MARK: Private

    private let container: CaptureContainerFacts
    private var currentSectionRetained = false
    private var totalFrames = 0
    private var untimedFrameCount = 0
    private var commentedFrameCount = 0
    private var firstTimestamp: Date?
    private var lastTimestamp: Date?
    private var previousTimestamp: Date?
    private var outOfOrderFrameCount = 0
}
