import Foundation

// MARK: - CaptureInfoSource

/// What the Get Info window describes: a saved file (managed or referenced) or
/// the live capture in progress.
enum CaptureInfoSource: Equatable {
    case saved(SavedCapture)
    case live(interface: String)
}

// MARK: - CaptureHashState

/// On-demand digest computation for the open capture.
enum CaptureHashState: Equatable {
    case idle
    case computing(fraction: Double?)
    case done(CaptureFileDigests)
    case failed(String)

    // MARK: Internal

    var isComputing: Bool {
        if case .computing = self {
            return true
        }
        return false
    }
}

// MARK: - CaptureInfoSnapshot

/// The immutable inputs of the Get Info window, projected once per render from
/// coordinator state. Every value is already typed and bounded; the view formats
/// and never computes.
struct CaptureInfoSnapshot: Equatable {
    let title: String
    let source: CaptureInfoSource
    let fileURL: URL?
    let properties: CaptureFileProperties?
    let activity: CaptureActivity?
    let metadata: CaptureMetadataSummary?
    let sessionCount: Int
    let visibleSessionCount: Int
    let warning: String?
    let captureStartedAt: Date?
    let hashState: CaptureHashState

    var isLive: Bool {
        if case .live = source {
            return true
        }
        return false
    }

    var fileName: String {
        fileURL?.lastPathComponent ?? title
    }

    /// The elapsed span between the first and last timed frame, or `nil` when
    /// unknown (no timed frames, or at least one untimed frame).
    var elapsed: TimeInterval? {
        activity?.duration
    }
}

// MARK: - CaptureInfoReport

/// Plain-text rendering of a snapshot for the Copy action. Same values as the
/// window, one "Key: value" line each, sections separated by a blank line.
enum CaptureInfoReport {
    static func text(for snapshot: CaptureInfoSnapshot) -> String {
        var lines: [String] = []
        func line(_ key: String, _ value: String?) {
            if let value, !value.isEmpty {
                lines.append("\(key): \(value)")
            }
        }
        lines.append("Capture: \(snapshot.title)")
        line("File", snapshot.fileURL?.path)
        if let properties = snapshot.properties {
            line("Format", CaptureInfoFormatting.format(properties))
            line("Size", CaptureInfoFormatting.bytes(properties.fileSize))
            line("Frames", properties.totalFrames.formatted())
            line("Untimed frames", properties.untimedFrameCount > 0 ? properties.untimedFrameCount.formatted() : nil)
            line(
                "Commented frames",
                properties.commentedFrameCount > 0 ? properties.commentedFrameCount.formatted() : nil
            )
            line("First frame", properties.firstTimestamp.map(CaptureInfoFormatting.instant))
            line("Last frame", properties.lastTimestamp.map(CaptureInfoFormatting.instant))
            line("Elapsed", properties.elapsed.map(CaptureInfoFormatting.elapsed))
            line(
                "Strict time order",
                properties.isStrictlyTimeOrdered ? "Yes" : "No (\(properties.outOfOrderFrameCount.formatted()) out of order)"
            )
            lines.append("")
            for section in properties.sections {
                lines
                    .append(
                        "Section \(section.id + 1) (\(section.littleEndian ? "little-endian" : "big-endian"), v\(section.majorVersion).\(section.minorVersion))"
                    )
                line("  Hardware", section.hardware?.text)
                line("  OS", section.operatingSystem?.text)
                line("  Application", section.application?.text)
                for comment in section.comments.values {
                    line("  Comment", comment.text)
                }
                for interface in section.interfaces {
                    lines.append("  Interface \(interface.id.interfaceID): \(interface.displayName)")
                    line("    Description", interface.interfaceDescription?.text)
                    line("    Link type", CaptureInfoFormatting.linkType(interface.linkType))
                    line("    Snapshot length", CaptureInfoFormatting.snapLength(interface.snapLength))
                    line("    Time resolution", CaptureInfoFormatting.resolution(interface.ticksPerSecond))
                    line("    Filter", interface.filter?.text)
                    line("    Frames", interface.frameCount.formatted())
                    if let statistics = interface.statistics {
                        line("    Received", statistics.received?.formatted())
                        line("    Dropped", statistics.dropped?.formatted())
                    }
                }
                lines.append("")
            }
            let blocks = properties.blockInventory
            line(
                "Name resolution blocks",
                blocks.nameResolutionBlockCount > 0 ? blocks.nameResolutionBlockCount.formatted() : nil
            )
            line(
                "Decryption secrets blocks",
                blocks.decryptionSecrets.isEmpty ? nil : blocks.decryptionSecrets.map(\.kindLabel)
                    .joined(separator: ", ")
            )
            line("Custom blocks", blocks.customBlockCount > 0 ? blocks.customBlockCount.formatted() : nil)
        }
        if case let .done(digests) = snapshot.hashState {
            line("SHA-256", digests.sha256)
            line("SHA-1", digests.sha1)
        }
        line("Sessions", snapshot.sessionCount.formatted())
        return lines.joined(separator: "\n")
    }
}

// MARK: - CaptureInfoFormatting

/// Formatting shared by the window and the report.
enum CaptureInfoFormatting {
    static func format(_ properties: CaptureFileProperties) -> String {
        switch properties.container {
        case let .pcap(facts):
            let resolution = facts.nanosecondResolution ? "nanosecond" : "microsecond"
            let order = facts.littleEndian ? "little-endian" : "big-endian"
            return "PCAP (libpcap), \(order), \(resolution)"
        case .pcapng:
            let sections = properties.sections.count + properties.sectionOverflowCount
            return sections > 1 ? "PCAPNG, \(sections.formatted()) sections" : "PCAPNG"
        }
    }

    static func bytes(_ count: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .file)
    }

    static func instant(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .standard)
    }

    static func elapsed(_ interval: TimeInterval) -> String {
        let total = Int(interval.rounded(.down))
        let days = total / 86_400
        let rest = total % 86_400
        let clock = String(format: "%02d:%02d:%02d", rest / 3_600, (rest % 3_600) / 60, rest % 60)
        let fraction = interval - interval.rounded(.down)
        let clockWithFraction = fraction > 0 ? clock + String(format: ".%03d", Int(fraction * 1_000)) : clock
        return days > 0 ? "\(days) day(s) \(clockWithFraction)" : clockWithFraction
    }

    static func snapLength(_ value: UInt32) -> String {
        value == 0 ? String(localized: "unlimited") : "\(value.formatted()) bytes"
    }

    static func resolution(_ ticksPerSecond: UInt64) -> String {
        switch ticksPerSecond {
        case 1_000_000: String(localized: "microseconds")
        case 1_000_000_000: String(localized: "nanoseconds")
        case 1_000: String(localized: "milliseconds")
        case 1: String(localized: "seconds")
        default: String(localized: "\(ticksPerSecond.formatted()) ticks per second")
        }
    }

    static func linkType(_ value: UInt32) -> String {
        let name: String? = switch value {
        case LinkType.null: "BSD loopback"
        case LinkType.ethernet: "Ethernet"
        case LinkType.raw: "Raw IP"
        case 105: "IEEE 802.11"
        case 113: "Linux cooked (SLL)"
        case 127: "802.11 Radiotap"
        case 228: "Raw IPv4"
        case 229: "Raw IPv6"
        case 276: "Linux cooked v2 (SLL2)"
        case 12,
             14: "Raw IP"
        default: nil
        }
        return name.map { "\($0) (\(value))" } ?? String(localized: "Link type \(value)")
    }
}
