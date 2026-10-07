import Foundation
import Observation

// MARK: - PacketBytesSubject

/// The bytes Show Packet Bytes was opened on, and where they came from.
struct PacketBytesSubject: Equatable {
    let title: String
    let bytes: [UInt8]
    /// The decode step the source suggests (a `Content-Encoding: gzip` body → gzip).
    var suggestedDecoding: PacketBytesDecoding = .none
    var suggestedPresentation: PacketBytesPresentation = .text
}

// MARK: - PacketBytesInspection

/// What the Show Packet Bytes window currently shows. Set by the route that opens
/// it; the window reads it. Capture data, so it is cleared with the capture.
@MainActor
@Observable
final class PacketBytesInspection {
    var subject: PacketBytesSubject?
    /// Bumped on every open so the window resets its pickers to the new suggestion.
    private(set) var revision = 0

    /// The decode step an HTTP `Content-Encoding` names, when Tracexy can undo it.
    nonisolated static func decoding(forContentEncoding encoding: String?) -> PacketBytesDecoding {
        switch encoding?.lowercased().trimmingCharacters(in: .whitespaces) {
        case "gzip",
             "x-gzip": .gzip
        case "deflate": .zlib
        default: .none
        }
    }

    /// The presentation a Content-Type suggests.
    nonisolated static func presentation(forContentType type: String?) -> PacketBytesPresentation {
        let type = type?.lowercased() ?? ""
        if type.contains("json") {
            return .json
        }
        if type.hasPrefix("image/") {
            return .image
        }
        return .text
    }

    func show(_ subject: PacketBytesSubject) {
        self.subject = subject
        revision &+= 1
    }
}
