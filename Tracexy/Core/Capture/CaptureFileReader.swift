import Foundation

/// Format-sniffing entry point for opening capture files: dispatches to
/// [`PcapngReader`] for pcapng (Wireshark's default) or [`PcapReader`] for the
/// classic `.pcap` format, based on the leading magic bytes rather than the
/// filename extension.
nonisolated enum CaptureFileReader {
    static func read(_ bytes: [UInt8]) throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        if PcapngReader.isPcapng(bytes) {
            return try PcapngReader.read(bytes)
        }
        return try PcapReader.read(bytes)
    }

    static func read(contentsOf url: URL) throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        try read([UInt8](Data(contentsOf: url)))
    }
}
