import Foundation

// MARK: - TracexyHelperProtocol

@objc
protocol TracexyHelperProtocol {
    /// Helper binary version, build number, protocol version.
    func getHelperInfo(withReply reply: @escaping (String, Int, Int) -> Void)

    /// Begin capturing with a typed, validated `configuration` (interface, snap
    /// length, promiscuous mode, optional BPF). Reply: (started, errorMessage).
    ///
    /// The helper re-validates the configuration and compiles any BPF against
    /// libpcap *before* replying, so an out-of-bounds value or a bad filter
    /// expression fails closed with a clear message and no capture is reported
    /// started. This is protocol v3 — the immutable `CaptureConfiguration` command
    /// surface replaced v2's bare `interface: String`. The app fails closed against
    /// an older helper (`getHelperInfo` classifies the protocol mismatch) rather
    /// than downgrading the start request.
    func startCapture(configuration: CaptureConfiguration, withReply reply: @escaping (Bool, String) -> Void)

    /// Stop the active capture and return the worker's final flushed batch plus
    /// final accounting. Returning this atomically avoids a stop→fetch race with
    /// the next capture generation.
    func stopCapture(withReply reply: @escaping (FrameBatchMessage) -> Void)

    /// Drain buffered frames as a typed, `NSSecureCoding` batch.
    ///
    /// Replaces the legacy `([Data], Int)` surface: every frame now carries its
    /// own libpcap timestamp, captured length, original on-wire length, and link
    /// type, and the batch carries the helper's cumulative buffer-drop count and
    /// `pcap_stats` accounting (see `FrameBatchMessage`). This is a protocol-v2
    /// change — the app fails closed against a v1 helper (`getHelperInfo` still
    /// classifies the mismatch) rather than falling back to an untyped drain.
    /// Process attribution stays an app-side enrichment (see `ProcessResolver`).
    func fetchFrames(withReply reply: @escaping (FrameBatchMessage) -> Void)
}

// MARK: - PktapHeader

/// Parser for the macOS PKTAP per-packet metadata header (DLT_PKTAP = 258).
/// pktap prefixes each captured frame with the originating process — the only
/// way passive capture can attribute traffic to an app. Lives in Shared so the
/// helper produces it and the app tests it. Layout per xnu `net/pktap.h`.
enum PktapHeader {
    // MARK: Internal

    struct Parsed {
        let frame: [UInt8]
        let innerDLT: UInt32
        let process: String
        let pid: Int32
        /// Effective PID — the *delegating* app for traffic carried by a daemon
        /// (e.g. nsurlsessiond). Prefer it when resolving the owning app.
        let effectivePID: Int32
        let interface: String
    }

    /// DLT value libpcap reports for a pktap capture.
    static let dlt: UInt32 = 258

    /// Splits a DLT_PKTAP packet into its wrapped frame + process metadata.
    static func parse(_ bytes: [UInt8]) -> Parsed? {
        guard bytes.count >= Field.minimumSize else {
            return nil
        }
        let headerLength = Int(u32le(bytes, Field.length))
        guard headerLength >= Field.minimumSize, headerLength <= bytes.count else {
            return nil
        }
        let pid = Int32(bitPattern: u32le(bytes, Field.pid))
        let effectivePID = headerLength >= Field.epid + 4
            ? Int32(bitPattern: u32le(bytes, Field.epid))
            : pid
        return Parsed(
            frame: Array(bytes[headerLength...]),
            innerDLT: u32le(bytes, Field.innerDLT),
            process: cString(bytes, at: Field.comm, max: 17),
            pid: pid,
            effectivePID: effectivePID,
            interface: cString(bytes, at: Field.ifName, max: 24)
        )
    }

    /// Derives a display app name from a process executable path:
    /// "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" → "Google Chrome".
    /// Falls back to the executable's file name for non-bundled daemons.
    static func appName(fromExecutablePath path: String) -> String {
        if let range = path.range(of: ".app/") {
            let bundlePath = String(path[..<range.lowerBound])
            return (bundlePath as NSString).lastPathComponent
        }
        return (path as NSString).lastPathComponent
    }

    // MARK: Private

    /// Field byte offsets within the (little-endian, host-order) header.
    /// `pth_svc` is uint32-aligned after the 17-byte `pth_comm`, so 3 bytes of
    /// padding push `pth_epid` to offset 84.
    private enum Field {
        static let length = 0 // uint32 pth_length (size of this header)
        static let innerDLT = 8 // uint32 pth_dlt (DLT of the wrapped frame)
        static let ifName = 12 // char[24] pth_ifname
        static let pid = 52 // int32 pth_pid
        static let comm = 56 // char[17] pth_comm (process name)
        static let epid = 84 // int32 pth_epid (effective / delegating process)
        static let minimumSize = 73 // through the end of pth_comm
    }

    private static func u32le(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func cString(_ bytes: [UInt8], at offset: Int, max: Int) -> String {
        var scalars: [UInt8] = []
        for index in offset ..< min(offset + max, bytes.count) {
            let byte = bytes[index]
            if byte == 0 {
                break
            }
            scalars.append(byte)
        }
        return String(bytes: scalars, encoding: .utf8) ?? ""
    }
}
