import Foundation

// MARK: - CapturePacketOptionCopier

/// Retains packet options that remain independently valid when frames are
/// selected or transformed, and normalizes their headers to PCAPNG little-endian.
nonisolated enum CapturePacketOptionCopier {
    // MARK: Internal

    static func copyIndependentOptions(
        _ reference: CaptureFrameCommentReference,
        maxBytes: Int,
        preserveHash: Bool,
        reconstructedFlags: UInt32?,
        from handle: FileHandle
    )
        throws -> (bytes: Data, preservedAllOptions: Bool)
    {
        let range = reference.optionsRange
        guard range.lowerBound <= range.upperBound,
              range.upperBound - range.lowerBound <= UInt64(maxBytes) else
        {
            return (Data(), false)
        }
        try handle.seek(toOffset: range.lowerBound)
        let data = try handle.read(upToCount: Int(range.count)) ?? Data()
        guard data.count == Int(range.count) else {
            throw FrameExportError.identityMismatch
        }
        let bytes = [UInt8](data)
        var cursor = 0
        var copied = Data()
        var preservedAllOptions = true
        while cursor <= bytes.count, bytes.count - cursor >= 4 {
            let code = reference.littleEndian
                ? UInt16(bytes[cursor]) | (UInt16(bytes[cursor + 1]) << 8)
                : (UInt16(bytes[cursor]) << 8) | UInt16(bytes[cursor + 1])
            let length = reference.littleEndian
                ? UInt16(bytes[cursor + 2]) | (UInt16(bytes[cursor + 3]) << 8)
                : (UInt16(bytes[cursor + 2]) << 8) | UInt16(bytes[cursor + 3])
            cursor += 4
            if code == 0 {
                guard length == 0 else {
                    throw FrameExportError.identityMismatch
                }
                break
            }
            let valueLength = Int(length)
            let paddedLength = (valueLength + 3) & ~3
            guard paddedLength <= bytes.count - cursor else {
                throw FrameExportError.identityMismatch
            }
            if code == 1 || (code == 3 && preserveHash) {
                appendOption(code, value: bytes[cursor ..< cursor + valueLength], to: &copied)
            } else if code == 2 {
                guard valueLength == 4 else {
                    throw FrameExportError.identityMismatch
                }
                let sourceFlags = if reference.littleEndian {
                    UInt32(bytes[cursor]) | (UInt32(bytes[cursor + 1]) << 8)
                        | (UInt32(bytes[cursor + 2]) << 16) | (UInt32(bytes[cursor + 3]) << 24)
                } else {
                    UInt32(bytes[cursor]) << 24 | UInt32(bytes[cursor + 1]) << 16
                        | UInt32(bytes[cursor + 2]) << 8 | UInt32(bytes[cursor + 3])
                }
                if sourceFlags != reconstructedFlags {
                    preservedAllOptions = false
                }
            } else if code != 5 {
                // The packet ID option is reconstructed losslessly from the typed
                // reference; other unsupported or sequence-dependent options are
                // reported to the caller as omitted.
                preservedAllOptions = false
            }
            cursor += paddedLength
        }
        return (copied, preservedAllOptions)
    }

    // MARK: Private

    private static func appendOption(_ code: UInt16, value: ArraySlice<UInt8>, to data: inout Data) {
        append16(code, to: &data)
        append16(UInt16(value.count), to: &data)
        data.append(contentsOf: value)
        while data.count % 4 != 0 {
            data.append(0)
        }
    }

    private static func append16(_ value: UInt16, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }
}
