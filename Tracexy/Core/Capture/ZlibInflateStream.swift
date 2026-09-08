import Foundation
import zlib

// MARK: - ZlibInflateStream

/// A resumable, chunk-at-a-time inflate stream over the system zlib.
///
/// Two things this type exists to guarantee:
///
///  * **No escaping pointers.** `z_stream.next_in`/`next_out` are only ever set
///    inside the `withUnsafe…` scopes that produced them and are cleared before
///    those scopes end, so zlib never holds a pointer into a Swift buffer across
///    calls. Unconsumed input is tracked by the *caller's* offset, not by a
///    pointer zlib kept.
///  * **Real validation.** gzip mode uses `inflateInit2` with `15 + 16`, so zlib
///    itself checks the member header (including reserved flag bits and the
///    optional name/comment/extra/header-CRC fields) and the trailing CRC-32 and
///    ISIZE. Tracexy does not reimplement any of that.
nonisolated final class ZlibInflateStream {
    // MARK: Lifecycle

    init(mode: Mode) throws {
        stream = z_stream()
        let status = inflateInit2_(&stream, mode.windowBits, zlibVersion(), Int32(MemoryLayout<z_stream>.size))
        guard status == Z_OK else {
            throw CaptureArchiveError.malformed("the decompressor could not be started")
        }
        isOpen = true
    }

    deinit {
        if isOpen {
            inflateEnd(&stream)
        }
    }

    // MARK: Internal

    enum Mode {
        /// A gzip member: zlib validates the header, CRC-32 and ISIZE.
        case gzip
        /// A raw deflate stream, as stored inside a ZIP entry — no header, no
        /// trailer; the ZIP central directory supplies the checksum and size.
        case rawDeflate

        // MARK: Internal

        var windowBits: Int32 {
            switch self {
            case .gzip: 15 + 16
            case .rawDeflate: -15
            }
        }
    }

    /// What one `step` achieved. `finished` means zlib reached the end of the
    /// current stream — for gzip that is one member, not necessarily the file.
    struct Outcome: Equatable {
        let consumed: Int
        let produced: Int
        let finished: Bool

        var madeProgress: Bool {
            consumed > 0 || produced > 0
        }
    }

    /// Runs one bounded inflate step: reads at most `available` bytes from
    /// `input[offset...]` and writes at most `output.count` bytes to `output`.
    func step(input: [UInt8], offset: Int, available: Int, into output: inout [UInt8]) throws -> Outcome {
        var status = Z_OK
        var consumed = 0
        var produced = 0
        let capacity = output.count
        input.withUnsafeBufferPointer { source in
            output.withUnsafeMutableBufferPointer { destination in
                guard let sourceBase = source.baseAddress, let destinationBase = destination.baseAddress else {
                    return
                }
                stream.next_in = UnsafeMutablePointer(mutating: sourceBase) + offset
                stream.avail_in = uInt(available)
                stream.next_out = destinationBase
                stream.avail_out = uInt(capacity)
                status = inflate(&stream, Z_NO_FLUSH)
                consumed = available - Int(stream.avail_in)
                produced = capacity - Int(stream.avail_out)
                // zlib must not keep a pointer into either Swift buffer.
                stream.next_in = nil
                stream.avail_in = 0
                stream.next_out = nil
                stream.avail_out = 0
            }
        }
        switch status {
        case Z_OK,
             Z_BUF_ERROR:
            return Outcome(consumed: consumed, produced: produced, finished: false)
        case Z_STREAM_END:
            return Outcome(consumed: consumed, produced: produced, finished: true)
        case Z_NEED_DICT:
            throw CaptureArchiveError.unsupportedFeature("a preset compression dictionary")
        case Z_DATA_ERROR:
            throw CaptureArchiveError.malformed("its compressed data failed zlib's own checks")
        case Z_MEM_ERROR:
            throw CaptureArchiveError.malformed("the decompressor ran out of memory")
        default:
            throw CaptureArchiveError.malformed("the decompressor stopped with status \(status)")
        }
    }

    /// Starts the next member of a concatenated gzip file on the same stream.
    func reset() throws {
        guard inflateReset(&stream) == Z_OK else {
            throw CaptureArchiveError.malformed("the decompressor could not start the next member")
        }
    }

    // MARK: Private

    private var stream: z_stream
    private var isOpen = false
}

// MARK: - ZlibChecksum

/// CRC-32 over a growing byte stream, computed by zlib so the polynomial and
/// bit order are never Tracexy's to get wrong.
nonisolated struct ZlibChecksum {
    // MARK: Internal

    /// The accumulated CRC-32, narrowed to the 32 bits a ZIP entry records.
    var value: UInt32 {
        UInt32(truncatingIfNeeded: accumulated)
    }

    mutating func update(_ buffer: [UInt8], offset: Int, count: Int) {
        guard count > 0 else {
            return
        }
        accumulated = buffer.withUnsafeBufferPointer { pointer in
            guard let base = pointer.baseAddress else {
                return accumulated
            }
            return crc32(accumulated, base + offset, uInt(count))
        }
    }

    // MARK: Private

    /// zlib's documented seed for "no bytes yet".
    private var accumulated: uLong = 0
}
