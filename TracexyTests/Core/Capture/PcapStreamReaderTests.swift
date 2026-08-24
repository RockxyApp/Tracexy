import Foundation
import Testing
@testable import Tracexy

struct PcapStreamReaderTests {
    // MARK: Internal

    // MARK: - Metadata & endianness

    @Test
    func littleEndianMicrosecondMetadata() throws {
        let file = Self.file(magic: .littleMicro, records: [
            Record(payload: [0xDE, 0xAD], tsSec: 1_700_000_000, tsFrac: 500_000)
        ])
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)
            #expect(reader.metadata.linkType == 1)
            #expect(reader.metadata.snapLength == 65_535)
            #expect(reader.metadata.littleEndian)
            #expect(!reader.metadata.nanosecond)
            #expect(reader.metadata.firstRecordOffset == 24)
            #expect(reader.metadata.identity.size == UInt64(file.count))
        }
    }

    @Test
    func bigEndianMicrosecondMetadata() throws {
        let file = Self.file(magic: .bigMicro, records: [
            Record(payload: [0x01, 0x02, 0x03], tsSec: 1, tsFrac: 0)
        ])
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)
            #expect(reader.metadata.linkType == 1)
            #expect(!reader.metadata.littleEndian)
            #expect(!reader.metadata.nanosecond)
        }
    }

    @Test
    func nanosecondFractionDecodesForBothOrders() throws {
        for magic in [Magic.littleNano, Magic.bigNano] {
            let file = Self.file(magic: magic, records: [
                Record(payload: [0xAA], tsSec: 10, tsFrac: 250_000_000)
            ])
            try Self.withTempFile(file) { url in
                let reader = try PcapStreamReader(contentsOf: url)
                #expect(reader.metadata.nanosecond)
                let event = try Self.expectFrame(reader.next())
                let expected = Date(timeIntervalSince1970: 10.25)
                #expect(abs(event.reference.timestamp.timeIntervalSince1970 - expected.timeIntervalSince1970) < 1e-6)
            }
        }
    }

    // MARK: - Exact offsets, bytes, and progress

    @Test
    func exactOffsetsBytesAndProgress() throws {
        let first: [UInt8] = [0x11, 0x22, 0x33, 0x44]
        let second: [UInt8] = [0x55, 0x66]
        let file = Self.file(magic: .littleMicro, records: [
            Record(payload: first, tsSec: 5, tsFrac: 0, origLen: 9),
            Record(payload: second, tsSec: 6, tsFrac: 0)
        ])
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)

            let firstEvent = try Self.expectFrame(reader.next())
            #expect(firstEvent.bytes == first)
            #expect(firstEvent.reference.recordHeaderOffset == 24)
            #expect(firstEvent.reference.payloadOffset == 40)
            #expect(firstEvent.reference.capturedLength == first.count)
            #expect(firstEvent.reference.originalLength == 9)
            #expect(firstEvent.progress.bytesConsumed == UInt64(40 + first.count))
            #expect(firstEvent.progress.totalBytes == UInt64(file.count))

            let secondEvent = try Self.expectFrame(reader.next())
            #expect(secondEvent.bytes == second)
            // header follows the first payload: 40 + 4 == 44
            #expect(secondEvent.reference.recordHeaderOffset == UInt64(40 + first.count))
            #expect(secondEvent.reference.payloadOffset == UInt64(40 + first.count + 16))
            #expect(secondEvent.progress.bytesConsumed > firstEvent.progress.bytesConsumed)
            #expect(secondEvent.progress.bytesConsumed == UInt64(40 + first.count + 16 + second.count))
            #expect(secondEvent.progress.totalBytes == UInt64(file.count))
        }
    }

    // MARK: - Terminals

    @Test
    func cleanEndOfFileAfterLastFrame() throws {
        let file = Self.file(magic: .littleMicro, records: [
            Record(payload: [0x01], tsSec: 1, tsFrac: 0)
        ])
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)
            _ = try Self.expectFrame(reader.next())
            let expected = PcapStreamCompletion(
                reason: .cleanEndOfFile,
                progress: PcapStreamProgress(
                    bytesConsumed: UInt64(file.count),
                    totalBytes: UInt64(file.count)
                )
            )
            #expect(try reader.next() == .end(expected))
            // Terminal is replayed on further pulls.
            #expect(try reader.next() == .end(expected))
        }
    }

    @Test
    func partialRecordHeaderTerminal() throws {
        var file = Self.file(magic: .littleMicro, records: [
            Record(payload: [0x01, 0x02], tsSec: 1, tsFrac: 0)
        ])
        file += [0xAA, 0xBB, 0xCC, 0xDD, 0xEE] // 5 stray bytes: less than a 16-byte header
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)
            _ = try Self.expectFrame(reader.next())
            let end = try Self.expectEnd(reader.next())
            #expect(end.reason == .partialRecordHeader)
            #expect(end.progress.bytesConsumed == UInt64(file.count))
            #expect(end.progress.totalBytes == UInt64(file.count))
        }
    }

    @Test
    func partialPayloadTerminalPreservesPriorFrame() throws {
        // A complete record header declaring 16 bytes, but only 4 payload bytes present.
        var file = Self.file(magic: .littleMicro, records: [
            Record(payload: [0x01, 0x02], tsSec: 1, tsFrac: 0)
        ])
        file += Self.leRecordHeader(tsSec: 2, tsFrac: 0, inclLen: 16, origLen: 16)
        file += [0x09, 0x08, 0x07, 0x06]
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)
            let event = try Self.expectFrame(reader.next())
            #expect(event.bytes == [0x01, 0x02])
            let end = try Self.expectEnd(reader.next())
            #expect(end.reason == .partialPayload)
            #expect(end.progress.bytesConsumed == UInt64(file.count))
            #expect(end.progress.totalBytes == UInt64(file.count))
        }
    }

    // MARK: - Malformed metadata

    @Test
    func unknownMagicThrows() throws {
        var file: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        file += [UInt8](repeating: 0, count: 20)
        try Self.withTempFile(file) { url in
            #expect(throws: PacketError.self) {
                _ = try PcapStreamReader(contentsOf: url)
            }
        }
    }

    @Test
    func shortGlobalHeaderThrows() throws {
        let file: [UInt8] = [0xD4, 0xC3, 0xB2, 0xA1]
        try Self.withTempFile(file) { url in
            #expect(throws: PacketError.self) {
                _ = try PcapStreamReader(contentsOf: url)
            }
        }
    }

    @Test
    func invalidMicrosecondFractionThrows() throws {
        let file = Self.file(magic: .littleMicro, records: [
            Record(payload: [0x01], tsSec: 1, tsFrac: 2_000_000)
        ])
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func invalidNanosecondFractionThrows() throws {
        let file = Self.file(magic: .littleNano, records: [
            Record(payload: [0x01], tsSec: 1, tsFrac: 2_000_000_000)
        ])
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func originalLengthBelowCapturedLengthThrows() throws {
        var file = Self.leGlobalHeader()
        file += Self.leRecordHeader(tsSec: 1, tsFrac: 0, inclLen: 8, origLen: 7)
        file += [UInt8](repeating: 0xAB, count: 8)
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(contentsOf: url)
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func overLimitCapturedLengthRejectedBeforeAllocation() throws {
        // Declare a 100-byte payload but ship none of it. A cap of 4 must reject
        // the record on its header alone, before any payload read/allocation.
        var file = Self.leGlobalHeader()
        file += Self.leRecordHeader(tsSec: 1, tsFrac: 0, inclLen: 100, origLen: 100)
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(
                contentsOf: url,
                configuration: .init(maxCapturedLength: 4)
            )
            #expect(throws: PacketError.self) {
                _ = try reader.next()
            }
        }
    }

    // MARK: - Cancellation

    @Test
    func injectedCancellationBeforeIOThrows() throws {
        let file = Self.file(magic: .littleMicro, records: [
            Record(payload: [0x01], tsSec: 1, tsFrac: 0)
        ])
        try Self.withTempFile(file) { url in
            let reader = try PcapStreamReader(
                contentsOf: url,
                configuration: .init(isCancelled: { true })
            )
            #expect(throws: CancellationError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func injectedCancellationBetweenHeaderAndPayloadThrows() throws {
        let file = Self.file(magic: .littleMicro, records: [
            Record(payload: [0x01, 0x02, 0x03], tsSec: 1, tsFrac: 0)
        ])
        try Self.withTempFile(file) { url in
            // Cancel only on the second consultation: the first (pre-IO) check
            // passes so the header is read, the second (pre-payload) check trips.
            let calls = Counter()
            let reader = try PcapStreamReader(
                contentsOf: url,
                configuration: .init(isCancelled: { calls.next() == 2 })
            )
            #expect(throws: CancellationError.self) {
                _ = try reader.next()
            }
            // The injected predicate is false again, but the descriptor already
            // consumed a record header. The reader must stay poisoned rather than
            // reinterpret payload bytes as the next header.
            #expect(throws: CancellationError.self) {
                _ = try reader.next()
            }
        }
    }

    @Test
    func defaultCancellationHonoursCurrentTask() async throws {
        let file = Self.file(magic: .littleMicro, records: [
            Record(payload: [0x01], tsSec: 1, tsFrac: 0)
        ])
        let url = try Self.makeTempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(file).write(to: url)

        let cancelled = await Task {
            // Building the reader happens before cancellation; only next() consults
            // the default Task.isCancelled predicate.
            guard let reader = try? PcapStreamReader(contentsOf: url) else {
                return false
            }
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                _ = try reader.next()
                return false
            } catch is CancellationError {
                return true
            } catch {
                return false
            }
        }.value
        #expect(cancelled)
    }

    @Test
    func sparseMultiGigabyteFileStartsIncrementallyAndCancels() throws {
        let payload: [UInt8] = [0x01]
        let prefix = Self.file(magic: .littleMicro, records: [
            Record(payload: payload, tsSec: 1, tsFrac: 0)
        ])
        let url = try Self.makeTempURL()
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(prefix).write(to: url)

        let sparseSize: UInt64 = 4 * 1_024 * 1_024 * 1_024
        let writer = try FileHandle(forWritingTo: url)
        try writer.truncate(atOffset: sparseSize)
        try writer.close()

        let calls = Counter()
        let reader = try PcapStreamReader(
            contentsOf: url,
            configuration: .init(isCancelled: { calls.next() >= 3 })
        )
        #expect(reader.metadata.identity.size == sparseSize)

        let event = try Self.expectFrame(reader.next())
        #expect(event.bytes == payload)
        #expect(event.progress.bytesConsumed == UInt64(prefix.count))
        #expect(event.progress.totalBytes == sparseSize)

        // The third cancellation consultation occurs before the next record IO,
        // so opening/cancelling never walks or allocates the sparse 4 GiB tail.
        #expect(throws: CancellationError.self) {
            _ = try reader.next()
        }
    }

    // MARK: Private

    // MARK: - Fixtures

    /// Lock-guarded so the `@Sendable` cancellation closure may capture it; the
    /// test itself only ever calls it on one thread.
    private final class Counter: @unchecked Sendable {
        // MARK: Internal

        func next() -> Int {
            lock.lock()
            defer { lock.unlock() }
            count += 1
            return count
        }

        // MARK: Private

        private let lock = NSLock()
        private var count = 0
    }

    private enum Magic {
        case littleMicro
        case bigMicro
        case littleNano
        case bigNano

        // MARK: Internal

        var isLittleEndian: Bool {
            switch self {
            case .littleMicro,
                 .littleNano: true
            case .bigMicro,
                 .bigNano: false
            }
        }
    }

    private struct Record {
        // MARK: Lifecycle

        init(payload: [UInt8], tsSec: UInt32, tsFrac: UInt32, origLen: UInt32? = nil) {
            self.payload = payload
            self.tsSec = tsSec
            self.tsFrac = tsFrac
            self.origLen = origLen
        }

        // MARK: Internal

        let payload: [UInt8]
        let tsSec: UInt32
        let tsFrac: UInt32
        var origLen: UInt32?
    }

    private static func expectFrame(_ outcome: PcapStreamOutcome) throws -> PcapFrameEvent {
        guard case let .frame(event) = outcome else {
            Issue.record("expected a frame, got \(outcome)")
            throw CancellationError()
        }
        return event
    }

    private static func expectEnd(_ outcome: PcapStreamOutcome) throws -> PcapStreamCompletion {
        guard case let .end(completion) = outcome else {
            Issue.record("expected an end, got \(outcome)")
            throw CancellationError()
        }
        return completion
    }

    // MARK: - Byte builders

    private static func le32(_ value: UInt32) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)]
    }

    private static func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
    }

    private static func be32(_ value: UInt32) -> [UInt8] {
        [UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    private static func be16(_ value: UInt16) -> [UInt8] {
        [UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    private static func leGlobalHeader() -> [UInt8] {
        globalHeader(magic: .littleMicro)
    }

    private static func globalHeader(magic: Magic) -> [UInt8] {
        let little = magic.isLittleEndian
        let rawMagic: UInt32 = switch magic {
        case .bigMicro: 0xA1B2C3D4
        case .littleMicro: 0xD4C3B2A1
        case .bigNano: 0xA1B23C4D
        case .littleNano: 0x4D3CB2A1
        }
        // The magic is laid down so a big-endian read of the raw bytes yields the
        // documented constant, regardless of the file's declared order.
        var header = be32(rawMagic)
        if little {
            header += le16(2) + le16(4)
            header += le32(0) + le32(0)
            header += le32(65_535)
            header += le32(1)
        } else {
            header += be16(2) + be16(4)
            header += be32(0) + be32(0)
            header += be32(65_535)
            header += be32(1)
        }
        return header
    }

    private static func leRecordHeader(tsSec: UInt32, tsFrac: UInt32, inclLen: UInt32, origLen: UInt32) -> [UInt8] {
        le32(tsSec) + le32(tsFrac) + le32(inclLen) + le32(origLen)
    }

    private static func record(_ record: Record, little: Bool) -> [UInt8] {
        let incl = UInt32(record.payload.count)
        let orig = record.origLen ?? incl
        if little {
            return le32(record.tsSec) + le32(record.tsFrac) + le32(incl) + le32(orig) + record.payload
        }
        return be32(record.tsSec) + be32(record.tsFrac) + be32(incl) + be32(orig) + record.payload
    }

    private static func file(magic: Magic, records: [Record]) -> [UInt8] {
        let little = magic.isLittleEndian
        var bytes = globalHeader(magic: magic)
        for entry in records {
            bytes += record(entry, little: little)
        }
        return bytes
    }

    // MARK: - Temp files

    private static func makeTempURL() throws -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("pcapstream-\(UUID().uuidString).pcap")
    }

    private static func withTempFile(_ bytes: [UInt8], _ body: (URL) throws -> Void) throws {
        let url = try makeTempURL()
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }
}
