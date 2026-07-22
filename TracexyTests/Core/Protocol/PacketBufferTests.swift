import Foundation
import Testing
@testable import Tracexy

// MARK: - PacketBufferTests

/// Exercises the zero-copy, bounds-checked byte reader that every decoder sits on top of.
@Suite("PacketBuffer")
struct PacketBufferTests {
    // MARK: Internal

    @Test("length and isEmpty reflect the backing bytes")
    func lengthAndEmptiness() {
        let buffer = PacketBuffer(sample)
        #expect(buffer.length == 8)
        #expect(buffer.isEmpty == false)

        let empty = PacketBuffer([])
        #expect(empty.length == 0)
        #expect(empty.isEmpty)
    }

    @Test("u8 reads single bytes at the requested offset")
    func readU8() throws {
        let buffer = PacketBuffer(sample)
        #expect(try buffer.u8(0) == 0x01)
        #expect(try buffer.u8(3) == 0x04)
        #expect(try buffer.u8(7) == 0xDD)
    }

    @Test("u16 and u32 decode big-endian (network order)")
    func readBigEndian() throws {
        let buffer = PacketBuffer(sample)
        // 0x01, 0x02 -> 0x0102
        #expect(try buffer.u16(0) == 0x0102)
        // 0xCC, 0xDD -> 0xCCDD
        #expect(try buffer.u16(6) == 0xCCDD)
        // 0x01,0x02,0x03,0x04 -> 0x01020304
        #expect(try buffer.u32(0) == 0x01020304)
        // 0xAA,0xBB,0xCC,0xDD -> 0xAABBCCDD
        #expect(try buffer.u32(4) == 0xAABBCCDD)
    }

    @Test("u16le and u32le decode little-endian")
    func readLittleEndian() throws {
        let buffer = PacketBuffer(sample)
        // bytes 0x01,0x02 little-endian -> 0x0201
        #expect(try buffer.u16le(0) == 0x0201)
        // bytes 0xCC,0xDD little-endian -> 0xDDCC
        #expect(try buffer.u16le(6) == 0xDDCC)
        // 0x01,0x02,0x03,0x04 little-endian -> 0x04030201
        #expect(try buffer.u32le(0) == 0x04030201)
        // 0xAA,0xBB,0xCC,0xDD little-endian -> 0xDDCCBBAA
        #expect(try buffer.u32le(4) == 0xDDCCBBAA)
    }

    @Test("bytes copies the exact requested slice")
    func bytesCopiesSlice() throws {
        let buffer = PacketBuffer(sample)
        #expect(try buffer.bytes(2, 3) == [0x03, 0x04, 0xAA])
        #expect(try buffer.bytes(0, 8) == sample)
        // Zero-length copy is valid and yields an empty array.
        #expect(try buffer.bytes(4, 0).isEmpty)
    }

    @Test("subset is a zero-copy view that reindexes from its own start")
    func subsetReindexes() throws {
        let buffer = PacketBuffer(sample)
        let tail = try buffer.subset(from: 4)
        #expect(tail.length == 4)
        #expect(try tail.u8(0) == 0xAA)
        #expect(try tail.u32(0) == 0xAABBCCDD)

        // Bounded subset.
        let middle = try buffer.subset(from: 2, count: 2)
        #expect(middle.length == 2)
        #expect(try middle.u16(0) == 0x0304)

        // Nested subset composes offsets correctly.
        let nested = try tail.subset(from: 2)
        #expect(nested.length == 2)
        #expect(try nested.u8(0) == 0xCC)
        #expect(try nested.u8(1) == 0xDD)
    }

    @Test("default-count subset extends to the end of the parent view")
    func subsetToEnd() throws {
        let buffer = PacketBuffer(sample)
        let tail = try buffer.subset(from: 5)
        #expect(tail.length == 3)
        #expect(try tail.bytes(0, 3) == [0xBB, 0xCC, 0xDD])
    }

    @Test("u8 past the end throws outOfBounds")
    func u8OutOfBounds() {
        let buffer = PacketBuffer(sample)
        #expect(throws: PacketError.outOfBounds(offset: 8, need: 1, have: 8)) {
            _ = try buffer.u8(8)
        }
    }

    @Test("u16 straddling the end throws outOfBounds")
    func u16OutOfBounds() {
        let buffer = PacketBuffer(sample)
        // offset 7 needs 2 bytes but only 1 remains.
        #expect(throws: PacketError.outOfBounds(offset: 7, need: 2, have: 8)) {
            _ = try buffer.u16(7)
        }
    }

    @Test("u32 past the end throws outOfBounds")
    func u32OutOfBounds() {
        let buffer = PacketBuffer(sample)
        #expect(throws: PacketError.outOfBounds(offset: 6, need: 4, have: 8)) {
            _ = try buffer.u32(6)
        }
    }

    @Test("bytes beyond the end throws outOfBounds")
    func bytesOutOfBounds() {
        let buffer = PacketBuffer(sample)
        #expect(throws: PacketError.outOfBounds(offset: 6, need: 4, have: 8)) {
            _ = try buffer.bytes(6, 4)
        }
    }

    @Test("subset beyond the end throws outOfBounds")
    func subsetOutOfBounds() {
        let buffer = PacketBuffer(sample)
        #expect(throws: PacketError.outOfBounds(offset: 4, need: 6, have: 8)) {
            _ = try buffer.subset(from: 4, count: 6)
        }
    }

    @Test("negative offset throws rather than crashing")
    func negativeOffsetThrows() {
        let buffer = PacketBuffer(sample)
        #expect(throws: PacketError.self) {
            _ = try buffer.u8(-1)
        }
    }

    @Test("any out-of-bounds access throws PacketError, never traps")
    func genericOutOfBoundsThrows() {
        let buffer = PacketBuffer(sample)
        #expect(throws: PacketError.self) {
            _ = try buffer.u32(100)
        }
    }

    // MARK: Private

    // A known fixture with distinctive byte values so endianness mistakes are visible.
    // Indices:  0     1     2     3     4     5     6     7
    private let sample: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]
}
