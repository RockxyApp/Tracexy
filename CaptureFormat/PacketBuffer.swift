import Foundation

// MARK: - PacketError

nonisolated enum PacketError: Error, Equatable {
    case outOfBounds(offset: Int, need: Int, have: Int)
    case malformed(String)
}

// MARK: - PacketBacking

/// Immutable byte store shared by all slices of a packet.
nonisolated final class PacketBacking: Sendable {
    // MARK: Lifecycle

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    // MARK: Internal

    let bytes: [UInt8]
}

// MARK: - PacketBuffer

nonisolated struct PacketBuffer {
    // MARK: Lifecycle

    init(_ bytes: [UInt8]) {
        backing = PacketBacking(bytes)
        start = 0
        length = bytes.count
    }

    private init(backing: PacketBacking, start: Int, length: Int) {
        self.backing = backing
        self.start = start
        self.length = length
    }

    // MARK: Internal

    let backing: PacketBacking
    let start: Int
    let length: Int

    var isEmpty: Bool {
        length == 0
    }

    /// Unsigned 8-bit at `offset`.
    func u8(_ offset: Int) throws -> UInt8 {
        try require(offset, 1)
        return backing.bytes[start + offset]
    }

    /// Unsigned 16-bit, big-endian (network order).
    func u16(_ offset: Int) throws -> UInt16 {
        try require(offset, 2)
        let i = start + offset
        return UInt16(backing.bytes[i]) << 8 | UInt16(backing.bytes[i + 1])
    }

    /// Unsigned 32-bit, big-endian (network order).
    func u32(_ offset: Int) throws -> UInt32 {
        try require(offset, 4)
        let i = start + offset
        return UInt32(backing.bytes[i]) << 24
            | UInt32(backing.bytes[i + 1]) << 16
            | UInt32(backing.bytes[i + 2]) << 8
            | UInt32(backing.bytes[i + 3])
    }

    /// Unsigned 16-bit, little-endian (used by the pcap file header).
    func u16le(_ offset: Int) throws -> UInt16 {
        try require(offset, 2)
        let i = start + offset
        return UInt16(backing.bytes[i + 1]) << 8 | UInt16(backing.bytes[i])
    }

    /// Unsigned 32-bit, little-endian.
    func u32le(_ offset: Int) throws -> UInt32 {
        try require(offset, 4)
        let i = start + offset
        return UInt32(backing.bytes[i + 3]) << 24
            | UInt32(backing.bytes[i + 2]) << 16
            | UInt32(backing.bytes[i + 1]) << 8
            | UInt32(backing.bytes[i])
    }

    /// Copy of `count` bytes from `offset` (only when bytes must leave the view).
    func bytes(_ offset: Int, _ count: Int) throws -> [UInt8] {
        try require(offset, count)
        let lo = start + offset
        return Array(backing.bytes[lo ..< lo + count])
    }

    /// Zero-copy sub-view from `offset`, `count` bytes (default: to end).
    func subset(from offset: Int, count: Int? = nil) throws -> PacketBuffer {
        let len = count ?? (length - offset)
        try require(offset, len)
        return PacketBuffer(backing: backing, start: start + offset, length: len)
    }

    // MARK: Private

    private func require(_ offset: Int, _ need: Int) throws {
        guard offset >= 0, need >= 0, offset + need <= length else {
            throw PacketError.outOfBounds(offset: offset, need: need, have: length)
        }
    }
}
