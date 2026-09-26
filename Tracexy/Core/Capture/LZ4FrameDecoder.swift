import Foundation

// MARK: - XXHash32

/// Streaming xxHash32 (seed 0), the checksum the LZ4 frame format uses for its
/// header, blocks and content.
nonisolated struct XXHash32 {
    // MARK: Lifecycle

    init(seed: UInt32 = 0) {
        self.seed = seed
        lanes = (seed &+ Self.prime1 &+ Self.prime2, seed &+ Self.prime2, seed, seed &- Self.prime1)
    }

    // MARK: Internal

    static func hash(_ bytes: ArraySlice<UInt8>) -> UInt32 {
        var state = XXHash32()
        state.update(bytes)
        return state.digest()
    }

    mutating func update(_ bytes: ArraySlice<UInt8>) {
        totalLength &+= UInt64(bytes.count)
        var input = bytes
        if !pending.isEmpty {
            let take = min(16 - pending.count, input.count)
            pending += input.prefix(take)
            input = input.dropFirst(take)
            guard pending.count == 16 else {
                return
            }
            consume(pending[...])
            pending.removeAll(keepingCapacity: true)
        }
        while input.count >= 16 {
            consume(input.prefix(16))
            input = input.dropFirst(16)
        }
        pending += input
    }

    func digest() -> UInt32 {
        var hash: UInt32 = if totalLength >= 16 {
            Self.rotl(lanes.0, 1) &+ Self.rotl(lanes.1, 7) &+ Self.rotl(lanes.2, 12) &+ Self.rotl(lanes.3, 18)
        } else {
            seed &+ Self.prime5
        }
        hash &+= UInt32(truncatingIfNeeded: totalLength)
        var index = pending.startIndex
        while index + 4 <= pending.endIndex {
            hash &+= Self.read32(pending, index) &* Self.prime3
            hash = Self.rotl(hash, 17) &* Self.prime4
            index += 4
        }
        while index < pending.endIndex {
            hash &+= UInt32(pending[index]) &* Self.prime5
            hash = Self.rotl(hash, 11) &* Self.prime1
            index += 1
        }
        hash ^= hash >> 15
        hash &*= Self.prime2
        hash ^= hash >> 13
        hash &*= Self.prime3
        hash ^= hash >> 16
        return hash
    }

    // MARK: Private

    private static let prime1: UInt32 = 2_654_435_761
    private static let prime2: UInt32 = 2_246_822_519
    private static let prime3: UInt32 = 3_266_489_917
    private static let prime4: UInt32 = 668_265_263
    private static let prime5: UInt32 = 374_761_393

    private let seed: UInt32
    private var lanes: (UInt32, UInt32, UInt32, UInt32)
    private var pending: [UInt8] = []
    private var totalLength: UInt64 = 0

    private static func rotl(_ value: UInt32, _ count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }

    private static func read32(_ bytes: [UInt8], _ index: Int) -> UInt32 {
        UInt32(bytes[index]) | UInt32(bytes[index + 1]) << 8 | UInt32(bytes[index + 2]) << 16
            | UInt32(bytes[index + 3]) << 24
    }

    private static func round(_ lane: UInt32, _ input: UInt32) -> UInt32 {
        rotl(lane &+ input &* prime2, 13) &* prime1
    }

    private mutating func consume(_ stripe: ArraySlice<UInt8>) {
        let bytes = Array(stripe)
        lanes.0 = Self.round(lanes.0, Self.read32(bytes, 0))
        lanes.1 = Self.round(lanes.1, Self.read32(bytes, 4))
        lanes.2 = Self.round(lanes.2, Self.read32(bytes, 8))
        lanes.3 = Self.round(lanes.3, Self.read32(bytes, 12))
    }
}

// MARK: - LZ4BlockDecoder

/// Decodes LZ4 blocks (the raw block format inside an LZ4 frame), keeping the last
/// 64 KiB of output so linked blocks — whose matches reach into the previous
/// block — decode as well as independent ones. Every offset and length is checked;
/// a malformed block throws instead of reading or writing out of bounds.
nonisolated struct LZ4BlockDecoder {
    // MARK: Internal

    enum Failure: Error, Equatable {
        case malformed(String)
        case blockTooLarge
    }

    static let windowLength = 65_536

    /// Decode one compressed block, appending at most `maximumOutput` bytes.
    mutating func decode(_ block: ArraySlice<UInt8>, maximumOutput: Int, linked: Bool) throws -> [UInt8] {
        if !linked {
            history.removeAll(keepingCapacity: true)
        }
        var output = history
        let base = output.count
        var index = block.startIndex
        let end = block.endIndex
        func readLength(_ start: Int) throws -> Int {
            var length = start
            guard start == 15 else {
                return length
            }
            while true {
                guard index < end else {
                    throw Failure.malformed("a length runs past the block")
                }
                let byte = Int(block[index])
                index += 1
                length += byte
                guard length <= maximumOutput else {
                    throw Failure.blockTooLarge
                }
                if byte != 255 {
                    return length
                }
            }
        }
        while index < end {
            let token = block[index]
            index += 1
            let literals = try readLength(Int(token >> 4))
            guard literals <= end - index else {
                throw Failure.malformed("literals run past the block")
            }
            guard output.count - base + literals <= maximumOutput else {
                throw Failure.blockTooLarge
            }
            output.append(contentsOf: block[index ..< index + literals])
            index += literals
            if index == end {
                break
            }
            guard end - index >= 2 else {
                throw Failure.malformed("a match offset is cut short")
            }
            let offset = Int(block[index]) | Int(block[index + 1]) << 8
            index += 2
            guard offset > 0, offset <= output.count else {
                throw Failure.malformed("a match points before the data")
            }
            let length = try readLength(Int(token & 0x0F)) + 4
            guard output.count - base + length <= maximumOutput else {
                throw Failure.blockTooLarge
            }
            var source = output.count - offset
            for _ in 0 ..< length {
                output.append(output[source])
                source += 1
            }
        }
        let produced = Array(output[base...])
        history = Array(output.suffix(Self.windowLength))
        return produced
    }

    /// A stored (uncompressed) block: nothing to decode, but a later linked block
    /// may still match into it.
    mutating func remember(_ bytes: [UInt8], linked: Bool) {
        history = linked ? Array((history + bytes).suffix(Self.windowLength)) : Array(bytes.suffix(Self.windowLength))
    }

    // MARK: Private

    private var history: [UInt8] = []
}
