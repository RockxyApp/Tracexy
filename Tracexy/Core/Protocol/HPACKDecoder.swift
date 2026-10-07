import Foundation

// MARK: - HPACKHeader

/// One header field as HPACK carries it: lowercase name, raw value.
nonisolated struct HPACKHeader: Hashable, Sendable {
    let name: String
    let value: String

    /// RFC 7541 §4.1: the size a field takes in the dynamic table.
    var tableSize: Int {
        name.utf8.count + value.utf8.count + 32
    }
}

// MARK: - HPACKError

nonisolated enum HPACKError: Error, Equatable, Sendable {
    /// The block ended inside a field.
    case truncated
    /// An index names no static or dynamic entry.
    case invalidIndex(Int)
    /// An integer ran past what any real block carries.
    case integerOverflow
    /// A Huffman string had a bad code, padding longer than 7 bits, or padding that
    /// was not the end-of-string prefix.
    case invalidHuffman
    /// A dynamic table size update above the permitted maximum, or after the first
    /// field of a block.
    case invalidTableSizeUpdate(Int)
    /// A field or the decoded list ran past this reader's bounds.
    case tooLarge
}

// MARK: - HPACKDecoder

/// Decodes HPACK header blocks (RFC 7541) for one direction of one HTTP/2
/// connection, keeping that direction's dynamic table between blocks.
///
/// An observer, not an endpoint: it accepts any dynamic table size up to
/// ``maximumTableSizeLimit`` that a size update announces, because the SETTINGS the
/// peer sent may not be in the capture. After an error the table can no longer be
/// trusted, so callers stop decoding that direction.
nonisolated struct HPACKDecoder: Sendable {
    // MARK: Lifecycle

    init(maximumTableSize: Int = 4_096) {
        self.maximumTableSize = min(maximumTableSize, Self.maximumTableSizeLimit)
    }

    // MARK: Internal

    /// Largest table size this reader follows, whatever a peer announces.
    static let maximumTableSizeLimit = 1 << 20
    /// Bounds on one decoded block.
    static let maximumFieldBytes = 64 * 1_024
    static let maximumFields = 512
    static let maximumListBytes = 256 * 1_024

    private(set) var dynamicTable: [HPACKHeader] = []
    private(set) var dynamicTableSize = 0
    private(set) var maximumTableSize: Int

    /// Decode one complete header block (HEADERS or PUSH_PROMISE plus any
    /// CONTINUATION payloads, joined).
    mutating func decode(_ block: [UInt8]) throws(HPACKError) -> [HPACKHeader] {
        var index = 0
        var fields: [HPACKHeader] = []
        var listBytes = 0
        while index < block.count {
            let byte = block[index]
            if byte & 0x80 != 0 {
                // Indexed field (§6.1).
                let entry = try Self.integer(block, &index, prefixBits: 7)
                guard entry > 0 else {
                    throw .invalidIndex(0)
                }
                try fields.append(field(at: entry))
            } else if byte & 0x40 != 0 {
                // Literal with incremental indexing (§6.2.1).
                let header = try literal(block, &index, prefixBits: 6)
                insert(header)
                fields.append(header)
            } else if byte & 0x20 != 0 {
                // Dynamic table size update (§6.3): only before the first field.
                let size = try Self.integer(block, &index, prefixBits: 5)
                guard fields.isEmpty, size <= Self.maximumTableSizeLimit else {
                    throw .invalidTableSizeUpdate(size)
                }
                maximumTableSize = size
                evict(toFit: 0)
            } else {
                // Literal without indexing (0000) or never indexed (0001) (§6.2.2–3).
                try fields.append(literal(block, &index, prefixBits: 4))
            }
            if let last = fields.last {
                listBytes += last.tableSize
                guard fields.count <= Self.maximumFields, listBytes <= Self.maximumListBytes else {
                    throw .tooLarge
                }
            }
        }
        return fields
    }

    // MARK: Private

    /// §5.1: an integer with an N-bit prefix, starting at `index`.
    private static func integer(_ bytes: [UInt8], _ index: inout Int, prefixBits: Int) throws(HPACKError) -> Int {
        guard index < bytes.count else {
            throw .truncated
        }
        let mask = (1 << prefixBits) - 1
        var value = Int(bytes[index]) & mask
        index += 1
        guard value == mask else {
            return value
        }
        var shift = 0
        while true {
            guard index < bytes.count else {
                throw .truncated
            }
            let byte = Int(bytes[index])
            index += 1
            guard shift <= 28 else {
                throw .integerOverflow
            }
            value += (byte & 0x7F) << shift
            shift += 7
            if byte & 0x80 == 0 {
                return value
            }
        }
    }

    /// §5.2: a string literal, raw or Huffman-coded.
    private static func string(_ bytes: [UInt8], _ index: inout Int) throws(HPACKError) -> String {
        guard index < bytes.count else {
            throw .truncated
        }
        let huffman = bytes[index] & 0x80 != 0
        let length = try integer(bytes, &index, prefixBits: 7)
        guard length <= maximumFieldBytes else {
            throw .tooLarge
        }
        guard length <= bytes.count - index else {
            throw .truncated
        }
        let raw = bytes[index ..< index + length]
        index += length
        let decoded = huffman ? try HPACKHuffman.decode(raw) : Array(raw)
        guard decoded.count <= maximumFieldBytes else {
            throw .tooLarge
        }
        // Field values are octets; show non-UTF-8 ones byte for byte (RFC 9110 §5.5).
        return String(bytes: decoded, encoding: .utf8) ?? String(bytes: decoded, encoding: .isoLatin1) ?? ""
    }

    private func field(at index: Int) throws(HPACKError) -> HPACKHeader {
        let staticCount = HPACKTables.staticTable.count
        if index <= staticCount {
            return HPACKTables.staticTable[index - 1]
        }
        let dynamicIndex = index - staticCount - 1
        guard dynamicIndex < dynamicTable.count else {
            throw .invalidIndex(index)
        }
        return dynamicTable[dynamicIndex]
    }

    /// A literal field whose name is either indexed (non-zero prefix) or a string.
    private func literal(_ bytes: [UInt8], _ index: inout Int, prefixBits: Int) throws(HPACKError) -> HPACKHeader {
        let nameIndex = try Self.integer(bytes, &index, prefixBits: prefixBits)
        let name = if nameIndex == 0 {
            try Self.string(bytes, &index)
        } else {
            try field(at: nameIndex).name
        }
        let value = try Self.string(bytes, &index)
        return HPACKHeader(name: name, value: value)
    }

    /// §4.4: newest first; an entry larger than the whole table empties it.
    private mutating func insert(_ header: HPACKHeader) {
        let size = header.tableSize
        guard size <= maximumTableSize else {
            dynamicTable.removeAll()
            dynamicTableSize = 0
            return
        }
        evict(toFit: size)
        dynamicTable.insert(header, at: 0)
        dynamicTableSize += size
    }

    private mutating func evict(toFit incoming: Int) {
        while dynamicTableSize + incoming > maximumTableSize, let oldest = dynamicTable.popLast() {
            dynamicTableSize -= oldest.tableSize
        }
    }
}

// MARK: - HPACKHuffman

/// The canonical Huffman code of RFC 7541 Appendix B, decoded bit by bit through a
/// binary trie built once from ``HPACKTables``.
nonisolated enum HPACKHuffman {
    // MARK: Internal

    static func decode(_ bytes: ArraySlice<UInt8>) throws(HPACKError) -> [UInt8] {
        var output: [UInt8] = []
        output.reserveCapacity(bytes.count * 8 / 5)
        var node = 0
        // Bits read since the last complete symbol, and whether all were 1s: the
        // only valid padding is at most 7 bits of the end-of-string prefix.
        var pendingBits = 0
        var pendingAllOnes = true
        for byte in bytes {
            for shift in stride(from: 7, through: 0, by: -1) {
                let bit = Int((byte >> UInt8(shift)) & 1)
                let next = trie[node].children[bit]
                guard next >= 0 else {
                    throw .invalidHuffman
                }
                pendingBits += 1
                pendingAllOnes = pendingAllOnes && bit == 1
                if let symbol = trie[next].symbol {
                    // End-of-string inside the data is an error (§5.2).
                    guard symbol < 256 else {
                        throw .invalidHuffman
                    }
                    output.append(UInt8(symbol))
                    node = 0
                    pendingBits = 0
                    pendingAllOnes = true
                } else {
                    node = next
                }
            }
        }
        guard pendingBits <= 7, pendingAllOnes else {
            throw .invalidHuffman
        }
        return output
    }

    // MARK: Private

    private struct Node {
        var children = [-1, -1]
        var symbol: Int?
    }

    private static let trie: [Node] = {
        var nodes = [Node()]
        func add(_ code: UInt32, length: Int, symbol: Int) {
            var node = 0
            for position in stride(from: length - 1, through: 0, by: -1) {
                let bit = Int((code >> UInt32(position)) & 1)
                if nodes[node].children[bit] < 0 {
                    nodes.append(Node())
                    nodes[node].children[bit] = nodes.count - 1
                }
                node = nodes[node].children[bit]
            }
            nodes[node].symbol = symbol
        }
        for symbol in 0 ..< 256 {
            add(HPACKTables.huffmanCodes[symbol], length: Int(HPACKTables.huffmanLengths[symbol]), symbol: symbol)
        }
        add(HPACKTables.endOfStringCode, length: HPACKTables.endOfStringLength, symbol: 256)
        return nodes
    }()
}
