import Foundation

// MARK: - DecodedByteMap

/// The byte → field half of the linked decode tree and hex pane: which field (or,
/// failing that, which layer) a frame byte belongs to, as Wireshark's bytes pane
/// answers when you point at or click a byte. The innermost owner wins — the
/// narrowest range, and among equal ranges a field over its layer and a deeper
/// layer over its parent.
enum DecodedByteMap {
    // MARK: Internal

    struct Hit: Equatable {
        /// The owning layer's title, then the field's name when a field owns the byte.
        let path: [String]
        let value: String?
        let range: Range<Int>

        /// "TCP, Source Port: 443" — the pointer line under the hex dump.
        var description: String {
            let name = path.joined(separator: ", ")
            return value.map { "\(name): \($0)" } ?? name
        }
    }

    /// The pointer line under the hex dump: the owning field and its bytes, e.g.
    /// "Transmission Control Protocol, Source Port: 443 (bytes 34–35)".
    static func pointerText(forByte index: Int, in layers: [DecodedLayer]) -> String {
        guard let owner = owner(ofByte: index, in: layers) else {
            return String(localized: "Byte \(String(index))")
        }
        let span = owner.range.count == 1
            ? String(localized: "byte \(String(owner.range.lowerBound))")
            : String(localized: "bytes \(String(owner.range.lowerBound))–\(String(owner.range.upperBound - 1))")
        return "\(owner.description) (\(span))"
    }

    static func owner(ofByte index: Int, in layers: [DecodedLayer]) -> Hit? {
        var best: (hit: Hit, rank: Int)?
        visit(layers, index: index, parents: [], depth: 0, best: &best)
        return best?.hit
    }

    // MARK: Private

    private static func visit(
        _ layers: [DecodedLayer],
        index: Int,
        parents: [String],
        depth: Int,
        best: inout (hit: Hit, rank: Int)?
    ) {
        for layer in layers {
            if let range = layer.byteRange, range.contains(index) {
                consider(Hit(path: parents + [layer.title], value: nil, range: range), rank: depth * 2, best: &best)
            }
            for field in layer.fields {
                guard let range = field.byteRange, range.contains(index) else {
                    continue
                }
                let hit = Hit(path: parents + [layer.title, field.name], value: field.value, range: range)
                consider(hit, rank: depth * 2 + 1, best: &best)
            }
            visit(layer.children, index: index, parents: parents + [layer.title], depth: depth + 1, best: &best)
        }
    }

    /// Narrower beats wider; at equal width the higher rank (field, deeper) wins.
    private static func consider(_ hit: Hit, rank: Int, best: inout (hit: Hit, rank: Int)?) {
        guard let current = best else {
            best = (hit, rank)
            return
        }
        if hit.range.count < current.hit.range.count
            || (hit.range.count == current.hit.range.count && rank > current.rank)
        {
            best = (hit, rank)
        }
    }
}
