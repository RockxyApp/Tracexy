import Foundation

/// Case-insensitive substring projection for already decoded protocol trees.
/// Matching a layer title or summary keeps its complete displayed subtree; field
/// matches keep only matching fields and the ancestors needed to reach them.
nonisolated enum DecodedLayerSearchProjection {
    static func filter(_ layers: [DecodedLayer], query: String) -> [DecodedLayer] {
        let normalizedQuery = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !normalizedQuery.isEmpty else {
            return layers
        }
        return layers.compactMap { layer in
            if layer.title.lowercased().contains(normalizedQuery)
                || layer.summary.lowercased().contains(normalizedQuery)
            {
                return layer
            }
            let matchingFields = layer.fields.filter {
                $0.name.lowercased().contains(normalizedQuery) || $0.value.lowercased().contains(normalizedQuery)
            }
            let matchingChildren = filter(layer.children, query: normalizedQuery)
            guard !matchingFields.isEmpty || !matchingChildren.isEmpty else {
                return nil
            }
            var projection = layer
            projection.fields = matchingFields
            projection.children = matchingChildren
            return projection
        }
    }
}
