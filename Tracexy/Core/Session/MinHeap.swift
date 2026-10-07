import Foundation

// MARK: - MinHeap

/// A binary min-heap: `push` and `popMin` in O(log n), `min` in O(1). Used where a
/// bounded table must repeatedly find its least element without scanning it.
nonisolated struct MinHeap<Element: Comparable> {
    private(set) var elements: [Element] = []

    var count: Int {
        elements.count
    }

    var min: Element? {
        elements.first
    }

    mutating func push(_ element: Element) {
        elements.append(element)
        var child = elements.count - 1
        while child > 0 {
            let parent = (child - 1) / 2
            guard elements[child] < elements[parent] else {
                break
            }
            elements.swapAt(child, parent)
            child = parent
        }
    }

    @discardableResult
    mutating func popMin() -> Element? {
        guard !elements.isEmpty else {
            return nil
        }
        elements.swapAt(0, elements.count - 1)
        let smallest = elements.removeLast()
        var parent = 0
        while true {
            let left = 2 * parent + 1
            let right = left + 1
            var candidate = parent
            if left < elements.count, elements[left] < elements[candidate] {
                candidate = left
            }
            if right < elements.count, elements[right] < elements[candidate] {
                candidate = right
            }
            guard candidate != parent else {
                break
            }
            elements.swapAt(parent, candidate)
            parent = candidate
        }
        return smallest
    }

    /// Replaces the contents with `newElements`, heapified in O(n).
    mutating func rebuild(_ newElements: [Element]) {
        elements = newElements
        var index = elements.count / 2
        while index > 0 {
            index -= 1
            var parent = index
            while true {
                let left = 2 * parent + 1
                let right = left + 1
                var candidate = parent
                if left < elements.count, elements[left] < elements[candidate] {
                    candidate = left
                }
                if right < elements.count, elements[right] < elements[candidate] {
                    candidate = right
                }
                guard candidate != parent else {
                    break
                }
                elements.swapAt(parent, candidate)
                parent = candidate
            }
        }
    }
}
