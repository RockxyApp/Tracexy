import Foundation

// MARK: - CaptureMetadataExportAccounting

/// Bounded metadata inventory facts used to report losses during PCAPNG export.
nonisolated enum CaptureMetadataExportAccounting {
    static func hasInventoryOverflow(_ properties: CaptureFileProperties) -> Bool {
        properties.sectionOverflowCount > 0 || properties.sections.contains { $0.interfaceOverflowCount > 0 }
    }

    static func omittedSectionMetadata(
        _ properties: CaptureFileProperties,
        excluding writtenSections: Set<Int>
    )
        -> Int
    {
        properties.sections.reduce(into: 0) { count, section in
            guard !writtenSections.contains(section.id) else {
                return
            }
            count += section.comments.values.count + section.comments.omittedCount
            count += [section.hardware, section.operatingSystem, section.application].compactMap { $0 }.count
        }
    }
}
