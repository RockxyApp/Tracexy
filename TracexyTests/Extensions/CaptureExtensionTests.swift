import CoreSpotlight
import Foundation
import SwiftUI
import Testing
@testable import Tracexy

// MARK: - CaptureExtensionTests

/// The Quick Look preview and Spotlight importer extensions compile their logic
/// into the test host so their output can be checked without the extension
/// hosts: the preview summary and its rendered image, and the indexed attributes.
struct CaptureExtensionTests {
    @Test
    func previewSummaryCarriesContainerFacts() throws {
        try ReplayCorpus.withTemporaryFile(CaptureContainerFixtures.showcasePcapng(), ext: "pcapng") { url in
            let summary = CapturePreviewSummary.scan(url)
            #expect(summary.fileName == url.lastPathComponent)
            #expect(summary.preview.status == .complete)
            #expect(summary.preview.records == ReplayCorpus.conversation().count + 1)
            #expect(summary.interfaces.map(\.displayName) == ["en0", "utun4"])
            #expect(summary.sectionApplication == "Tracexy fixture builder")
            #expect(summary.sectionComment == "Section comment one")
        }
    }

    @Test
    func previewSummaryForUnknownFileHasNoInterfaces() throws {
        try ReplayCorpus.withTemporaryFile(Array("not a capture".utf8), ext: "txt") { url in
            let summary = CapturePreviewSummary.scan(url)
            #expect(summary.preview.status == .unknownFormat)
            #expect(summary.interfaces.isEmpty)
        }
    }

    @MainActor
    @Test
    func previewViewRendersAnImage() throws {
        try ReplayCorpus.withTemporaryFile(CaptureContainerFixtures.showcasePcapng(), ext: "pcapng") { url in
            let summary = CapturePreviewSummary.scan(url)
            let renderer = ImageRenderer(content: CapturePreviewView(summary: summary).frame(width: 520, height: 320))
            renderer.scale = 2
            let image = try #require(renderer.nsImage)
            #expect(image.size.width == 520)
            #expect(image.size.height == 320)
            if let out = ProcessInfo.processInfo.environment["TRACEXY_PREVIEW_PNG"],
               let tiff = image.tiffRepresentation,
               let bitmap = NSBitmapImageRep(data: tiff),
               let png = bitmap.representation(using: .png, properties: [:])
            {
                try png.write(to: URL(fileURLWithPath: out))
            }
        }
    }

    @Test
    func spotlightImporterIndexesBoundedFactsOnly() throws {
        try ReplayCorpus.withTemporaryFile(CaptureContainerFixtures.showcasePcapng(), ext: "pcapng") { url in
            let attributes = CSSearchableItemAttributeSet(contentType: .data)
            try ImportExtension().update(attributes, forFileAt: url)
            let description = try #require(attributes.contentDescription)
            #expect(description.contains("PCAPNG"))
            #expect(description.contains("\(ReplayCorpus.conversation().count + 1) records"))
            #expect(description.contains("interfaces: en0, utun4"))
            #expect(description.contains("written by Tracexy fixture builder"))
            #expect(attributes.keywords?.contains("en0") == true)
            #expect(attributes.creator == "Tracexy fixture builder")
            #expect(attributes.contentCreationDate == ReplayCorpus.epoch
                .addingTimeInterval(TimeInterval(ReplayCorpus.conversation().map(\.offsetSeconds).min() ?? 0)))
            #expect(attributes.duration != nil)
            // Never index anything that could be a host name or address.
            #expect(!description.contains("example"))
            #expect(!description.contains("198.51"))
        }
    }

    @Test
    func spotlightImporterRefusesNonCaptures() throws {
        try ReplayCorpus.withTemporaryFile(Array("hello".utf8), ext: "pcap") { url in
            let attributes = CSSearchableItemAttributeSet(contentType: .data)
            #expect(throws: (any Error).self) {
                try ImportExtension().update(attributes, forFileAt: url)
            }
        }
    }
}
