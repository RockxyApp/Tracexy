import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - StatisticsImageFormat

/// The image formats a statistics chart or diagram saves as (Wireshark: PNG, PDF…).
enum StatisticsImageFormat: String, CaseIterable, Identifiable {
    case png
    case pdf

    // MARK: Internal

    var id: String {
        rawValue
    }

    var menuTitle: String {
        switch self {
        case .png: String(localized: "PNG Image…")
        case .pdf: String(localized: "PDF Document…")
        }
    }

    var fileExtension: String {
        rawValue
    }

    var contentType: UTType {
        switch self {
        case .png: .png
        case .pdf: .pdf
        }
    }
}

// MARK: - StatisticsExport

/// Saves what a statistics window shows: its data as text, or its chart as an image
/// rendered in the light appearance on white, as a document would print it. Each
/// call returns the failure to show, or `nil` when it saved or the user cancelled.
@MainActor
enum StatisticsExport {
    // MARK: Internal

    static func saveText(_ text: String, suggestedName: String, type: UTType = .commaSeparatedText) -> String? {
        guard let url = savePanel(suggestedName: suggestedName, type: type) else {
            return nil
        }
        do {
            try Data(text.utf8).write(to: url, options: .atomic)
            return nil
        } catch {
            return String(localized: "Couldn’t save: \(error.localizedDescription)")
        }
    }

    /// One image of `content` at `size` points.
    static func saveImage(
        _ content: some View,
        size: CGSize,
        format: StatisticsImageFormat,
        suggestedName: String
    )
        -> String?
    {
        guard let url = savePanel(suggestedName: suggestedName, type: format.contentType) else {
            return nil
        }
        let data: Data? = switch format {
        case .png: pngData(content, size: size)
        case .pdf: pdfData(pages: [AnyView(content)], pageSize: size)
        }
        return write(data, to: url)
    }

    /// A PDF with one page per view, each `pageSize` points.
    static func savePDF(pages: [AnyView], pageSize: CGSize, suggestedName: String) -> String? {
        guard let url = savePanel(suggestedName: suggestedName, type: .pdf) else {
            return nil
        }
        return write(pdfData(pages: pages, pageSize: pageSize), to: url)
    }

    static func pngData(_ content: some View, size: CGSize) -> Data? {
        let renderer = ImageRenderer(content: document(content, size: size))
        renderer.scale = 2
        guard let image = renderer.cgImage else {
            return nil
        }
        return NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    }

    static func pdfData(pages: [AnyView], pageSize: CGSize) -> Data? {
        let data = NSMutableData()
        var box = CGRect(origin: .zero, size: pageSize)
        guard let consumer = CGDataConsumer(data: data as CFMutableData),
              let context = CGContext(consumer: consumer, mediaBox: &box, nil) else
        {
            return nil
        }
        for page in pages {
            let renderer = ImageRenderer(content: document(page, size: pageSize))
            context.beginPDFPage(nil)
            renderer.render { _, draw in
                draw(context)
            }
            context.endPDFPage()
        }
        context.closePDF()
        return data as Data
    }

    // MARK: Private

    private static func document(_ content: some View, size: CGSize) -> some View {
        content
            .frame(width: size.width, height: size.height, alignment: .topLeading)
            .background(Color.white)
            .environment(\.colorScheme, .light)
    }

    private static func savePanel(suggestedName: String, type: UTType) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [type]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK else {
            return nil
        }
        return panel.url
    }

    private static func write(_ data: Data?, to url: URL) -> String? {
        guard let data else {
            return String(localized: "Couldn’t render the image.")
        }
        do {
            try data.write(to: url, options: .atomic)
            return nil
        } catch {
            return String(localized: "Couldn’t save: \(error.localizedDescription)")
        }
    }
}
