import Foundation
import PDFKit
import SwiftUI
import Testing
@testable import Tracexy

/// Statistics windows save their charts and diagrams as PNG or PDF and their
/// tables as CSV. The Flow Graph PDF carries every frame, one page per 40.
@MainActor
struct StatisticsExportTests {
    // MARK: Internal

    @Test
    func flowGraphPDFPaginatesAndPNGRendersAtTwiceTheSize() throws {
        let rows = (1 ... 95).map { Self.row(UInt64($0), $0.isMultiple(of: 2) ? "10.0.0.5" : "192.0.2.1") }
        let graph = CaptureFlowGraph(rows: rows)
        #expect(graph.arrows.count == 95)
        let pageSize = FlowGraphPage.size(lanes: graph.lanes.count, rows: FlowGraphPage.rowsPerPage)
        let pages = stride(from: 0, to: graph.arrows.count, by: FlowGraphPage.rowsPerPage).map { start in
            AnyView(FlowGraphPage(
                lanes: graph.lanes,
                arrows: Array(graph.arrows[start ..< min(start + FlowGraphPage.rowsPerPage, graph.arrows.count)]),
                origin: graph.arrows.first?.timestamp
            ))
        }
        let pdf = try #require(StatisticsExport.pdfData(pages: pages, pageSize: pageSize))
        let document = try #require(PDFDocument(data: pdf))
        #expect(document.pageCount == 3)
        #expect(document.page(at: 0)?.bounds(for: .mediaBox).size == pageSize)
        #expect(document.page(at: 2)?.string?.contains("frame 95") == true)

        let size = FlowGraphPage.size(lanes: graph.lanes.count, rows: 10)
        let png = try #require(StatisticsExport.pngData(
            FlowGraphPage(lanes: graph.lanes, arrows: Array(graph.arrows.prefix(10)), origin: nil), size: size
        ))
        let image = try #require(NSBitmapImageRep(data: png))
        #expect(image.pixelsWide == Int(size.width * 2))
        #expect(image.pixelsHigh == Int(size.height * 2))
    }

    @Test
    func protocolHierarchyCSVIndentsByDepth() {
        let sessions = [
            Self.session("a", [.ethernet, .ipv4, .tcp, .tls], bytes: 300),
            Self.session("b", [.ethernet, .ipv4, .udp, .dns], bytes: 100),
        ]
        let csv = ProtocolHierarchyNode.csv(ProtocolHierarchy.roots(of: sessions), totalSessions: 2, totalBytes: 400)
        let lines = csv.components(separatedBy: "\r\n")
        #expect(lines.first == "Protocol,Sessions,Percent Sessions,Bytes,Percent Bytes")
        #expect(lines.contains { $0.hasPrefix("    TCP,1,50.00,300,75.00") })
        #expect(lines.contains { $0.hasPrefix("      TLS,1,50.00,300,75.00") })
    }

    // MARK: Private

    private static func row(_ ordinal: UInt64, _ source: String) -> CaptureFrameRow {
        CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(ordinal),
                timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(ordinal)),
                capturedLength: 60, originalLength: 60, linkType: LinkType.ethernet
            ),
            source: source, destination: source == "10.0.0.5" ? "192.0.2.1" : "10.0.0.5",
            protocolName: "TCP", info: "frame \(ordinal)", sessionID: nil, interfaceID: 0, hasComment: false
        )
    }

    private static func session(_ seed: String, _ stack: [ProtocolKind], bytes: Int) -> SessionSummary {
        SessionSummary(
            id: SessionBuilder.stableID("export-\(seed)"), startTime: nil, duration: nil, processName: nil,
            host: seed, sourceEndpoint: "10.0.0.5:5000", destinationEndpoint: "192.0.2.1:443",
            protocolStack: stack, status: .ok, latencyMilliseconds: nil, bytesUp: bytes, bytesDown: 0
        )
    }
}
