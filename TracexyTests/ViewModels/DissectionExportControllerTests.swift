import Testing
@testable import Tracexy

// MARK: - DissectionExportControllerTests

@MainActor
@Suite("Dissection export outcomes")
struct DissectionExportControllerTests {
    @Test("Zero-row export reports the selected capture scope")
    func emptyScopeWarnings() {
        let empty = DissectionExporter.Summary(writtenFrameCount: 0, scannedFrameCount: 4)
        #expect(DissectionExportController.dissectionExportWarning(
            summary: empty, markedOnly: true, hasFrameSelection: false, hasFrameExpression: false
        )?.contains("No marked frame") == true)
        #expect(DissectionExportController.dissectionExportWarning(
            summary: empty, markedOnly: false, hasFrameSelection: false, hasFrameExpression: false
        )?.contains("sessions in view") == true)
        #expect(DissectionExportController.dissectionExportWarning(
            summary: empty, markedOnly: false, hasFrameSelection: true, hasFrameExpression: false
        )?.contains("selected capture range") == true)
        #expect(DissectionExportController.dissectionExportWarning(
            summary: .init(writtenFrameCount: 0, scannedFrameCount: 4, excludedIgnoredFrameCount: 4),
            markedOnly: false, hasFrameSelection: true, hasFrameExpression: false
        )?.contains("ignored frame(s) were excluded") == true)
        #expect(DissectionExportController.dissectionExportWarning(
            summary: .init(
                writtenFrameCount: 0, scannedFrameCount: 4,
                unknownExpressionFrameCount: 2, excludedIgnoredFrameCount: 1
            ),
            markedOnly: false, hasFrameSelection: false, hasFrameExpression: true
        )?.contains("2 frame(s) could not be evaluated and 1 ignored frame(s) were excluded") == true)
    }

    @Test("Expression outcomes distinguish no match and unknown frames")
    func expressionWarnings() {
        let noMatch = DissectionExporter.Summary(writtenFrameCount: 0, scannedFrameCount: 4)
        #expect(DissectionExportController.dissectionExportWarning(
            summary: noMatch, markedOnly: false, hasFrameSelection: false, hasFrameExpression: true
        )?.contains("No frame matched") == true)

        let unknown = DissectionExporter.Summary(
            writtenFrameCount: 0, scannedFrameCount: 4, unknownExpressionFrameCount: 2
        )
        #expect(DissectionExportController.dissectionExportWarning(
            summary: unknown, markedOnly: false, hasFrameSelection: false, hasFrameExpression: true
        )?.contains("2 frame(s) could not be evaluated") == true)
        #expect(DissectionExportController.dissectionExportWarning(
            summary: .init(writtenFrameCount: 1, scannedFrameCount: 4, unknownExpressionFrameCount: 2),
            markedOnly: false, hasFrameSelection: false, hasFrameExpression: true
        )?.contains("2 frame(s) could not be evaluated") == true)
        #expect(DissectionExportController.dissectionExportWarning(
            summary: .init(
                writtenFrameCount: 1, scannedFrameCount: 4,
                unknownExpressionFrameCount: 2, excludedIgnoredFrameCount: 1
            ),
            markedOnly: false, hasFrameSelection: false, hasFrameExpression: true
        )?.contains("1 ignored frame(s) were excluded") == true)
    }
}
